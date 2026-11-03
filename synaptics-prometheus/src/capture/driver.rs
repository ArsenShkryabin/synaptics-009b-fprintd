//! `CaptureSession` — the arm + read + teardown + re-arm state machine (Stage 3).
//!
//! One owner for a live capture over a [`Session`]: it holds the resolved [`CaptureConfig`] +
//! calibration inputs, remembers the arm currently on the sensor, and drives the two read contracts
//! ([`ReadMode::Polled`] `0x51` vs the EP-0x82 stream/[`ReadMode::Calibrate`]) through the existing
//! `Session` primitives. Modeled on [`run_wof`](super::run_wof) — the only other place arm + read +
//! teardown were unified — but generalized to the frame paths.
//!
//! By construction it enforces the four guarantees the ad-hoc viewer/example plumbing kept getting
//! wrong (see `docs/…` / the capture-spec refactor plan):
//!  1. **Re-arm iff the program changed.** [`plan_rearm`] compares the *serialized* program (so a
//!     hand-edited arm-lab program re-arms too) and the read mode; on a change it tears the previous
//!     mode down *first* (the "hang on Path switch" fix) before arming the new one.
//!  2. **Arm-once freeze.** An unchanged polled program whose frame is already captured returns the
//!     cached frame with no re-poll (the "jumping boxes" fix).
//!  3. **One fault-reaction site.** A capture fault ([`Status::requests_sensor_reboot_retry`] / a
//!     short stream frame) triggers exactly one reboot + re-arm, here — not scattered across callers.
//!  4. **Teardown on drop.** [`Drop`] tears the armed mode down on every exit path, so a read can
//!     never leak the sensor armed.
//!
//! The two read contracts are **kept separate, never merged** (Rule: sibling paths disagree): polled
//! goes through [`Session::capture_vfm_polled`] (finger latch, `0x51`), stream/calibrate through
//! [`FrameCapturer::capture_one`] (EP-0x82 bulk, re-armed per frame).

use crate::calibration::CalResults;
use crate::capture::{
    CaptureControl, CaptureIo, FrameCapturer, MatcherSubmode, PolledFrame, RawFrame, ReadMode,
};
use crate::capture_prog::{ArmProgram, ArmSpec, CaptureConfig};
use crate::capture_pipeline::UploadCmdBuildPath;
use crate::error::{Result, Status};
use crate::pre_arm::PreArmMode;
use crate::session::Session;
use crate::transport::Transport;

/// Settle delay after a `0x05` soft reboot before the sensor re-enumerates and accepts a re-arm
/// (same value the scattered recovery sites used — see [`Session::capture_one_recovering`]).
const REBOOT_SETTLE: std::time::Duration =
    std::time::Duration::from_millis(crate::session::REBOOT_SETTLE_MS);

/// Arm status words that mean "armed OK, a frame may follow" (`0x0000` accepted, `0x0412` armed).
/// Shared by both read paths (matches [`RawFrame::is_ok`] and the polled example's `status != 0`).
fn armed_ok(status: u16) -> bool {
    matches!(status, 0x0000 | 0x0412)
}

/// The read contract + read-shaped parameters for one [`CaptureSession::capture`] call. Everything a
/// path needs beyond the [`ArmProgram`] bytes themselves.
#[derive(Debug, Clone, Copy)]
pub struct CaptureOpts {
    /// Which read contract to drive (also selects the teardown/dearm sequence).
    pub read: ReadMode,
    /// Pre-arm ROM config to send before the arm — `Some(mode)` for identify/enroll (the DLL sends
    /// the pre-arm as the arm's first op), `None` for stream/calibrate frames-sync, which the DLL
    /// never pre-arms. Sending a per-frame pre-arm on the re-arming stream path gets the sensor's
    /// second `0x06` rejected `0x04aa` (same wrong-state as calibration; see `session_cal.rs`).
    pub pre_arm: Option<PreArmMode>,
    /// Polled: matcher submode for [`Session::capture_vfm_polled`].
    pub submode: MatcherSubmode,
    /// Polled: gate the first `0x51` behind the touch latch (finger-present wait).
    pub finger_gate: bool,
    /// Reboot + re-arm **once** on a capture fault. Off for pure arm probes.
    pub recover: bool,
    /// Force a fresh arm even when the program/mode is unchanged — the "re-arm every frame" mode
    /// (viewer `arm_once = false`): a new arm is what yields a fresh polled still without drifting
    /// the cursor. `false` keeps the arm-once freeze (guarantee #2).
    pub force_rearm: bool,
    /// Stream/Calibrate: sync-frame count driving the EP-0x82 buffer geometry + `req_lines`.
    pub sync_frames: u32,
}

impl CaptureOpts {
    /// Polled `0x51` identify/enroll read with fault recovery on.
    pub fn polled(submode: MatcherSubmode, finger_gate: bool) -> Self {
        Self {
            read: ReadMode::Polled,
            // read_mode 2 (identify) uses the Mode2 pre-arm ROM config — `want_flags=0x400000` —
            // NOT Standard (`0x80`): `syna_capture_identify_enroll@0x180053400` calls
            // `syna_capture_send_pre_arm_rom_config_mode2@0x180068800` for read_mode 2. The Mode2
            // module reconfigures finger-detect, which the `0x48` last-frame baseline depends on
            // (a Standard-primed sensor faults on the `0x48` arm; task #29).
            pre_arm: Some(PreArmMode::Mode2),
            submode,
            finger_gate,
            recover: true,
            force_rearm: false,
            sync_frames: 0,
        }
    }

    /// Polled recon=8 **image** read (`syna_capture_image@0x180099540`) — same as [`Self::polled`]
    /// but the **Standard** `0x80` pre-arm, not identify/enroll's Mode2 `0x400000`. The DLL's image
    /// path (`syna_capture_read_dispatch` → `syna_capture_send_pre_arm_rom_config`, `want=0x80`)
    /// differs from the identify/enroll path (`syna_capture_send_pre_arm_rom_config_mode2`).
    pub fn polled_image(submode: MatcherSubmode, finger_gate: bool) -> Self {
        Self { pre_arm: Some(PreArmMode::Standard), ..Self::polled(submode, finger_gate) }
    }

    /// EP-0x82 stream read for `sync_frames` frames, fault recovery on.
    pub fn stream(sync_frames: u32) -> Self {
        Self {
            read: ReadMode::Stream,
            // Frames-sync stream sends NO pre-arm — the DLL only pre-arms identify/enroll, and the
            // per-frame re-arm otherwise gets the second `0x06` rejected `0x04aa`.
            pre_arm: None,
            submode: MatcherSubmode::StreamEnroll,
            finger_gate: false,
            recover: true,
            force_rearm: false,
            sync_frames,
        }
    }

    /// Frames-sync CALIBRATE read (same transport as [`Self::stream`], calibrate teardown).
    pub fn calibrate(sync_frames: u32) -> Self {
        Self { read: ReadMode::Calibrate, ..Self::stream(sync_frames) }
    }
}

/// The result of one capture call.
#[derive(Debug, Clone)]
pub enum CaptureOutcome {
    /// A polled `0x51` frame (fresh, or the frozen cache on an unchanged arm).
    Polled(PolledFrame),
    /// An EP-0x82 stream/calibrate frame.
    Stream(RawFrame),
    /// Armed OK, but the bounded read produced no frame (polled: `keep_going` expired / no finger;
    /// stream: arm rejected). Carries the last arm status word.
    NoFrame { arm_status: u16 },
}

/// What the arm currently on the sensor is, so the next call can decide whether to re-arm.
struct ArmedState {
    /// The serialized `0x02` program bytes on the sensor (the re-arm key — hand edits included).
    serialized: Vec<u8>,
    /// The read mode it was armed for (picks the teardown when it is superseded).
    read: ReadMode,
    /// The most recent polled frame captured on this arm — the arm-once freeze cache (`None` for
    /// stream, which produces a fresh frame each read).
    frozen: Option<PolledFrame>,
    /// The arm status word from the last (re-)arm.
    arm_status: u16,
}

/// The re-arm decision for the next capture given the currently-armed state. Pure so guarantees #1/#2
/// are unit-testable without hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rearm {
    /// Program + mode unchanged and a polled frame is cached → reuse it, no wire I/O (freeze).
    ReuseFrozen,
    /// Program + mode unchanged, nothing cached → read again on the existing arm (no re-arm).
    ReadExisting,
    /// Program or mode changed (or first arm) → tear `teardown_prev` down (if any) then arm.
    Arm { teardown_prev: Option<ReadMode> },
}

/// Apply `force_rearm` to a base plan: a same-mode reuse (`ReuseFrozen`/`ReadExisting`) becomes a
/// fresh `Arm` with no teardown (`arm_polled_capture`'s stop-before-arm covers the prior arm). A
/// genuine mode/program change keeps its `teardown_prev` — force must NOT skip a cross-mode dearm.
/// The pre-arm to actually send given what's already loaded on the sensor this session. The pre-arm
/// `0x06` loads a firmware module the sensor accepts ONCE per session, so send `desired` only when
/// nothing is loaded yet; `None` otherwise (a re-arm, or a *different* mode that needs a re-establish
/// — gated by [`pre_arm_needs_reestablish`]). Pure so [`CaptureSession`]'s once-per-session rule is
/// unit-testable without hardware.
fn resolve_pre_arm(loaded: Option<PreArmMode>, desired: Option<PreArmMode>) -> Option<PreArmMode> {
    match desired {
        Some(m) if loaded.is_none() => Some(m),
        _ => None,
    }
}

/// Whether `desired` needs a fresh session before it can be applied — a *different* pre-arm mode is
/// already loaded, which no in-session teardown clears (verified `examples/prearm_lifetime`).
fn pre_arm_needs_reestablish(loaded: Option<PreArmMode>, desired: Option<PreArmMode>) -> bool {
    matches!((desired, loaded), (Some(m), Some(l)) if m != l)
}

fn force_upgrade(base: Rearm, force_rearm: bool) -> Rearm {
    if force_rearm && !matches!(base, Rearm::Arm { .. }) {
        Rearm::Arm { teardown_prev: None }
    } else {
        base
    }
}

/// Decide how to service the next capture. See [`Rearm`].
fn plan_rearm(armed: Option<&ArmedState>, next: &[u8], next_read: ReadMode) -> Rearm {
    match armed {
        Some(a) if a.serialized == next && a.read == next_read => {
            if a.frozen.is_some() {
                Rearm::ReuseFrozen
            } else {
                Rearm::ReadExisting
            }
        }
        Some(a) => Rearm::Arm { teardown_prev: Some(a.read) },
        None => Rearm::Arm { teardown_prev: None },
    }
}

/// The arm+read+teardown state machine over a live [`Session`]. Borrow a session for the capture's
/// lifetime; the session is released (and the armed mode torn down) when the `CaptureSession` drops.
pub struct CaptureSession<'s, T: Transport> {
    session: &'s mut Session<T>,
    cfg: CaptureConfig,
    factory_cal: Vec<u8>,
    vendor_cal: Option<CalResults>,
    st8: u16,
    st9: u16,
    /// Flex "needs-finalize" bit for the teardown gate; the silicon gate (`st8==6 && st9>0x13`)
    /// covers 0x2449, so `false` here is correct (matches the existing teardown call sites).
    flex_finalize_bit: bool,
    armed: Option<ArmedState>,
    /// The pre-arm `0x06` ROM-config mode currently loaded on the sensor **this TLS session**. The
    /// sensor accepts a pre-arm module ONCE per session — re-sending it returns `0x04aa` from idle,
    /// or hard-resets the device if sent while armed; nothing in-session clears it (not stop, not
    /// finalize/dearm — only a fresh session / USB reset). Verified `examples/prearm_lifetime`. So we
    /// send it on the first arm that wants it and pass `None` on every re-arm; a *different* mode
    /// needs a re-establish ([`Self::needs_reestablish_for`]). `None` = nothing loaded yet.
    pre_arm_loaded: Option<PreArmMode>,
}

impl<'s, T: Transport> CaptureSession<'s, T> {
    /// Bind a session for capture with the resolved config + calibration inputs. `st8`/`st9` come
    /// from bootstrap ([`crate::session::DeviceContext`]) or [`Session::status_bytes_for_teardown`].
    pub fn new(
        session: &'s mut Session<T>,
        cfg: CaptureConfig,
        factory_cal: Vec<u8>,
        vendor_cal: Option<CalResults>,
        st8: u16,
        st9: u16,
    ) -> Self {
        Self {
            session,
            cfg,
            factory_cal,
            vendor_cal,
            st8,
            st9,
            flex_finalize_bit: false,
            armed: None,
            pre_arm_loaded: None,
        }
    }

    /// The pre-arm to actually send for the next arm, given the caller's desired mode and what is
    /// already loaded this session. Sends a `Some(m)` only the first time (or after a session/reboot
    /// clears it); `None` on re-arms (re-sending the same `0x06` is rejected `0x04aa`). A *different*
    /// desired mode returns `None` here — the caller must [`Self::needs_reestablish_for`]-gate first,
    /// since nothing in-session can swap the loaded pre-arm.
    fn pre_arm_to_send(&self, desired: Option<PreArmMode>) -> Option<PreArmMode> {
        resolve_pre_arm(self.pre_arm_loaded, desired)
    }

    /// Whether `desired` needs a fresh TLS session (re-establish / USB reset) before it can be
    /// applied — a *different* pre-arm mode is already loaded, which no in-session teardown clears
    /// (verified `examples/prearm_lifetime`). The capture thread re-establishes when this is true.
    #[must_use]
    pub fn needs_reestablish_for(&self, desired: Option<PreArmMode>) -> bool {
        pre_arm_needs_reestablish(self.pre_arm_loaded, desired)
    }

    /// Resolve a canonical/overridden [`ArmSpec`] into the concrete program to send, using this
    /// session's calibration inputs. Convenience over [`CaptureConfig::resolve_arm`].
    pub fn resolve(&self, spec: &ArmSpec) -> Option<(ArmProgram, UploadCmdBuildPath)> {
        self.cfg.resolve_arm(spec, &self.factory_cal, self.vendor_cal.as_ref())
    }

    /// Borrow the resolved config (geometry, stride helpers).
    pub fn config(&self) -> &CaptureConfig {
        &self.cfg
    }

    /// Whether a measured vendor calibration is loaded (so polled/stream arms fold the dark).
    pub fn has_vendor_cal(&self) -> bool {
        self.vendor_cal.is_some()
    }

    /// Capture a vendor calibration on demand (step-3/step-6 dark fold) and load it, so subsequent
    /// [`Self::resolve`]d arms fold it. Because the folded program serializes differently, the next
    /// [`Self::capture`] re-arms automatically (no manual invalidation needed). For the polled path
    /// when bootstrap skipped calibration.
    pub fn capture_vendor_cal(&mut self) -> Result<()> {
        let cal = self.session.capture_vendor_cal(&self.cfg, &self.factory_cal)?;
        self.vendor_cal = Some(cal);
        Ok(())
    }

    /// Capture one frame for `program` under `opts`, re-arming only if the program/mode changed.
    /// `keep_going` bounds the (polled) wait — return `false` past the caller's deadline so a
    /// finger-gated read times out instead of hanging.
    pub fn capture(
        &mut self,
        program: &ArmProgram,
        opts: CaptureOpts,
        keep_going: impl FnMut() -> bool,
    ) -> Result<CaptureOutcome> {
        let bytes = program.serialize();
        match opts.read {
            ReadMode::Polled => self.capture_polled(bytes, opts, keep_going),
            // WakeOnFinger has no frame read; treat it as the stream transport for symmetry (no
            // canonical caller reaches it — SCM WOF uses `run_wof`).
            ReadMode::Stream | ReadMode::Calibrate | ReadMode::WakeOnFinger => {
                self.capture_stream(bytes, opts)
            }
        }
    }

    /// Tear down the armed mode now (if any) and forget it, surfacing the dearm result. The `Drop`
    /// teardown is then a no-op. Use over the implicit drop when the teardown outcome must be seen.
    pub fn finish(mut self) -> Result<()> {
        self.teardown_armed()
    }

    fn teardown_armed(&mut self) -> Result<()> {
        if let Some(a) = self.armed.take() {
            self.session.teardown(a.read, self.st8, self.st9, self.flex_finalize_bit)?;
        }
        Ok(())
    }

    /// Arm a polled program **without reading a frame** — re-arming (and tearing a prior mode down)
    /// only if the program/mode changed, with the single fault-reaction (guarantee #3). Returns the
    /// arm status word. For arm-only probes, or before a manual read; [`Self::capture`] calls it too.
    pub fn arm_polled(&mut self, program: &ArmProgram, opts: CaptureOpts) -> Result<u16> {
        self.arm_polled_bytes(&program.serialize(), opts)
    }

    fn arm_polled_bytes(&mut self, bytes: &[u8], opts: CaptureOpts) -> Result<u16> {
        let plan =
            force_upgrade(plan_rearm(self.armed.as_ref(), bytes, ReadMode::Polled), opts.force_rearm);
        match plan {
            Rearm::Arm { teardown_prev } => {
                if let Some(prev) = teardown_prev {
                    // Guarantee #1 — tear the old mode down before arming the new one.
                    log::info!(
                        "capture: mode-switch teardown of {prev:?} before Polled arm (st8={:#x} st9={:#x})",
                        self.st8,
                        self.st9
                    );
                    if let Err(e) =
                        self.session.teardown(prev, self.st8, self.st9, self.flex_finalize_bit)
                    {
                        log::warn!("capture: {prev:?} teardown errored: {e}");
                    }
                }
                let status = self.arm_polled_recovering(bytes, opts)?;
                if !armed_ok(status) {
                    log::warn!("capture: Polled arm rejected status={}", Status::from_wire(status));
                }
                self.armed = Some(ArmedState {
                    serialized: bytes.to_vec(),
                    read: ReadMode::Polled,
                    frozen: None,
                    arm_status: status,
                });
                Ok(status)
            }
            // Already armed with this exact program — reuse it.
            Rearm::ReuseFrozen | Rearm::ReadExisting => {
                Ok(self.armed.as_ref().map_or(0, |a| a.arm_status))
            }
        }
    }

    fn capture_polled(
        &mut self,
        bytes: Vec<u8>,
        opts: CaptureOpts,
        keep_going: impl FnMut() -> bool,
    ) -> Result<CaptureOutcome> {
        // Guarantee #2 — an unchanged program with a cached frame returns it, no wire I/O. Skipped
        // in re-arm-every-frame mode (`force_rearm`), which wants a fresh still each call.
        if !opts.force_rearm
            && let Rearm::ReuseFrozen = plan_rearm(self.armed.as_ref(), &bytes, ReadMode::Polled)
            && let Some(frame) = self.armed.as_ref().and_then(|a| a.frozen.clone())
        {
            return Ok(CaptureOutcome::Polled(frame));
        }
        // `arm_polled_bytes` honors `force_rearm` (fresh arm) while preserving cross-mode teardown.
        let status = self.arm_polled_bytes(&bytes, opts)?;
        if !armed_ok(status) {
            return Ok(CaptureOutcome::NoFrame { arm_status: status });
        }

        // Read on the (freshly or previously) armed sensor.
        let body_len = self.cfg.polled_body_len();
        let frame = self.session.capture_vfm_polled(
            opts.submode,
            opts.finger_gate,
            body_len,
            keep_going,
        );
        // DLL post-read ack (`syna_capture_complete_ack`), best-effort.
        let _ = self.session.capture_complete_ack();
        match frame {
            Some(f) => {
                if let Some(a) = self.armed.as_mut() {
                    a.frozen = Some(f.clone()); // arm the freeze cache
                }
                Ok(CaptureOutcome::Polled(f))
            }
            None => {
                let arm_status = self.armed.as_ref().map_or(0, |a| a.arm_status);
                Ok(CaptureOutcome::NoFrame { arm_status })
            }
        }
    }

    /// DLL-faithful **prime → folded** capture for the 0x0199 polled path. The decrypted DLL calibrate
    /// trace (`captures/lenovo-009a-pairing`) sends an UNFOLDED prime arm — whose reply is the baseline
    /// the dark fold references — immediately followed by the FOLDED arm: two `0x02` arms back-to-back,
    /// **no stop/teardown between** (which the normal re-arm path inserts and which clears the prime,
    /// re-faulting the die). Reads the polled frame off the folded arm. Experimental (`SYNA_PRIME_ARM`
    /// in `synfp png`): the identify-mode prime is extrapolated from the calibrate trace — the identify
    /// flow is in no captured trace, so validate against a fresh DLL identify trace before making it
    /// the default.
    pub fn capture_primed(
        &mut self,
        prime: &ArmProgram,
        folded: &ArmProgram,
        opts: CaptureOpts,
        keep_going: impl FnMut() -> bool,
    ) -> Result<CaptureOutcome> {
        // Pre-arm once (0x06); the prime arm follows with the die left armed (no stop after it).
        let pre_arm = self.pre_arm_to_send(opts.pre_arm);
        if let Some(pa) = pre_arm {
            let outcome = self.session.send_pre_arm_rom_config(pa)?;
            log::info!(target: "syna::cmd", "pre-arm {pa:?} → {outcome:?}");
            self.pre_arm_loaded = Some(pa);
        }
        let prime_st = CaptureIo::arm(self.session, &prime.serialize())?;
        log::info!(target: "syna::cmd", "prime arm status = {prime_st:#06x}");
        // Folded arm back-to-back — no stop, no teardown, no re-pre-arm (already loaded this session).
        let folded_bytes = folded.serialize();
        let st = CaptureIo::arm(self.session, &folded_bytes)?;
        log::info!(target: "syna::cmd", "folded arm status = {st:#06x}");
        if !armed_ok(st) {
            return Ok(CaptureOutcome::NoFrame { arm_status: st });
        }
        self.armed = Some(ArmedState {
            serialized: folded_bytes,
            read: ReadMode::Polled,
            frozen: None,
            arm_status: st,
        });
        let body_len = self.cfg.polled_body_len();
        let frame =
            self.session.capture_vfm_polled(opts.submode, opts.finger_gate, body_len, keep_going);
        let _ = self.session.capture_complete_ack();
        Ok(match frame {
            Some(f) => CaptureOutcome::Polled(f),
            None => CaptureOutcome::NoFrame { arm_status: st },
        })
    }

    /// Arm a polled capture, applying the single fault-reaction site (guarantee #3): on a fault the
    /// DLL's `syna_vfm_reboot_sensor_mode0` order — `0x05` reboot → settle → `0x04` stop → re-arm —
    /// runs exactly once.
    fn arm_polled_recovering(&mut self, bytes: &[u8], opts: CaptureOpts) -> Result<u16> {
        // Pre-arm once per session; `None` on re-arms (re-sending `0x06` → `0x04aa`).
        let pre_arm = self.pre_arm_to_send(opts.pre_arm);
        let status = self.session.arm_polled_capture(bytes, pre_arm)?;
        if let Some(m) = pre_arm {
            self.pre_arm_loaded = Some(m);
        }
        if opts.recover && Status::from_wire(status).requests_sensor_reboot_retry() {
            log::warn!(
                "capture fault (arm status {}) — soft reboot (0x05) + single re-arm",
                Status::from_wire(status)
            );
            let _ = self.session.reboot_sensor();
            std::thread::sleep(REBOOT_SETTLE);
            CaptureIo::stop(self.session)?;
            // The `0x05` reboot cleared the sensor's pre-arm state — re-send it on the re-arm.
            self.pre_arm_loaded = None;
            let pre_arm = self.pre_arm_to_send(opts.pre_arm);
            let status = self.session.arm_polled_capture(bytes, pre_arm)?;
            if let Some(m) = pre_arm {
                self.pre_arm_loaded = Some(m);
            }
            return Ok(status);
        }
        Ok(status)
    }

    fn capture_stream(&mut self, bytes: Vec<u8>, opts: CaptureOpts) -> Result<CaptureOutcome> {
        // Stream re-arms inside `capture_one` per frame, so the only cross-call obligation here is to
        // tear a *different* prior mode down first (guarantee #1 on a Path switch).
        if let Rearm::Arm { teardown_prev: Some(prev) } =
            plan_rearm(self.armed.as_ref(), &bytes, opts.read)
        {
            log::info!(
                "capture: mode-switch teardown of {prev:?} before {:?} arm (st8={:#x} st9={:#x})",
                opts.read,
                self.st8,
                self.st9
            );
            if let Err(e) = self.session.teardown(prev, self.st8, self.st9, self.flex_finalize_bit) {
                log::warn!("capture: {prev:?} teardown errored: {e}");
            }
        }
        let capturer = FrameCapturer::new(
            self.cfg.sync_layout(opts.sync_frames).wire_stride(),
            self.cfg.stream_req_lines(opts.sync_frames) as usize,
        );
        let raw = if opts.recover {
            // Guarantee #3 — the stream fault site (reboot + single re-arm) lives in
            // `capture_one_recovering`; reuse it rather than duplicating the predicate.
            self.session.capture_one_recovering(&capturer, &bytes, opts.pre_arm)?
        } else {
            capturer.capture_one(self.session, &bytes, opts.pre_arm)?
        };
        let arm_status = raw.arm_status;
        if !matches!(arm_status, 0x0000 | 0x0412 | 0x0450) {
            log::warn!(
                "capture: {:?} arm rejected status={}",
                opts.read,
                Status::from_wire(arm_status)
            );
        }
        self.armed = Some(ArmedState {
            serialized: bytes,
            read: opts.read,
            frozen: None,
            arm_status,
        });
        if raw.is_ok() {
            Ok(CaptureOutcome::Stream(raw))
        } else {
            Ok(CaptureOutcome::NoFrame { arm_status })
        }
    }
}

impl<T: Transport> Drop for CaptureSession<'_, T> {
    fn drop(&mut self) {
        // Guarantee #4 — best-effort dearm of the live mode on every exit path.
        let _ = self.teardown_armed();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn armed(serialized: &[u8], read: ReadMode, frozen: bool) -> ArmedState {
        ArmedState {
            serialized: serialized.to_vec(),
            read,
            frozen: frozen.then(|| PolledFrame {
                header: crate::capture::PolledFrameHeader {
                    height: 56,
                    width: 144,
                    raw_line_count: 0,
                    field_6: 0,
                    field_8: 0,
                    field_a: 0,
                },
                body: Vec::new(),
            }),
            arm_status: 0,
        }
    }

    #[test]
    fn first_capture_arms_without_teardown() {
        assert_eq!(
            plan_rearm(None, b"\x02arm", ReadMode::Polled),
            Rearm::Arm { teardown_prev: None }
        );
    }

    #[test]
    fn pre_arm_sent_once_per_session_then_none() {
        use PreArmMode::{Mode2, Standard};
        // Nothing loaded → send the desired pre-arm on the first arm.
        assert_eq!(resolve_pre_arm(None, Some(Mode2)), Some(Mode2));
        // Same mode already loaded → None (re-sending 0x06 is rejected 0x04aa).
        assert_eq!(resolve_pre_arm(Some(Mode2), Some(Mode2)), None);
        // A different mode loaded → None here (never re-send); needs a re-establish instead.
        assert_eq!(resolve_pre_arm(Some(Standard), Some(Mode2)), None);
        // No pre-arm wanted (stream/calibrate) → always None.
        assert_eq!(resolve_pre_arm(None, None), None);
        assert_eq!(resolve_pre_arm(Some(Mode2), None), None);
    }

    #[test]
    fn reestablish_only_on_a_different_loaded_mode() {
        use PreArmMode::{Mode2, Standard};
        // Nothing loaded, or the same mode, or no pre-arm wanted → no re-establish.
        assert!(!pre_arm_needs_reestablish(None, Some(Mode2)));
        assert!(!pre_arm_needs_reestablish(Some(Mode2), Some(Mode2)));
        assert!(!pre_arm_needs_reestablish(Some(Mode2), None));
        // A different mode is loaded → must re-establish (in-session teardown can't swap it).
        assert!(pre_arm_needs_reestablish(Some(Standard), Some(Mode2)));
        assert!(pre_arm_needs_reestablish(Some(Mode2), Some(Standard)));
    }

    #[test]
    fn unchanged_polled_program_reads_then_freezes() {
        let a = armed(b"\x02arm", ReadMode::Polled, false);
        assert_eq!(plan_rearm(Some(&a), b"\x02arm", ReadMode::Polled), Rearm::ReadExisting);
        let a = armed(b"\x02arm", ReadMode::Polled, true);
        assert_eq!(plan_rearm(Some(&a), b"\x02arm", ReadMode::Polled), Rearm::ReuseFrozen);
    }

    #[test]
    fn changed_program_rearms_and_tears_down_prev() {
        let a = armed(b"\x02arm", ReadMode::Polled, true);
        assert_eq!(
            plan_rearm(Some(&a), b"\x02DIFFERENT", ReadMode::Polled),
            Rearm::Arm { teardown_prev: Some(ReadMode::Polled) }
        );
    }

    #[test]
    fn mode_switch_tears_prev_mode_down_even_if_bytes_match() {
        // The "hang on Path switch" case: same bytes, different read contract → re-arm + teardown.
        let a = armed(b"\x02arm", ReadMode::Polled, true);
        assert_eq!(
            plan_rearm(Some(&a), b"\x02arm", ReadMode::Stream),
            Rearm::Arm { teardown_prev: Some(ReadMode::Polled) }
        );
    }

    #[test]
    fn stream_never_freezes_so_it_keeps_reading() {
        let a = armed(b"\x02s", ReadMode::Stream, false);
        assert_eq!(plan_rearm(Some(&a), b"\x02s", ReadMode::Stream), Rearm::ReadExisting);
    }

    #[test]
    fn force_rearm_arms_fresh_same_mode_but_keeps_cross_mode_teardown() {
        // Same-mode reuse → fresh arm, no teardown (stop-before-arm covers the prior arm).
        assert_eq!(
            force_upgrade(Rearm::ReuseFrozen, true),
            Rearm::Arm { teardown_prev: None }
        );
        assert_eq!(
            force_upgrade(Rearm::ReadExisting, true),
            Rearm::Arm { teardown_prev: None }
        );
        // A genuine mode switch must STILL tear the prior mode down — force can't skip it.
        assert_eq!(
            force_upgrade(Rearm::Arm { teardown_prev: Some(ReadMode::Stream) }, true),
            Rearm::Arm { teardown_prev: Some(ReadMode::Stream) }
        );
        // No force → unchanged.
        assert_eq!(force_upgrade(Rearm::ReuseFrozen, false), Rearm::ReuseFrozen);
    }
}
