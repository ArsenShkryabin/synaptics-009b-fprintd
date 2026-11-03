//! Read modes + capture teardown/dearm + the wake-on-finger (WoF) run loop — the `CCaptureImage`
//! engine (`syna_wbdi_capture_start@0x18001addc`, `_read_fp_data@0x18001a818`,
//! `_wait_for_finger@0x18001c0a8`): the `CaptureControl`/`WofIo` traits, `CaptureContext`,
//! `TeardownStep`/`teardown_steps`, and `run_wof`. Extracted from the capture module; uses the
//! parent's frame/finger-detect helpers via `super`, re-exported by `mod.rs`.

use super::*;

/// The sensor's frame READ MODES. The WBDI engine selects one from the capture mode (`ctx+0x88`)
/// and the WOF flag (`ctx+0xa0`); each clocks frames differently and has its own teardown
/// ([`teardown_steps`]). This is the transport-level distinction the vendor's own debug names
/// (`CCaptureImage::*`) draw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadMode {
    /// **Polled image** — engine mode 2. Host-clocked `0x51` frame-chunk poll with an *advancing
    /// sensor cursor* (no offset in the request); one still frame → identify/verify/enroll.
    /// `syna_capture_image@0x180099540`; assembled by [`assemble_polled_frame`]. Arm =
    /// `cmd02(req_lines=0, mode=2, flags=0xa0030)`.
    Polled,
    /// **Streaming** — engine mode 3. Device-pushed: a completion/interrupt callback is armed
    /// (`vfmDeviceCtl_180054be0`, dev-ctl code 1), the host blocks on the event, then reads the
    /// multi-line frame over EP-0x82 bulk. `syna_capture_and_reconstruct`; driven by [`FrameCapturer`].
    /// Arm = `cmd02(req_lines>0)` with a pre-posted RX buffer.
    Stream,
    /// **Wake-on-finger (SCM)** — low-power presence only, *no image*. Arms the `0x76` wake record
    /// (`syna_vfm_scm_wof_arm_disarm`) and polls `SCM_WOF_STATUS` via [`run_wof`] when `CCaptureImage+0xa0==1`.
    /// On `0x2449` SCM WOF is **spurious** — Hello uses [`FingerPresenceStrategy::CaptureFingerDetect`]
    /// instead (EP-0x83 + `0x26` chunk, [`wait_capture_finger_detect`]).
    WakeOnFinger,
    /// **Calibrate dark-field** — imaging drive off, otherwise the streaming transport. `scsWindsorCal`.
    /// Driven by [`FrameCapturer`] with a calibrate arm; teardown identical to [`ReadMode::Polled`].
    Calibrate,
}

/// Wire opcodes used to arm/tear down a read. NB the `scsCommands_*` builders index a **host handler
/// table** (`syna_cmd_table_dispatch` at `0x180064700` → `handler_table[idx]`, base `0x18013dc30`),
/// so the descriptor's first field is an INDEX, not the wire opcode; the real opcodes below were read
/// from each handler's `syna_cmd_alloc_buf(<opcode>, …)`. Each aliases a [`crate::proto::Opcode`].
pub mod stop_cmd {
    use crate::proto::Opcode;
    /// Soft capture abort — enough to let the next arm through; sent before each `frames_sync` arm.
    pub const ABORT: u8 = Opcode::CaptureStop as u8; // 0x04
    /// Capture STOP — `syna_vfm_capture_stop@0x180052750`'s first command (`scsCommands_18005e0a0`,
    /// handler-index 0xa → `syna_cmd_04_capture_stop`). Same wire opcode as [`ABORT`].
    pub const STOP: u8 = Opcode::CaptureStop as u8; // 0x04
    /// Capture FINALIZE — the stop's second command (`scsCommands_18005e220`, handler-index 0x36 →
    /// `syna_cmd_52_noarg_request`). Sent AFTER [`STOP`] only when [`super::needs_finalize`].
    pub const FINALIZE: u8 = Opcode::NoArgRequest52 as u8; // 0x52
    /// WOF arm/disarm — `scsCommands_18005f280` (handler-index 0x2f → `syna_cmd_76_send_record_header`).
    /// **The wire command is a STRUCTURED record header** (`[tag][be32×3][be16×2][u8×4]` + optional
    /// var data), NOT a bare `[opcode, mask]`; the finger mask is the record `tag`. Building it needs
    /// the per-subtype print-cmd-helper struct — see [`crate::session`]'s `arm_wof` (not yet built).
    pub const WOF: u8 = Opcode::SendRecordHeader as u8; // 0x76
}

/// Silicon revision at which the FINALIZE command becomes mandatory: `st8 == 6 && st9 > 0x13`.
const FINALIZE_ST8: u16 = 6;
const FINALIZE_ST9_MIN: u16 = 0x13;

/// Whether this silicon needs the second FINALIZE command (`0x36`) after STOP. DLL gate
/// (`syna_vfm_capture_stop@0x180052750`): the flex "needs-finalize" bit **or** silicon
/// `st8 == 6 && st9 > 0x13` (our `0x2449` = `6/0x14` qualifies). Data predicate, not a special-case
/// (Rule #6).
pub fn needs_finalize(st8: u16, st9: u16, flex_finalize_bit: bool) -> bool {
    flex_finalize_bit || (st8 == FINALIZE_ST8 && st9 > FINALIZE_ST9_MIN)
}

/// One ordered step of a mode's teardown. A live caller executes each against the session: tunnel a
/// stop/finalize command, cancel the pending interrupt/bulk URB, or disarm the WOF program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeardownStep {
    /// Tunnel a stop/finalize sensor command (see [`stop_cmd`]).
    Command(u8),
    /// Cancel the pending interrupt/bulk transfer (`vfmDeviceCtl_180054d10`, dev-ctl code 1) — only
    /// the device-pushed modes ([`ReadMode::Stream`]/[`ReadMode::WakeOnFinger`]) have one posted.
    CancelTransfer,
    /// Disarm the WOF program (`syna_vfm_scm_wof_arm_disarm(sensor,0,0)` → cmd `0x2f`, mask `0`).
    WofDisarm,
}

/// The ordered teardown for `mode` on the given silicon, faithful to the DLL:
///  * device-pushed modes ([`ReadMode::Stream`], [`ReadMode::WakeOnFinger`]) first **cancel the
///    posted URB** so no transfer completes mid-teardown (`vfmDeviceCtl_180054d10`);
///  * WOF then **disarms its wake program** (`syna_vfm_scm_wof_arm_disarm(…,0)`), and does *not* issue the
///    capture stop — it is presence detection, not a frame capture;
///  * the frame modes ([`ReadMode::Polled`]/[`ReadMode::Stream`]/[`ReadMode::Calibrate`]) issue **STOP** and, when
///    [`needs_finalize`], **FINALIZE** (`syna_vfm_capture_stop`).
pub fn teardown_steps(
    mode: ReadMode,
    st8: u16,
    st9: u16,
    flex_finalize_bit: bool,
) -> Vec<TeardownStep> {
    let mut steps = Vec::new();
    match mode {
        ReadMode::WakeOnFinger => {
            // WOF is not a capture: cancel the IRQ transfer, then disarm the wake program. No STOP.
            steps.push(TeardownStep::CancelTransfer);
            steps.push(TeardownStep::WofDisarm);
        }
        ReadMode::Polled | ReadMode::Stream | ReadMode::Calibrate => {
            if mode == ReadMode::Stream {
                steps.push(TeardownStep::CancelTransfer); // device-pushed: kill the pending URB first
            }
            steps.push(TeardownStep::Command(stop_cmd::STOP));
            if needs_finalize(st8, st9, flex_finalize_bit) {
                steps.push(TeardownStep::Command(stop_cmd::FINALIZE));
            }
        }
    }
    steps
}

/// WOF status/arm bit constants (`syna_wbdi_wait_for_finger` / `syna_wbdi_get_wof_status`).
pub mod wof {
    /// The arm byte OR's this in (`mask | 2`) alongside the caller's finger-event mask
    /// (`syna_wbdi_wait_for_finger`: `bVar9 = param_2 & 1 | 2`).
    pub const ARM_ENABLE: u8 = 0x02;
    /// `GetWOFStatus` "pending / not yet" — keep polling (`syna_wbdi_get_wof_status`, `0xd1`).
    pub const STATUS_PENDING: u16 = 0x00d1;

    /// Default wake-indicator LED colour the record carries (`syna_scs_build_wof_record_class3`:
    /// `local_64 = 0xff00cc`, overridable at runtime from `ctx+0x29c`).
    pub const DEFAULT_LED_COLOR: u32 = 0x00ff_00cc;
    /// The `0x3f` wake-config chunk marker (`local_48`).
    const WAKE_MARKER: u32 = 0x0040_1004;
    /// Wake-detect timeout embedded in the record (`local_3c`, class 3).
    const WAKE_TIMEOUT: u16 = 2000;

    /// 0x2449 wake tail — alias for [`crate::wake_flex::wake_flex_block`] (0x2449).
    pub const WAKE_FLEX_2449: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0xf2, 0x02, 0x01, 0x00];

    /// Class-3 AFE writes for `0x2449` — prefer [`crate::wake_flex::afe_writes_for_class`].
    pub const CLASS3_AFE_WRITES: [(u32, u32); 2] =
        [(0x8000_03a0, 0x00ff_ffff), (0x8000_0374, 0x0000_0012)];

    /// The record `tag` the WOF **arm** sends: `(mask & 1) | ARM_ENABLE` (the DLL's
    /// `syna_vfm_scm_wof_arm_disarm(sensor,0, mask&1 | 2)`). **Disarm** sends tag `0`.
    pub fn arm_tag(mask: u8) -> u8 {
        (mask & 1) | ARM_ENABLE
    }

    /// Build the WOF arm/disarm wire command — opcode `0x76` (`SendRecordHeader`) carrying the
    /// class-3 (0x2449) `0x3f` wake-config chunk, then the `wake_flex` tail
    /// ([`WAKE_FLEX_2449`], or `&[]` for none). `syna_cmd_76` copies the fields **verbatim**
    /// (`syna_shared_util_1800e1420` is IDENTITY — the "byteswap" plate comment was wrong), so all
    /// fields are little-endian: `[0x76][tag][pad×3][u32le marker][u32le led][u32le led2][u16le timeout]
    /// [u16le wake_size = wake_flex.len()][3,0,0,0][wake_flex…]`. `tag` = [`arm_tag`] to arm / `0` disarm.
    ///
    /// **Validated** `0x76` record layout for 0x2449; SCM discrimination **failed** on this SKU
    /// (spurious — see `wof_probe`). Setup (`cfg57`, probe-DB, `0x800000` module, AFE) lives in
    /// `Session::arm_wof` via [`crate::wake_flex`].
    pub fn arm_command(tag: u8, led_color: u32, led_color2: u32, wake_flex: &[u8]) -> Vec<u8> {
        let wake_size = wake_flex.len() as u16; // `local_8c`
        let mut cmd = Vec::with_capacity(0x19 + wake_flex.len());
        cmd.push(crate::proto::Opcode::SendRecordHeader as u8); // 0x76
        cmd.push(tag);
        cmd.extend_from_slice(&[0, 0, 0]); // pad — the tag occupies a 4-byte slot in the 0x18 header
        cmd.extend_from_slice(&WAKE_MARKER.to_le_bytes());
        cmd.extend_from_slice(&led_color.to_le_bytes());
        cmd.extend_from_slice(&led_color2.to_le_bytes());
        cmd.extend_from_slice(&WAKE_TIMEOUT.to_le_bytes());
        cmd.extend_from_slice(&wake_size.to_le_bytes());
        cmd.extend_from_slice(&[3, 0, 0, 0]); // record[0x14..0x18] (`local_38..`), verbatim
        cmd.extend_from_slice(wake_flex);
        cmd
    }

    /// `cfg57` (opcode `0x57`, `syna_set_u16_cfg57`): set the WOF u16 config. The WOF arm/disarm path
    /// sends `value = 0`. Wire = `[0x57][value:u16 le]`.
    pub fn cfg57_command(value: u16) -> Vec<u8> {
        let mut cmd = vec![crate::proto::Opcode::SetU16Param as u8];
        cmd.extend_from_slice(&value.to_le_bytes());
        cmd
    }

    /// The class-3 (0x2449) AFE register writes `syna_vfm_scm_wof_arm_disarm` does before the arm record:
    /// `(0x800003a0, 0xffffff)` then `(0x80000374, 0x12)`.
    /// Prefer [`crate::wake_flex::afe_writes_for_class`].
    /// A `0x08` write-hw-reg32 command: `[0x08][addr:u32 le][val:u32 le][0x04]`. Fields are verbatim
    /// (`syna_cmd_08_write_hw_reg32`; `1800e1420` is identity — same little-endian form as
    /// [`crate::device`]'s `write_hw_reg32`).
    pub fn hw_reg_write_command(addr: u32, val: u32) -> Vec<u8> {
        let mut cmd = vec![crate::proto::Opcode::WriteHwReg32 as u8];
        cmd.extend_from_slice(&addr.to_le_bytes());
        cmd.extend_from_slice(&val.to_le_bytes());
        cmd.push(4);
        cmd
    }
}

/// Executes a mode's teardown against a live session. A live impl provides the three teardown
/// primitives; the provided [`Self::teardown`] method is the **canonical** dearm path — it runs
/// [`teardown_steps`] and dispatches each step, so callers (and [`run_wof`]) never re-derive the
/// order. Kept as a trait so the transport/TLS/IRQ details stay in the caller (mirrors [`CaptureIo`]
/// / [`crate::calibrate::CalibrateIo`]).
pub trait CaptureControl {
    /// Tunnel a stop/finalize sensor command (`STOP 0x0a` / `FINALIZE 0x36`; see [`stop_cmd`]).
    fn send_stop_command(&mut self, cmd: u8) -> Result<()>;
    /// Cancel the pending interrupt/bulk transfer (`vfmDeviceCtl_180054d10`, dev-ctl code 1).
    fn cancel_transfer(&mut self) -> Result<()>;
    /// Disarm the WOF program (`syna_vfm_scm_wof_arm_disarm(sensor,0,0)` → cmd `0x2f`, mask `0`).
    fn disarm_wof(&mut self) -> Result<()>;

    /// Canonical teardown: run [`teardown_steps`] for `mode`/silicon and execute each step in order.
    /// This is the single source of truth for dearm — do not open-code the dispatch elsewhere.
    fn teardown(
        &mut self,
        mode: ReadMode,
        st8: u16,
        st9: u16,
        flex_finalize_bit: bool,
    ) -> Result<()> {
        for step in teardown_steps(mode, st8, st9, flex_finalize_bit) {
            match step {
                TeardownStep::Command(cmd) => self.send_stop_command(cmd)?,
                TeardownStep::CancelTransfer => self.cancel_transfer()?,
                TeardownStep::WofDisarm => self.disarm_wof()?,
            }
        }
        Ok(())
    }

    /// Open a RAII [`CaptureContext`] over a mutable borrow of `self` for `mode`: teardown runs
    /// automatically when the context drops. `let ctx = io.context(mode, st8, st9, flex);` then use
    /// `ctx` (it derefs to the session) and let scope-exit dearm.
    fn context(
        &mut self,
        mode: ReadMode,
        st8: u16,
        st9: u16,
        flex_finalize_bit: bool,
    ) -> CaptureContext<&mut Self>
    where
        Self: Sized,
    {
        CaptureContext::open(self, mode, st8, st9, flex_finalize_bit)
    }
}

/// A `&mut` to a control session is itself a control session — so a [`CaptureContext`] can own either
/// the session by value *or* a `&mut Session` borrow (`io.context(..)`). Forwards each primitive.
impl<T: CaptureControl + ?Sized> CaptureControl for &mut T {
    fn send_stop_command(&mut self, cmd: u8) -> Result<()> {
        (**self).send_stop_command(cmd)
    }
    fn cancel_transfer(&mut self) -> Result<()> {
        (**self).cancel_transfer()
    }
    fn disarm_wof(&mut self) -> Result<()> {
        (**self).disarm_wof()
    }
}

/// An open capture context — the vendor capture-ctx analogue (the DLL keeps the mode at `ctx+0x88`,
/// WOF at `ctx+0xa0`, and frees it through the capture-stop path). It **owns** its session `S` (a
/// value, or a `&mut Session` borrow) and **must** tear down: [`Drop`] runs the canonical
/// [`CaptureControl::teardown`] for `mode` on every exit — normal return, an early `?`, or a panic —
/// so a read can never leak the sensor armed. Interact with the session through deref
/// (`ctx.arm_wof(..)`, `ctx.read_frame(..)`). Reclaim the session with [`Self::finish`] (tears down,
/// returns the session) or [`Self::into_session`] (skips teardown — handoff).
#[must_use = "the context tears the capture down on drop; bind it for the capture's scope"]
pub struct CaptureContext<S: CaptureControl> {
    /// `Some` while open; `None` after [`Self::finish`]/[`Self::into_session`] so `Drop` tears down
    /// at most once and never after the session has been handed back.
    session: Option<S>,
    mode: ReadMode,
    st8: u16,
    st9: u16,
    flex_finalize_bit: bool,
}

impl<S: CaptureControl> CaptureContext<S> {
    /// Open a context that will tear `mode` down on drop. Silicon (`st8`/`st9`) + `flex_finalize_bit`
    /// pick the FINALIZE gate ([`needs_finalize`]); inert for [`ReadMode::WakeOnFinger`].
    pub fn open(session: S, mode: ReadMode, st8: u16, st9: u16, flex_finalize_bit: bool) -> Self {
        Self {
            session: Some(session),
            mode,
            st8,
            st9,
            flex_finalize_bit,
        }
    }

    /// Tear down now and, on success, return the reclaimed session; the subsequent drop is a no-op.
    /// Use this over an implicit drop when the teardown outcome must be observed.
    pub fn finish(mut self) -> Result<S> {
        let mut session = self
            .session
            .take()
            .expect("context open until finish/into_session");
        session.teardown(self.mode, self.st8, self.st9, self.flex_finalize_bit)?;
        Ok(session)
    }

    /// Reclaim the session WITHOUT tearing down (teardown is handled elsewhere / handed off).
    pub fn into_session(mut self) -> S {
        self.session
            .take()
            .expect("context open until finish/into_session")
    }
}

impl<S: CaptureControl> std::ops::Deref for CaptureContext<S> {
    type Target = S;
    fn deref(&self) -> &S {
        self.session.as_ref().expect("context open")
    }
}
impl<S: CaptureControl> std::ops::DerefMut for CaptureContext<S> {
    fn deref_mut(&mut self) -> &mut S {
        self.session.as_mut().expect("context open")
    }
}
impl<S: CaptureControl> Drop for CaptureContext<S> {
    fn drop(&mut self) {
        if let Some(session) = self.session.as_mut() {
            // Best-effort: Drop can't return a Result — callers who must observe it use finish().
            let _ = session.teardown(self.mode, self.st8, self.st9, self.flex_finalize_bit);
        }
    }
}

/// SCM wake-on-finger (`CCaptureImage+0xa0 == 1` branch of `syna_wbdi_wait_for_finger@0x18001c0a8`).
/// Arms `0x76`, blocks on EP-0x83, polls remapped `SCM_WOF_STATUS`. For Hello identify on `0x2449`
/// use [`wait_capture_finger_detect`] instead — SCM WOF is spurious there.
pub trait WofIo: CaptureControl {
    /// Arm the WOF program with `mask` (`syna_vfm_scm_wof_arm_disarm(sensor,0,mask|2)` → cmd `0x2f`).
    fn arm_wof(&mut self, mask: u8) -> Result<()>;
    /// Block until the finger IRQ fires or the caller's deadline passes. `Ok(true)` = event,
    /// `Ok(false)` = timeout (`WaitForSingleObject` in the DLL; here the caller bounds the wait).
    fn wait_event(&mut self) -> Result<bool>;
    /// Read the WOF status byte (`syna_wbdi_get_wof_status` → `syna_vfm_wof_status_read`). The caller
    /// ANDs it with the mask; [`wof::STATUS_PENDING`] means "not yet".
    fn wof_status(&mut self) -> Result<u8>;
}

/// Forwarding blanket so a `CaptureContext<&mut Session>` can drive the WOF read (mirrors the
/// `CaptureControl for &mut T` blanket above).
impl<T: WofIo + ?Sized> WofIo for &mut T {
    fn arm_wof(&mut self, mask: u8) -> Result<()> {
        (**self).arm_wof(mask)
    }
    fn wait_event(&mut self) -> Result<bool> {
        (**self).wait_event()
    }
    fn wof_status(&mut self) -> Result<u8> {
        (**self).wof_status()
    }
}

/// Run one **SCM WOF** wait (`syna_wbdi_wait_for_finger` when `CCaptureImage+0xa0 != 0`): arm `0x76`,
/// loop (IRQ → `GetWOFStatus` → match `status & mask`). Teardown via [`CaptureContext`].
/// Not used for Hello capture finger-detect on `0x2449` — see [`wait_capture_finger_detect`].
pub fn run_wof<IO: WofIo>(
    io: &mut IO,
    mask: u8,
    mut keep_going: impl FnMut() -> bool,
) -> Result<bool> {
    let mut ctx = io.context(ReadMode::WakeOnFinger, 0, 0, false);
    ctx.arm_wof(mask)?; // any `?` below drops `ctx` → teardown runs; no manual dearm needed
    let mut detected = false;
    while keep_going() {
        if !ctx.wait_event()? {
            break; // timeout
        }
        if ctx.wof_status()? & mask != 0 {
            detected = true;
            break;
        }
    }
    ctx.finish()?; // eager teardown so the dearm Result is surfaced on the happy path
    Ok(detected)
}


