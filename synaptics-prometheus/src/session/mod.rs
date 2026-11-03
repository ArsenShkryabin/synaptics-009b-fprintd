//! Live TLS-tunneled sensor session — the concrete [`CaptureIo`] / [`CaptureControl`] / [`WofIo`]
//! implementation that drives real hardware.
//!
//! A [`Session`] owns a [`Transport`] plus the established [`SessionKeys`] and speaks the encrypted
//! app-data command protocol (every command rides inside a TLS `ApplicationData` record; see
//! [`crate::tls`]). It implements the three capture read-mode traits from [`crate::capture`], so
//! [`crate::capture::CaptureContext`] and [`crate::capture::run_wof`] run against the sensor with
//! their RAII teardown intact — arm a mode, read, and let the context dearm on scope exit.
//!
//! Generic over `T: Transport` so it unit-tests against a mock (the tests here decrypt the written
//! records to assert the exact wire opcodes). For live use, `T = crate::transport::NusbTransport`
//! (behind the `nusb` feature); construct with [`Session::new`] from an already-handshaked
//! `(transport, keys)` pair (the handshake orchestration lives in the example binaries).
//!
//! Wire opcodes (all recovered from `synaWudfBioUsb.dll`, see [`crate::capture::stop_cmd`]): arm =
//! `0x02` program upload; polled read = `0x51`; stop = `0x0a`, finalize = `0x36`; WOF arm/disarm =
//! `0x2f` (mask, `0` = disarm); WOF status = `0x30` (`scsCommands_18005f580`, byte remapped).

use p256::SecretKey;
use p256::ecdsa::SigningKey;
use getrandom::SysRng;
use p256::elliptic_curve::Generate;
use rand_core::{Rng, UnwrapErr};

/// The OS entropy source. rand_core 0.9 moved `OsRng` out; `SysRng` is the same syscall-backed
/// generator, and `UnwrapErr` adapts its fallible `TryRng` to the infallible `Rng`/`CryptoRng` the
/// key-generation and `fill_bytes` call sites expect (a failing OS RNG panics, as it did before).
pub fn os_rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

use crate::bringup::{self, BringUpPlan};
use crate::calibration::{flex_cal_for_subtype, CalResults};
use crate::capture_prog::CaptureConfig;
use crate::calibration::cap;
use crate::fw_registry::{self, SensorIdentity};
use crate::proto::{FwInfo, Opcode, Response, SensorStatus};
use crate::crypto::prf;
use crate::error::{Error, Result, Status};
use crate::handshake::{
    Transcript, certificate_verify, client_hello, client_key_exchange, finished,
    parse_server_hello, verify_data,
};
use crate::pairing::{Pairing, parse_cert_store};
use crate::tls::{self, IV_LEN, RecordType, SessionKeys};
use crate::transport::{Transport, hex_preview};
use log::trace;

/// WOF status command — `scsCommands_18005f580@0x18005f580` (host handler-index 0x30 →
/// `syna_cmd_77_reset_noargs`, wire opcode 0x77, no-arg); returns a status byte the vendor remaps
/// 0→0, 1→2, 2→1 (`syna_vfm_wof_status_read@0x180052b50`).
const WOF_STATUS_CMD: u8 = crate::proto::Opcode::ResetNoArgs as u8; // 0x77
/// Max interrupt packet drained / awaited on EP-0x83. python-validity reads this endpoint with a
/// **1024**-byte buffer (`usb.wait_int`: `dev.read(131, 1024)`); a 64-byte buffer OVERFLOWS when the
/// 0x0199 die raises its (larger) post-arm finger-detect interrupt, which nusb surfaces as a device
/// disconnect — the "die resets ~1s into the finger wait" symptom. Match pv's 1024.
const INTR_MAX: usize = 1024;
/// Step-7 `req_lines=0` frames-sync: wait for EP-0x83 capture-complete (`syna_capture_frames_sync`).
const ZERO_FRAME_INTR_WAIT_MS: u64 = 5_000;
const ZERO_FRAME_INTR_POLL_MS: u64 = 50;
/// How long [`WofIo::wait_event`] blocks on the wake interrupt before reporting a timeout.
const WOF_WAIT_MS: u64 = 250;
/// Settle delay after a `0x05` soft reboot (`syna_vfm_reboot_sensor_mode0`) before the sensor
/// re-enumerates and accepts a re-arm / re-establish. Shared by the bootstrap capture-fault retry
/// ([`Session::bootstrap_with`]), the in-loop recovery ([`Session::capture_one_recovering`]), and
/// the [`StaleStatePolicy::Hard`] startup clear.
pub(crate) const REBOOT_SETTLE_MS: u64 = 400;
/// Short timeout used when draining stale interrupt packets.
const DRAIN_MS: u64 = 15;
/// Generous upper bound for a `read_cmd` reply / bulk frame.
const REPLY_MAX: usize = 16384;
/// Reply cap for the short wake/init preamble reads during the handshake.
const PREAMBLE_REPLY_MAX: usize = 256;
/// Outer command-envelope tag the driver wraps each handshake flight in (`[0x44, len24…]`).
const CMD_ENVELOPE_TAG: u8 = 0x44;
/// TLS ChangeCipherSpec record, sent between flight-2 and the client Finished.
const CHANGE_CIPHER_SPEC: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
/// Handshake message types used during [`Session::establish`]: Certificate / ServerHello.
const HS_CERTIFICATE: u8 = 0x0b;
const HS_SERVER_HELLO: u8 = 0x02;

/// Target string for command-layer trace logs (`RUST_LOG=syna::cmd=trace`).
const CMD: &str = "syna::cmd";

/// Label a tunneled command by its leading opcode byte — `Name(0xNN)` when the [`Opcode`] is known,
/// else `unknown(0xNN)`. Only built when trace logging is enabled (the `log` macros are lazy).
fn opcode_label(cmd: &[u8]) -> String {
    match cmd.first() {
        Some(&b) => match Opcode::from_byte(b) {
            Some(op) => format!("{op:?}(0x{b:02x})"),
            None => format!("unknown(0x{b:02x})"),
        },
        None => "empty".to_string(),
    }
}

/// Label a decrypted reply by its leading `u16` status word via [`Status`]'s `Display`
/// (`0xNNNN name (label)`), or note a too-short reply.
fn reply_status_label(pt: &[u8]) -> String {
    match pt.get(..2) {
        Some(b) => format!("status {}", Status::from_wire(u16::from_le_bytes([b[0], b[1]]))),
        None => format!("(short reply, {}B)", pt.len()),
    }
}

/// Sentinel for `ctx+0x280` before `syna_classify_device_subtype` runs.
pub const SUBTYPE_CLASSIFY_UNSET: i32 = -1;

/// Prod-23 subtype-classify register poke (`syna_classify_subtype_prod23@0x18006fa60`).
mod classify_reg {
    /// SCM_ANALOG_TEST — power/clock domain select for prod-'3' classify.
    pub const PROD23_POWER_CLOCK: u32 = 0x8000_2060;
    /// Classify readback register.
    pub const PROD23_READBACK: u32 = 0x8000_2080;
    /// Value written before readback (`sub 0xb`).
    pub const PROD23_PEEK_SUB: u32 = 0x0b;
}

/// Post-TLS bootstrap options ([`Session::bootstrap_with`]).
#[derive(Debug, Clone, Copy)]
pub struct BootstrapOptions {
    /// Skip `syna_lib_run_calibration` (env: `STATIC_FOLD=1` when using [`BootstrapOptions::default`]).
    pub skip_calibration: bool,
    /// On capture-fault status (`0xc9`/`0xca`/`0x0450`), send `syna_vfm_reboot_sensor_mode0` and retry bootstrap once.
    pub reboot_on_capture_fault: bool,
}

impl BootstrapOptions {
    /// True when env `STATIC_FOLD` is set (static DAT line-update fallbacks, skip vendor cal).
    pub fn static_fold_enabled() -> bool {
        std::env::var("STATIC_FOLD").is_ok()
    }
}

impl Default for BootstrapOptions {
    fn default() -> Self {
        Self {
            skip_calibration: BootstrapOptions::static_fold_enabled(),
            reboot_on_capture_fault: true,
        }
    }
}

/// How aggressively [`Session::open_nusb`] clears sensor state left by a *prior process* before
/// first use.
///
/// We run as a restartable application, not the sole persistent WINBIO driver: a sensor can carry a
/// stale capture arm / autonomous state from a crashed or killed run, which yields `0x0450`
/// ("already armed") or a not-idle `0xca` on the first arm. The vendor driver never sees this — it
/// session-resets at open (`syna_scs_session_reset` inside `syna_open_init_decide_format@0x18006e830`)
/// and owns the device for its whole lifetime. [`Session::open_nusb`] always performs a USB port
/// reset (re-enumerate) on open; this selects the *additional* firmware/arm clearing on top.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StaleStatePolicy {
    /// Nothing beyond the open-time USB port reset.
    None,
    /// Send `0x04` (CaptureStop) + drain stale interrupts before first use — clears a stale arm
    /// cheaply, no re-enumerate. The lightweight analogue of the DLL's per-open session reset.
    Soft,
    /// [`Self::Soft`] plus a `0x05` firmware reboot (`syna_vfm_reboot_sensor_mode0`), after which the
    /// transport is re-opened and TLS re-established (the reboot re-enumerates the device). The
    /// fullest reset — only for manual deep-clearing. Costs a second TLS handshake per open.
    #[default]
    Hard,
}

/// Captured device/context state after [`Session::bootstrap`] — mirrors the DLL ctx fields
/// capture paths consume (`ctx+0x280`, `ctx+0x2d0`, flex lookup, factory cal, measured fold).
#[derive(Debug, Clone)]
pub struct DeviceContext {
    pub cfg: CaptureConfig,
    /// Per-line factory calib blob from `0x6f` tag [`FACTORY_TAG_BLOCK_TABLE`] (14 / 0x0e).
    pub factory_cal_values: Vec<u8>,
    /// Measured calibration fold when bootstrap ran vendor cal; `None` when skipped or failed softly.
    pub vendor_cal: Option<CalResults>,
    /// `ctx+0x280` — `syna_classify_subtype_prod23` result.
    pub subtype_classify: i32,
    /// `ctx+0x2d0` — fw-module upload dedup flag after in-session fw-info refresh.
    pub fw_upload_context: bool,
    /// Live status bytes `[8]`/`[9]` from `GetSensorState` (program select + classify branches).
    pub st8: u16,
    pub st9: u16,
}

impl DeviceContext {
    /// Stderr summary after [`Session::bootstrap`] — shared by example binaries.
    pub fn log_bootstrap(&self, program: &str) {
        if BootstrapOptions::static_fold_enabled() {
            eprintln!("# {program}: STATIC_FOLD=1 — skipping vendor calibration");
            return;
        }
        if self.vendor_cal.is_some() {
            eprintln!("# {program}: vendor calibration OK (steps 3+6 folded when enabled)");
            if flex_cal_for_subtype(self.cfg.subtype)
                .map(|f| f.cap_bits & cap::STEP6 != 0)
                .unwrap_or(false)
            {
                eprintln!(
                    "# {program}: step 6 dark-frame ran at session start (sensor was clear)"
                );
            }
        } else {
            eprintln!(
                "# {program}: vendor calibration unavailable — fold_calib uses step 3 only"
            );
        }
    }
}

/// Prod-'3' status byte at `SensorStatus.key_08` / `status[8]` (`syna_classify_subtype_prod23` gate).
pub const STATUS_BYTE8_PROD3: u8 = 0x06;

/// Map classify readback + status bytes to `ctx+0x280` (`syna_classify_subtype_prod23@0x18006fa60`).
pub fn map_subtype_classify_prod23(readback: u32, st8: u8, st9: u8) -> i32 {
    match readback {
        0 => {
            if st8 == STATUS_BYTE8_PROD3 && st9 == 0x14 {
                10
            } else if st8 == STATUS_BYTE8_PROD3 && (10 < st9) && (st9 < 0x14) {
                2
            } else {
                0
            }
        }
        1 => 1,
        _ => SUBTYPE_CLASSIFY_UNSET,
    }
}

/// A live, TLS-tunneled sensor session. See the module docs.
pub struct Session<T: Transport> {
    transport: T,
    keys: SessionKeys,
    /// Mirrors `ctx+0x2d0` — set after the first successful fw-module upload (`syna_scs_fw_upload_context`).
    fw_upload_context: bool,
    /// Cached ROM identity for fw-module selection (`*(ctx+0x28)`).
    cached_identity: Option<SensorIdentity>,
    /// Recon-config (`tag 0x30000288`) captured from the most recent `0x02` capture-arm reply, the
    /// host-side analogue of the DLL's `ctx+0x88` windsor view (`syna_capture_recon_setup`). Consumed
    /// by the matcher reconstruction, NOT the re-stride capture read. See [`Self::take_recon_config`].
    last_recon_config: Option<crate::capture_prog::windsor::WindsorReconConfig>,
    /// Gracefully shut the capture context down when the session is dropped ([`Self::drop`] →
    /// [`Self::graceful_shutdown`]) so the die is left idle for the next session. Default `true`;
    /// suppress with [`Self::set_shutdown_on_drop`] when handing the device to another session/tool, or
    /// after an explicit [`Self::reboot_sensor`] (which supersedes it).
    shutdown_on_drop: bool,
}

impl<T: Transport> Drop for Session<T> {
    /// Graceful shutdown on drop: stop any in-flight capture and drain interrupts so the die is left
    /// idle (no stale `0x02` arm) for the next session — WITHOUT the heavy `0x05` firmware reboot,
    /// which re-enumerates the USB device. For a full firmware reset (clears on-chip calibration-RAM /
    /// finger-detect state too) use the explicit [`Self::reboot_sensor`] (`synfp reboot`). Best-effort;
    /// skipped while panicking (no tunnel I/O during unwinding). Suppress via
    /// [`Self::set_shutdown_on_drop`].
    fn drop(&mut self) {
        if self.shutdown_on_drop && !std::thread::panicking() {
            self.graceful_shutdown();
        }
    }
}

impl<T: Transport> Session<T> {
    /// Wrap an already-handshaked transport + derived session keys.
    pub fn new(transport: T, keys: SessionKeys) -> Self {
        Self::new_with_context(transport, keys, false, None)
    }

    /// Like [`Self::new`] but seeds `ctx+0x2d0` upload dedup and a cached ROM identity.
    pub fn new_with_context(
        transport: T,
        keys: SessionKeys,
        fw_upload_context: bool,
        cached_identity: Option<SensorIdentity>,
    ) -> Self {
        Self {
            transport,
            keys,
            fw_upload_context,
            cached_identity,
            last_recon_config: None,
            shutdown_on_drop: true,
        }
    }

    /// Enable/disable the graceful-shutdown-on-drop cleanup (default enabled). Disable when another
    /// session or tool will take over the device, or after an explicit [`Self::reboot_sensor`].
    pub fn set_shutdown_on_drop(&mut self, v: bool) {
        self.shutdown_on_drop = v;
    }

    /// Best-effort graceful shutdown: stop any in-flight capture (`0x04`) and drain pending interrupts
    /// so the die is left idle for the next session — no firmware reboot, no USB re-enumeration. Used
    /// by [`Self::drop`]; safe to call explicitly. Errors are ignored (the device may already be gone).
    pub fn graceful_shutdown(&mut self) {
        use crate::capture::CaptureIo;
        let _ = CaptureIo::stop(self);
        self.drain_interrupts();
    }

    /// Perform the full pairing + TLS handshake over `transport` and return an established session.
    /// `cert_store` is the raw pairing cert-store bytes; `binding` is the host-binding secret (empty
    /// `b""` for the default seat binding). The caller opens/resets the transport first (e.g.
    /// `NusbTransport::reset_and_open_any`). Mirrors the DLL wake → ClientHello → cert/kex/verify →
    /// Finished exchange; the crypto is [`crate::handshake`]/[`crate::tls`] (verified vs
    /// python-validity). Errors if the sensor's Finished doesn't verify.
    pub fn establish(transport: T, cert_store: &[u8], binding: &[u8]) -> Result<Self> {
        Self::establish_with_plan(transport, cert_store, binding, None)
    }

    /// Like [`Self::establish`] but accepts an optional [`BringUpPlan`] from pre-TLS bring-up
    /// (seeds `fw_upload_context` + cached identity without re-probing).
    pub fn establish_with_plan(
        mut transport: T,
        cert_store: &[u8],
        binding: &[u8],
        plan: Option<&BringUpPlan>,
    ) -> Result<Self> {
        let store = parse_cert_store(cert_store)?;
        let pair = Pairing::open_with_binding(&store, binding)?;
        let signer = SigningKey::from(&pair.host_priv);

        // Wake/init preamble before the TLS flights — also seeds upload-context when unplanned.
        transport.write_cmd(&[Opcode::GetRomInfo.byte()])?;
        let rom_raw = transport.read_cmd(PREAMBLE_REPLY_MAX)?;
        let (fw_upload_context, cached_identity) = if let Some(p) = plan {
            (p.fw_upload_context, Some(p.identity.clone()))
        } else {
            seed_upload_context_from_rom_reply(&mut transport, &rom_raw)?
        };
        transport.write_cmd(&[Opcode::InitStep.byte()])?;
        transport.read_cmd(PREAMBLE_REPLY_MAX)?;

        // Flight 1: ClientHello → ServerHello.
        let mut tr = Transcript::new();
        let client_random = rand32();
        let ch = client_hello(&client_random);
        tr.update(&ch);
        let mut flight1 = vec![CMD_ENVELOPE_TAG, 0, 0, 0];
        flight1.extend(plaintext_record(RecordType::Handshake as u8, &ch));
        transport.write_cmd(&flight1)?;
        let resp1 = transport.read_cmd(REPLY_MAX)?;
        let server_random = parse_flight1(&resp1, &mut tr)
            .ok_or_else(|| Error::Malformed("no ServerHello".into()))?;

        // ECDH → session keys + master secret.
        let eph = SecretKey::generate_from_rng(&mut os_rng());
        let shared =
            p256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), pair.sensor_pub.as_affine());
        let pre = shared.raw_secret_bytes();
        let keys = SessionKeys::derive(pre, &client_random, &server_random);
        let mut ms_seed = b"master secret".to_vec();
        ms_seed.extend_from_slice(&client_random);
        ms_seed.extend_from_slice(&server_random);
        let master = prf(pre, &ms_seed, 0x30);

        // Flight 2: Certificate ‖ ClientKeyExchange ‖ CertificateVerify ‖ ChangeCipherSpec ‖ Finished.
        let mut certbody = Vec::new();
        for _ in 0..2 {
            certbody.push(0);
            certbody.extend_from_slice(&(pair.host_cert.len() as u16).to_be_bytes());
        }
        certbody.extend_from_slice(&[0xac, 0x16]);
        certbody.extend_from_slice(&pair.host_cert);
        let cert_msg = handshake_msg(HS_CERTIFICATE, &certbody);
        tr.update(&cert_msg);
        let kex = client_key_exchange(&eph.public_key());
        tr.update(&kex);
        let cv = certificate_verify(&signer, &tr)?;
        tr.update(&cv);

        let mut flight2 = cert_msg.clone();
        flight2.extend_from_slice(&kex);
        flight2.extend_from_slice(&cv);
        let vd = verify_data(&master, b"client finished", &tr);
        let mut fin_iv = [0u8; IV_LEN];
        os_rng().fill_bytes(&mut fin_iv);
        let fin_rec = tls::wrap(&keys, RecordType::Handshake, &finished(&vd), fin_iv)?;
        let mut f2 = vec![CMD_ENVELOPE_TAG, 0, 0, 0];
        f2.extend(plaintext_record(RecordType::Handshake as u8, &flight2));
        f2.extend_from_slice(&CHANGE_CIPHER_SPEC);
        f2.extend_from_slice(&fin_rec);
        transport.write_cmd(&f2)?;

        let resp2 = transport.read_cmd(REPLY_MAX)?;
        match first_record(&resp2, RecordType::Handshake as u8).map(|r| tls::unwrap(&keys, &r)) {
            Some(Ok(_)) => Ok(Self::new_with_context(
                transport,
                keys,
                fw_upload_context,
                cached_identity,
            )),
            _ => Err(Error::Malformed("session Finished not verified".into())),
        }
    }

    /// Borrow the underlying transport (e.g. for a raw bulk/interrupt read the traits don't cover).
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }


    /// One encrypted command round-trip: wrap `cmd` as `ApplicationData` (fresh random IV), write it,
    /// read the reply, and unwrap the first app-data record. Returns the decrypted response payload
    /// (`[status:u16][..]`).
    pub fn tunnel(&mut self, cmd: &[u8]) -> Result<Vec<u8>> {
        if cmd.first() == Some(&0x02) && std::env::var_os("SYNA_DUMP_ARM").is_some() {
            let _ = std::fs::write(format!("captures/our_arm_{}.bin", cmd.len()), cmd);
        }
        trace!(
            target: CMD,
            "→ {} {}B: {}",
            opcode_label(cmd),
            cmd.len(),
            hex_preview(cmd, 32),
        );
        let mut iv = [0u8; IV_LEN];
        os_rng().fill_bytes(&mut iv);
        let record = tls::wrap(&self.keys, RecordType::ApplicationData, cmd, iv)?;
        self.transport.write_cmd(&record)?;
        let reply = self.transport.read_cmd(REPLY_MAX)?;
        let app = first_record(&reply, RecordType::ApplicationData as u8)
            .ok_or_else(|| Error::Malformed("no app-data record in reply".into()))?;
        let (_, plaintext) = tls::unwrap(&self.keys, &app)?;
        trace!(
            target: CMD,
            "← {} {}B: {}",
            reply_status_label(&plaintext),
            plaintext.len(),
            hex_preview(&plaintext, 32),
        );
        Ok(plaintext)
    }

    /// Status word (leading `u16`) of a tunneled reply, or `0xffff` if too short.
    pub(crate) fn status_of(reply: &[u8]) -> u16 {
        reply
            .get(..2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .unwrap_or(0xffff)
    }
}

mod read;
mod fw_upload;
mod arm;
mod bootstrap;
mod io_impls;
mod framing;
pub(crate) use framing::*;

#[cfg(test)]
mod tests;
