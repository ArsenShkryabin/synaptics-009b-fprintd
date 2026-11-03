//! Minimal replica of the stock DLL's Hello-identify sequence, to test whether actually **sending
//! the mode2 pre-arm ROM config** (which our driver currently dedups away) changes finger-detect.
//!
//! Ground truth (Windows USBPcap `captures/win-usbpcap/`, decoded by record size): the DLL's identify
//! session is `TLS → 0x2940 (mode2 pre-arm, ONCE, t=0.192) → 0x49f0 (capture program) → arm
//! (Started@0.324) → wait ~6s → real finger`. No calibration in between. Our driver instead runs full
//! calibration in bootstrap and then **skips** the pre-arm (`SkippedDedup`, the `fw_upload_context`
//! bug) — and when forced, the `0x06` upload was rejected `0x04AA` (likely calibration-state).
//!
//! This probe mirrors the DLL order: skip calibration, seed `fw_upload_context=0`, send the mode2
//! pre-arm ONCE as the first post-bootstrap command, print its status, then arm and watch EP-0x83.
//!
//! Phase 1 (no finger, automatic): after arm, watch 800 ms — PASS if quiet (no spurious FingerDown).
//! Phase 2 (FINGER-GATED, opt-in `SYNA_WAIT_FINGER=1`): keep watching up to 30 s for a real touch;
//! success = a **type-3 measurement stream** (byte0=3) — the functional signal our arm currently lacks.
//!
//! Env knobs:
//! - `SYNA_CALIBRATE=1`   run full calibration (produces the settle frame the `0x48` baseline is
//!   sourced from; without it the arm carries no `0x48`).
//! - `SYNA_WAIT_FINGER=1`  run the finger-gated type-3 phase.
//! - `SYNA_DUMP_SETTLE=1` / `SYNA_DUMP_ARM=1`  dump the settle frame / arm bytes and exit.
//! - `SYNA_ARM_ANYWAY=1`  arm even if the pre-arm `0x06` upload is rejected (wire-size capture).
//!   (This probe forces the pre-arm send itself via `set_fw_upload_context(false)`; the driver path
//!   now seeds `fw_upload_context=false` automatically on cold 009b — the provision-state read gate
//!   in `bringup::infer_fw_upload_context` — so `finger_detect_probe`/`live_viewer` re-upload the
//!   pre-arm on every arm with no env override needed.)
//!
//! ```console
//! cargo run --release --bin prearm_dll_seq -- certstore.bin                       # phase 1 only
//! # full 0x48 identify test (device; touch when Phase 2 prompts); 0x48 baseline is default-on:
//! SYNA_CALIBRATE=1 SYNA_WAIT_FINGER=1 SYNA_PCAP=/tmp/x.pcap \
//!   cargo run --release --bin prearm_dll_seq -- certstore.bin
//! ```

use std::time::Instant;

use synaptics_prometheus::capture::{CaptureFingerDetectIo, CaptureIo};
use synaptics_prometheus::capture_pipeline::{build_upload_cmd_detailed, ArmRecipe, ReadMechanism};
use synaptics_prometheus::capture_prog::CaptureEvent;
use synaptics_prometheus::pre_arm::PreArmMode;
use synaptics_prometheus::session::{BootstrapOptions, DeviceContext, Session};

const QUIET_WINDOW_MS: u128 = 800;
const FINGER_WAIT_MS: u128 = 30_000;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
}

fn tag(pkt: &[u8]) -> &'static str {
    match CaptureEvent::parse(pkt) {
        Some(CaptureEvent::Started) => "Started(0)",
        Some(CaptureEvent::FingerDown) => "FingerDown(2)",
        Some(CaptureEvent::Complete) | Some(CaptureEvent::Progress) => "type-3",
        _ => "other",
    }
}

/// Minimal stderr logger so the `tunnel` choke point (`target: "syna::cmd"`) traces every post-TLS
/// command + reply status without pulling `env_logger` (a dev-dep) into `src/bin`. Prints the full
/// wire order — which `0x06` upload the device rejects, and what preceded it.
struct StderrLog;
impl log::Log for StderrLog {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, r: &log::Record) {
        eprintln!("[{:<5} {}] {}", r.level(), r.target(), r.args());
    }
    fn flush(&self) {}
}
static LOGGER: StderrLog = StderrLog;

fn main() -> synaptics_prometheus::Result<()> {
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(log::LevelFilter::Trace);
    let certstore = std::env::args().nth(1).unwrap_or_else(|| "certstore.bin".into());
    let wait_finger = std::env::var("SYNA_WAIT_FINGER").is_ok();

    println!("# prearm_dll_seq — DLL-order pre-arm probe. KEEP SENSOR CLEAR until told otherwise.");
    let mut session = Session::open_nusb(&certstore)?;

    // DLL order: no calibration between TLS and the pre-arm. Skip it so the sensor is in the same
    // "warm" state the DLL's Hello session sees (calibration happened in an earlier boot session).
    // SYNA_CALIBRATE=1 runs full calibration instead → the with-cal arm (to size-check vs DLL 0x49f0).
    let calibrate = std::env::var("SYNA_CALIBRATE").is_ok();
    let opts = BootstrapOptions { skip_calibration: !calibrate, reboot_on_capture_fault: true };
    let ctx = session.bootstrap_with(opts)?;
    let DeviceContext { cfg, factory_cal_values: fcv, vendor_cal, .. } = ctx;
    println!(
        "# bootstrap (skip_calibration): subtype=0x{:04x} vendor_cal={}",
        cfg.subtype,
        vendor_cal.is_some()
    );

    // Phase-0 diagnostic: dump the retained step-7 settle frame (the DLL's 0x48 source) so we can
    // compare its line count / stride / headers to the real DLL 0x48 (152×56 interlaced, field byte
    // 0x02) at /tmp/dll_arm_382.bin offset 10349. Run with SYNA_CALIBRATE=1 to populate baseline_frame.
    if std::env::var("SYNA_DUMP_SETTLE").is_ok() {
        match vendor_cal.as_ref().and_then(|c| c.baseline_frame.as_ref()) {
            Some(f) => {
                let stride = 152usize; // 0x2449 wire stride (144 line_width + 8 SYNC_LINE_HEADER)
                let lines = f.len() / stride;
                println!(
                    "# (SYNA_DUMP_SETTLE) settle frame {} B = {} lines × {stride} stride (rem {})",
                    f.len(),
                    lines,
                    f.len() % stride
                );
                for i in 0..lines.min(4) {
                    println!("#   line {i}: hdr [{}]", hex(&f[i * stride..i * stride + 8]));
                }
                let out =
                    std::env::var("SYNA_SETTLE_OUT").unwrap_or_else(|_| "/tmp/our_settle.bin".into());
                std::fs::write(&out, f).ok();
                println!("# wrote raw settle frame to {out}");
            }
            None => println!(
                "# (SYNA_DUMP_SETTLE) no baseline_frame — run with SYNA_CALIBRATE=1 (settle needs calibration)"
            ),
        }
        return Ok(());
    }

    let Some((arm, path)) = build_upload_cmd_detailed(
        &cfg,
        &fcv,
        ReadMechanism::Polled,
        &ArmRecipe::IDENTIFY_VERIFY,
        0,
        vendor_cal.as_ref(),
    ) else {
        eprintln!("# could not build identify arm");
        return Ok(());
    };
    println!("# arm program: {} bytes, build_path={path:?}", arm.len());
    if std::env::var("SYNA_DUMP_ARM").is_ok() {
        let out = std::env::var("SYNA_ARM_OUT").unwrap_or_else(|_| "/tmp/our_arm.bin".into());
        std::fs::write(&out, &arm).ok();
        println!("# (SYNA_DUMP_ARM) wrote arm bytes to {out}");
        return Ok(());
    }

    // Mirror the DLL: fw_upload_context stays 0 on provisioned 009b → the pre-arm actually uploads.
    session.set_fw_upload_context(false);
    println!("\n>>> sending mode2 pre-arm ROM config (0x06), ONCE, as first post-bootstrap command…");
    match session.send_pre_arm_rom_config(PreArmMode::Mode2) {
        Ok(outcome) => println!("    pre-arm outcome: {outcome:?}"),
        Err(e) => {
            println!("    pre-arm FAILED: {e}");
            println!("    (0x04AA rejection — pre-arm did NOT reach the sensor)");
            if std::env::var("SYNA_ARM_ANYWAY").is_err() {
                return Ok(());
            }
            println!("    (SYNA_ARM_ANYWAY: continuing to arm for wire-size capture)");
        }
    }

    // Re-dedup subsequent sends the way the DLL does (ctx+0x220 per-record) — set the flag back so a
    // future arm in this session would skip re-upload. For this one-shot probe it does not matter.
    session.set_fw_upload_context(true);

    CaptureIo::stop(&mut session)?;
    let status = CaptureIo::arm(&mut session, &arm)?;
    println!("# arm status = 0x{status:04x} [{}]", if status == 0 { "OK" } else { "REJECTED" });
    if status != 0 {
        return Ok(());
    }

    // Phase 1: quiet window (no finger).
    println!("\n>>> Phase 1 — KEEP SENSOR CLEAR. Watching {QUIET_WINDOW_MS} ms for a spurious FingerDown…");
    let start = Instant::now();
    let mut spurious = false;
    while start.elapsed().as_millis() < QUIET_WINDOW_MS {
        let pkt = session.read_capture_interrupt(40)?;
        if pkt.is_empty() {
            continue;
        }
        let t = start.elapsed().as_millis();
        println!("    +{t:>5}ms  [{}]  {}", hex(&pkt), tag(&pkt));
        if matches!(CaptureEvent::parse(&pkt), Some(CaptureEvent::FingerDown)) {
            spurious = true;
            break;
        }
    }
    println!(
        "    => Phase 1: {}",
        if spurious { "SPURIOUS FingerDown ✗ (same as before)" } else { "QUIET ✓ (like the DLL)" }
    );

    // Phase 2: real touch (finger-gated, opt-in).
    if wait_finger {
        println!("\n>>> Phase 2 — TOUCH AND HOLD now. Watching up to {}s for a type-3 stream…", FINGER_WAIT_MS / 1000);
        let start = Instant::now();
        let mut saw_type3 = false;
        while start.elapsed().as_millis() < FINGER_WAIT_MS {
            let pkt = session.read_capture_interrupt(100)?;
            if pkt.is_empty() {
                continue;
            }
            let t = start.elapsed().as_millis();
            let ev = tag(&pkt);
            println!("    +{t:>6}ms  [{}]  {ev}", hex(&pkt));
            if matches!(CaptureEvent::parse(&pkt), Some(CaptureEvent::Complete | CaptureEvent::Progress)) {
                saw_type3 = true;
            }
        }
        println!(
            "    => Phase 2: {}",
            if saw_type3 {
                "type-3 stream seen ✓ — the pre-arm FIXED finger-detect!"
            } else {
                "NO type-3 on touch ✗ — pre-arm alone did not fix it"
            }
        );
    } else {
        println!("\n# (set SYNA_WAIT_FINGER=1 to run the finger-gated type-3 phase)");
    }

    let _ = session.capture_complete_ack();
    let _ = CaptureIo::stop(&mut session);
    Ok(())
}
