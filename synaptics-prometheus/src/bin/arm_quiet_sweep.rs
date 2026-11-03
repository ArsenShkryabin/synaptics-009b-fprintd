//! Automated "is the finger-detect arm QUIET with no finger?" sweep.
//!
//! Ground truth (Windows USBPcap, `captures/win-usbpcap/`): after arming with no finger, the stock
//! DLL sensor emits **only** a `Started(0)` and then stays silent until a real touch (~seconds
//! later). Our arm instead fires a **spurious `FingerDown(2)` milliseconds after arm** — the bug.
//!
//! This binary bootstraps once, then arms under several candidate configs and, for each, watches
//! EP-0x83 for a short window. PASS = no `FingerDown(2)` in the window (quiet, like the DLL);
//! FAIL = a spurious `FingerDown(2)` fired. **Keep the sensor CLEAR (do not touch) for the whole
//! run.** No manual judgement needed — it prints a PASS/FAIL table and exits non-zero if any config
//! that should be quiet fired a spurious event.
//!
//! CAVEAT (RE, `syna_wbdi_wait_for_finger@0x18001c0a8`): the DLL's finger-detect wait blocks on an
//! event and, on *every* EP-0x83 wake, re-queries `syna_vfm_query_capture_touch_status(query 1)`,
//! latching only on `(status & 0x06)`. So the raw byte0 `FingerDown(2)` onset merely *wakes* the DLL
//! — it requeries, sees no finger, and loops. The spurious `02 00 40 10 00` at ~102 ms is therefore
//! **cosmetic** (our wait dismisses it too — see `tests/finger_detect_kat.rs`). This sweep measures
//! that cosmetic symptom (Windows sensor stays fully silent; ours emits a settling onset). The
//! *functional* gap — no type-3 measurement stream on a real touch — is the sensor's AFE finger-detect
//! baseline (pre-arm ROM config), which is FINGER-GATED and not testable here.
//!
//! It's a `src/bin/` target (not an example) on purpose: examples pull the driver's dev-deps
//! (incl. the in-flight `synaptics-pipeline-graph`), binaries do not — so this builds regardless.
//!
//! ```console
//! cargo run --release --bin arm_quiet_sweep -- certstore.bin
//! ```

use std::time::Instant;

use synaptics_prometheus::capture::{CaptureFingerDetectIo, CaptureIo};
use synaptics_prometheus::capture_pipeline::{
    build_upload_cmd_detailed, ArmRecipe, ReadMechanism,
};
use synaptics_prometheus::capture_prog::{CaptureConfig, CaptureEvent};
use synaptics_prometheus::calibration::CalResults;
use synaptics_prometheus::fw_registry;
use synaptics_prometheus::pre_arm::PreArmMode;
use synaptics_prometheus::session::{BootstrapOptions, DeviceContext, Session};
use synaptics_prometheus::transport::NusbTransport;

/// How long to watch for a spurious event after arm. The real touch is seconds out; a spurious
/// FingerDown fires within milliseconds — 800 ms is a generous quiet window.
const QUIET_WINDOW_MS: u128 = 800;

struct Candidate {
    label: &'static str,
    pre_arm: PreArmMode,
    finger_detect: bool,
    omit_2e: bool,
}

fn candidates() -> Vec<Candidate> {
    use PreArmMode::{Mode2, Standard};
    vec![
        Candidate { label: "Mode2 + finger-detect + 0x2e (baseline)", pre_arm: Mode2, finger_detect: true, omit_2e: false },
        Candidate { label: "Mode2 + finger-detect, NO 0x2e", pre_arm: Mode2, finger_detect: true, omit_2e: true },
        Candidate { label: "Mode2, NO finger-detect, NO 0x2e (minimal)", pre_arm: Mode2, finger_detect: false, omit_2e: true },
        Candidate { label: "Standard, NO finger-detect, NO 0x2e (minimal)", pre_arm: Standard, finger_detect: false, omit_2e: true },
    ]
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
}

/// What one candidate's quiet-window probe observed.
struct QuietProbe {
    /// The `0x02` arm was built AND accepted. `false` ⇒ the candidate was skipped, not measured.
    armed: bool,
    /// The quiet window elapsed with no spurious `FingerDown` — the property under test.
    quiet: bool,
    /// Every EP-0x83 interrupt packet seen in the window, as `(ms since arm, packet)`.
    events: Vec<(u128, Vec<u8>)>,
}

/// Arm under one candidate and watch EP-0x83 for the quiet window.
fn probe_quiet(
    session: &mut Session<NusbTransport>,
    cfg: &CaptureConfig,
    fcv: &[u8],
    vendor_cal: Option<&CalResults>,
    cand: &Candidate,
) -> synaptics_prometheus::Result<QuietProbe> {
    // Clean slate before arming.
    let _ = CaptureIo::stop(session);
    for _ in 0..8 {
        if session.read_capture_interrupt(15)?.is_empty() {
            break;
        }
    }

    let recipe = ArmRecipe { finger_detect: cand.finger_detect, omit_chunk_2e: cand.omit_2e, ..ArmRecipe::IDENTIFY_VERIFY };
    let Some((arm, _path)) =
        build_upload_cmd_detailed(cfg, fcv, ReadMechanism::Polled, &recipe, 0, vendor_cal)
    else {
        return Ok(QuietProbe { armed: false, quiet: false, events: Vec::new() });
    };

    let outcome = session.send_pre_arm_rom_config(cand.pre_arm)?;
    println!("    pre-arm ({:?}) -> {outcome:?}", cand.pre_arm);
    CaptureIo::stop(session)?;
    let status = CaptureIo::arm(session, &arm)?;
    if status != 0 {
        eprintln!("    arm rejected: status=0x{status:04x}");
        return Ok(QuietProbe { armed: false, quiet: false, events: Vec::new() });
    }

    let start = Instant::now();
    let mut events = Vec::new();
    let mut spurious = false;
    while start.elapsed().as_millis() < QUIET_WINDOW_MS {
        let pkt = session.read_capture_interrupt(40)?;
        if pkt.is_empty() {
            continue;
        }
        let t = start.elapsed().as_millis();
        let is_finger = matches!(CaptureEvent::parse(&pkt), Some(CaptureEvent::FingerDown));
        events.push((t, pkt.clone()));
        if is_finger {
            spurious = true;
            break; // a spurious FingerDown with no finger is the failure we hunt
        }
    }

    let _ = session.capture_complete_ack();
    let _ = CaptureIo::stop(session);
    Ok(QuietProbe { armed: true, quiet: !spurious, events })
}

fn main() -> synaptics_prometheus::Result<()> {
    let certstore = std::env::args().nth(1).unwrap_or_else(|| "certstore.bin".into());

    println!("# arm-quiet sweep — KEEP SENSOR CLEAR (do NOT touch) for the whole run.");
    let mut session = Session::open_nusb(&certstore)?;
    let caps = session.presence_caps()?;
    println!(
        "# caps: subtype-pref={:?} scs_sensor={} spurious_type2_irq={}",
        caps.preferred, caps.scs_sensor, caps.spurious_type2_irq
    );
    let ctx = session.bootstrap_with(BootstrapOptions::default())?;
    let DeviceContext { cfg, factory_cal_values: fcv, vendor_cal, .. } = ctx;
    println!("# bootstrap: subtype=0x{:04x} vendor_cal={}\n", cfg.subtype, vendor_cal.is_some());

    let id = session.sensor_identity()?;
    for (label, want) in [
        ("Standard/0x80", fw_registry::FwWantFlags::PRE_ARM),
        ("Mode2/0x400000", fw_registry::FwWantFlags::PRE_ARM_MODE2),
    ] {
        match fw_registry::select_pre_arm(fw_registry::REGISTRY, &id, want) {
            Some(r) => println!("# fw module for {label}: src_addr=0x{:x} len=0x{:x} -> data/fw_modules/fwmod_{:016x}.bin", r.src_addr, r.len, r.src_addr),
            None => println!("# pre-arm module for {label}: NO REGISTRY MATCH"),
        }
    }
    println!();

    let mut all_pass = true;
    let mut results: Vec<(String, String)> = Vec::new();
    for cand in candidates() {
        println!(">>> {}", cand.label);
        let probe = probe_quiet(&mut session, &cfg, &fcv, vendor_cal.as_ref(), &cand)?;
        for (t, pkt) in &probe.events {
            let tag = match CaptureEvent::parse(pkt) {
                Some(CaptureEvent::Started) => "Started(0)",
                Some(CaptureEvent::FingerDown) => "FingerDown(2)  <-- SPURIOUS",
                Some(CaptureEvent::Complete) | Some(CaptureEvent::Progress) => "type-3",
                _ => "other",
            };
            println!("    +{t:>4}ms  [{}]  {tag}", hex(pkt));
        }
        let verdict = if !probe.armed {
            "SKIP (arm rejected / no build)".to_string()
        } else if probe.quiet {
            "PASS — quiet ✓".to_string()
        } else {
            all_pass = false;
            "FAIL — spurious FingerDown ✗".to_string()
        };
        println!("    => {verdict}\n");
        results.push((cand.label.to_string(), verdict));
    }

    println!("# SUMMARY");
    for (label, verdict) in &results {
        println!("  {label:<44}  {verdict}");
    }
    println!(
        "\n# A quiet finger-detect config (PASS) is the goal — it matches the DLL (silent until a real\n\
         # touch). If Standard fails but Mode2 passes, the pre-arm mode was the fix. If the OMITTED\n\
         # configs are quiet but the finger-detect ones are not, the 0x26 chunk itself trips at arm."
    );

    if all_pass {
        Ok(())
    } else {
        std::process::exit(1)
    }
}
