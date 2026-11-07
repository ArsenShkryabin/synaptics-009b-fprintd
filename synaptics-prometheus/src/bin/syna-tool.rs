use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use synaptics_biometric::{ConditionedImage, HostBiometricBackend, MatchLevel};
use synaptics_prometheus::capture::{CaptureOpts, CaptureOutcome, CaptureSession};
use synaptics_prometheus::capture_prog::capture_spec::CaptureMode;
use synaptics_prometheus::capture_prog::ArmOverrides;
use synaptics_prometheus::reconstruct::reconstruct_sync_frame;
use synaptics_prometheus::session::{BootstrapOptions, DeviceContext, Session};
use synaptics_prometheus::template_store::TemplateStore;
use synaptics_prometheus_qm::QmBackend;

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn sig_handler(_: libc::c_int) {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
}

const TEMPLATE_DIR: &str = "/var/lib/fprint/synaptics";
const CERTSTORE_PATH: &str = "/etc/synaptics/certstore.bin";

fn subtype_to_name(subtype: u8) -> &'static str {
    match subtype {
        1 => "right-thumb",
        2 => "right-index-finger",
        3 => "right-middle-finger",
        4 => "right-ring-finger",
        5 => "right-little-finger",
        6 => "left-thumb",
        7 => "left-index-finger",
        8 => "left-middle-finger",
        9 => "left-ring-finger",
        10 => "left-little-finger",
        _ => "unknown",
    }
}

fn name_to_subtype(name: &str) -> Option<u8> {
    match name {
        "right-thumb" => Some(1),
        "right-index-finger" => Some(2),
        "right-middle-finger" => Some(3),
        "right-ring-finger" => Some(4),
        "right-little-finger" => Some(5),
        "left-thumb" => Some(6),
        "left-index-finger" => Some(7),
        "left-middle-finger" => Some(8),
        "left-ring-finger" => Some(9),
        "left-little-finger" => Some(10),
        "any" => Some(0),
        _ => None,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Templates are biometric data. Even when `syna-tool` is run directly
    // (not through the root daemon), never create them world-readable.
    unsafe {
        libc::umask(0o077);
        libc::signal(libc::SIGTERM, sig_handler as *const () as usize);
        libc::signal(libc::SIGINT, sig_handler as *const () as usize);
    }

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: syna-tool <pair|enroll|verify|list|delete|inspect> ...");
        std::process::exit(1);
    }

    let cmd = &args[1];
    let store = TemplateStore::open(TEMPLATE_DIR)?;

    match cmd.as_str() {
        "pair" => {
            let out_path = args.get(2).map(|s| s.as_str()).unwrap_or(CERTSTORE_PATH);
            let reuse_key = args.iter().any(|a| a == "--reuse-existing");
            let host_sk = if reuse_key && Path::new(CERTSTORE_PATH).exists() {
                let existing = std::fs::read(CERTSTORE_PATH)?;
                let st = synaptics_crypto::pairing::parse_cert_store(&existing)?;
                st.priv_blob.as_deref().and_then(|pb| {
                    synaptics_crypto::pairing::unseal_host_key(
                        pb,
                        &synaptics_crypto::crypto::derive_gwk(b""),
                    )
                    .ok()
                })
            } else {
                None
            };
            eprintln!("Pairing with 06cb:009b sensor (flashless path)...");
            let (mut dev, (vid, pid)) = synaptics_prometheus::RawDevice::open_any()?;
            eprintln!("Opened device {vid:04x}:{pid:04x}");
            let certstore_bytes = synaptics_prometheus::init::pair_009b_flashless(&mut dev, host_sk)?;
            if let Some(parent) = Path::new(out_path).parent() {
                std::fs::create_dir_all(parent)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
                }
            }
            std::fs::write(out_path, &certstore_bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(out_path, std::fs::Permissions::from_mode(0o600));
            }
            println!("PAIRED:{}", out_path);
        }
        "list" => {
            if args.len() < 3 {
                eprintln!("Usage: syna-tool list <uid>");
                std::process::exit(1);
            }
            let uid: u32 = args[2].parse()?;
            if let Ok(entries) = store.list_fingers(uid) {
                for st in entries {
                    println!("{}", subtype_to_name(st));
                }
            }
        }
        "inspect" => {
            if args.len() < 3 {
                eprintln!("Usage: syna-tool inspect <uid> [finger_name]");
                std::process::exit(1);
            }
            let uid: u32 = args[2].parse()?;
            let filter_st = args.get(3).and_then(|s| name_to_subtype(s));
            let entries = store.list_fingers(uid)?;
            for st in entries {
                if let Some(want) = filter_st
                    && want != st
                {
                    continue;
                }
                let Some(stored) = store.load(uid, st)? else {
                    continue;
                };
                let enrolled = synaptics_prometheus_qm::EnrolledTemplate::from_blob(&stored.blob)
                    .map_err(|e| format!("invalid enrolled template: {e:?}"))?;
                println!(
                    "finger={} (subtype=0x{st:02x}) bytes={} views={}",
                    subtype_to_name(st),
                    stored.blob.len(),
                    enrolled.views.len()
                );
                for (vi, v) in enrolled.views.iter().enumerate() {
                    let mut shifted = v.clone();
                    for (mi, m) in shifted.minutiae.iter_mut().enumerate() {
                        m.x = m.x.saturating_add(3);
                        m.y = m.y.saturating_add(2);
                        m.descriptor[mi % 8] ^= 0x07;
                        m.descriptor[(mi + 3) % 8] ^= 0x13;
                    }
                    let ds = synaptics_prometheus_qm::diagnose(
                        &shifted,
                        v,
                        synaptics_prometheus_qm::types::MatchLevel::Level1,
                        synaptics_prometheus_qm::matcher::DEFAULT_IMAGE_W,
                        synaptics_prometheus_qm::matcher::DEFAULT_IMAGE_H,
                    );
                    println!(
                        "  view[{vi}]: minutiae={:3} split={:2} field_0c=0x{:04x} shifted(+3,+2): anchors={:3} score={:4}/{} cons=({},occ={},peak={})",
                        v.minutiae.len(),
                        v.split,
                        v.field_0c,
                        ds.anchor_count,
                        ds.score,
                        ds.threshold,
                        ds.consensus.found,
                        ds.consensus.occupied,
                        ds.consensus.peak,
                    );
                }
                for (i, a) in enrolled.views.iter().enumerate() {
                    for (j, b) in enrolled.views.iter().enumerate() {
                        if i == j {
                            continue;
                        }
                        let d = synaptics_prometheus_qm::diagnose(
                            a,
                            b,
                            synaptics_prometheus_qm::types::MatchLevel::Level1,
                            synaptics_prometheus_qm::matcher::DEFAULT_IMAGE_W,
                            synaptics_prometheus_qm::matcher::DEFAULT_IMAGE_H,
                        );
                        let xforms: Vec<_> = d
                            .anchors
                            .iter()
                            .filter(|an| an.is_anchor)
                            .map(|an| an.transform.to_xform_record(1))
                            .collect();
                        let ungated = synaptics_prometheus_qm::consensus::geometric_consensus_pick(
                            &xforms,
                            synaptics_prometheus_qm::matcher::DEFAULT_IMAGE_W,
                            synaptics_prometheus_qm::matcher::DEFAULT_IMAGE_H,
                        );
                        println!(
                            "  pair {i}->{j}: anchors={:2} score={:4}/{} gated_cons=({},occ={},peak={}) ungated_cons=({},occ={},peak={})",
                            d.anchor_count,
                            d.score,
                            d.threshold,
                            d.consensus.found,
                            d.consensus.occupied,
                            d.consensus.peak,
                            ungated.found,
                            ungated.occupied,
                            ungated.peak,
                        );
                    }
                }
            }
        }
        "delete" => {
            if args.len() < 3 {
                eprintln!("Usage: syna-tool delete <uid> [finger_name]");
                std::process::exit(1);
            }
            let uid: u32 = args[2].parse()?;
            if args.len() >= 4 {
                if let Some(st) = name_to_subtype(&args[3]) {
                    let _ = store.delete(uid, st);
                }
            } else if let Ok(entries) = store.list_fingers(uid) {
                for st in entries {
                    let _ = store.delete(uid, st);
                }
            }
            println!("OK");
        }
        "enroll" => {
            if args.len() < 4 {
                eprintln!("Usage: syna-tool enroll <uid> <finger_name>");
                std::process::exit(1);
            }
            let uid: u32 = args[2].parse()?;
            let finger_name = &args[3];
            let subtype = name_to_subtype(finger_name).ok_or("Invalid finger name")?;

            let certstore = if PathBuf::from(CERTSTORE_PATH).exists() {
                CERTSTORE_PATH
            } else {
                "certstore.bin"
            };

            let mut session = Session::open_nusb(certstore)?;
            let ctx = session.bootstrap_with(BootstrapOptions::default())?;
            let DeviceContext { cfg, factory_cal_values: fcv, vendor_cal, st8, st9, .. } = ctx;

            let sync_frames = 3;
            let spec = CaptureMode::Stream
                .spec_with(&ArmOverrides { sync_frames: Some(sync_frames), ..Default::default() });

            let mut capture = CaptureSession::new(&mut session, cfg.clone(), fcv, vendor_cal, st8, st9);
            let (program, _) = capture.resolve(&spec).unwrap();

            let layout = cfg.sync_layout(sync_frames);
            let params = synaptics_prometheus::reconstruct::recon_params(cfg.prog.program).unwrap();

            let backend = QmBackend::new();
            let mut enroll = backend.new_enrollment();

            println!("STATUS:READY");
            std::io::stdout().flush()?;

            let mut stage = 0;
            let mut ready_for_touch = false;
            let mut finger_down = false;

            for _ in 0..600 {
                if STOP_REQUESTED.load(Ordering::SeqCst) {
                    eprintln!("enroll: stop requested via signal");
                    break;
                }
                let outcome = match capture.capture(&program, CaptureOpts::stream(sync_frames), || !STOP_REQUESTED.load(Ordering::SeqCst)) {
                    Ok(o) => o,
                    Err(e) => {
                        if STOP_REQUESTED.load(Ordering::SeqCst) {
                            break;
                        }
                        eprintln!("transient frame error: {e}");
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                };
                match outcome {
                    CaptureOutcome::Stream(raw) => {
                        if let Some(img) = reconstruct_sync_frame(&raw.bytes, layout, params) {
                            let px = &img.pixels;
                            let sum: u64 = px.iter().map(|&p| p as u64).sum();
                            let mean = sum as f64 / px.len() as f64;
                            let var = px.iter().map(|&p| (p as f64 - mean).powi(2)).sum::<f64>() / px.len() as f64;

                            // Empirical thresholds from live telemetry:
                            // Startup settling: var < 600
                            // Sensor empty/idle noise: 1200 <= var <= 1450
                            // Finger touching sensor: var >= 1800
                            if !ready_for_touch {
                                if (1100.0..=1450.0).contains(&var) {
                                    ready_for_touch = true;
                                }
                                continue;
                            }

                            if var >= 1800.0 && !finger_down {
                                finger_down = true;
                                stage += 1;

                                let cond = synaptics_prometheus::reconstruct::condition_onchip(px, None, img.width, img.height);
                                let cond_img = ConditionedImage {
                                    pixels: &cond.pixels,
                                    width: img.width as u16,
                                    height: img.height as u16,
                                    stride: img.width as u16,
                                };
                                let prog = enroll.add_sample(cond_img)?;
                                println!("PROGRESS:enroll-stage-passed:{}", prog.percent);
                                std::io::stdout().flush()?;

                                if stage >= 10 || enroll.is_complete() {
                                    break;
                                }
                            } else if var <= 1450.0 && finger_down {
                                finger_down = false;
                                println!("PROGRESS:enroll-remove-and-retry:0");
                                std::io::stdout().flush()?;
                            }
                        }
                    }
                    _ => {}
                }
                std::thread::sleep(Duration::from_millis(80));
            }

            let _ = capture.finish();
            let _ = session.reboot_sensor();

            if stage >= 6 || enroll.is_complete() {
                let blob = enroll.finalize()?;
                store.store(uid, subtype, &blob)?;
                println!("DONE:enroll-completed");
                std::io::stdout().flush()?;
            } else {
                println!("DONE:enroll-failed");
                std::io::stdout().flush()?;
                std::process::exit(1);
            }
        }
        "verify" => {
            if args.len() < 4 {
                eprintln!("Usage: syna-tool verify <uid> <finger_name>");
                std::process::exit(1);
            }
            let uid: u32 = args[2].parse()?;
            let requested_finger = &args[3];
            let requested_subtype = name_to_subtype(requested_finger).unwrap_or(0);

            let enrolled_subtypes: Vec<u8> = if requested_subtype == 0 {
                store.list_fingers(uid).unwrap_or_default()
            } else {
                vec![requested_subtype]
            };

            let mut templates: Vec<(u8, Vec<u8>)> = Vec::new();
            for st in enrolled_subtypes {
                if let Ok(Some(blob)) = store.load_blob(uid, st) {
                    templates.push((st, blob));
                }
            }

            if templates.is_empty() {
                eprintln!("ERROR:no-enrolled-prints");
                std::process::exit(2);
            }

            let certstore = if PathBuf::from(CERTSTORE_PATH).exists() {
                CERTSTORE_PATH
            } else {
                "certstore.bin"
            };

            let mut session = Session::open_nusb(certstore)?;
            let ctx = session.bootstrap_with(BootstrapOptions::default())?;
            let DeviceContext { cfg, factory_cal_values: fcv, vendor_cal, st8, st9, .. } = ctx;

            let sync_frames = 3;
            let spec = CaptureMode::Stream
                .spec_with(&ArmOverrides { sync_frames: Some(sync_frames), ..Default::default() });

            let mut capture = CaptureSession::new(&mut session, cfg.clone(), fcv, vendor_cal, st8, st9);
            let (program, _) = capture.resolve(&spec).unwrap();

            let layout = cfg.sync_layout(sync_frames);
            let params = synaptics_prometheus::reconstruct::recon_params(cfg.prog.program).unwrap();

            let backend = QmBackend::new();

            println!("STATUS:READY");
            std::io::stdout().flush()?;

            let mut matched_finger = None;

            for _ in 0..300 {
                if STOP_REQUESTED.load(Ordering::SeqCst) {
                    eprintln!("verify: stop requested via signal");
                    break;
                }
                let outcome = match capture.capture(&program, CaptureOpts::stream(sync_frames), || !STOP_REQUESTED.load(Ordering::SeqCst)) {
                    Ok(o) => o,
                    Err(e) => {
                        if STOP_REQUESTED.load(Ordering::SeqCst) {
                            break;
                        }
                        eprintln!("transient frame error: {e}");
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                };
                match outcome {
                    CaptureOutcome::Stream(raw) => {
                        if let Some(img) = reconstruct_sync_frame(&raw.bytes, layout, params) {
                            let mut sum: u64 = 0;
                            for &p in &img.pixels { sum += p as u64; }
                            let _avg = sum as f64 / img.pixels.len() as f64;
                            let mut min = 255u8;
                            let mut max = 0u8;
                            for &p in &img.pixels {
                                if p < min { min = p; }
                                if p > max { max = p; }
                            }
                            let diff = max as i32 - min as i32;

                            if diff > 175 {
                                let cond = synaptics_prometheus::reconstruct::condition_onchip(&img.pixels, None, img.width, img.height);
                                let cond_img = ConditionedImage {
                                    pixels: &cond.pixels,
                                    width: img.width as u16,
                                    height: img.height as u16,
                                    stride: img.width as u16,
                                };
                                match backend.extract_template(cond_img) {
                                    Ok(probe) => {
                                        for (st, blob) in &templates {
                                            match backend.verify(&probe, blob, MatchLevel::Level1) {
                                                Ok(res) => {
                                                    // `strict` is the DLL-faithful decision
                                                    // (geometric consensus AND score above the
                                                    // level threshold). The keep-going decision
                                                    // below stays unchanged until a real finger
                                                    // confirms that strict still accepts.
                                                    let strict =
                                                        res.consensus_ok && res.score > res.threshold;
                                                    eprintln!(
                                                        "VERIFY: diff={diff} anchors={} score={}/{} \
                                                         consensus={} strict={} matched={}",
                                                        res.anchor_count,
                                                        res.score,
                                                        res.threshold,
                                                        res.consensus_ok,
                                                        strict,
                                                        res.matched
                                                    );
                                                    if res.matched {
                                                        matched_finger = Some(*st);
                                                        break;
                                                    }
                                                }
                                                Err(e) => eprintln!("VERIFY_ERROR: {e:?}"),
                                            }
                                        }
                                        if matched_finger.is_some() {
                                            break;
                                        }
                                    }
                                    Err(e) => eprintln!("EXTRACT_ERROR: {e:?}"),
                                }
                            }
                        }
                    }
                    _ => {}
                }
                std::thread::sleep(Duration::from_millis(80));
            }

            let _ = capture.finish();
            let _ = session.reboot_sensor();

            if let Some(st) = matched_finger {
                println!("MATCH:{}", subtype_to_name(st));
                std::io::stdout().flush()?;
            } else {
                println!("NO_MATCH");
                std::io::stdout().flush()?;
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("Unknown command: {cmd}");
            std::process::exit(1);
        }
    }

    Ok(())
}
