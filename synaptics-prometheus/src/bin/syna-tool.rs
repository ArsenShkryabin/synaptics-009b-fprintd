use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;
use synaptics_biometric::{ConditionedImage, HostBiometricBackend, MatchLevel};
use synaptics_prometheus::capture::{CaptureOpts, CaptureOutcome, CaptureSession};
use synaptics_prometheus::capture_prog::capture_spec::CaptureMode;
use synaptics_prometheus::capture_prog::ArmOverrides;
use synaptics_prometheus::reconstruct::reconstruct_sync_frame;
use synaptics_prometheus::session::{BootstrapOptions, DeviceContext, Session};
use synaptics_prometheus::template_store::TemplateStore;
use synaptics_prometheus_qm::QmBackend;

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
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: syna-tool <enroll|verify|list|delete> ...");
        std::process::exit(1);
    }

    let cmd = &args[1];
    let store = TemplateStore::open(TEMPLATE_DIR)?;

    match cmd.as_str() {
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
            let mut finger_down = false;

            for _ in 0..300 {
                let outcome = match capture.capture(&program, CaptureOpts::stream(sync_frames), || true) {
                    Ok(o) => o,
                    Err(e) => {
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
                            let avg = sum as f64 / img.pixels.len() as f64;
                            let mut min = 255u8;
                            let mut max = 0u8;
                            for &p in &img.pixels {
                                if p < min { min = p; }
                                if p > max { max = p; }
                            }
                            let diff = max as i32 - min as i32;
                            let touching = diff > 130;

                            if touching && !finger_down {
                                finger_down = true;
                                stage += 1;
                                let cond = synaptics_prometheus::reconstruct::condition_onchip(&img.pixels, None, img.width, img.height);
                                let cond_img = ConditionedImage {
                                    pixels: &cond.pixels,
                                    width: img.width as u16,
                                    height: img.height as u16,
                                    stride: img.width as u16,
                                };
                                let prog = enroll.add_sample(cond_img)?;
                                println!("PROGRESS:enroll-stage-passed:{}", prog.percent);
                                std::io::stdout().flush()?;

                                if stage >= 6 || enroll.is_complete() {
                                    break;
                                }
                            } else if !touching && finger_down {
                                finger_down = false;
                                println!("PROGRESS:enroll-remove-and-retry:0");
                                std::io::stdout().flush()?;
                            }
                        }
                    }
                    _ => {}
                }
                std::thread::sleep(Duration::from_millis(100));
            }

            let _ = capture.finish();

            if stage >= 4 || enroll.is_complete() {
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
            let mut retry_throttle = std::time::Instant::now();

            for _ in 0..300 {
                let outcome = match capture.capture(&program, CaptureOpts::stream(sync_frames), || true) {
                    Ok(o) => o,
                    Err(e) => {
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

                            if diff > 130 {
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
                                                    eprintln!("VERIFY_ATTEMPT: diff={diff} anchors={} score={}/{} matched={}",
                                                        res.anchor_count, res.score, res.threshold, res.matched);
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
                                        } else if retry_throttle.elapsed() > Duration::from_millis(800) {
                                            retry_throttle = std::time::Instant::now();
                                            println!("PROGRESS:verify-retry-scan");
                                            std::io::stdout().flush()?;
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
