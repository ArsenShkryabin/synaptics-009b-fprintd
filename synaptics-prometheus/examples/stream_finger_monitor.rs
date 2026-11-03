use std::time::Duration;
use synaptics_prometheus::capture::{CaptureOpts, CaptureOutcome, CaptureSession};
use synaptics_prometheus::capture_prog::capture_spec::CaptureMode;
use synaptics_prometheus::capture_prog::ArmOverrides;
use synaptics_prometheus::session::{BootstrapOptions, DeviceContext, Session};
use synaptics_prometheus::reconstruct::reconstruct_sync_frame;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let certstore = "certstore.bin";
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

    println!("\n========================================================");
    println!(">>> СЕНСОР ГОТОВ (РЕЖИМ STREAM EP-0x82)");
    println!(">>> Приложи левый указательный палец прямо сейчас!");
    println!("========================================================\n");

    let mut saved = false;

    for i in 1..=40 {
        match capture.capture(&program, CaptureOpts::stream(sync_frames), || true)? {
            CaptureOutcome::Stream(raw) => {
                if let Some(img) = reconstruct_sync_frame(&raw.bytes, layout, params) {
                    let mut sum: u64 = 0;
                    let mut min = 255u8;
                    let mut max = 0u8;
                    for &p in &img.pixels {
                        sum += p as u64;
                        if p < min { min = p; }
                        if p > max { max = p; }
                    }
                    let avg = sum as f64 / img.pixels.len() as f64;
                    let diff = max as i32 - min as i32;

                    println!("Кадр #{:02}: размах={:3} (min={:3}, max={:3}, среднее={:.1})",
                        i, diff, min, max, avg);

                    if diff > 130 && !saved {
                        std::fs::write("/tmp/live_finger.png", img.to_png()).ok();
                        println!(">>> ★ ОБНАРУЖЕНО КАСАНИЕ! Кадр сохранен в /tmp/live_finger.png");
                        saved = true;
                    }
                }
            }
            _ => {}
        }
        std::thread::sleep(Duration::from_millis(150));
    }

    let _ = capture.finish();
    let _ = session.reboot_sensor();

    if saved {
        println!("\n>>> Отлично! Отпечаток успешно считан с сенсора!");
    } else {
        println!("\n>>> Касание не зафиксировано (попробуй прижать палец плотнее).");
    }

    Ok(())
}
