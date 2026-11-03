use std::time::Duration;
use synaptics_prometheus::capture::{CaptureOpts, CaptureOutcome, CaptureSession};
use synaptics_prometheus::capture_prog::capture_spec::CaptureMode;
use synaptics_prometheus::capture_prog::ArmOverrides;
use synaptics_prometheus::session::{BootstrapOptions, DeviceContext, Session};
use synaptics_prometheus::reconstruct::reconstruct_sync_frame;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let certstore = "/etc/synaptics/certstore.bin";
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

    println!("READY_TO_TOUCH");

    for i in 1..=60 {
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
                    let mut var_sum = 0f64;
                    for &p in &img.pixels {
                        let d = p as f64 - avg;
                        var_sum += d * d;
                    }
                    let var = (var_sum / img.pixels.len() as f64) as i32;

                    println!("F#{i:02}: var={var:4} min={min:3} max={max:3} avg={avg:.1}");
                }
            }
            _ => {}
        }
        std::thread::sleep(Duration::from_millis(80));
    }

    let _ = capture.finish();
    Ok(())
}
