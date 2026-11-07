//! Diagnostic only: mirrors the `syna-tool enroll` capture loop and logs per-frame statistics
//! (min/max/diff/variance/minutiae) so touch/lift behaviour can be measured on real hardware.
use std::io::Write;
use std::time::{Duration, Instant};
use synaptics_biometric::{ConditionedImage, HostBiometricBackend};
use synaptics_prometheus::capture::{CaptureOpts, CaptureOutcome, CaptureSession};
use synaptics_prometheus::capture_prog::capture_spec::CaptureMode;
use synaptics_prometheus::capture_prog::ArmOverrides;
use synaptics_prometheus::reconstruct::reconstruct_sync_frame;
use synaptics_prometheus::session::{BootstrapOptions, DeviceContext, Session};
use synaptics_prometheus_qm::QmBackend;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secs: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(25);
    let mut log = std::fs::File::create("/tmp/opencode/enroll_probe.log")?;

    let mut session = Session::open_nusb("/etc/synaptics/certstore.bin")?;
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

    println!(">>> READY. В течение {secs} c: приложи палец, подержи 1 c, убери, подожди 2 c. Повтори 3-4 раза.");
    std::io::stdout().flush()?;

    let start = Instant::now();
    let mut n = 0u32;
    while start.elapsed() < Duration::from_secs(secs) {
        n += 1;
        let t = start.elapsed().as_millis();
        let line = match capture.capture(&program, CaptureOpts::stream(sync_frames), || true) {
            Err(e) => format!("{t:6}ms #{n:03} ERR {e}"),
            Ok(CaptureOutcome::NoFrame { arm_status }) => {
                format!("{t:6}ms #{n:03} NOFRAME arm={arm_status:#06x}")
            }
            Ok(CaptureOutcome::Polled(_)) => format!("{t:6}ms #{n:03} POLLED?"),
            Ok(CaptureOutcome::Stream(raw)) => match reconstruct_sync_frame(&raw.bytes, layout, params) {
                None => format!("{t:6}ms #{n:03} RECON_NONE bytes={}", raw.bytes.len()),
                Some(img) => {
                    let px = &img.pixels;
                    let (mut mn, mut mx, mut sum) = (255u8, 0u8, 0u64);
                    for &p in px {
                        mn = mn.min(p);
                        mx = mx.max(p);
                        sum += p as u64;
                    }
                    let mean = sum as f64 / px.len() as f64;
                    let var = px.iter().map(|&p| (p as f64 - mean).powi(2)).sum::<f64>() / px.len() as f64;
                    let cond = synaptics_prometheus::reconstruct::condition_onchip(px, None, img.width, img.height);
                    let ci = ConditionedImage {
                        pixels: &cond.pixels,
                        width: img.width as u16,
                        height: img.height as u16,
                        stride: img.width as u16,
                    };
                    let minutiae = match backend.extract_template(ci) {
                        Ok(blob) => synaptics_prometheus_qm::Template::from_blob(&blob)
                            .map(|t| t.minutiae.len() as i64)
                            .unwrap_or(-2),
                        Err(_) => -1,
                    };
                    format!(
                        "{t:6}ms #{n:03} arm={:#06x} min={mn:3} max={mx:3} diff={:3} mean={mean:6.1} var={var:7.1} minutiae={minutiae}",
                        raw.arm_status,
                        mx as i32 - mn as i32
                    )
                }
            },
        };
        println!("{line}");
        writeln!(log, "{line}")?;
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = capture.finish();
    let _ = session.reboot_sensor();
    println!(">>> DONE. Лог: /tmp/opencode/enroll_probe.log");
    Ok(())
}
