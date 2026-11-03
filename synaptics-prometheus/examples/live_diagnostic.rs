use std::time::Duration;
use synaptics_biometric::{ConditionedImage, HostBiometricBackend, MatchLevel};
use synaptics_prometheus::capture::{CaptureOpts, CaptureOutcome, CaptureSession};
use synaptics_prometheus::capture_prog::capture_spec::CaptureMode;
use synaptics_prometheus::capture_prog::ArmOverrides;
use synaptics_prometheus::session::{BootstrapOptions, DeviceContext, Session};
use synaptics_prometheus::reconstruct::reconstruct_sync_frame;
use synaptics_prometheus::template_store::TemplateStore;
use synaptics_prometheus_qm::QmBackend;

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

    let store = TemplateStore::open("/var/lib/fprint/synaptics")?;
    let enrolled_blob = match store.load_blob(1000, 7)? {
        Some(b) => b,
        None => {
            eprintln!("Ошибка: нет сохраненного шаблона в /var/lib/fprint/synaptics/1000/07.tmpl");
            return Ok(());
        }
    };

    let backend = QmBackend::new();

    println!("\n========================================================");
    println!(">>> ЖИВОЙ ТЕСТ СЕНСОРА: ЧИТАЕМ ПОТОК КАДРОВ В РЕАЛЬНОМ ВРЕМЕНИ");
    println!(">>> Приложи левый указательный палец прямо сейчас!");
    println!("========================================================\n");

    for i in 1..=100 {
        match capture.capture(&program, CaptureOpts::stream(sync_frames), || true)? {
            CaptureOutcome::Stream(raw) => {
                if let Some(img) = reconstruct_sync_frame(&raw.bytes, layout, params) {
                    let mut sum: u64 = 0;
                    for &p in &img.pixels { sum += p as u64; }
                    let avg = sum as f64 / img.pixels.len() as f64;
                    let mut var_sum = 0f64;
                    for &p in &img.pixels {
                        let d = p as f64 - avg;
                        var_sum += d * d;
                    }
                    let var = (var_sum / img.pixels.len() as f64) as i32;

                    if var < 200 {
                        print!("\r[Кадр #{i:02}] Сенсор пуст (шум={var}). Жду палец...          ");
                        use std::io::Write;
                        std::io::stdout().flush().ok();
                    } else {
                        println!("\n[Кадр #{i:02}] ★ КАСАНИЕ ОБНАРУЖЕНО! (размах/дисперсия={var})");
                        let cond = synaptics_prometheus::reconstruct::condition_onchip(&img.pixels, None, img.width, img.height);
                        let cond_img = ConditionedImage {
                            pixels: &cond.pixels,
                            width: img.width as u16,
                            height: img.height as u16,
                            stride: img.width as u16,
                        };
                        match backend.extract_template(cond_img) {
                            Ok(probe) => {
                                match backend.verify(&probe, &enrolled_blob, MatchLevel::Level1) {
                                    Ok(res) => {
                                        println!("    --> Сверка: anchors={} score={}/{} matched={}",
                                            res.anchor_count, res.score, res.threshold, res.matched);
                                        if res.matched {
                                            println!("\n★ ПОЛНЫЙ УСПЕХ! Отпечаток совпал, разблокировка РАБОТАЕТ!");
                                            let _ = capture.finish();
                                            return Ok(());
                                        }
                                    }
                                    Err(e) => println!("    --> Ошибка сверки: {e:?}"),
                                }
                            }
                            Err(e) => println!("    --> Не удалось извлечь шаблон (палец смазан?): {e:?}"),
                        }
                    }
                }
            }
            _ => {}
        }
        std::thread::sleep(Duration::from_millis(80));
    }

    let _ = capture.finish();
    println!("\nТест завершен.");
    Ok(())
}
