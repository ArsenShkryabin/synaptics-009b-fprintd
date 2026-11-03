//! Micro-benchmark isolating the per-frame cost that the live viewer's ENROLL→GALLERY→IDENTIFY tail
//! pays on the UI thread after ONE enrolment view is captured. Mirrors `identify_probe` +
//! `EnrollNode.run` in `synaptics-pipeline-graph`.
//!
//! Run: `cargo run -q --release -p synaptics-prometheus-qm --example bench_identify_perframe`

use std::time::Instant;
use synaptics_prometheus_qm::extractor::{extract_template, ConditionedImage};
use synaptics_prometheus_qm::types::MatchLevel;
use synaptics_prometheus_qm::{diagnose, EnrollAccumulator};

const W: usize = 144;
const H: usize = 56;

fn varied_texture(seed: u32) -> Vec<u8> {
    let mut px = vec![0u8; W * H];
    for y in 0..H {
        for x in 0..W {
            let h = (x as u32)
                .wrapping_mul(2_654_435_761)
                .wrapping_add((y as u32).wrapping_mul(40_503))
                .wrapping_add(seed.wrapping_mul(2_246_822_519));
            px[y * W + x] = (((h >> 13) ^ (h >> 7)) & 0xff) as u8;
        }
    }
    px
}

fn template_from(seed: u32) -> synaptics_prometheus_qm::Template {
    let px = varied_texture(seed);
    extract_template(ConditionedImage {
        pixels: &px,
        width: W as u16,
        height: H as u16,
        stride: W as u16,
    })
    .expect("varied texture yields a template")
}

fn ms(t: Instant, n: u32) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0 / n as f64
}

fn main() {
    // A single-view transient, exactly what ENROLL holds after ONE "Capture touch".
    let mut acc = EnrollAccumulator::new(0x2449);
    acc.add_sample(template_from(1));
    let enrolled = acc.finalize().expect("one view");
    let level = MatchLevel::Level2;

    // The live probe re-extracted each frame (this cost is paid BEFORE and AFTER capture, so it is
    // NOT the post-capture delta — measured only for reference).
    let probe = template_from(1);
    println!(
        "transient views={}  probe minutiae={}  view0 minutiae={}",
        enrolled.view_count(),
        probe.minutiae.len(),
        enrolled.views[0].minutiae.len()
    );

    const N: u32 = 200;

    // (reference) probe extraction — the Minutiae node, runs every frame regardless of enrolment.
    let t = Instant::now();
    for s in 0..N {
        std::hint::black_box(template_from(1 + (s % 4)));
    }
    println!("[ref ] probe extract (Minutiae node)   {:.3} ms/frame", ms(t, N));

    // ENROLL.run per frame: re-serialize the transient to a blob.
    let t = Instant::now();
    for _ in 0..N {
        std::hint::black_box(enrolled.to_blob().unwrap());
    }
    let blob = enrolled.to_blob().unwrap();
    println!("[NEW ] ENROLL to_blob (transient)      {:.3} ms/frame  ({} bytes)", ms(t, N), blob.len());

    // IDENTIFY per frame: deserialize every candidate blob (from_blob).
    let t = Instant::now();
    for _ in 0..N {
        std::hint::black_box(
            synaptics_prometheus_qm::EnrolledTemplate::from_blob(&blob).unwrap(),
        );
    }
    println!("[NEW ] IDENTIFY from_blob (candidate)  {:.3} ms/frame", ms(t, N));

    // IDENTIFY per frame: the 1:N ranking pass (tmpl.identify over the single candidate).
    let t = Instant::now();
    for _ in 0..N {
        std::hint::black_box(enrolled.identify(&probe, level));
    }
    println!("[NEW ] IDENTIFY tmpl.identify (1:N)    {:.3} ms/frame", ms(t, N));

    // IDENTIFY per frame: diagnose EVERY view of the winner (the overlay geometry pass).
    let (w, h) = (W as i32, H as i32);
    let t = Instant::now();
    for _ in 0..N {
        for view in &enrolled.views {
            std::hint::black_box(diagnose(&probe, view, level, w, h));
        }
    }
    println!("[NEW ] IDENTIFY diagnose per view      {:.3} ms/frame", ms(t, N));

    // OLD path (before the fix): identify() ranks by diagnosing every view, THEN the geometry loop
    // diagnoses the winner's views a second time — each view matched twice per frame.
    let t = Instant::now();
    for _ in 0..N {
        let blob = enrolled.to_blob().unwrap();
        let reloaded =
            synaptics_prometheus_qm::EnrolledTemplate::from_blob(&blob).unwrap();
        std::hint::black_box(reloaded.identify(&probe, level));
        for view in &reloaded.views {
            std::hint::black_box(diagnose(&probe, view, level, w, h));
        }
    }
    println!("[OLD ] === identify + re-diagnose      {:.3} ms/frame ===", ms(t, N));

    // NEW path (after the fix): diagnose each view ONCE; ranking + geometry share the result.
    let t = Instant::now();
    for _ in 0..N {
        let blob = enrolled.to_blob().unwrap();
        let reloaded =
            synaptics_prometheus_qm::EnrolledTemplate::from_blob(&blob).unwrap();
        let diags: Vec<_> = reloaded
            .views
            .iter()
            .map(|v| diagnose(&probe, v, level, w, h))
            .collect();
        std::hint::black_box(diags.iter().map(|d| d.score).max());
    }
    println!("[NEW ] === single diagnose pass        {:.3} ms/frame ===", ms(t, N));

    // Behaviour preservation: single-pass max score == identify()'s winning score.
    let via_identify = enrolled.identify(&probe, level).map(|(_, r)| r.score).unwrap_or(0);
    let via_single = enrolled
        .views
        .iter()
        .map(|v| diagnose(&probe, v, level, w, h).score)
        .max()
        .unwrap_or(0);
    assert_eq!(via_identify, via_single, "single-pass ranking must equal identify()");
    println!("[chk ] ranking preserved: identify score {via_identify} == single-pass {via_single}");
}
