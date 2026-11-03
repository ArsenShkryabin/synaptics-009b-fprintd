//! Empirical complexity of a single `matcher::diagnose(probe, gallery)` as the minutia count grows.
//! Builds synthetic templates with N minutiae and times one diagnose, printing the growth ratio so
//! the algorithmic order is visible (O(N^2) doubles → ×4, O(N^3) doubles → ×8).
//!
//! Run: `cargo run -q --release -p synaptics-prometheus-qm --example bench_diagnose_scaling`

use std::time::Instant;
use synaptics_prometheus_qm::types::MatchLevel;
use synaptics_prometheus_qm::{diagnose, Minutia, Template};

/// A template with `n` minutiae on a jittered grid, distinct 8-byte descriptors.
fn synth(n: usize, seed: u32) -> Template {
    let mut minutiae = Vec::with_capacity(n);
    for i in 0..n {
        let h = (i as u32)
            .wrapping_mul(2_654_435_761)
            .wrapping_add(seed.wrapping_mul(2_246_822_519));
        let mut d = [0u8; 8];
        for (k, b) in d.iter_mut().enumerate() {
            *b = ((h >> (k * 3)) ^ (h >> (k + 1))) as u8;
        }
        minutiae.push(Minutia {
            descriptor: d,
            x: ((i * 7) % 144) as u8,
            y: ((i * 5) % 56) as u8,
            angle_deg: (h % 180) as u16,
        });
    }
    Template { descriptor: [0; 8], split: n as u8, field_0c: 0, minutiae }
}

fn main() {
    let level = MatchLevel::Level2;
    let (w, h) = (144i32, 56i32);
    println!("{:>6}  {:>12}  {:>8}  {:>8}", "N", "ms/diagnose", "t/N^2", "ratio");
    let mut prev_ms = 0.0f64;
    let mut prev_n = 0usize;
    for &n in &[16usize, 32, 64, 128, 192, 256] {
        // Probe matches gallery (a self-ish match) so anchors form and the full path runs.
        let probe = synth(n, 1);
        let gallery = synth(n, 1);
        let iters = (2_000_000 / (n * n * n).max(1)).clamp(3, 400) as u32;
        let t = Instant::now();
        for _ in 0..iters {
            std::hint::black_box(diagnose(&probe, &gallery, level, w, h));
        }
        let ms = t.elapsed().as_secs_f64() * 1000.0 / iters as f64;
        let per_n2 = ms / (n * n) as f64 * 1e6; // ns per N^2 unit
        let ratio = if prev_ms > 0.0 {
            format!("{:.2}x /{}x", ms / prev_ms, n / prev_n.max(1))
        } else {
            "-".to_string()
        };
        println!("{n:>6}  {ms:>12.4}  {per_n2:>8.2}  {ratio:>8}");
        prev_ms = ms;
        prev_n = n;
    }
    println!("\n(doubling N: O(N^2) => ~4x, O(N^3) => ~8x. 't/N^2' rising ~linearly => cubic.)");
}
