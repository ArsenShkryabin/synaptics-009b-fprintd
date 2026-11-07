//! Peak-list composition validated against the real `synaWudfBioUsb.dll` on a **captured frame**.
//!
//! Pins the 3×3 tiled PASS-1 path: per-tile DoH → `syna_qm_detect_peaks_nms@0x18000cee0` →
//! `syna_qm_refine_subpixel_hessian@0x18000d520` → tile-proper filter → border reject → score sort
//! → global cap — matching [`synaptics_prometheus_qm::extractor::detect_peaks_in_tiles`] with
//! [`DetectParams::dll_baseline`].
//!
//! Provenance: same `fixtures/qmflip_0000.u8` as `doh_field_oracle.rs`. Golden from
//! `tools/qm-dll-oracle` section 27 (`golden/peaks_field.txt`).
//!
//! Per AGENTS.md #7 this is a fixed diagnostic vector, not a fingerprint claim. Empty / near-empty
//! peak lists under thr1 on this fixture are a valid outcome — do not flip crate defaults here.

use std::path::Path;
use synaptics_prometheus_qm::extractor::{
    detect_peaks_in_tiles, doh_response_tiles, DetectParams,
};

const W: usize = 144;
const H: usize = 56;

fn load_fixture_and_golden() -> Option<(Vec<u8>, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tools/qm-dll-oracle");
    let img_path = root.join("fixtures/qmflip_0000.u8");
    let gld_path = root.join("golden/peaks_field.txt");
    let Ok(image) = std::fs::read(&img_path) else {
        eprintln!("skipping peaks_field_oracle test: missing {}", img_path.display());
        return None;
    };
    let Ok(golden) = std::fs::read_to_string(&gld_path) else {
        eprintln!("skipping peaks_field_oracle test: missing {}", gld_path.display());
        return None;
    };
    Some((image, golden))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeakRec {
    x: i32,
    y: i32,
    score: i32,
    class: u8,
    tile: u8,
}

fn golden_peaks(golden: &str) -> Vec<PeakRec> {
    golden
        .lines()
        .filter_map(|l| {
            let rest = l.strip_prefix("PEAKSFIELD_PEAK ")?;
            let (_idx, body) = rest.split_once(" : ")?;
            let mut x = None;
            let mut y = None;
            let mut score = None;
            let mut class = None;
            let mut tile = None;
            for tok in body.split_whitespace() {
                if let Some(v) = tok.strip_prefix("x=") {
                    x = Some(v.parse().ok()?);
                } else if let Some(v) = tok.strip_prefix("y=") {
                    y = Some(v.parse().ok()?);
                } else if let Some(v) = tok.strip_prefix("score=") {
                    score = Some(v.parse().ok()?);
                } else if let Some(v) = tok.strip_prefix("class=") {
                    class = Some(v.parse().ok()?);
                } else if let Some(v) = tok.strip_prefix("tile=") {
                    tile = Some(v.parse().ok()?);
                }
            }
            Some(PeakRec {
                x: x?,
                y: y?,
                score: score?,
                class: class?,
                tile: tile?,
            })
        })
        .collect()
}

fn golden_count(golden: &str) -> usize {
    golden
        .lines()
        .find_map(|l| l.strip_prefix("PEAKSFIELD_COUNT ")?.parse().ok())
        .expect("PEAKSFIELD_COUNT")
}

#[test]
fn fixture_matches_peaks_field_input_hash() {
    let Some((image, golden)) = load_fixture_and_golden() else {
        return;
    };
    assert_eq!(image.len(), W * H);
    let want = golden
        .lines()
        .find_map(|l| {
            l.strip_prefix("PEAKSFIELD_INPUT ")?
                .split_once("hash=")?
                .1
                .split_whitespace()
                .next()
        })
        .expect("PEAKSFIELD_INPUT hash");
    let want = u64::from_str_radix(want, 16).unwrap();
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let got = image.iter().fold(OFFSET, |h, &b| (h ^ u64::from(b)).wrapping_mul(PRIME));
    assert_eq!(got, want);
}

#[test]
fn peaks_field_matches_oracle_golden() {
    let Some((image, golden)) = load_fixture_and_golden() else {
        return;
    };
    let params = DetectParams::dll_baseline(0x2449);
    assert_eq!(params.nms_max_out, 125);
    assert_eq!(params.nms_margin, 10);
    assert_eq!(params.tiles, 3);

    let tiles = doh_response_tiles(&image, W, H, &params);
    assert_eq!(tiles.len(), 9);
    let cands = detect_peaks_in_tiles(&tiles, W, H, &params);
    let got: Vec<PeakRec> = cands
        .iter()
        .map(|c| PeakRec {
            x: c.x,
            y: c.y,
            score: c.score,
            class: c.class,
            tile: c.tile,
        })
        .collect();
    let want = golden_peaks(&golden);
    assert_eq!(got.len(), golden_count(&golden), "peak count vs PEAKSFIELD_COUNT");
    assert_eq!(
        got, want,
        "peak list differs from DLL oracle (composition: 3×3 DoH→NMS→refine→border→cap)"
    );
}
