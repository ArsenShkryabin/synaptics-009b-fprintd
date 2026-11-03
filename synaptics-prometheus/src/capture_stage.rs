//! Load exact stage taps from a recorded capture-bundle frame directory.
//!
//! Bundle PNGs are named `{nn}_{stage}.png` (`synaptics-pipeline-graph` write path); the numeric
//! prefix moves when the graph changes, so callers look up by **stage kind** (`qm_flip`,
//! `descramble`, …), not by a hard-coded index.
//!
//! DoH / oracle fixtures want the DLL-faithful QM input: `reconstruct_roi` → QmFlip. On current
//! recordings that is already the `qm_flip` (or `conditioned`) tap as byte-domain `f32`. Older
//! bundles still carry the host z-score conditioner there — those fall back to rebuilding from
//! `descramble` via [`crate::ir_normalize::reconstruct_roi`].

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::image_io::{read_png_sidecar, ExactPlane};
use crate::ir_normalize::{field_to_u8_clamped, reconstruct_roi, RoiBounds};

/// Find `{nn}_{stage}.png` under a frame directory (`frames/0000/`, …).
pub fn find_stage_png(frame_dir: &Path, stage: &str) -> io::Result<PathBuf> {
    let suffix = format!("_{stage}.png");
    let mut hits = Vec::new();
    for ent in fs::read_dir(frame_dir)? {
        let path = ent?.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.ends_with(&suffix) {
            hits.push(path);
        }
    }
    match hits.len() {
        1 => Ok(hits.remove(0)),
        0 => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no *_{stage}.png under {}", frame_dir.display()),
        )),
        n => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{n} *_{stage}.png under {} — expected one", frame_dir.display()),
        )),
    }
}

/// Exact gray `f32` plane from a stage PNG's `saFX` chunk.
pub fn load_stage_gray_f32(png_path: &Path) -> io::Result<(usize, usize, Vec<f32>)> {
    let bytes = fs::read(png_path)?;
    let side = read_png_sidecar(&bytes).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{}: not a PNG", png_path.display()))
    })?;
    let exact: ExactPlane = side.exact.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: no saFX chunk (record with exact planes enabled)", png_path.display()),
        )
    })?;
    let field = exact.plane_f32("gray").or_else(|| {
        // Single-plane taps sometimes use the only name present.
        exact.planes.first().and_then(|(n, _)| exact.plane_f32(n))
    }).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{}: no f32 gray plane", png_path.display()))
    })?;
    Ok((exact.width, exact.height, field))
}

/// True when samples are already in the byte domain the QM path carries (0..255), not a signed
/// host z-score / base-sub residual.
pub fn is_byte_domain(field: &[f32]) -> bool {
    field.iter().all(|&v| (-0.5..255.5).contains(&v))
}

/// Vertical row reverse — the graph's `QmFlip` / `qm::extractor::flip_vertical_rows`.
pub fn flip_vertical_u8(img: &[u8], width: usize, height: usize) -> Vec<u8> {
    let mut out = vec![0u8; width * height];
    for r in 0..height {
        out[r * width..(r + 1) * width]
            .copy_from_slice(&img[(height - 1 - r) * width..(height - r) * width]);
    }
    out
}

/// DLL-faithful DoH / oracle input (`u8`) from one recorded frame directory.
///
/// Prefers a byte-domain `qm_flip` tap (includes stream dark-ref subtract when the graph armed it).
/// Falls back to byte-domain `conditioned` + flip, then to `descramble` → `reconstruct_roi` → flip
/// for older bundles whose conditioned taps are still the host z-score field.
pub fn load_qm_doh_input_u8(frame_dir: &Path) -> io::Result<(usize, usize, Vec<u8>)> {
    if let Ok(png) = find_stage_png(frame_dir, "qm_flip") {
        let (w, h, field) = load_stage_gray_f32(&png)?;
        if is_byte_domain(&field) {
            return Ok((w, h, field_to_u8_clamped(&field)));
        }
    }
    if let Ok(png) = find_stage_png(frame_dir, "conditioned") {
        let (w, h, field) = load_stage_gray_f32(&png)?;
        if is_byte_domain(&field) {
            return Ok((w, h, flip_vertical_u8(&field_to_u8_clamped(&field), w, h)));
        }
    }
    let png = find_stage_png(frame_dir, "descramble")?;
    let (w, h, field) = load_stage_gray_f32(&png)?;
    if !is_byte_domain(&field) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: descramble is not byte-domain", png.display()),
        ));
    }
    let mut img = field_to_u8_clamped(&field);
    reconstruct_roi(&mut img, w, h, RoiBounds::full(w as u16, h as u16));
    Ok((w, h, flip_vertical_u8(&img, w, h)))
}

/// Resolve `frames/{frame:04}/` under a bundle root.
pub fn bundle_frame_dir(bundle: &Path, frame: u32) -> PathBuf {
    bundle.join("frames").join(format!("{frame:04}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_capture(name: &str) -> Option<PathBuf> {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../captures/bundles")
            .join(name)
            .join("frames/0000");
        p.is_dir().then_some(p)
    }

    #[test]
    fn finds_qm_flip_by_kind_not_index() {
        let Some(dir) = repo_capture("20260803T205040Z_stream_1f") else {
            return;
        };
        let png = find_stage_png(&dir, "qm_flip").unwrap();
        assert!(png.file_name().unwrap().to_str().unwrap().ends_with("_qm_flip.png"));
        let (w, h, field) = load_stage_gray_f32(&png).unwrap();
        assert_eq!((w, h), (144, 56));
        assert!(is_byte_domain(&field), "new topology recordings are byte-domain");
    }

    #[test]
    fn doh_input_from_new_capture_uses_recorded_qm_flip() {
        let Some(dir) = repo_capture("20260803T205040Z_stream_1f") else {
            return;
        };
        let (w, h, img) = load_qm_doh_input_u8(&dir).unwrap();
        assert_eq!((w, h, img.len()), (144, 56, 144 * 56));
        let mean = img.iter().map(|&b| b as f64).sum::<f64>() / img.len() as f64;
        // Recorded qm_flip on this bundle (dark-ref armed) — not the ~158 descramble-only rebuild.
        assert!((100.0..130.0).contains(&mean), "mean={mean}");
    }

    #[test]
    fn doh_input_from_legacy_signed_capture_rebuilds_from_descramble() {
        let Some(dir) = repo_capture("20260803T152516Z_stream_3f") else {
            return;
        };
        let (w, h, img) = load_qm_doh_input_u8(&dir).unwrap();
        assert_eq!((w, h), (144, 56));
        let mean = img.iter().map(|&b| b as f64).sum::<f64>() / img.len() as f64;
        assert!(
            (140.0..180.0).contains(&mean),
            "legacy signed qm_flip must fall back to reconstruct_roi (mean={mean})"
        );
    }
}
