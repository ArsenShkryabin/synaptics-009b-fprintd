//! Matcher IR post-process: the stages that turn a descrambled `u8` frame into the image QM
//! actually sees.
//!
//! Call chain (polled identify/enroll), after `syna_ir_recon_condition_frame`:
//!
//! ```text
//! vcsIRreconFrame@0x1800b7d10
//!   ├─ syna_ir_normalize_frame(src, scratch, w, h, bias=0x80)   // SelectFrame ONLY — freed
//!   ├─ vcsIR2DSelectFrame(scratch)                              // quality gate
//!   └─ copy ctx+0x398 → ctx+0x238, then
//!        syna_ir_reconstruct_roi@0x1800b9430(ctx+0x238)         // ← what ASP/QM receives
//! ```
//!
//! `syna_ir_reconstruct_roi` is geometry-driven (no subtype table): snap ROI edges by
//! [`ROI_EDGE_MARGIN`], histogram-stat the ROI, then either
//!
//! - **full-width ROI** (`x0==0 && x1==w`): [`row_midrange_recenter`] over the band (and the
//!   above/below edge bands), bias = ROI mean; or
//! - **partial ROI**: [`normalize_frame`] **in-place** with bias = ROI mean (row then column).
//!
//! The fixed-`0x80` normalize in the SelectFrame scratch is **not** the QM input. Docs that said
//! "row then column around 0x80" for the matcher path were wrong for both reasons: that call is
//! out-of-place (column-only survives) and its buffer is discarded.
//!
//! Stream cf640 identify, if used, does not take this path — this module is the polled-matcher
//! conditioner. Host z-score (`conditioning::{apply_col,apply_row}_condition`) remains a separate
//! diagnostic.

/// Re-centre bias `vcsIRreconFrame` passes into the SelectFrame scratch normalize.
pub const SELECT_FRAME_BIAS: i32 = 0x80;

/// Edge snap in `syna_ir_reconstruct_roi@0x1800b9430`: a bound within this many pixels of the frame
/// edge is pulled to the edge (`local_24 = 10`).
pub const ROI_EDGE_MARGIN: u32 = 10;

/// Low percentile for the robust midrange / ROI histogram (10 %).
pub const ROBUST_PERCENTILE_LO: u32 = 10;

/// High percentile for the robust midrange / ROI histogram (90 %).
pub const ROBUST_PERCENTILE_HI: u32 = 90;

/// Inclusive pixel rectangle in frame coordinates, as the four `u16`s packed into the ROI bounds
/// argument of `syna_ir_reconstruct_roi`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoiBounds {
    pub x0: u16,
    pub x1: u16,
    pub y0: u16,
    pub y1: u16,
}

impl RoiBounds {
    /// The whole frame — after margin snap this takes the full-width midrange path.
    pub fn full(width: u16, height: u16) -> Self {
        Self { x0: 0, x1: width, y0: 0, y1: height }
    }
}

/// `p10`, `p90`, and arithmetic mean over an ROI — `syna_ir_roi_histogram_stats@0x1800b90b0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoiStats {
    pub p10: u32,
    pub p90: u32,
    pub mean: u32,
}

/// Truncating integer mean of a contiguous `u8` run — `syna_cal_mean@0x1800ce890`.
pub fn mean_u8(row: &[u8]) -> u32 {
    if row.is_empty() {
        return 0;
    }
    let sum: u32 = row.iter().map(|&b| b as u32).sum();
    sum / row.len() as u32
}

/// Truncating integer mean of a strided column — `syna_cal_mean_strided@0x1800ce910`.
pub fn mean_strided_u8(img: &[u8], width: usize, height: usize, col: usize) -> u32 {
    if height == 0 || col >= width {
        return 0;
    }
    let mut sum = 0u32;
    for y in 0..height {
        sum += img[y * width + col] as u32;
    }
    sum / height as u32
}

fn clamp_u8(v: i32) -> u8 {
    v.clamp(0, 255) as u8
}

/// `dst[i] = clamp(src[i] - (center - bias))`.
fn recenter_pixel(sample: u8, center: u32, bias: i32) -> u8 {
    clamp_u8(sample as i32 - (center as i32 - bias))
}

/// Row-then-column (or column-only) mean removal around `bias`.
///
/// `syna_ir_normalize_frame@0x1800b8e90`. Pass 1 always reads `src` and writes `dst`. Pass 2 always
/// reads **`src` again** (the original pointer) for column means, then writes `dst`. Consequences:
///
/// - `src` and `dst` distinct → pass 2 overwrites every byte from the original → **column-only**.
/// - `src == dst` (same buffer) → pass 1's row-normalized values feed pass 2 → **row then column**.
pub fn normalize_frame(src: &[u8], dst: &mut [u8], width: usize, height: usize, bias: i32) {
    let n = width * height;
    assert_eq!(src.len(), n);
    assert_eq!(dst.len(), n);
    if width == 0 || height == 0 {
        return;
    }

    for y in 0..height {
        let row = &src[y * width..(y + 1) * width];
        let m = mean_u8(row);
        for x in 0..width {
            dst[y * width + x] = recenter_pixel(src[y * width + x], m, bias);
        }
    }

    for x in 0..width {
        let m = mean_strided_u8(src, width, height, x);
        for y in 0..height {
            dst[y * width + x] = recenter_pixel(src[y * width + x], m, bias);
        }
    }
}

/// In-place form used by the partial-ROI branch of `syna_ir_reconstruct_roi`.
pub fn normalize_frame_inplace(img: &mut [u8], width: usize, height: usize, bias: i32) {
    // The DLL passes the same pointer as src and dst. Emulate that with a temporary for pass 1's
    // source snapshot so pass 2 still sees the pre-pass-1 columns when we cannot alias — wait: for
    // true in-place, pass 1 mutates, then pass 2's mean_strided reads the mutated rows. So we must
    // NOT snapshot: do pass 1 in place, then pass 2 on the result.
    let n = width * height;
    assert_eq!(img.len(), n);
    if width == 0 || height == 0 {
        return;
    }

    for y in 0..height {
        let m = mean_u8(&img[y * width..(y + 1) * width]);
        for x in 0..width {
            let i = y * width + x;
            img[i] = recenter_pixel(img[i], m, bias);
        }
    }

    // Column means over the already row-normalized image.
    for x in 0..width {
        let m = mean_strided_u8(img, width, height, x);
        for y in 0..height {
            let i = y * width + x;
            img[i] = recenter_pixel(img[i], m, bias);
        }
    }
}

/// Robust midrange of a contiguous run: average of the ~10th and ~90th percentile gray values.
/// `syna_ir_row_robust_midrange@0x1800ced80`.
pub fn robust_midrange_u8(samples: &[u8]) -> u32 {
    let n = samples.len() as u32;
    if n == 0 {
        return 0;
    }
    let lo_count = (n * ROBUST_PERCENTILE_LO) / 100;
    let hi_count = (n * ROBUST_PERCENTILE_HI) / 100;
    // Unused by the return, but the DLL also computes the median threshold; keep the histogram path
    // identical so we cannot drift on off-by-ones in the cumulant walk.
    let _mid_count = (n * 50) / 100;

    let mut hist = [0u8; 256];
    for &b in samples {
        hist[b as usize] = hist[b as usize].wrapping_add(1);
    }
    for i in 1..256 {
        hist[i] = hist[i].wrapping_add(hist[i - 1]);
    }

    let mut p10 = 0i32;
    for (i, &h) in hist.iter().enumerate() {
        if lo_count < h as u32 {
            p10 = i as i32;
            break;
        }
    }

    let mut p90 = 0i32;
    for i in (0..=254i32).rev() {
        if (hist[i as usize] as u32) <= hi_count {
            p90 = i + 1;
            break;
        }
    }

    (p10 as u32 + p90 as u32) / 2
}

/// Per-row midrange re-centre around `bias` — `syna_ir_row_midrange_recenter@0x1800b9320`.
///
/// For each of `nrows` rows starting at `rows`, the midrange is taken over columns `[x0, x1)`, then
/// every column in `0..width` is rewritten with that midrange. `stride` is the row pitch in the
/// underlying buffer (equals `width` when the image is contiguous).
#[allow(clippy::too_many_arguments)] // geometry + window params; each is a distinct scalar knob
pub fn row_midrange_recenter(
    img: &mut [u8],
    width: usize,
    nrows: usize,
    stride: usize,
    row0: usize,
    x0: usize,
    x1: usize,
    bias: i32,
) {
    assert!(x1 >= x0);
    assert!(x1 <= width);
    for r in 0..nrows {
        let base = (row0 + r) * stride;
        let mid = robust_midrange_u8(&img[base + x0..base + x1]);
        for x in 0..width {
            let i = base + x;
            img[i] = recenter_pixel(img[i], mid, bias);
        }
    }
}

/// Histogram stats over a rectangular ROI — `syna_ir_roi_histogram_stats@0x1800b90b0`.
pub fn roi_histogram_stats(img: &[u8], width: usize, height: usize, roi: RoiBounds) -> RoiStats {
    let x0 = roi.x0 as usize;
    let x1 = roi.x1 as usize;
    let y0 = roi.y0 as usize;
    let y1 = roi.y1 as usize;
    let rw = x1.saturating_sub(x0);
    let rh = y1.saturating_sub(y0);
    let area = (rw * rh) as u32;

    let lo_count = (area * ROBUST_PERCENTILE_LO) / 100;
    let hi_count = (area * ROBUST_PERCENTILE_HI) / 100;

    let mut hist = [0u16; 256];
    let mut sum = 0u32;
    for y in y0..y1.min(height) {
        for x in x0..x1.min(width) {
            let b = img[y * width + x] as usize;
            hist[b] = hist[b].wrapping_add(1);
            sum += b as u32;
        }
    }
    for i in 1..256 {
        hist[i] = hist[i].wrapping_add(hist[i - 1]);
    }

    let mut p10 = 0u32;
    for (i, &h) in hist.iter().enumerate() {
        if lo_count < h as u32 {
            p10 = i as u32;
            break;
        }
    }

    let mut p90 = 0u32;
    let mut i = 254i32;
    loop {
        if i < 0 {
            break;
        }
        if (hist[i as usize] as u32) <= hi_count {
            p90 = (i + 1) as u32;
            break;
        }
        i -= 1;
    }

    let mean = sum.checked_div(area).unwrap_or(0);
    RoiStats { p10, p90, mean }
}

/// Pull ROI edges to the frame edge when they sit within [`ROI_EDGE_MARGIN`].
pub fn snap_roi(width: u32, height: u32, mut roi: RoiBounds) -> RoiBounds {
    let m = ROI_EDGE_MARGIN;
    if (roi.x0 as u32) < m {
        roi.x0 = 0;
    }
    if width.saturating_sub(roi.x1 as u32) < m {
        roi.x1 = width as u16;
    }
    if (roi.y0 as u32) < m {
        roi.y0 = 0;
    }
    if height.saturating_sub(roi.y1 as u32) < m {
        roi.y1 = height as u16;
    }
    roi
}

/// In-place ROI conditioner — `syna_ir_reconstruct_roi@0x1800b9430`.
///
/// This is the function whose output (at `ctx+0x238`) is flipped and fed to
/// `syna_qm_probe_setup`. Full-frame bounds take the midrange path; a cropped ROI takes in-place
/// [`normalize_frame_inplace`] with bias = ROI mean.
pub fn reconstruct_roi(img: &mut [u8], width: usize, height: usize, roi: RoiBounds) {
    assert_eq!(img.len(), width * height);
    let roi = snap_roi(width as u32, height as u32, roi);
    let stats = roi_histogram_stats(img, width, height, roi);
    let bias = stats.mean as i32;

    let x0 = roi.x0 as usize;
    let x1 = roi.x1 as usize;
    let y0 = roi.y0 as usize;
    let y1 = roi.y1 as usize;

    if x0 == 0 && x1 == width {
        // Full-width: midrange-recenter the ROI band, then the above/below strips if any.
        let band_h = y1.saturating_sub(y0);
        if band_h > 0 {
            row_midrange_recenter(img, width, band_h, width, y0, x0, x1, bias);
        }
        if y0 > 0 {
            row_midrange_recenter(img, width, y0, width, 0, 0, width, bias);
        }
        if y1 < height {
            row_midrange_recenter(img, width, height - y1, width, y1, 0, width, bias);
        }
    } else {
        normalize_frame_inplace(img, width, height, bias);
    }
}

/// Convert a gray `f32` field already in byte domain into `u8` via round+clamp.
///
/// Used when feeding `reconstruct_roi` from a descramble tap (byte-domain `f32`).
pub fn field_to_u8_clamped(field: &[f32]) -> Vec<u8> {
    field.iter().map(|&v| v.round().clamp(0.0, 255.0) as u8).collect()
}

/// Historical helper: mid-grey `u8` → signed `f32` (`b as f32 − 128`). Not used on the QM path
/// anymore (Conditioned carries reconstruct_roi bytes as `f32` 0..255); kept for callers that
/// still reason about SelectFrame scratch mid-grey.
pub fn u8_midgrey_to_signed_field(img: &[u8]) -> Vec<f32> {
    img.iter().map(|&b| b as f32 - SELECT_FRAME_BIAS as f32).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_place_normalize_is_column_only() {
        // Distinct src/dst: pass 2 reads the original, so row work is discarded.
        let w = 4usize;
        let h = 3usize;
        // Rows differ; columns are constant → column mean = the column value, so out-of-place
        // with bias=mean leaves a flat bias field.
        let src: Vec<u8> = vec![
            10, 20, 30, 40, //
            10, 20, 30, 40, //
            10, 20, 30, 40,
        ];
        let mut dst = vec![0u8; w * h];
        let bias = 128;
        normalize_frame(&src, &mut dst, w, h, bias);
        // Each column c has mean = 10+10*c, so out = c_val - (c_val - 128) = 128.
        assert!(dst.iter().all(|&b| b == 128), "got {dst:?}");
    }

    #[test]
    fn in_place_normalize_cascades_row_then_column() {
        let w = 3usize;
        let h = 3usize;
        // A ramp that is not separable into independent row/col flats.
        let mut img: Vec<u8> = (0..(w * h) as u8).map(|i| 40 + i * 3).collect();
        let before = img.clone();
        normalize_frame_inplace(&mut img, w, h, SELECT_FRAME_BIAS);
        assert_ne!(img, before);
        // Out-of-place on the original must differ when row structure matters.
        let mut oop = vec![0u8; w * h];
        normalize_frame(&before, &mut oop, w, h, SELECT_FRAME_BIAS);
        assert_ne!(img, oop, "in-place and out-of-place must disagree on a non-separable field");
    }

    #[test]
    fn full_frame_roi_takes_midrange_path() {
        let w = 16usize;
        let h = 8usize;
        let mut img = vec![100u8; w * h];
        for y in 0..h {
            img[y * w + 3] = 200;
        }
        let before = img.clone();
        reconstruct_roi(&mut img, w, h, RoiBounds::full(w as u16, h as u16));
        assert_ne!(img, before);
        // Midrange of a mostly-flat row ignores the single spike, so non-spike pixels shift by the
        // same amount in every row; the spike stays an outlier by the same delta.
        let delta_flat = before[0] as i32 - img[0] as i32;
        let delta_spike = before[3] as i32 - img[3] as i32;
        assert_eq!(delta_flat, delta_spike);
        for y in 0..h {
            assert_eq!(img[y * w], img[0]);
            assert_eq!(img[y * w + 3], img[3]);
        }
    }

    #[test]
    fn partial_roi_uses_inplace_normalize() {
        // Image large enough that an interior ROI survives the 10-px edge snap.
        let w = 40usize;
        let h = 30usize;
        let mut img: Vec<u8> = (0..(w * h)).map(|i| 50u8.wrapping_add((i % 200) as u8)).collect();
        let roi = RoiBounds { x0: 12, x1: 28, y0: 12, y1: 20 };
        let snapped = snap_roi(w as u32, h as u32, roi);
        assert!(snapped.x0 > 0 || snapped.x1 < w as u16, "ROI must stay partial after snap");

        let mut via_roi = img.clone();
        reconstruct_roi(&mut via_roi, w, h, roi);

        let stats = roi_histogram_stats(&img, w, h, snapped);
        normalize_frame_inplace(&mut img, w, h, stats.mean as i32);
        assert_eq!(via_roi, img);
    }

    #[test]
    fn robust_midrange_of_a_flat_run_is_that_value() {
        assert_eq!(robust_midrange_u8(&[77; 100]), 77);
    }
}
