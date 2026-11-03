//! Pure host conditioning + raster helpers, shared by the live viewer's optional host stubs and by
//! reflective/headless stage runs. These are UI-agnostic float-field transforms (no egui, no
//! transport) so they can be unit-tested and reused by the `synaptics-pipeline-graph` crate.
//!
//! Moved verbatim out of `examples/live_viewer.rs` (which previously reimplemented them inline).
//! **Not on the QM path** — the graph's Conditioned stage is `syna_ir_reconstruct_roi` (see
//! `docs/qm/conditioning-topology.md`). Host `base_sub` / col / row remain optional stubs only.
//! Rule #7: trust finger-dependence (the Δ panel), not appearance.

use crate::capture_prog::SYNC_LINE_HEADER;
use crate::reconstruct::descramble_timeslot_image;

/// Timeslots per de-scramble block (the 16-wide Hadamard/`transform16` group — shared by stream
/// `cf640` and the polled-path matcher IR-recon).
pub const TIMESLOTS_PER_BLOCK: usize = 16;

/// Mid-grey a zero difference maps to in the Δ (finger-dependence) view.
pub const DELTA_MID: f32 = 128.0;

/// Reshape a flat body into a `blocks*16`-wide float raster, optionally de-scrambling (mode-2
/// `transform16` per 16-byte block — the kernel the matcher's IR-recon runs on polled `0x51`
/// identify/enroll frames; `cf640` is the same kernel's stream-path caller). `meta_offset` skips
/// leading bytes before the raster. Polled-path helper.
pub fn reshape(body: &[u8], blocks: usize, meta_offset: usize, descramble: bool) -> (usize, usize, Vec<f32>) {
    let width = blocks * TIMESLOTS_PER_BLOCK;
    if width == 0 {
        return (0, 0, Vec::new());
    }
    let slice = &body[meta_offset.min(body.len())..];
    let height = slice.len() / width;
    if height == 0 {
        return (width, 0, Vec::new());
    }
    let n = width * height;
    if descramble {
        let img = descramble_timeslot_image(&slice[..n], blocks);
        (width, height, img.pixels.iter().map(|&b| b as f32).collect())
    } else {
        (width, height, slice[..n].iter().map(|&b| b as f32).collect())
    }
}

/// De-stride an EP-0x82 wire buffer into a flat `data_width`-wide body (8-byte wire header stripped
/// per `stride`-byte line). Stream-path helper.
pub fn destride_sync_lines(raw: &[u8], stride: usize, data_width: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(raw.len());
    for chunk in raw.chunks_exact(stride) {
        if chunk.len() >= SYNC_LINE_HEADER + data_width {
            body.extend_from_slice(&chunk[SYNC_LINE_HEADER..SYNC_LINE_HEADER + data_width]);
        }
    }
    body
}

/// Intermediate outputs of the conditioning pipeline.
#[derive(Debug, Clone)]
pub struct ConditionStages {
    pub base_sub: Vec<f32>,
    pub col_only: Vec<f32>,
    pub row_only: Vec<f32>,
    pub conditioned: Vec<f32>,
}

/// Compact min/max/mean for a float field.
#[derive(Debug, Clone, Copy)]
pub struct FieldStats {
    pub min: f32,
    pub max: f32,
    pub mean: f32,
}

pub fn field_stats(field: &[f32]) -> FieldStats {
    if field.is_empty() {
        return FieldStats { min: 0.0, max: 0.0, mean: 0.0 };
    }
    let mut min = f32::MAX;
    let mut max = f32::MIN;
    let mut sum = 0.0f32;
    for &v in field {
        min = min.min(v);
        max = max.max(v);
        sum += v;
    }
    FieldStats { min, max, mean: sum / field.len() as f32 }
}

/// `field - baseline` elementwise over `n` (missing entries treated as 0). `baseline = None` ⇒ copy.
pub fn subtract_baseline_field(field: &[f32], baseline: Option<&[f32]>, n: usize) -> Vec<f32> {
    (0..n)
        .map(|i| {
            field.get(i).copied().unwrap_or(0.0)
                - baseline.and_then(|b| b.get(i)).copied().unwrap_or(0.0)
        })
        .collect()
}

/// Per-field, per-column z-score normalize (kills the timeslot field-DC + per-column fixed pattern).
/// `fields` = interleave/repeat count; rows are grouped `r % fields`.
pub fn apply_col_condition(f: &mut [f32], width: usize, height: usize, fields: usize) {
    let fields = fields.max(1);
    for fld in 0..fields {
        let rows: Vec<usize> = (fld..height).step_by(fields).collect();
        if rows.is_empty() {
            continue;
        }
        for c in 0..width {
            let mut sum = 0.0f32;
            for &r in &rows {
                sum += f[r * width + c];
            }
            let mean = sum / rows.len() as f32;
            let mut var = 0.0f32;
            for &r in &rows {
                let d = f[r * width + c] - mean;
                var += d * d;
            }
            let std = (var / rows.len() as f32).sqrt().max(1e-6);
            for &r in &rows {
                let idx = r * width + c;
                f[idx] = (f[idx] - mean) / std;
            }
        }
    }
}

/// Per-row mean removal.
pub fn apply_row_condition(f: &mut [f32], width: usize, height: usize) {
    for r in 0..height {
        let base = r * width;
        let mean: f32 = f[base..base + width].iter().sum::<f32>() / width as f32;
        for v in &mut f[base..base + width] {
            *v -= mean;
        }
    }
}

/// Stepped conditioning: baseline subtract, optional col-only / row-only, and the fused output.
pub fn condition_stages(
    field: &[f32],
    baseline: Option<&[f32]>,
    width: usize,
    height: usize,
    fields: usize,
    col: bool,
    row: bool,
) -> ConditionStages {
    let n = width * height;
    let base_sub = subtract_baseline_field(field, baseline, n);
    let mut col_only = base_sub.clone();
    if col {
        apply_col_condition(&mut col_only, width, height, fields);
    }
    let mut row_only = base_sub.clone();
    if row {
        apply_row_condition(&mut row_only, width, height);
    }
    let mut conditioned = base_sub.clone();
    if col {
        apply_col_condition(&mut conditioned, width, height, fields);
    }
    if row {
        apply_row_condition(&mut conditioned, width, height);
    }
    ConditionStages { base_sub, col_only, row_only, conditioned }
}

/// Mean absolute difference between two float fields (over their overlapping prefix).
pub fn mean_abs_diff(a: &[f32], b: &[f32]) -> f32 {
    let n = a.len().min(b.len());
    if n == 0 {
        return 0.0;
    }
    a[..n].iter().zip(&b[..n]).map(|(x, y)| (x - y).abs()).sum::<f32>() / n as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn condition_stages_base_sub_only_without_col_row() {
        let field = vec![10.0, 20.0, 30.0, 40.0];
        let baseline = vec![1.0, 2.0, 3.0, 4.0];
        let s = condition_stages(&field, Some(&baseline), 2, 2, 1, false, false);
        assert_eq!(s.base_sub, vec![9.0, 18.0, 27.0, 36.0]);
        assert_eq!(s.col_only, s.base_sub);
        assert_eq!(s.row_only, s.base_sub);
        assert_eq!(s.conditioned, s.base_sub);
    }

    #[test]
    fn condition_stages_row_removes_row_mean() {
        let field = vec![1.0, 3.0, 5.0, 7.0];
        let s = condition_stages(&field, None, 2, 2, 1, false, true);
        assert!((s.row_only[0] + 1.0).abs() < 1e-5);
        assert!((s.row_only[1] - 1.0).abs() < 1e-5);
        assert!((s.row_only[2] + 1.0).abs() < 1e-5);
        assert!((s.row_only[3] - 1.0).abs() < 1e-5);
    }

    #[test]
    fn field_stats_computes_mean() {
        let s = field_stats(&[0.0, 2.0, 4.0]);
        assert_eq!(s.min, 0.0);
        assert_eq!(s.max, 4.0);
        assert!((s.mean - 2.0).abs() < 1e-5);
    }

    #[test]
    fn destride_strips_8byte_header() {
        // two 12-byte lines (stride 12), data_width 4 → keep bytes [8..12] of each.
        let raw: Vec<u8> = (0..24).collect();
        let body = destride_sync_lines(&raw, 12, 4);
        assert_eq!(body, vec![8, 9, 10, 11, 20, 21, 22, 23]);
    }

    #[test]
    fn reshape_no_descramble_is_identity_floats() {
        let body: Vec<u8> = (0..32).collect(); // 1 block wide (16), 2 rows
        let (w, h, f) = reshape(&body, 1, 0, false);
        assert_eq!((w, h), (16, 2));
        assert_eq!(f.len(), 32);
        assert_eq!(f[0], 0.0);
        assert_eq!(f[17], 17.0);
    }
}
