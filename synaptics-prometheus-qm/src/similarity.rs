//! Q16 similarity-transform fitting between matched minutia neighborhoods.
//!
//! Ports: `syna_qm_minutia_pair_matcher@0x1800073d0`, `FUN_1800072e0@0x1800072e0`,
//! `FUN_180007340@0x180007340`, `FUN_180006d60@0x180006d60`, `FUN_180006e70@0x180006e70`,
//! `FUN_1800073a0@0x1800073a0` → `syna_qm_apply_xform_q16@0x180006b10`.

use crate::consensus::apply_xform_q16;
use crate::int_math::{div_trunc, isqrt, normalize_q16};
use crate::types::SynaQmXformRecord;

/// Q16 similarity transform `{cos, sin, tx, ty}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimilarityQ16 {
    pub cos: i32,
    pub sin: i32,
    pub tx: i32,
    pub ty: i32,
}

impl SimilarityQ16 {
    pub fn to_xform_record(self, valid: i32) -> SynaQmXformRecord {
        SynaQmXformRecord {
            cos_q16: self.cos,
            sin_q16: self.sin,
            tx: self.tx,
            ty: self.ty,
            valid_flag: valid,
        }
    }
}

/// Two-point Q16 similarity fit — bit-exact port of `FUN_180006d60@0x180006d60`. Fits the transform
/// mapping the two probe points to the two gallery points. **Argument layout (oracle-verified, FIT2
/// golden):** `probe_pts = [P0x, P0y, P1x, P1y]` (both probe points), `gallery_pts = [G0x, G0y, G1x,
/// G1y]` (both gallery points) — i.e. one probe-vector and one gallery-vector, NOT two per-correspondence
/// `[Px,Py,Gx,Gy]` pairs. The rotation comes from the vectors' cross/dot product; a pure translation
/// gives `cos=0x10000, sin=0` and the exact `tx/ty`. Returns `None` when the probe/gallery vectors are
/// degenerate (`mag==0`, e.g. coincident points).
pub fn fit_two_point(probe_pts: [i32; 4], gallery_pts: [i32; 4]) -> Option<SimilarityQ16> {
    let pvx = probe_pts[2] - probe_pts[0];
    let pvy = probe_pts[3] - probe_pts[1];
    let gvx = gallery_pts[2] - gallery_pts[0];
    let gvy = gallery_pts[3] - gallery_pts[1];
    let num_sin = gvy * pvx - pvy * gvx;
    let num_cos = gvy * pvy + gvx * pvx;
    let mag = isqrt((num_sin as i64 * num_sin as i64 + num_cos as i64 * num_cos as i64) as u32);
    if mag == 0 {
        return None;
    }
    let cos = div_trunc(num_cos * 0x10000, mag as i32);
    let sin = div_trunc(num_sin * 0x10000, mag as i32);
    let tx = ((probe_pts[1] + probe_pts[3]) * sin - (probe_pts[0] + probe_pts[2]) * cos
        + (gallery_pts[0] + gallery_pts[2]) * 0x10000)
        >> 1;
    let ty = (((gallery_pts[3] + gallery_pts[1]) * 0x10000 - (probe_pts[1] + probe_pts[3]) * cos)
        - (probe_pts[0] + probe_pts[2]) * sin)
        >> 1;
    Some(SimilarityQ16 { cos, sin, tx, ty })
}

/// Least-squares Q16 fit — `FUN_180006e70@0x180006e70`.
pub fn fit_least_squares(probe: &[[i32; 2]], gallery: &[[i32; 2]]) -> Option<SimilarityQ16> {
    let n = probe.len();
    if n == 0 {
        return None;
    }
    let n_i = n as i32;
    let mut sum_px = 0i32;
    let mut sum_py = 0i32;
    let mut sum_gx = 0i32;
    let mut sum_gy = 0i32;
    for i in 0..n {
        sum_px += probe[i][0];
        sum_py += probe[i][1];
        sum_gx += gallery[i][0];
        sum_gy += gallery[i][1];
    }
    let mean_px = div_trunc(sum_px, n_i);
    let mean_py = div_trunc(sum_py, n_i);
    let mean_gx = div_trunc(sum_gx, n_i);
    let mean_gy = div_trunc(sum_gy, n_i);

    let mut acc_a = 0i32;
    let mut acc_b = 0i32;
    for i in 0..n {
        let dpx = probe[i][0] - mean_px;
        let dpy = probe[i][1] - mean_py;
        let dgx = gallery[i][0] - mean_gx;
        let dgy = gallery[i][1] - mean_gy;
        acc_a = acc_a + dpx * dgy - dpy * dgx;
        acc_b = acc_b + dpx * dgx - dpy * dgy;
    }
    let a = div_trunc(acc_a, n_i);
    let b = div_trunc(acc_b, n_i);
    let mag = isqrt((a as i64 * a as i64 + b as i64 * b as i64) as u32);
    if mag == 0 {
        return None;
    }
    let mut cos = div_trunc(b * 0x10000, mag as i32);
    let mut sin = div_trunc(a * 0x10000, mag as i32);
    normalize_q16(&mut cos, &mut sin);
    let tx = div_trunc(sum_gx * 0x10000 + (sin * sum_py - cos * sum_px), n_i);
    let ty = div_trunc((sum_gy * 0x10000 - cos * sum_py) - sin * sum_px, n_i);
    Some(SimilarityQ16 { cos, sin, tx, ty })
}

/// Apply transform to one point — `FUN_1800073a0@0x1800073a0`.
pub fn apply_similarity(x: i32, y: i32, xf: &SimilarityQ16) -> (i32, i32) {
    let rec = xf.to_xform_record(1);
    apply_xform_q16(x, y, &rec)
}

/// Pair matcher selecting a similarity from candidate correspondences —
/// `syna_qm_minutia_pair_matcher@0x1800073d0`.
///
/// `probe`/`gallery` are parallel `(x,y)` pairs; `angle_diff` holds per-pair angle deltas.
pub fn minutia_pair_matcher(
    probe: &[[i32; 2]],
    gallery: &[[i32; 2]],
    angle_diff: &[i32],
    spatial_thresh: i32,
) -> (Option<SimilarityQ16>, Vec<usize>) {
    let n = probe.len();
    if n == 0 {
        return (None, Vec::new());
    }
    let mut best_support = 0i32;
    let mut best_i = -1i32;
    let mut best_j = -1i32;
    for i in 0..n {
        for j in (i + 1)..n {
            let ad = (angle_diff[i] - angle_diff[j]).abs();
            if ad >= 0x11 {
                continue;
            }
            let probe_pair = [probe[i][0], probe[i][1], probe[j][0], probe[j][1]];
            let gallery_pair = [gallery[i][0], gallery[i][1], gallery[j][0], gallery[j][1]];
            let Some(xf) = fit_two_point(probe_pair, gallery_pair) else {
                continue;
            };
            let mut support = 0;
            for k in 0..n {
                let (tx, ty) = apply_similarity(probe[k][0], probe[k][1], &xf);
                let dx = tx - gallery[k][0];
                let dy = ty - gallery[k][1];
                if dx * dx + dy * dy <= spatial_thresh {
                    support += 1;
                }
            }
            if support > best_support {
                best_support = support;
                best_i = i as i32;
                best_j = j as i32;
            }
        }
    }
    if best_support <= 2 {
        return (None, Vec::new());
    }
    let i = best_i as usize;
    let j = best_j as usize;
    let probe_pair = [probe[i][0], probe[i][1], probe[j][0], probe[j][1]];
    let gallery_pair = [gallery[i][0], gallery[i][1], gallery[j][0], gallery[j][1]];
    let Some(xf_seed) = fit_two_point(probe_pair, gallery_pair) else {
        return (None, Vec::new());
    };
    let mut inliers = Vec::new();
    let mut probe_in = Vec::new();
    let mut gallery_in = Vec::new();
    for k in 0..n {
        let (tx, ty) = apply_similarity(probe[k][0], probe[k][1], &xf_seed);
        let dx = tx - gallery[k][0];
        let dy = ty - gallery[k][1];
        if dx * dx + dy * dy <= spatial_thresh {
            inliers.push(k);
            probe_in.push(probe[k]);
            gallery_in.push(gallery[k]);
        }
    }
    let xf = fit_least_squares(&probe_in, &gallery_in);
    (xf, inliers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_two_point_matches_oracle_golden() {
        // FIT2 (geomfeat.txt): probe P0=(23,13),P1=(8,30); gallery = probe + (3,2). A pure translation
        // → identity rotation, tx=3<<16, ty=2<<16. Args are (both probe points, both gallery points).
        let xf = fit_two_point([23, 13, 8, 30], [26, 15, 11, 32]).expect("non-degenerate");
        assert_eq!(xf.cos, 0x10000);
        assert_eq!(xf.sin, 0);
        assert_eq!(xf.tx, 196608);
        assert_eq!(xf.ty, 131072);
        // The transform maps each probe point onto its gallery point.
        assert_eq!(apply_similarity(23, 13, &xf), (26, 15));
        assert_eq!(apply_similarity(8, 30, &xf), (11, 32));
    }

    #[test]
    fn pair_matcher_finds_translation_inliers() {
        // A clean (3,2) translation of 6 scattered points → all 6 are inliers (regression guard for the
        // fit_two_point argument-layout fix; the old grouping degenerated on pure translations).
        let probe = [[23, 13], [8, 30], [46, 26], [31, 43], [54, 8], [69, 39]];
        let gallery: Vec<[i32; 2]> = probe.iter().map(|p| [p[0] + 3, p[1] + 2]).collect();
        let ad = vec![0i32; probe.len()];
        let (xf, inliers) = minutia_pair_matcher(&probe, &gallery, &ad, 8);
        assert!(xf.is_some());
        assert_eq!(inliers.len(), 6);
    }
}
