//! Phase 3 — minutiae candidate emission from the DoH response field.
//!
//! Ports (see `../../docs/qm/qm-minutiae-detector.md`):
//! - `syna_qm_detect_peaks_nms@0x18000cee0` — 3×3 non-max-suppression local maxima of the response,
//!   above threshold, with min-distance suppression and polarity classification.
//! - `syna_qm_refine_subpixel_hessian@0x18000d520` + `syna_qm_solve_2x2@0x18000d410` — quadratic
//!   sub-pixel peak fit + singular/large-offset rejection.
//! - `syna_qm_emit_border_reject@0x18000a8b0` — border rejection (a candidate must satisfy
//!   `2 < c < dim-3`).
//!
//! Fidelity: bit-exact to `syna_qm_detect_peaks_nms@0x18000cee0`, validated against the real DLL via
//! `tools/qm-dll-oracle` (golden/nms.txt). Per-tile emit budget is `cfg+0 >> 2` (125 on 0x2449) and
//! NMS margin is cfg+8 radius (10) — see [`NmsParams::dll`]. Rule #7: candidates are processed
//! diagnostics, validated by finger-dependence.

use super::config::DetectConfig;
use super::field::DohField;
use super::Candidate;

/// NMS + emission knobs, mirroring the DLL `SynaQmDetectCtx` fields `detect_peaks_nms` reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NmsParams {
    /// `engine+0x20` — strict gate: a peak must satisfy `v > thr1`.
    pub thr1: i32,
    /// `engine+0x24` — second gate: `v >= thr2` (subsumed by `thr1` for 0x2449, applied faithfully).
    pub thr2: i32,
    /// Exclusion threshold on `dx²+dy²` between kept peaks. DLL: `((engine+0x48 >> 6)²) >> 20` (=1 for
    /// 0x2449 — near no-op). For the tunable path this is `min_distance²`.
    pub min_dist_sq: i32,
    /// Hard cap on emitted candidates.
    pub max_candidates: usize,
    /// Scan border margin (DLL `emit_candidates` `param_6` = cfg+8 radius). Min 1 (for 3×3 access).
    pub margin: i32,
    /// On a min-distance replace, the DLL writes the *previous appended* candidate's class byte (a
    /// latent stale-byte bug). `false` = reproduce that; `true` = recompute the class fresh (cleaner).
    pub recompute_class_on_replace: bool,
}

impl NmsParams {
    /// DLL-faithful params from the detector cfg — engine thr/min-dist via `detect_kernel_params`,
    /// per-tile `max_out = cfg+0 >> 2`, margin = cfg+8 radius (`syna_qm_emit_candidates@0x18000d290`).
    pub fn dll(cfg: &DetectConfig) -> Self {
        Self {
            thr1: cfg.nms_thr1(),
            thr2: DetectConfig::NMS_THR2,
            min_dist_sq: cfg.nms_min_dist_sq(),
            max_candidates: cfg.nms_max_out(),
            margin: cfg.nms_margin(),
            recompute_class_on_replace: false,
        }
    }

    /// Tunable path: single `threshold` gate (`thr2=0`), a 4px exclusion, margin 1 — viewer
    /// adaptive/structural mode.
    pub fn with_threshold(threshold: i32, cfg: &DetectConfig) -> Self {
        Self {
            thr1: threshold,
            thr2: 0,
            min_dist_sq: 4 * 4,
            max_candidates: cfg.max_minutiae as usize,
            margin: 1,
            recompute_class_on_replace: false,
        }
    }
}

/// Maximum response over the **interior** (excluding the `reject_border` margin). The `0x800000` halo
/// pad makes the image-edge pixels — where real content meets the halo — the strongest responses, but
/// the DLL emits candidates interior-only (`syna_qm_emit_border_reject@0x18000a8b0`) and never lets
/// the border set the scale, so interior-max keeps any response-fraction threshold meaningful for
/// interior features.
pub fn interior_max(field: &DohField) -> i32 {
    let (w, h) = (field.width, field.height);
    let (lo, hi) = (DetectConfig::BORDER_MARGIN_LO, DetectConfig::BORDER_MARGIN_HI);
    if w as i32 <= lo + hi || h as i32 <= lo + hi {
        return field.response.iter().copied().max().unwrap_or(0);
    }
    let mut max = 0i32;
    for y in (lo as usize + 1)..(h - hi as usize) {
        for x in (lo as usize + 1)..(w - hi as usize) {
            max = max.max(field.response[y * w + x]);
        }
    }
    max
}

/// A response threshold as a fraction of the field's interior max — used at our (non-bit-exact)
/// response scale in place of the DLL's absolute `500`. `frac` in `0.0..1.0`.
pub fn adaptive_threshold(field: &DohField, frac: f32) -> i32 {
    ((interior_max(field) as f64) * frac as f64) as i32
}

/// Polarity/class byte from the two 2nd-derivative signs — `syna_qm_detect_peaks_nms`:
/// `c = true; if Lxx < 0 { c = (-1 < Lyy) }` — i.e. **class 0 only when `Lxx < 0 AND Lyy < 0`**.
/// Validated against the DLL (`tools/qm-dll-oracle` golden/nms.txt: `Lxx<0,Lyy=-5 → 0`; `Lyy=50 → 1`;
/// `Lxx≥0 → 1`). NOTE the DLL predicate is `Lyy >= 0`, not the earlier port's `Lyy >= -1`.
///
/// Point-wise so a diagnostic view can render the same decision over the whole field rather than
/// re-deriving the predicate (`0` = ridge ending, `1` = bifurcation, as the overlay colours them).
pub fn minutia_class(lxx: i32, lyy: i32) -> u8 {
    let mut c = true;
    if lxx < 0 {
        c = lyy >= 0;
    }
    c as u8
}

fn polarity(field: &DohField, idx: usize) -> u8 {
    minutia_class(field.lxx[idx], field.lyy[idx])
}

/// 3×3 non-max-suppression peak detection over the DoH response — bit-exact port of
/// `syna_qm_detect_peaks_nms@0x18000cee0` (validated vs the DLL, `tools/qm-dll-oracle` golden/nms.txt).
/// Two-gate threshold (`v > thr1 && v >= thr2`), strict 3×3 max on the raw signed response, `score=|v|`,
/// `((r>>6)²)>>20`-style exclusion (`min_dist_sq`), stop-at-first-near + replace-if-stronger, and the
/// `Lxx<0 → Lyy>=0` class byte. Scans the interior `[margin, dim-margin)`.
pub fn detect_peaks(field: &DohField, p: &NmsParams) -> Vec<Candidate> {
    let (w, h) = (field.width, field.height);
    let r = &field.response;
    let margin = p.margin.max(1) as usize;
    let mut out: Vec<Candidate> = Vec::new();
    if w <= 2 * margin || h <= 2 * margin {
        return out;
    }
    // The DLL computes the class only on the *append* branch and reuses that (stale) byte on a
    // subsequent min-distance replace. Track the last appended class to reproduce that faithfully.
    let mut last_class: u8 = 0;
    for y in margin..h - margin {
        for x in margin..w - margin {
            let idx = y * w + x;
            let v = r[idx];
            // Two-gate threshold on the raw signed response (engine+0x20 strict, +0x24 `>=`).
            if !(v > p.thr1 && v >= p.thr2) {
                continue;
            }
            // strict 3×3 local maximum (raw signed, all neighbours `< v`)
            let is_max = [
                r[idx - w - 1], r[idx - w], r[idx - w + 1],
                r[idx - 1],                 r[idx + 1],
                r[idx + w - 1], r[idx + w], r[idx + w + 1],
            ]
            .iter()
            .all(|&n| n < v);
            if !is_max {
                continue;
            }
            let score = v.abs(); // DLL: `if v < 1 { v = -v }` (v>0 past the threshold, so score = v)
            // min-distance suppression against already-kept peaks (keep the stronger); stop at first.
            let (xi, yi) = (x as i32, y as i32);
            let mut near = false;
            for k in out.iter_mut() {
                let (dx, dy) = (xi - k.x, yi - k.y);
                if dx * dx + dy * dy <= p.min_dist_sq {
                    near = true;
                    if score > k.score {
                        k.x = xi;
                        k.y = yi;
                        k.score = score;
                        k.class = if p.recompute_class_on_replace { polarity(field, idx) } else { last_class };
                    }
                    break;
                }
            }
            if !near {
                let class = polarity(field, idx);
                last_class = class;
                out.push(Candidate {
                    x: xi,
                    y: yi,
                    score,
                    class,
                    ..Default::default()
                });
                if out.len() >= p.max_candidates {
                    return out;
                }
            }
        }
    }
    out
}

/// Drop candidates within `[BORDER_MARGIN_LO, dim-BORDER_MARGIN_HI]` of the image edge —
/// `syna_qm_emit_border_reject@0x18000a8b0`'s `2 < c < dim-3` guard.
pub fn reject_border(mut candidates: Vec<Candidate>, w: usize, h: usize) -> Vec<Candidate> {
    let (lo, hi) = (DetectConfig::BORDER_MARGIN_LO, DetectConfig::BORDER_MARGIN_HI);
    candidates.retain(|c| c.x > lo && c.x < w as i32 - hi && c.y > lo && c.y < h as i32 - hi);
    candidates
}

/// Solve the 2×2 system `[a b; b d]·δ = [gx; gy]` with the DLL's `>>4` pre-scaling and truncating
/// division. Port of `syna_qm_solve_2x2@0x18000d410`. Products use `i64` — the DLL's `>>4` avoids
/// i32 overflow at its Q16.16 response scale, but our (larger, non-bit-exact) response scale needs the
/// wider accumulator; the shift/division structure is preserved. Returns `None` if singular.
fn solve_2x2(a: i32, b: i32, d: i32, gx: i32, gy: i32) -> Option<(i32, i32)> {
    let (a4, b4, d4) = ((a >> 4) as i64, (b >> 4) as i64, (d >> 4) as i64);
    let (gx4, gy4) = ((gx >> 4) as i64, (gy >> 4) as i64);
    let bb = b4 * b4;
    let ad = d4 * a4;
    let det_neg = (bb - ad) >> 7;
    let det_pos = (ad - bb) >> 7;
    if det_pos == 0 || det_neg == 0 {
        return None;
    }
    let dx = (d4 * gx4 - gy4 * b4) / det_pos;
    let dy = (b4 * gx4 - gy4 * a4) / det_neg;
    Some((dx as i32, dy as i32))
}

/// Sub-pixel refine + stability reject — bit-exact port of `syna_qm_refine_subpixel_hessian@0x18000d520`
/// (validated vs the DLL, `tools/qm-dll-oracle` golden/nms.txt `REFINE`). Fits a quadratic to the
/// response at each candidate (local Hessian + gradient — identical to the DLL), solves for the sub-pixel
/// offset `(dx,dy)`, **drops** candidates with `|off| > SUBPIXEL_REJECT` or a singular Hessian, and for
/// survivors writes back the refined coordinate and zeroes the angle.
///
/// Write-back: the DLL stores `rec = (ix·0x80 + off)·0x200 · (1<<(tile+0x60))` as Q16.16, which
/// `minutia_refine_xy_angle@0x18000a860` later `>>16`s back to an integer global coord. `tile+0x60`
/// (the subsample shift) is the tile's row index = **0** for this SKU's single full-frame tile-per-region,
/// so the tile-local integer becomes `ix + (off >> 7)` (a −1/0/+1 nudge). The full-precision sub-pixel is
/// discarded by the `>>16` (and the template stores integer coords), so this is the observable effect.
pub fn refine_and_reject(field: &DohField, candidates: Vec<Candidate>) -> Vec<Candidate> {
    let (w, h) = (field.width, field.height);
    let r = &field.response;
    candidates
        .into_iter()
        .filter_map(|mut c| {
            let (x, y) = (c.x as usize, c.y as usize);
            if x == 0 || y == 0 || x + 1 >= w || y + 1 >= h {
                return None;
            }
            let idx = y * w + x;
            let (cc, l, rr) = (r[idx], r[idx - 1], r[idx + 1]);
            let (u, dn) = (r[idx - w], r[idx + w]);
            let (dr, ul, dl, ur) = (r[idx + w + 1], r[idx - w - 1], r[idx + w - 1], r[idx - w + 1]);
            // Hessian of R (>>2 as in the DLL) and negated gradient.
            let dxx = (rr - 2 * cc + l) >> 2;
            let dyy = (dn - 2 * cc + u) >> 2;
            let dxy = (((dr + ul) >> 2) - ((dl + ur) >> 2)) >> 2;
            let gx = -((rr - l) >> 1) >> 2;
            let gy = -((dn - u) >> 1) >> 2;
            let (dx, dy) = solve_2x2(dxx, dxy, dyy, gx, gy)?;
            if dx.abs() > DetectConfig::SUBPIXEL_REJECT || dy.abs() > DetectConfig::SUBPIXEL_REJECT {
                return None;
            }
            // Faithful sub-pixel write-back (shift = tile+0x60 = 0 → `ix + (off >> 7)`).
            c.x += dx >> 7;
            c.y += dy >> 7;
            c.angle = 0;
            Some(c)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::config::CONFIG_2449;
    use super::super::field::doh_response;
    use super::*;

    // Mid-grey (128) background so the DLL's 0x800000 halo pad equals the background and injects no
    // border edge — the real-frame condition the faithful halo targets (`doh-detector-faithful.md`).
    fn blob_image(w: usize, h: usize, centers: &[(i32, i32)]) -> Vec<u8> {
        let mut px = vec![128u8; w * h];
        for &(cx, cy) in centers {
            for y in 0..h as i32 {
                for x in 0..w as i32 {
                    let d2 = (x - cx) * (x - cx) + (y - cy) * (y - cy);
                    let v = 20.0 + 200.0 * (-(d2 as f32) / 12.0).exp();
                    let p = (y as usize) * w + x as usize;
                    px[p] = (px[p] as f32).max(v).min(255.0) as u8;
                }
            }
        }
        px
    }

    #[test]
    fn detects_blob_peaks_near_true_centers() {
        let (w, h) = (48usize, 40usize);
        let centers = [(12, 12), (30, 24)];
        let px = blob_image(w, h, &centers);
        let field = doh_response(&px, w, h, &crate::detect::DohParams { ksize: crate::detect::gaussian_taps(1.5), sigma: 1.5, scale: 1 });
        let thr = adaptive_threshold(&field, 0.15);
        let peaks = detect_peaks(&field, &NmsParams::with_threshold(thr, &CONFIG_2449));
        // each true center has a detected peak within a few px
        for &(cx, cy) in &centers {
            let hit = peaks.iter().any(|p| (p.x - cx).abs() <= 3 && (p.y - cy).abs() <= 3);
            assert!(hit, "no peak near ({cx},{cy}); got {:?}", peaks.iter().map(|p| (p.x, p.y)).collect::<Vec<_>>());
        }
    }

    #[test]
    fn min_distance_suppresses_duplicates() {
        let (w, h) = (48usize, 40usize);
        let px = blob_image(w, h, &[(24, 20)]);
        let field = doh_response(&px, w, h, &crate::detect::DohParams { ksize: crate::detect::gaussian_taps(1.5), sigma: 1.5, scale: 1 });
        let thr = adaptive_threshold(&field, 0.15);
        let mut p = NmsParams::with_threshold(thr, &CONFIG_2449);
        p.min_dist_sq = 8 * 8;
        let peaks = detect_peaks(&field, &p);
        // one blob -> at most one peak survives the 8px exclusion radius near the center
        let near_center = peaks.iter().filter(|c| (c.x - 24).abs() <= 8 && (c.y - 20).abs() <= 8).count();
        assert_eq!(near_center, 1, "min-distance should keep a single peak per blob");
    }

    // --- Bit-exact validation against the real DLL (tools/qm-dll-oracle/golden/nms.txt) ---

    /// Build a DohField with a planted response + sign maps (other planes zeroed) — mirrors the oracle
    /// harness's crafted field so `detect_peaks` can be compared to `detect_peaks_nms` output.
    fn crafted_field(w: usize, h: usize, peaks: &[(usize, usize, i32, i32, i32)]) -> super::super::field::DohField {
        let mut response = vec![0i32; w * h];
        let mut lxx = vec![0i32; w * h];
        let mut lyy = vec![0i32; w * h];
        for &(c, r, v, lx, ly) in peaks {
            let p = r * w + c;
            response[p] = v;
            lxx[p] = lx;
            lyy[p] = ly;
        }
        let zeros = vec![0i32; w * h];
        super::super::field::DohField {
            width: w,
            height: h,
            response,
            lxx,
            lyy,
            lxy: zeros.clone(),
            lx: zeros.clone(),
            ly: zeros,
        }
    }

    #[test]
    fn detect_peaks_matches_oracle_golden() {
        // Same field + real 0x2449 engine params as tools/qm-dll-oracle. Golden (golden/nms.txt):
        //   (5,4) R8000 -> score8000 class1 ; (10,7) R6000 -> class0 ; R5000 rejected ; (3,9) R7000 class1.
        let peaks = [
            (5usize, 4usize, 8000i32, -100i32, 50i32),
            (10, 7, 6000, -100, -5),
            (13, 3, 5000, -100, 50),
            (3, 9, 7000, 100, 0),
        ];
        let field = crafted_field(16, 12, &peaks);
        // Oracle section 5 uses margin=1 on this tiny field; real emit uses cfg.radius (=10).
        let mut p = NmsParams::dll(&CONFIG_2449);
        p.margin = 1;
        let got = detect_peaks(&field, &p);
        let got: Vec<(i32, i32, i32, u8)> = got.iter().map(|c| (c.x, c.y, c.score, c.class)).collect();
        assert_eq!(got, vec![(5, 4, 8000, 1), (10, 7, 6000, 0), (3, 9, 7000, 1)]);
    }

    #[test]
    fn refine_matches_oracle_golden() {
        // golden/nms.txt REFINE: peak (5,4)=8000, right=3000 left=500 down=2000 up=400.
        // solve -> (dx=13, dy=7); write-back nudge (dx>>7, dy>>7) = (0, 0) -> stays (5,4), angle 0.
        let (w, h) = (16usize, 12usize);
        let mut response = vec![0i32; w * h];
        for &(x, y, v) in &[(5, 4, 8000), (6, 4, 3000), (4, 4, 500), (5, 5, 2000), (5, 3, 400)] {
            response[y * w + x] = v;
        }
        let z = vec![0i32; w * h];
        let field = super::super::field::DohField {
            width: w,
            height: h,
            response,
            lxx: z.clone(),
            lyy: z.clone(),
            lxy: z.clone(),
            lx: z.clone(),
            ly: z,
        };
        let cand = vec![Candidate { x: 5, y: 4, score: 8000, class: 1, ..Default::default() }];
        let kept = refine_and_reject(&field, cand);
        assert_eq!(kept.len(), 1);
        assert_eq!((kept[0].x, kept[0].y, kept[0].angle), (5, 4, 0));
    }

    #[test]
    fn solve_2x2_matches_oracle_golden() {
        // golden/nms.txt SOLVE2X2 rows: solve_2x2(dxx, dxy, dyy, gx, gy).
        assert_eq!(solve_2x2(-0x8000, 0x1000, -0x6000, 0x400, -0x200), Some((-3, 2)));
        assert_eq!(solve_2x2(-0x4000, 0, -0x4000, 0x800, 0x300), Some((-16, -6)));
        assert_eq!(solve_2x2(0, 0, 0, 0x10, 0x10), None); // singular
        assert_eq!(solve_2x2(-0x10000, 0x2000, -0xc000, -0x1200, 0x900), Some((8, -4)));
    }

    #[test]
    fn border_reject_drops_edge_candidates() {
        let c = vec![
            Candidate { x: 1, y: 10, ..Default::default() },   // too close to left
            Candidate { x: 20, y: 10, ..Default::default() },  // interior — keep
            Candidate { x: 141, y: 10, ..Default::default() }, // too close to right (w=144)
        ];
        let kept = reject_border(c, 144, 56);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].x, 20);
    }
}
