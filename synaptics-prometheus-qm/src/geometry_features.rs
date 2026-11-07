//! The QM geometry-feature computation behind `syna_qm_compute_features@0x1800081f0` that
//! `work_record::fill_geometry_stubs` stands in for (gap #4). It turned out to be **fully portable from
//! static RE** — every leaf is context-free (arrays/scalars/records in → values out), so all of it is
//! ported bit-exact and oracle-validated with crafted inputs (`tools/qm-dll-oracle`, golden `geomfeat.txt`):
//!   - [`descriptor_match_loop`] (`@0x180004180`) — transform each neighbour, grid-look-up its gallery
//!     match, emit the per-neighbour descriptor-Hamming + orientation angle-delta byte streams;
//!   - [`descriptor_hamming`] (`@0x180003490`), [`angle_delta`] (`FUN_180003440`);
//!   - [`feature_mean_median`] (`@0x180003e50`), [`feature_avg_dist_dual`] (`@0x180004010`) +
//!     [`folded_hamming_accum`] (`@0x180003fc0`) — the mean/median/avg reductions of those streams.
//!
//! The assembly of these reductions into the work record is now RE-verified and wired in
//! [`crate::work_record`]: `neighbor_compare@0x180004380` (its `param_1` = workRec+0x68) writes
//! `feature_mean_median` → `+0x68`/`+0x6c` and `feature_avg_dist_dual` → `+0x98`/`+0x9c`/`+0xa0`.
//! What still needs a live match context / real golden is the spatial-coverage histogram
//! (`feature_coverage_histogram@0x180003b00` + `coverage_stamp@0x1800039b0` + the descriptor grid
//! from `descriptor_grid_init@0x180003a70`, → `+0x74..+0x84`) and the descriptor-match features that
//! `compute_features@0x1800081f0` writes (`+0x88`/`+0x8c`) — both left at the DLL's uncomputed sentinel.

use crate::consensus::apply_xform_q16;
use crate::detect::fixedtrig::atan2_q16rad;
use crate::types::SynaQmXformRecord;

/// Circular minimal angular distance on the 180° minutia-orientation scale, with `offset` applied to the
/// first angle. Bit-exact port of `FUN_180003440`: `x = (a+offset) mod 180`, `d = |x − b|`, → `min(d, 180−d)`.
pub fn angle_delta(a: u8, b: u8, offset: i32) -> i32 {
    let x = (a as i32 + offset) % 0xb4;
    let mut d = x - b as i32;
    if d < 1 {
        d = b as i32 - x;
    }
    let folded = 0xb4 - d;
    if d < folded {
        d
    } else {
        folded
    }
}

/// One accumulation step of `syna_qm_folded_hamming_accum@0x180003fc0`: fold `angle` to `[0,45]`
/// (`min(angle, 90−angle)`), add it to `sum1`, add `(folded·100/45 + 100)·weight` to `sum2`, bump `count`.
pub fn folded_hamming_accum(sum1: &mut i32, sum2: &mut i32, count: &mut i32, angle: u8, weight: u8) {
    let folded = (angle as i32).min(0x5a - angle as i32);
    *sum1 += folded;
    *sum2 += (folded * 100 / 0x2d + 100) * weight as i32;
    *count += 1;
}

/// Output of [`feature_mean_median`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeanMedian {
    /// Mean of all `data` bytes (`0x7fff` if empty).
    pub mean: i32,
    /// Mean of the `data` bytes whose matched index is class-0 (`0x7fff` if none). Only set when a
    /// class mask is supplied.
    pub class0_mean: i32,
    /// Count of class-0 entries.
    pub class0_count: i32,
    /// Median = `sorted[(n−1)/2]`. Only set when `want_median`.
    pub median: i32,
}

/// Bit-exact port of `syna_qm_feature_mean_median@0x180003e50` (with the optional pre-pass
/// `FUN_180003ce0` skipped — the DLL only runs it for a separate input path). Computes, over `data`:
/// the overall mean; the class-0-filtered mean (`indices[i]` — a **byte** matched-gallery index —
/// indexes `class_mask`; entries whose mask byte is `0` are class-0); and the median.
/// `indices`/`class_mask` may be empty to skip the class pass.
pub fn feature_mean_median(data: &[u8], indices: &[u8], class_mask: &[u8], want_median: bool) -> MeanMedian {
    let n = data.len() as i32;
    let mut mean: i32 = data.iter().map(|&b| b as i32).sum();

    let (mut class0_mean, mut class0_count) = (0i32, 0i32);
    if !class_mask.is_empty() {
        for (i, &b) in data.iter().enumerate() {
            let idx = indices.get(i).copied().unwrap_or(0);
            if class_mask.get(idx as usize).copied().unwrap_or(1) == 0 {
                class0_count += 1;
                class0_mean += b as i32;
            }
        }
        class0_mean = if class0_count < 1 { 0x7fff } else { class0_mean / class0_count };
    }

    let median = if want_median && !data.is_empty() {
        let mut sorted = data.to_vec();
        sorted.sort_unstable();
        sorted[((data.len() as i32 - 1) / 2) as usize] as i32
    } else {
        0
    };

    mean = if n < 1 { 0x7fff } else { mean / n };
    MeanMedian { mean, class0_mean, class0_count, median }
}

/// Output of [`feature_avg_dist_dual`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvgDistDual {
    /// `sum1 / n` — the averaged folded distance over all `n` entries (`0x7fff` if empty).
    pub avg_all: i32,
    /// `sum2 / (n·10)` — the class-0-weighted average (`0x7fff` if no class-0 entry).
    pub avg_class0: i32,
}

/// Bit-exact port of `syna_qm_feature_avg_dist_dual@0x180004010`: fold each of `n = angles.len()`
/// entries via [`folded_hamming_accum`] (class-0-filtered when a mask is given, `weights[i]` is the
/// per-entry class weight), then `avg_all = sum1/n`, `avg_class0 = sum2/(n·10)`.
pub fn feature_avg_dist_dual(angles: &[u8], weights: &[u8], indices: &[u8], class_mask: &[u8]) -> AvgDistDual {
    let n = angles.len() as i32;
    let (mut sum1, mut sum2, mut count) = (0i32, 0i32, 0i32);
    for (i, &a) in angles.iter().enumerate() {
        let w = weights.get(i).copied().unwrap_or(0);
        if class_mask.is_empty() {
            folded_hamming_accum(&mut sum1, &mut sum2, &mut count, a, w);
        } else {
            let idx = indices.get(i).copied().unwrap_or(0);
            if class_mask.get(idx as usize).copied().unwrap_or(1) == 0 {
                folded_hamming_accum(&mut sum1, &mut sum2, &mut count, a, w);
            }
        }
    }
    let avg_all = if n < 1 { 0x7fff } else { sum1 / n };
    // NB the DLL divides sum2 by n·10 (not count), and returns 0x7fff only when `count < 1`.
    let avg_class0 = if count < 1 { 0x7fff } else { sum2 / (n * 10) };
    AvgDistDual { avg_all, avg_class0 }
}

/// Hamming distance between two 8-byte binary descriptors — bit-exact port of
/// `syna_qm_descriptor_hamming_dist@0x180003490` (byteLen 8): `2 · Σ popcount(a[i] ^ b[i])`, range 0..128.
pub fn descriptor_hamming(a: &[u8; 8], b: &[u8; 8]) -> i32 {
    let pop: u32 = a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum();
    (pop as i32) * 2
}

/// One matched neighbour of `descriptor_match_loop`: the minutia's position, orientation and descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeighborMin {
    pub x: i32,
    pub y: i32,
    pub angle: u8,
    pub desc: [u8; 8],
}

/// The per-neighbour Hamming/angle-delta byte streams produced by [`descriptor_match_loop`], which the
/// [`feature_mean_median`] / [`feature_avg_dist_dual`] kernels then reduce.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatchLoopOut {
    /// Angle-delta byte per matched neighbour (`FUN_180003440` between the two orientations).
    pub angle_delta: Vec<u8>,
    /// Descriptor Hamming distance per matched neighbour.
    pub hamming: Vec<u8>,
    /// Source neighbour index per match.
    pub neighbor_idx: Vec<u8>,
    /// Matched gallery index per match.
    pub gallery_idx: Vec<u8>,
    /// Neighbours that landed on an occupied grid cell but the cell was `0xff` (no gallery entry).
    pub reject_count: i32,
}

/// Bit-exact port of `syna_qm_descriptor_match_loop@0x180004180`. Transforms each `neighbor` by `xform`,
/// looks up the landing grid cell (`grid[px + py·grid_w]`, a gallery index or `0xff`), and — when a
/// gallery match is found — emits its descriptor Hamming distance and orientation angle-delta (offset by
/// the transform's rotation, `atan2_q16rad(cos,sin)·180/2π`). Reads the ported `atan2_q16rad` /
/// `apply_xform_q16` / [`descriptor_hamming`] / [`angle_delta`] primitives — all context-free.
pub fn descriptor_match_loop(
    neighbors: &[NeighborMin],
    gallery: &[NeighborMin],
    xform: &SynaQmXformRecord,
    grid_w: u8,
    grid_h: u8,
    grid: &[u8],
) -> MatchLoopOut {
    let mut out = MatchLoopOut::default();
    // The transform's rotation in half-circle degrees: (atan2_q16rad(cos,sin) · 180) / 2π(=0x6487e).
    let rot = atan2_q16rad(xform.cos_q16, xform.sin_q16);
    let offset = (rot.wrapping_mul(0xb4)) / 0x6487e;
    for (i, nb) in neighbors.iter().enumerate() {
        let (px, py) = apply_xform_q16(nb.x, nb.y, xform);
        if px < 0 || px >= grid_w as i32 || py < 0 || py >= grid_h as i32 {
            continue;
        }
        let cell = grid[(px + py * grid_w as i32) as usize];
        if cell < 0xff {
            let g = &gallery[cell as usize];
            out.hamming.push(descriptor_hamming(&nb.desc, &g.desc) as u8);
            out.angle_delta.push(angle_delta(nb.angle, g.angle, offset) as u8);
            out.neighbor_idx.push(i as u8);
            out.gallery_idx.push(cell);
        } else {
            out.reject_count += 1;
        }
    }
    out
}

/// Bit-exact port of `syna_qm_coverage_stamp@0x1800039b0`: fill the box
/// `[max(0,x−r), min(w,x+r)) × [max(0,y−r), min(h,y+r))` of the `w×h` byte buffer `buf` with `value`,
/// where `(x, y) = positions[index]`. Linear index is `row·w + col` (row = y, col = x). Note the box is
/// half-open on the high side (width `2r`, not `2r+1`), matching the DLL's clamp-to-`w`/`h`.
pub fn coverage_stamp(buf: &mut [u8], w: u8, h: u8, positions: &[(i32, i32)], index: usize, radius: i32, value: u8) {
    let (x, y) = positions[index];
    let xlo = (x - radius).max(0);
    let ylo = (y - radius).max(0);
    let xhi = (x + radius).min(w as i32);
    let yhi = (y + radius).min(h as i32);
    let mut row = ylo;
    while row < yhi {
        let mut col = xlo;
        while col < xhi {
            buf[(row * w as i32 + col) as usize] = value;
            col += 1;
        }
        row += 1;
    }
}

/// Bit-exact port of `syna_qm_descriptor_grid_init@0x180003a70`: fill the `w×h` grid with `0xff`, then
/// stamp each minutia's index (`value = i`, radius 2) via [`coverage_stamp`]. Later minutiae overwrite
/// earlier ones in overlaps. The result is the position→minutia-index grid `descriptor_match_loop`
/// looks up (`0xff` = no minutia).
pub fn descriptor_grid_init(grid: &mut [u8], w: u8, h: u8, positions: &[(i32, i32)]) {
    grid[..(w as usize * h as usize)].fill(0xff);
    for i in 0..positions.len() {
        coverage_stamp(grid, w, h, positions, i, 2, i as u8);
    }
}

/// Output of [`feature_coverage_histogram`]: the coverage scalar (workRec `+0x70`) + the 5 rank buckets
/// (workRec `+0x74..+0x84`, score-feature indices 2/3/4/10/11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageHistogram {
    pub scalar: u32,
    pub buckets: [u32; 5],
}

/// Bit-exact port of `syna_qm_feature_coverage_histogram@0x180003b00`. Stamps each `(idx[i], val[i])`
/// into a fresh `w×h` coverage buffer (init `0x80`) via [`coverage_stamp`] radius 5, sorts it ascending,
/// then for each threshold in {0x11,0x21,0x31,0x41,0x51} records the sorted position where it falls
/// between consecutive coverage values (a rank/CDF). `uVar7` = index of the highest non-`0x80` cell
/// (= stamped-cell count − 1); buckets init to it, get refined downward, then non-monotone buckets are
/// zeroed; `scalar = buckets[3]`. Reproduces the DLL's off-by-one (the last stamped cell is never
/// examined, so a threshold above every coverage value keeps its init value).
pub fn feature_coverage_histogram(
    w: u8,
    h: u8,
    positions: &[(i32, i32)],
    idx: &[u8],
    val: &[u8],
) -> CoverageHistogram {
    const BOUNDS: [i32; 5] = [0x11, 0x21, 0x31, 0x41, 0x51];
    let n = w as usize * h as usize;
    let mut scratch = vec![0x80u8; n];
    for (i, &mi) in idx.iter().enumerate() {
        coverage_stamp(&mut scratch, w, h, positions, mi as usize, 5, val[i]);
    }
    scratch.sort_unstable();

    // uVar7: scan down from n-2 for the highest non-0x80 cell; −1 (0xffffffff) if none / n==1.
    let mut u: i64 = n as i64 - 1;
    let uvar7: i64 = if u != 0 {
        let mut p = u;
        let mut found = -1i64;
        loop {
            p -= 1;
            u -= 1;
            if scratch[p as usize] != 0x80 {
                found = u;
                break;
            }
            if u == 0 {
                break;
            }
        }
        found
    } else {
        -1
    };

    let mut buckets = [uvar7 as u32; 5];
    if uvar7 > 1 {
        let mut pos: u32 = 1;
        let mut k: usize = 0;
        loop {
            for (j, &b) in BOUNDS.iter().enumerate() {
                if (scratch[k] as i32) <= b && b < (scratch[k + 1] as i32) {
                    buckets[j] = pos;
                }
            }
            pos += 1;
            k += 1;
            if (pos as i64) >= uvar7 {
                break;
            }
        }
    }
    for i in 0..4 {
        if (buckets[i + 1] as i32) < (buckets[i] as i32) {
            buckets[i] = 0;
        }
    }
    let scalar = if uvar7 == 0 { 0 } else { buckets[3] };
    CoverageHistogram { scalar, buckets }
}

/// The neighbour-compare tail record (workRec `+0x68..+0xa0`), i.e. every score feature
/// `syna_qm_minutia_neighbor_compare@0x180004380` produces. Oracle-confirmed that `compute_features`
/// does NOT touch these — it feeds the consensus path — so this record IS the geometry-feature set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompareRecord {
    pub hamming_mean: i32,        // +0x68 (feat 13)
    pub hamming_median: i32,      // +0x6c (feat 9)
    pub coverage_scalar: u32,     // +0x70 (not a feature)
    pub coverage_buckets: [u32; 5], // +0x74..+0x84 (feats 2,3,4,10,11)
    pub match_count: i32,         // +0x88 (feat 14) — descriptor_match_loop match count
    pub reject_count: i32,        // +0x8c (feat 7) — descriptor_match_loop reject count
    pub angle_avg_all: i32,       // +0x98 (feat 0)
    pub angle_avg_class0: i32,    // +0x9c (feat 1)
    pub angle_count: i32,         // +0xa0 (not a feature; propagated to +0xac)
}

impl CompareRecord {
    /// The record when `descriptor_match_loop` finds no gallery match (`count == 0`): the DLL's inner
    /// gate `*piVar1 != 0` (`0x180004480`) skips the three feature kernels, leaving those slots at the
    /// `init_work_record` (`0x1800078d0`) defaults (`0x7fff` sentinels on `+0x68/+0x6c/+0x70/+0x84/+0x98/+0x9c`,
    /// `0` on `+0x74..+0x80`).
    fn empty(reject: i32) -> Self {
        CompareRecord {
            hamming_mean: 0x7fff,
            hamming_median: 0x7fff,
            coverage_scalar: 0x7fff,
            coverage_buckets: [0, 0, 0, 0, 0x7fff],
            match_count: 0,
            reject_count: reject,
            angle_avg_all: 0x7fff,
            angle_avg_class0: 0x7fff,
            angle_count: 0,
        }
    }
}

/// Bit-exact port of `syna_qm_minutia_neighbor_compare@0x180004380` (its `param_1` = workRec+0x68):
/// build the position→index grid from `gallery` ([`descriptor_grid_init`]), match the `xform`-ed
/// `probe` neighbours against it ([`descriptor_match_loop`]), then reduce the resulting streams:
///   - [`feature_mean_median`] over the **Hamming** stream → `hamming_mean`/`hamming_median`;
///   - [`feature_avg_dist_dual`] over the **angle-delta** stream weighted by the **Hamming** stream →
///     `angle_avg_all`/`angle_avg_class0`/`angle_count`;
///   - [`feature_coverage_histogram`] over the **gallery** positions, indexed by the matched gallery
///     index with the Hamming value → the coverage scalar + 5 rank buckets;
///   - the match/reject counts → `match_count`/`reject_count`.
///
/// Oracle-validated end-to-end (NCOMPARE golden). NB: the three kernels run only when ≥1 gallery match.
pub fn neighbor_compare(
    probe: &[NeighborMin],
    gallery: &[NeighborMin],
    xform: &SynaQmXformRecord,
    w: u8,
    h: u8,
) -> CompareRecord {
    let gallery_pos: Vec<(i32, i32)> = gallery.iter().map(|g| (g.x, g.y)).collect();
    let mut grid = vec![0u8; w as usize * h as usize];
    descriptor_grid_init(&mut grid, w, h, &gallery_pos);
    neighbor_compare_with_grid(probe, gallery, xform, w, h, &grid, &gallery_pos)
}

/// [`neighbor_compare`] with a precomputed descriptor grid (gallery TemplateCache).
pub fn neighbor_compare_with_grid(
    probe: &[NeighborMin],
    gallery: &[NeighborMin],
    xform: &SynaQmXformRecord,
    w: u8,
    h: u8,
    grid: &[u8],
    gallery_pos: &[(i32, i32)],
) -> CompareRecord {
    let ml = descriptor_match_loop(probe, gallery, xform, w, h, grid);
    let count = ml.hamming.len() as i32;
    if count == 0 {
        return CompareRecord::empty(ml.reject_count);
    }
    let mm = feature_mean_median(&ml.hamming, &[], &[], true);
    let avg = feature_avg_dist_dual(&ml.angle_delta, &ml.hamming, &[], &[]);
    let cov = feature_coverage_histogram(w, h, gallery_pos, &ml.gallery_idx, &ml.hamming);
    CompareRecord {
        hamming_mean: mm.mean,
        hamming_median: mm.median,
        coverage_scalar: cov.scalar,
        coverage_buckets: cov.buckets,
        match_count: count,
        reject_count: ml.reject_count,
        angle_avg_all: avg.avg_all,
        angle_avg_class0: avg.avg_class0,
        angle_count: count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn angle_delta_matches_oracle_golden() {
        // ANGDELTA (tools/qm-dll-oracle/golden/geomfeat.txt).
        for &(a, b, off, want) in &[
            (30u8, 170u8, 0i32, 40i32), (10, 20, 0, 10), (0, 90, 0, 90), (179, 1, 0, 2),
            (45, 45, 0, 0), (100, 10, 30, 60), (80, 175, 15, 80),
        ] {
            assert_eq!(angle_delta(a, b, off), want, "angle_delta({a},{b},{off})");
        }
    }

    #[test]
    fn folded_hamming_accum_matches_oracle_golden() {
        // FOLDACC — each from a fresh accumulator.
        for &(ang, w, s1, s2, cnt) in &[
            (30u8, 2u8, 30i32, 332i32, 1i32), (60, 1, 30, 166, 1), (45, 3, 45, 600, 1),
            (10, 5, 10, 610, 1), (0, 1, 0, 100, 1), (90, 4, 0, 400, 1), (23, 7, 23, 1057, 1),
        ] {
            let (mut a, mut b, mut c) = (0, 0, 0);
            folded_hamming_accum(&mut a, &mut b, &mut c, ang, w);
            assert_eq!((a, b, c), (s1, s2, cnt), "folded_hamming_accum({ang},{w})");
        }
    }

    #[test]
    fn feature_mean_median_matches_oracle_golden() {
        // MEANMED: data + byte idx + class mask → mean/median/class0-mean/class0-count.
        let r = feature_mean_median(&[5, 10, 3, 20, 8], &[0, 1, 2, 3, 4], &[0, 1, 0, 1, 0], true);
        assert_eq!((r.mean, r.median, r.class0_mean, r.class0_count), (9, 8, 5, 3));
    }

    #[test]
    fn avg_dist_dual_composes_validated_accum() {
        // feature_avg_dist_dual is a thin loop over the (oracle-validated) folded_hamming_accum: with no
        // mask, avg_all = Σfold/n and avg_class0 = Σweighted/(n·10). Cross-checked by hand from FOLDACC.
        let r = feature_avg_dist_dual(&[30, 60], &[2, 1], &[], &[]);
        // fold(30)=30, fold(60)=30 → Σ=60, n=2 → avg_all=30. Σweighted=332+166=498, /(2·10)=24.
        assert_eq!((r.avg_all, r.avg_class0), (30, 24));
    }

    #[test]
    fn descriptor_hamming_matches() {
        assert_eq!(descriptor_hamming(&[0xA0; 8], &[0xAA; 8]), 32);
        assert_eq!(descriptor_hamming(&[0xFF; 8], &[0x00; 8]), 128); // all 64 bits differ
        assert_eq!(descriptor_hamming(&[0x12; 8], &[0x12; 8]), 0);
    }

    #[test]
    fn coverage_stamp_matches_oracle_golden() {
        // COVSTAMP idx=1 r=2 v=7 (geomfeat.txt): minutia 1 at (5,5), 8×8 grid init 0.
        let pos = [(2, 2), (5, 5), (1, 6), (6, 1), (4, 4)];
        let mut grid = vec![0u8; 64];
        coverage_stamp(&mut grid, 8, 8, &pos, 1, 2, 7);
        let set: Vec<usize> = grid.iter().enumerate().filter(|&(_, &v)| v != 0).map(|(i, _)| i).collect();
        assert_eq!(
            set,
            vec![27, 28, 29, 30, 35, 36, 37, 38, 43, 44, 45, 46, 51, 52, 53, 54]
        );
        assert!(grid.iter().all(|&v| v == 0 || v == 7));
    }

    #[test]
    fn descriptor_grid_init_matches_oracle_golden() {
        // GRIDINIT (geomfeat.txt): 5 minutiae, radius 2, 8×8, later stamps overwrite earlier.
        let pos = [(2, 2), (5, 5), (1, 6), (6, 1), (4, 4)];
        let mut grid = vec![0u8; 64];
        descriptor_grid_init(&mut grid, 8, 8, &pos);
        let mut expected = [0xffu8; 64];
        for &(i, v) in &[
            (0, 0), (1, 0), (2, 0), (3, 0), (4, 3), (5, 3), (6, 3), (7, 3), (8, 0), (9, 0), (10, 0),
            (11, 0), (12, 3), (13, 3), (14, 3), (15, 3), (16, 0), (17, 0), (18, 4), (19, 4), (20, 4),
            (21, 4), (22, 3), (23, 3), (24, 0), (25, 0), (26, 4), (27, 4), (28, 4), (29, 4), (30, 1),
            (32, 2), (33, 2), (34, 4), (35, 4), (36, 4), (37, 4), (38, 1), (40, 2), (41, 2), (42, 4),
            (43, 4), (44, 4), (45, 4), (46, 1), (48, 2), (49, 2), (50, 2), (51, 1), (52, 1), (53, 1),
            (54, 1), (56, 2), (57, 2), (58, 2),
        ] {
            expected[i as usize] = v;
        }
        assert_eq!(grid, expected.to_vec());
    }

    #[test]
    fn feature_coverage_histogram_matches_oracle_golden() {
        // COVHIST (geomfeat.txt): 20×20 grid, minutiae spread apart, coverage values {10,30,50,70,20}.
        let pos = [(3, 3), (16, 3), (3, 16), (16, 16), (10, 10)];
        let out = feature_coverage_histogram(20, 20, &pos, &[0, 1, 2, 3, 4], &[10, 30, 50, 70, 20]);
        assert_eq!(out.scalar, 275);
        assert_eq!(out.buckets, [55, 215, 215, 275, 339]);
    }

    #[test]
    fn neighbor_compare_matches_oracle_golden() {
        // NCOMPARE (geomfeat.txt): 20×20, identity xform. probe {(5,5,90,0xA0),(15,15,45,0x50),
        // (6,6,10,0x10)} vs gallery {(5,5,100,0xAA),(15,15,40,0x55)}. p0→g0, p1→g1, p2→g0 (r2 stamp).
        let nb = |x, y, ang, d: u8| NeighborMin { x, y, angle: ang, desc: [d; 8] };
        let probe = [nb(5, 5, 90, 0xA0), nb(15, 15, 45, 0x50), nb(6, 6, 10, 0x10)];
        let gallery = [nb(5, 5, 100, 0xAA), nb(15, 15, 40, 0x55)];
        let xf = SynaQmXformRecord { cos_q16: 0x10000, sin_q16: 0, tx: 0, ty: 0, valid_flag: 1 };
        let r = neighbor_compare(&probe, &gallery, &xf, 20, 20);
        assert_eq!(r.hamming_mean, 48);
        assert_eq!(r.hamming_median, 32);
        assert_eq!(r.coverage_scalar, 100);
        assert_eq!(r.coverage_buckets, [0, 100, 100, 100, 199]);
        assert_eq!(r.match_count, 3);
        assert_eq!(r.reject_count, 0);
        assert_eq!(r.angle_avg_all, 5);
        assert_eq!(r.angle_avg_class0, 515);
        assert_eq!(r.angle_count, 3);
    }

    #[test]
    fn descriptor_match_loop_matches_oracle_golden() {
        // MATCHLOOP: identity transform, a 8×8 grid mapping two cells to gallery entries, one miss.
        let nb = |x, y, ang, d: u8| NeighborMin { x, y, angle: ang, desc: [d; 8] };
        let neighbors = [nb(3, 2, 90, 0xA0), nb(5, 4, 45, 0x50), nb(7, 7, 10, 0x10)];
        let gallery = [nb(0, 0, 100, 0xAA), nb(0, 0, 40, 0x55)];
        let mut grid = vec![0xffu8; 64];
        grid[3 + 2 * 8] = 0; // neighbour 0 → gallery 0
        grid[5 + 4 * 8] = 1; // neighbour 1 → gallery 1
        let xf = crate::types::SynaQmXformRecord { cos_q16: 0x10000, sin_q16: 0, tx: 0, ty: 0, valid_flag: 1 };
        let out = descriptor_match_loop(&neighbors, &gallery, &xf, 8, 8, &grid);
        assert_eq!(out.reject_count, 1);
        assert_eq!(out.hamming, vec![32, 32]);
        assert_eq!(out.angle_delta, vec![10, 5]);
        assert_eq!(out.neighbor_idx, vec![0, 1]);
        assert_eq!(out.gallery_idx, vec![0, 1]);
    }
}
