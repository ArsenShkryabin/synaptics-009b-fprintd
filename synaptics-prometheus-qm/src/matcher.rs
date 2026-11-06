//! Top-level template-pair → score path — ports `syna_qm_match_core@0x180100620` static stages.
//!
//! Pipeline: per-minutia local neighborhoods → descriptor pairing → Q16 similarity fit →
//! geometric consensus → 17×2 feature vector → z-norm MLP → 0..3000 score.

use crate::consensus::{geometric_consensus_pick_gated, Consensus, VoteGate};
use crate::descriptor::{angle_diff_mod180, hamming, NeighborCandidate};
use crate::geometry_features::{neighbor_compare_with_grid, CompareRecord, NeighborMin};
use crate::neighbor::{build_neighbor_candidates, MinutiaNeighbors};
use crate::scorer::score_feature_vector;
use crate::similarity::{minutia_pair_matcher, SimilarityQ16};
use crate::template::{Minutia, Template};
use crate::template_cache::{
    prepare_probe_neighbor_mins, prepare_probe_neighbors, PreparedView,
};
use crate::types::{
    DISTANCE_RANGE_COUNT_MIN, DISTANCE_RANGE_DIST_MAX, FEATURE_SENTINEL, FEATURE_WORKREC_OFFSETS,
    MIN_MATCHED_NEIGHBORS, MIN_PROBE_MINUTIAE, MINUTIA_STRONG_SCORE, MatchLevel, NEIGHBOR_REJECT_DIST,
    SCORE_ANCHOR_MINUTIAE, SCORE_FEATURE_VECTOR_LEN, SCORE_FEATURES_PER_MINUTIA, SynaQmXformRecord,
    XFORM_FIXED_ONE,
};
use crate::work_record::WorkRecord;

/// Default conditioned-image dimensions for subtype `0x2449` (144×56).
pub const DEFAULT_IMAGE_W: i32 = crate::template::DEFAULT_TEMPLATE_IMAGE_W as i32;
/// See [`DEFAULT_IMAGE_W`].
pub const DEFAULT_IMAGE_H: i32 = crate::template::DEFAULT_TEMPLATE_IMAGE_H as i32;

/// Per-minutia match diagnostics for UI / debug overlays.
#[derive(Debug, Clone)]
pub struct AnchorDiagnostic {
    pub probe_index: usize,
    pub gallery_index: usize,
    pub probe_x: u8,
    pub probe_y: u8,
    pub gallery_x: u8,
    pub gallery_y: u8,
    pub avg_hamming: i32,
    pub match_count: i32,
    pub transform: SimilarityQ16,
    pub is_anchor: bool,
    pub strong: bool,
    pub top_candidates: Vec<NeighborCandidate>,
}

/// Full matcher output for score + feature / correspondence visualization.
#[derive(Debug, Clone)]
pub struct MatchDiagnostics {
    pub score: u32,
    pub threshold: u32,
    pub decision: bool,
    pub consensus: Consensus,
    pub anchor_count: usize,
    /// Top two scoring anchor probe indices (by match_count, then avg_hamming).
    pub top_anchor_probe_indices: [Option<usize>; 2],
    pub anchors: Vec<AnchorDiagnostic>,
    pub features: [i32; SCORE_FEATURE_VECTOR_LEN],
    /// Neighbor correspondences for the best anchor (for vector overlays).
    pub best_anchor_candidates: Vec<NeighborCandidate>,
}

impl MatchDiagnostics {
    /// Compact [`MatchResult`] view of this diagnostic run.
    pub fn as_result(&self) -> MatchResult {
        MatchResult {
            tmpl_index: 0,
            score: self.score,
            decision: self.decision,
            consensus: self.consensus,
            threshold_used: self.threshold,
            anchor_count: self.anchor_count,
        }
    }
}

/// Spatial inlier threshold squared — `syna_qm_minutia_pair_matcher` param_8 (= 8).
const PAIR_MATCHER_DIST2: i32 = 8;

/// Result of a template-pair match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchResult {
    pub tmpl_index: u32,
    pub score: u32,
    pub decision: bool,
    pub consensus: Consensus,
    pub threshold_used: u32,
    pub anchor_count: usize,
}

struct AnchorStats {
    avg_dist: i32,
    match_count: i32,
    xf: SimilarityQ16,
    is_anchor: bool,
    strong: bool,
    /// The bit-exact neighbour-compare tail (workRec +0x68..+0xa0); `None` on reject.
    compare: Option<CompareRecord>,
}

fn find_best_gallery(probe: &Minutia, gallery: &[Minutia]) -> usize {
    gallery
        .iter()
        .enumerate()
        .min_by_key(|(_, g)| hamming(&probe.descriptor, &g.descriptor))
        .map(|(i, _)| i)
        .unwrap_or(0)
}

/// `syna_qm_is_empty_match@0x18000b370` — identity Q16 transform means the entry was never filled.
fn is_empty_match(xf: &SimilarityQ16) -> bool {
    xf.cos == XFORM_FIXED_ONE && xf.sin == 0 && xf.tx == 0 && xf.ty == 0
}

/// `syna_qm_check_distance_range@0x18000b320`.
fn check_distance_range(count: u8, dist: u8) -> bool {
    count > DISTANCE_RANGE_COUNT_MIN && dist < DISTANCE_RANGE_DIST_MAX
}

/// `syna_qm_find_valid_match@0x180007a10` stand-in via compare-tail fields
/// (`compute_features` uses the same predicate on work`+0x88`/`+0x68`).
fn find_valid_match(stats: &[AnchorStats]) -> bool {
    stats.iter().any(|s| {
        s.compare
            .as_ref()
            .is_some_and(|c| check_distance_range(c.match_count as u8, c.hamming_mean as u8))
    })
}

struct NeighborMatch {
    xf: SimilarityQ16,
    avg: i32,
    match_count: i32,
    cands: Vec<NeighborCandidate>,
    rejected: bool,
    compare: Option<CompareRecord>,
}

fn reject(match_count: i32, cands: Vec<NeighborCandidate>) -> NeighborMatch {
    NeighborMatch {
        xf: SimilarityQ16 {
            cos: XFORM_FIXED_ONE,
            sin: 0,
            tx: 0,
            ty: 0,
        },
        avg: NEIGHBOR_REJECT_DIST as i32,
        match_count,
        cands,
        rejected: true,
        compare: None,
    }
}

#[allow(clippy::too_many_arguments)] // one hot inner-loop call; each arg is a distinct matcher input
fn minutia_neighbor_match_prepared(
    probe: &[Minutia],
    gallery: &[Minutia],
    probe_ctx: &MinutiaNeighbors,
    gallery_ctx: &MinutiaNeighbors,
    probe_mins: &[NeighborMin],
    gallery_mins: &[NeighborMin],
    gallery_grid: &[u8],
    w: i32,
    h: i32,
) -> NeighborMatch {
    let mut cands = build_neighbor_candidates(probe_ctx, gallery_ctx, probe, gallery);
    cands.sort_by_key(|c| c.hamming_dist);
    let keep = cands.len().min(0x19);
    cands.truncate(keep);
    let cand_count = keep;
    if cand_count < MIN_MATCHED_NEIGHBORS as usize {
        return reject(0, cands);
    }
    let probe_xy: Vec<[i32; 2]> = cands.iter().map(|c| [c.probe_x, c.probe_y]).collect();
    let gallery_xy: Vec<[i32; 2]> = cands.iter().map(|c| [c.gallery_x, c.gallery_y]).collect();
    let angle_diff: Vec<i32> = cands
        .iter()
        .map(|c| angle_diff_mod180(c.probe_angle as u8, c.gallery_angle as u8))
        .collect();
    let (xf_opt, inliers) =
        minutia_pair_matcher(&probe_xy, &gallery_xy, &angle_diff, PAIR_MATCHER_DIST2);
    let inlier_count = inliers.len() as i32;
    let (Some(xf), true) = (xf_opt, inlier_count >= MIN_MATCHED_NEIGHBORS) else {
        return reject(inlier_count, cands);
    };
    let match_count = inlier_count;
    let sum: i32 = inliers.iter().map(|&k| cands[k].hamming_dist).sum();
    let avg = sum / match_count;
    let gallery_pos: Vec<(i32, i32)> = gallery_mins.iter().map(|m| (m.x, m.y)).collect();
    let compare = neighbor_compare_with_grid(
        probe_mins,
        gallery_mins,
        &xf.to_xform_record(1),
        w as u8,
        h as u8,
        gallery_grid,
        &gallery_pos,
    );
    NeighborMatch {
        xf,
        avg,
        match_count,
        cands,
        rejected: false,
        compare: Some(compare),
    }
}

fn build_work_record(stats: &AnchorStats, cands: &[NeighborCandidate], rejected: bool) -> WorkRecord {
    let mut wr = WorkRecord::new();
    wr.apply_neighbor_match(
        &stats.xf,
        stats.avg_dist,
        stats.match_count,
        cands.len() as i32,
        rejected,
    );
    if let Some(cr) = &stats.compare {
        wr.apply_neighbor_compare(cr);
        wr.apply_kernel_propagation();
    }
    wr
}

fn compute_feature_vector(work_records: &[&WorkRecord]) -> [i32; SCORE_FEATURE_VECTOR_LEN] {
    let mut feats = [FEATURE_SENTINEL; SCORE_FEATURE_VECTOR_LEN];
    for (slot, wr) in work_records.iter().enumerate().take(SCORE_ANCHOR_MINUTIAE) {
        let per = wr.score_features();
        let base = slot * SCORE_FEATURES_PER_MINUTIA;
        for (i, &off) in FEATURE_WORKREC_OFFSETS.iter().enumerate() {
            feats[base + i] = per[i];
            let _ = off;
        }
    }
    feats
}

/// Too-weak gate inside `syna_qm_score_features@0x1800088d0`: all `match_count` ≤ 3 → score 0.
fn all_match_counts_weak(stats: &[AnchorStats]) -> bool {
    !stats.is_empty() && stats.iter().all(|s| s.match_count <= 3)
}

/// Anchor ranking inside `syna_qm_score_features@0x1800088d0` (`qsort` comparator `@0x1800088a0`):
/// primary key is `work[+0x68]` (`compare.hamming_mean`, ascending; `0x7fff` sentinel when empty),
/// secondary key is `work[+0x60]` (`match_count`, descending).
fn sort_anchor_order(stats: &[AnchorStats]) -> Vec<usize> {
    let hamming_mean = |s: &AnchorStats| s.compare.as_ref().map_or(0x7fff, |c| c.hamming_mean);
    let mut order: Vec<usize> = stats
        .iter()
        .enumerate()
        .filter(|(_, s)| s.is_anchor)
        .map(|(i, _)| i)
        .collect();
    order.sort_by(|&a, &b| {
        hamming_mean(&stats[a])
            .cmp(&hamming_mean(&stats[b]))
            .then(stats[b].match_count.cmp(&stats[a].match_count))
            .then(stats[a].avg_dist.cmp(&stats[b].avg_dist))
    });
    order
}

fn empty_diagnostics(threshold: u32) -> MatchDiagnostics {
    MatchDiagnostics {
        score: 0,
        threshold,
        decision: false,
        consensus: Consensus {
            found: false,
            occupied: 0,
            peak: 0,
        },
        anchor_count: 0,
        top_anchor_probe_indices: [None, None],
        anchors: Vec::new(),
        features: [FEATURE_SENTINEL; SCORE_FEATURE_VECTOR_LEN],
        best_anchor_candidates: Vec::new(),
    }
}

/// Score a probe against a gallery template.
pub fn score(probe: &Template, gallery: &Template, level: MatchLevel) -> MatchResult {
    diagnose(probe, gallery, level, DEFAULT_IMAGE_W, DEFAULT_IMAGE_H).as_result()
}

/// Same-view redundancy scorer for enrollment — ValidFlag-gated consensus (see module history).
pub fn score_redundancy(probe: &Template, gallery: &Template, level: MatchLevel) -> MatchResult {
    diagnose_gated(probe, gallery, level, DEFAULT_IMAGE_W, DEFAULT_IMAGE_H, VoteGate::ValidFlag)
        .as_result()
}

/// [`score`] with explicit conditioned-image dimensions for the consensus vote grid.
pub fn score_with_dims(
    probe: &Template,
    gallery: &Template,
    level: MatchLevel,
    w: i32,
    h: i32,
) -> MatchResult {
    diagnose(probe, gallery, level, w, h).as_result()
}

/// Full match diagnostics (DLL-faithful `Translation` vote gate).
pub fn diagnose(
    probe: &Template,
    gallery: &Template,
    level: MatchLevel,
    w: i32,
    h: i32,
) -> MatchDiagnostics {
    diagnose_gated(probe, gallery, level, w, h, VoteGate::ValidFlag)
}

/// [`diagnose`] against a [`PreparedView`] (gallery neighbor lists + grids already built).
pub fn diagnose_prepared(
    probe: &Template,
    gallery: &PreparedView,
    level: MatchLevel,
    w: i32,
    h: i32,
) -> MatchDiagnostics {
    diagnose_prepared_gated(probe, gallery, level, w, h, VoteGate::ValidFlag)
}

/// [`diagnose`] with the consensus vote gate selectable.
pub fn diagnose_gated(
    probe: &Template,
    gallery: &Template,
    level: MatchLevel,
    w: i32,
    h: i32,
    gate: VoteGate,
) -> MatchDiagnostics {
    let prepared = PreparedView::from_template(gallery.clone());
    diagnose_prepared_gated(probe, &prepared, level, w, h, gate)
}

/// Core diagnose against a prepared gallery view.
pub fn diagnose_prepared_gated(
    probe: &Template,
    gallery: &PreparedView,
    level: MatchLevel,
    w: i32,
    h: i32,
    gate: VoteGate,
) -> MatchDiagnostics {
    let threshold = level.threshold();
    if (probe.minutiae.len() as i32) < MIN_PROBE_MINUTIAE {
        return empty_diagnostics(threshold);
    }

    let probe_neighbors = prepare_probe_neighbors(probe);
    let probe_mins = prepare_probe_neighbor_mins(probe, &probe_neighbors);
    let gallery_mins_all = &gallery.template.minutiae;

    let mut stats_vec: Vec<AnchorStats> = Vec::with_capacity(probe.minutiae.len());
    let mut work_records = Vec::with_capacity(probe.minutiae.len());
    let mut per_minutia_cands: Vec<Vec<NeighborCandidate>> =
        Vec::with_capacity(probe.minutiae.len());
    let mut best_gallery = Vec::with_capacity(probe.minutiae.len());
    // syna_qm_minutiae_match_kernel: best_anchor when work+0x38 > 0x7c4.
    let mut best_anchor: Option<usize> = None;

    for (pi, p) in probe.minutiae.iter().enumerate() {
        // Kernel skip: once a strong anchor exists, skip already-filled match entries
        // (`is_empty_match@0x18000b370`). Single forward pass is a no-op for prior slots;
        // retained for gate fidelity.
        if best_anchor.is_some() && pi < stats_vec.len() && !is_empty_match(&stats_vec[pi].xf) {
            continue;
        }

        let gi = find_best_gallery(p, gallery_mins_all);
        best_gallery.push(gi);
        let g_ctx = &gallery.neighbors[gi];
        let g_mins = &gallery.neighbor_mins[gi];
        let g_grid = gallery.descriptor_grid(gi, w as u8, h as u8);
        let nm = minutia_neighbor_match_prepared(
            &probe.minutiae,
            gallery_mins_all,
            &probe_neighbors[pi],
            g_ctx,
            &probe_mins[pi],
            g_mins,
            &g_grid,
            w,
            h,
        );
        let is_anchor = nm.match_count >= MIN_MATCHED_NEIGHBORS;
        let st = AnchorStats {
            avg_dist: nm.avg,
            match_count: nm.match_count,
            xf: nm.xf,
            is_anchor,
            strong: false,
            compare: nm.compare,
        };
        work_records.push(build_work_record(&st, &nm.cands, nm.rejected));
        stats_vec.push(st);
        per_minutia_cands.push(nm.cands);

        // Incremental score_features: DLL re-scores after every minutia; we only pay the MLP when
        // a new anchor appears (rejects cannot raise the score above 1988).
        if is_anchor && !all_match_counts_weak(&stats_vec) {
            let order = sort_anchor_order(&stats_vec);
            let wrs: Vec<&WorkRecord> = order.iter().map(|&i| &work_records[i]).collect();
            let feats = compute_feature_vector(&wrs);
            let sc = score_feature_vector(&feats).max(0) as u32;
            if sc > MINUTIA_STRONG_SCORE {
                best_anchor = Some(pi);
                if let Some(s) = stats_vec.last_mut() {
                    s.strong = true;
                }
            }
        }
    }

    let (feats, score) = if all_match_counts_weak(&stats_vec) {
        ([FEATURE_SENTINEL; SCORE_FEATURE_VECTOR_LEN], 0u32)
    } else {
        let anchor_order = sort_anchor_order(&stats_vec);
        let anchor_wrs: Vec<&WorkRecord> =
            anchor_order.iter().map(|&i| &work_records[i]).collect();
        let feats = compute_feature_vector(&anchor_wrs);
        let score = score_feature_vector(&feats).max(0) as u32;
        if score > MINUTIA_STRONG_SCORE {
            if best_anchor.is_none() {
                best_anchor = anchor_order.first().copied();
            }
            for s in &mut stats_vec {
                if s.is_anchor {
                    s.strong = true;
                }
            }
        }
        (feats, score)
    };

    // Consensus only if strong anchor ∧ find_valid_match (kernel@0x180008e60).
    let consensus = if best_anchor.is_some() && find_valid_match(&stats_vec) {
        let xforms: Vec<SynaQmXformRecord> = stats_vec
            .iter()
            .filter(|s| s.is_anchor)
            .map(|s| s.xf.to_xform_record(1))
            .collect();
        geometric_consensus_pick_gated(&xforms, w, h, gate)
    } else {
        Consensus {
            found: false,
            occupied: 0,
            peak: 0,
        }
    };

    let anchor_order = sort_anchor_order(&stats_vec);
    // Exact decision rule in `syna_qm_match_core@0x180100620` (`0x1801015a2`:
    // `cmp DWORD PTR [rax+0x4], ecx; jbe ...; mov DWORD PTR [rax+0x8], 1`).
    // `consensus.found` sets `result->strong_flag` (`+0x0c`, `0x1801014dc`), not `decision`.
    let decision = score > threshold;

    let mut diag_anchors = Vec::with_capacity(probe.minutiae.len());
    for (pi, p) in probe.minutiae.iter().enumerate() {
        let gi = best_gallery[pi];
        let g = &gallery.template.minutiae[gi];
        let st = &stats_vec[pi];
        let cands = &per_minutia_cands[pi];
        diag_anchors.push(AnchorDiagnostic {
            probe_index: pi,
            gallery_index: gi,
            probe_x: p.x,
            probe_y: p.y,
            gallery_x: g.x,
            gallery_y: g.y,
            avg_hamming: st.avg_dist,
            match_count: st.match_count,
            transform: st.xf,
            is_anchor: st.is_anchor,
            strong: st.strong,
            top_candidates: cands.iter().take(10).cloned().collect(),
        });
    }

    let top_anchor_probe_indices = [
        anchor_order.first().copied(),
        anchor_order.get(1).copied(),
    ];
    let best_anchor_candidates = anchor_order
        .first()
        .map(|&i| per_minutia_cands[i].iter().take(10).cloned().collect())
        .unwrap_or_default();

    MatchDiagnostics {
        score,
        threshold,
        decision,
        consensus,
        anchor_count: anchor_order.len(),
        top_anchor_probe_indices,
        anchors: diag_anchors,
        features: feats,
        best_anchor_candidates,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpl(minutiae: Vec<Minutia>) -> Template {
        Template {
            descriptor: [0; 8],
            split: minutiae.len() as u8,
            field_0c: 0,
            minutiae,
        }
    }

    fn m(desc: [u8; 8], x: u8, y: u8) -> Minutia {
        Minutia {
            descriptor: desc,
            x,
            y,
            angle_deg: 0,
        }
    }

    #[test]
    fn identical_templates_score_and_decide() {
        let mins: Vec<Minutia> = (0..12)
            .map(|i| {
                m(
                    [i as u8, 0x5a, 0x11, 0x22, 0x33, 0x44, 0x55, i as u8],
                    (i * 10) as u8,
                    (i * 5) as u8,
                )
            })
            .collect();
        let t = tmpl(mins);
        // Translated re-capture (+3,0) — a non-degenerate match (exact self-match has zero
        // per-correspondence displacement → no transform fit → 0 anchors).
        let mut ts = t.clone();
        for mm in &mut ts.minutiae {
            mm.x = mm.x.wrapping_add(3);
        }
        let r = score(&t, &ts, MatchLevel::Level1);
        assert_eq!(r.threshold_used, 1200);
        assert!(r.anchor_count > 0);
        assert!(r.score <= 3000);
    }

    #[test]
    fn too_few_probe_minutiae_rejects() {
        let probe = tmpl(vec![m([0; 8], 1, 1), m([1; 8], 2, 2)]);
        let gallery = tmpl((0..12).map(|i| m([i; 8], i * 5, i * 3)).collect());
        let r = score(&probe, &gallery, MatchLevel::Level1);
        assert!(!r.decision);
        assert_eq!(r.anchor_count, 0);
    }

    #[test]
    fn disjoint_templates_have_no_anchors() {
        let probe = tmpl(vec![m([0x00; 8], 1, 1), m([0x01; 8], 2, 2)]);
        let gallery = tmpl(vec![m([0xff; 8], 3, 3), m([0xfe; 8], 4, 4)]);
        let r = score(&probe, &gallery, MatchLevel::Level2);
        assert_eq!(r.threshold_used, 2251);
        assert_eq!(r.anchor_count, 0);
    }

    #[test]
    fn diagnose_self_match_has_anchors() {
        let mins: Vec<Minutia> = (0..12)
            .map(|i| {
                m(
                    [i as u8, 0x5a, 0x11, 0x22, 0x33, 0x44, 0x55, i as u8],
                    (i * 10) as u8,
                    (i * 5) as u8,
                )
            })
            .collect();
        let t = tmpl(mins);
        // A translated re-capture (+3,0): an EXACT self-match is degenerate (zero per-correspondence
        // displacement → fit_two_point returns no transform), so shift to exercise the anchor pipeline.
        let mut ts = t.clone();
        for mm in &mut ts.minutiae {
            mm.x = mm.x.wrapping_add(3);
        }
        let d = diagnose(&t, &ts, MatchLevel::Level1, DEFAULT_IMAGE_W, DEFAULT_IMAGE_H);
        assert!(d.anchor_count > 0);
        assert!(d.top_anchor_probe_indices[0].is_some());
        assert!(!d.best_anchor_candidates.is_empty());
        assert_eq!(d.as_result().score, d.score);
    }

    #[test]
    fn prepared_view_agrees_with_unprepared_diagnose() {
        let mins: Vec<Minutia> = (0..12)
            .map(|i| {
                m(
                    [i as u8, 0x5a, 0x11, 0x22, 0x33, 0x44, 0x55, i as u8],
                    (i * 10) as u8,
                    (i * 5) as u8,
                )
            })
            .collect();
        let t = tmpl(mins);
        let mut ts = t.clone();
        for mm in &mut ts.minutiae {
            mm.x = mm.x.wrapping_add(3);
        }
        let direct = diagnose(&t, &ts, MatchLevel::Level1, DEFAULT_IMAGE_W, DEFAULT_IMAGE_H);
        let prepared = crate::template_cache::PreparedView::from_template(ts);
        let via = diagnose_prepared(&t, &prepared, MatchLevel::Level1, DEFAULT_IMAGE_W, DEFAULT_IMAGE_H);
        assert_eq!(direct.score, via.score);
        assert_eq!(direct.anchor_count, via.anchor_count);
        assert_eq!(direct.decision, via.decision);
        assert_eq!(direct.features, via.features);
        assert_eq!(direct.consensus, via.consensus);
    }

    #[test]
    fn too_weak_match_counts_skip_mlp_and_consensus() {
        // Two-minutia templates never reach MIN_PROBE; use enough minutiae but force weak pairing
        // via disjoint descriptors so every match_count stays ≤ 3.
        let probe = tmpl(
            (0..12)
                .map(|i| m([i; 8], i * 10, i * 4))
                .collect(),
        );
        let gallery = tmpl(
            (0..12)
                .map(|i| m([0xff - i; 8], i * 10 + 50, i * 4 + 20))
                .collect(),
        );
        let d = diagnose(&probe, &gallery, MatchLevel::Level2, DEFAULT_IMAGE_W, DEFAULT_IMAGE_H);
        assert_eq!(d.score, 0, "too-weak path writes score 0");
        assert!(!d.consensus.found, "consensus skipped without strong anchor");
        assert!(!d.decision);
    }

    #[test]
    fn work_record_feature_order_matches_scorer() {
        let mut wr = WorkRecord::new();
        wr.apply_neighbor_match(
            &SimilarityQ16 {
                cos: 0x10000,
                sin: 0,
                tx: 1,
                ty: 2,
            },
            21,
            8,
            10,
            false,
        );
        let feats = wr.score_features();
        assert_eq!(feats[5], 42 - 21);
        assert_eq!(feats[6], 8);
    }

    #[test]
    fn sort_anchor_order_ranks_by_hamming_mean_asc_then_match_count_desc() {
        let mk = |match_count: i32, avg_dist: i32, hamming_mean: Option<i32>| AnchorStats {
            avg_dist,
            match_count,
            xf: SimilarityQ16 {
                cos: XFORM_FIXED_ONE,
                sin: 0,
                tx: 0,
                ty: 0,
            },
            is_anchor: match_count >= MIN_MATCHED_NEIGHBORS,
            strong: false,
            compare: hamming_mean.map(|hm| CompareRecord {
                hamming_mean: hm,
                hamming_median: hm,
                coverage_scalar: 0x7fff,
                coverage_buckets: [0, 0, 0, 0, 0x7fff],
                match_count: 10,
                reject_count: 0,
                angle_avg_all: 0x7fff,
                angle_avg_class0: 0x7fff,
                angle_count: 10,
            }),
        };
        let stats = vec![
            // Slot 0: high RANSAC match_count (25) & low local avg_dist (10), but poor global hamming_mean (40)
            mk(25, 10, Some(40)),
            // Slot 1: empty compare record (sentinel 0x7fff) — must sort last among anchors
            mk(25, 5, Some(0x7fff)),
            // Slot 2: good global hamming_mean (12), lower match_count (15)
            mk(15, 20, Some(12)),
            // Slot 3: same global hamming_mean (12), higher match_count (25) — must win
            mk(25, 20, Some(12)),
        ];
        let order = sort_anchor_order(&stats);
        assert_eq!(order, vec![3, 2, 0, 1]);
    }
}







