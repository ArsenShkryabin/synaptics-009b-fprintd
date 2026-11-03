//! Host-side multi-view enrollment — port of the `CEohMohEIV` accumulator
//! (`syna_qm_enroll_extract_vt90@0x1800ff610` / `syna_qm_template_match@0x180002210`).
//!
//! The DLL builds an enrolled template as a **set of diverse views** in a `VTML` container: each
//! accepted capture is appended as one new view (tagged field 3 = view count); it does **not** fuse or
//! average minutiae. A capture is skipped when its redundancy score against an accepted view exceeds
//! the enroll threshold (`FUN_180001f80@0x180001f80`, default 150); enrollment completes on
//! `quality==100` (`FUN_180001d50@0x180001d50`) **or** the sample + accumulated-minutiae gate.
//!
//! See `../../docs/qm/qm-enrollment.md`. Rule #7: an enrolled template is processed data; validate by
//! finger-dependence, never assert it "is" a fingerprint.

use crate::matcher::{diagnose_gated, DEFAULT_IMAGE_H, DEFAULT_IMAGE_W};
use crate::consensus::VoteGate;
use crate::template::Template;
use crate::types::{MatchLevel, MIN_PROBE_MINUTIAE};

/// Fixed sample-count bias in the DLL's required-sample formula (`engine_param(2) + 6`).
pub const SAMPLE_COUNT_BIAS: u32 = 6;
/// Consecutive out-of-spec captures before enrollment hard-fails (`engineState+0x1c >= 4`).
pub const REJECT_STREAK_MAX: u32 = 4;
/// Default `engine_param(2)` / quality denominator (`FUN_180001310@0x180001310` `cfg[3]=0x12`).
pub const DEFAULT_QUALITY_DENOM: u32 = 0x12;
/// Default required touches: `engine_param(2) + SAMPLE_COUNT_BIAS` (= 24).
pub const DEFAULT_REQUIRED_SAMPLES: u32 = DEFAULT_QUALITY_DENOM + SAMPLE_COUNT_BIAS;
/// Default accumulated-minutiae coverage gate (`engineState+0x50`).
pub const DEFAULT_REQUIRED_MINUTIAE: u32 = 1;
/// Default redundancy score threshold — `(10 - cfg[6]) * 0x19` with `cfg[6]=4` → 150
/// (`FUN_180001f80@0x180001f80`).
pub const DEFAULT_REDUNDANCY_THRESHOLD: u32 = 150;
/// How many accepted views to check for redundancy (`engine_param(10)` = `cfg[5]`).
pub const DEFAULT_REDUNDANCY_BUDGET: usize = 6;

/// DLL `param_4[2]` subcodes from `syna_qm_enroll_extract_vt90`.
pub const SUBCODE_PROBE_FAIL: u8 = 0x43;
pub const SUBCODE_REDUNDANT: u8 = 0x44;
pub const SUBCODE_SKIP: u8 = 0x45;
pub const SUBCODE_REJECT_STREAK: u8 = 0x47;

/// Per-subtype enrollment tuning (AGENTS.md #6). Defaults match the engine cfg table, not Tudor’s
/// WBF stage override (set knobs explicitly for an 8-touch session).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrollParams {
    /// Quality denominator (`engine_param(2)` / `cfg[3]`).
    pub quality_denom: u32,
    /// Touches required for the sample gate (`engine_param(2) + SAMPLE_COUNT_BIAS`).
    pub required_samples: u32,
    /// Accumulated minutiae required alongside the sample gate (`engineState+0x50`).
    pub required_minutiae: u32,
    /// Redundancy skip when any checked view scores strictly above this.
    pub redundancy_threshold: u32,
    /// Cap on accepted views scored for redundancy.
    pub redundancy_budget: usize,
    /// Consecutive rejects before [`SampleOutcome::Failed`].
    pub reject_streak_max: u32,
    /// Minimum minutiae on a probe before it is considered in-spec.
    pub min_probe_minutiae: u32,
}

impl EnrollParams {
    /// Defaults for a silicon subtype. Only `0x2449` is characterized; others fall back to it.
    pub fn for_subtype(_subtype: u16) -> Self {
        Self {
            quality_denom: DEFAULT_QUALITY_DENOM,
            required_samples: DEFAULT_REQUIRED_SAMPLES,
            required_minutiae: DEFAULT_REQUIRED_MINUTIAE,
            redundancy_threshold: DEFAULT_REDUNDANCY_THRESHOLD,
            redundancy_budget: DEFAULT_REDUNDANCY_BUDGET,
            reject_streak_max: REJECT_STREAK_MAX,
            min_probe_minutiae: MIN_PROBE_MINUTIAE as u32,
        }
    }
}

impl Default for EnrollParams {
    fn default() -> Self {
        Self::for_subtype(0x2449)
    }
}

/// Best redundancy hit against an already-accepted view (for UI / diagnostics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedundancyHit {
    pub view_idx: usize,
    pub score: u32,
    pub threshold: u32,
    pub corr_count: usize,
    /// Compact correspondence stubs `(probe_x, probe_y, gallery_x, gallery_y)` for overlays.
    pub pairs: Vec<(i32, i32, i32, i32)>,
}

/// Snapshot of accumulator counters after the last sample (and the last redundancy probe, if any).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnrollSampleStats {
    pub quality: u8,
    pub samples: u32,
    pub accepted_views: usize,
    pub accumulated_minutiae: usize,
    pub reject_streak: u32,
    pub last_outcome: Option<SampleOutcome>,
    pub last_subcode: Option<u8>,
    pub last_redundancy: Option<RedundancyHit>,
}

/// Result of feeding one capture to the accumulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleOutcome {
    /// A new distinct view was appended.
    Accepted { views: usize, quality: u8 },
    /// The capture overlapped an accepted view — skipped (coverage unchanged).
    Redundant { views: usize, vs_view: usize, score: u32 },
    /// The capture was out-of-spec and dropped.
    Rejected { reason: RejectReason },
    /// Too many consecutive rejects — enrollment has failed and should be abandoned.
    Failed,
}

/// Why a capture was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// Fewer than the configured min-probe minutiae detected.
    TooFewMinutiae,
}

/// A finalized enrolled template: the set of accepted views.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledTemplate {
    pub views: Vec<Template>,
}

/// Stateful multi-view enrollment accumulator. Feed captures via [`Self::add_sample`] until
/// [`Self::is_complete`], then [`Self::finalize`].
#[derive(Debug, Clone)]
pub struct EnrollAccumulator {
    views: Vec<Template>,
    samples: u32,
    reject_streak: u32,
    params: EnrollParams,
    last_stats: EnrollSampleStats,
}

impl EnrollAccumulator {
    /// New accumulator with subtype-keyed defaults.
    pub fn new(subtype: u16) -> Self {
        Self::with_params(EnrollParams::for_subtype(subtype))
    }

    pub fn with_params(params: EnrollParams) -> Self {
        Self {
            views: Vec::new(),
            samples: 0,
            reject_streak: 0,
            params,
            last_stats: EnrollSampleStats::default(),
        }
    }

    pub fn samples(&self) -> u32 {
        self.samples
    }
    pub fn view_count(&self) -> usize {
        self.views.len()
    }
    pub fn params(&self) -> EnrollParams {
        self.params
    }
    pub fn reject_streak(&self) -> u32 {
        self.reject_streak
    }
    pub fn last_stats(&self) -> &EnrollSampleStats {
        &self.last_stats
    }

    /// Sum of minutiae across accepted views (`engineState+0x10` coverage field proxy).
    pub fn accumulated_minutiae(&self) -> usize {
        self.views.iter().map(|v| v.minutiae.len()).sum()
    }

    /// DLL enrollment quality 0..=100 — `((views - adj) * 100) / quality_denom`
    /// (`FUN_180001d50@0x180001d50`; `adj` left at 0 until the `cfg+0x2c` path is ported).
    pub fn quality(&self) -> u8 {
        quality_from_views(self.views.len(), self.params.quality_denom)
    }

    /// Feed one captured view.
    ///
    /// Touch counter (`engineState+0x4c`) advances on **every** in-spec attempt, including
    /// redundant skips. Out-of-spec captures bump the reject streak (hard fail at
    /// [`EnrollParams::reject_streak_max`]).
    pub fn add_sample(&mut self, view: Template) -> SampleOutcome {
        if (view.minutiae.len() as u32) < self.params.min_probe_minutiae {
            return self.record_reject(RejectReason::TooFewMinutiae);
        }

        // Every in-spec touch advances the sample counter, then may accept or skip.
        self.samples = self.samples.saturating_add(1);

        if let Some(hit) = self.find_redundancy(&view) {
            self.reject_streak = 0;
            let outcome = SampleOutcome::Redundant {
                views: self.views.len(),
                vs_view: hit.view_idx,
                score: hit.score,
            };
            self.publish_stats(outcome, Some(SUBCODE_REDUNDANT), Some(hit));
            return outcome;
        }

        self.reject_streak = 0;
        self.views.push(view);
        let q = self.quality();
        let outcome = SampleOutcome::Accepted { views: self.views.len(), quality: q };
        self.publish_stats(outcome, None, None);
        outcome
    }

    /// Record an out-of-spec capture that never produced a [`Template`].
    pub fn reject(&mut self) -> SampleOutcome {
        self.record_reject(RejectReason::TooFewMinutiae)
    }

    /// Enrollment quality percent (DLL `param_4[1]` / progress when not sample-gated).
    pub fn percent(&self) -> u8 {
        self.quality()
    }

    /// Complete when quality hits 100 **or** (samples ∧ accumulated minutiae) gates pass.
    pub fn is_complete(&self) -> bool {
        if self.quality() >= 100 {
            return true;
        }
        self.samples >= self.params.required_samples
            && (self.accumulated_minutiae() as u32) >= self.params.required_minutiae
    }

    /// Consume the accumulator into an enrolled template. Returns `None` if no views were accepted.
    pub fn finalize(self) -> Option<EnrolledTemplate> {
        (!self.views.is_empty()).then_some(EnrolledTemplate { views: self.views })
    }

    /// Non-consuming snapshot of the accepted views into an [`EnrolledTemplate`].
    pub fn enrolled(&self) -> Option<EnrolledTemplate> {
        (!self.views.is_empty()).then(|| EnrolledTemplate { views: self.views.clone() })
    }

    /// The accepted views so far (read-only).
    pub fn views(&self) -> &[Template] {
        &self.views
    }

    fn record_reject(&mut self, reason: RejectReason) -> SampleOutcome {
        self.samples = self.samples.saturating_add(1);
        self.reject_streak = self.reject_streak.saturating_add(1);
        if self.reject_streak >= self.params.reject_streak_max {
            let outcome = SampleOutcome::Failed;
            self.publish_stats(outcome, Some(SUBCODE_REJECT_STREAK), None);
            return outcome;
        }
        let outcome = SampleOutcome::Rejected { reason };
        self.publish_stats(outcome, Some(SUBCODE_PROBE_FAIL), None);
        outcome
    }

    fn find_redundancy(&self, view: &Template) -> Option<RedundancyHit> {
        let thr = self.params.redundancy_threshold;
        let budget = self.params.redundancy_budget.min(self.views.len());
        let mut best: Option<RedundancyHit> = None;
        for (i, v) in self.views.iter().take(budget).enumerate() {
            let diag = diagnose_gated(
                view,
                v,
                MatchLevel::Level1,
                DEFAULT_IMAGE_W,
                DEFAULT_IMAGE_H,
                VoteGate::ValidFlag,
            );
            if diag.score > thr {
                let pairs: Vec<(i32, i32, i32, i32)> = diag
                    .best_anchor_candidates
                    .iter()
                    .map(|c| (c.probe_x, c.probe_y, c.gallery_x, c.gallery_y))
                    .collect();
                let hit = RedundancyHit {
                    view_idx: i,
                    score: diag.score,
                    threshold: thr,
                    corr_count: pairs.len(),
                    pairs,
                };
                if best.as_ref().is_none_or(|b| hit.score > b.score) {
                    best = Some(hit);
                }
            }
        }
        best
    }

    fn publish_stats(
        &mut self,
        outcome: SampleOutcome,
        subcode: Option<u8>,
        redundancy: Option<RedundancyHit>,
    ) {
        self.last_stats = EnrollSampleStats {
            quality: self.quality(),
            samples: self.samples,
            accepted_views: self.views.len(),
            accumulated_minutiae: self.accumulated_minutiae(),
            reject_streak: self.reject_streak,
            last_outcome: Some(outcome),
            last_subcode: subcode,
            last_redundancy: redundancy,
        };
    }
}

fn quality_from_views(views: usize, denom: u32) -> u8 {
    if denom == 0 {
        return 100;
    }
    let q = (views as u64).saturating_mul(100) / u64::from(denom);
    q.min(100) as u8
}

impl EnrolledTemplate {
    /// Number of stored views.
    pub fn view_count(&self) -> usize {
        self.views.len()
    }

    /// 1:N verify — score `probe` against every view, returning the best (highest-scoring) match.
    pub fn identify(&self, probe: &Template, level: MatchLevel) -> Option<(usize, crate::matcher::MatchResult)> {
        self.identify_with_dims(
            probe,
            level,
            crate::matcher::DEFAULT_IMAGE_W,
            crate::matcher::DEFAULT_IMAGE_H,
        )
        .map(|(i, d)| (i, d.as_result()))
    }

    /// Like [`Self::identify`] but with live conditioned-image dimensions (vote grid + descriptor grid).
    pub fn identify_with_dims(
        &self,
        probe: &Template,
        level: MatchLevel,
        w: i32,
        h: i32,
    ) -> Option<(usize, crate::matcher::MatchDiagnostics)> {
        self.views
            .iter()
            .enumerate()
            .map(|(i, v)| (i, crate::matcher::diagnose(probe, v, level, w, h)))
            .max_by_key(|(_, d)| d.score)
    }

    /// Like [`Self::identify_with_dims`] but returns the winning view's full diagnostics
    /// (single diagnose pass — no re-rank + re-diagnose).
    pub fn identify_diagnostic(
        &self,
        probe: &Template,
        level: MatchLevel,
        w: i32,
        h: i32,
    ) -> Option<(usize, crate::matcher::MatchDiagnostics)> {
        self.identify_with_dims(probe, level, w, h)
    }

    /// Serialize to a length-prefixed multi-view blob: `u32 view_count` then per view
    /// `u32 blob_len ++ Template::to_blob`.
    pub fn to_blob(&self) -> Result<Vec<u8>, crate::template::TemplateError> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.views.len() as u32).to_le_bytes());
        for v in &self.views {
            let b = v.to_blob()?;
            out.extend_from_slice(&(b.len() as u32).to_le_bytes());
            out.extend_from_slice(&b);
        }
        Ok(out)
    }

    /// Parse a multi-view blob produced by [`Self::to_blob`].
    pub fn from_blob(bytes: &[u8]) -> Result<Self, crate::template::TemplateError> {
        let mut c = 0usize;
        let read_u32 = |c: &mut usize| -> Option<u32> {
            let v = bytes.get(*c..*c + 4)?;
            *c += 4;
            Some(u32::from_le_bytes(v.try_into().ok()?))
        };
        let n = read_u32(&mut c).ok_or(crate::template::TemplateError::UnexpectedEof)? as usize;
        let mut views = Vec::with_capacity(n);
        for _ in 0..n {
            let len = read_u32(&mut c).ok_or(crate::template::TemplateError::UnexpectedEof)? as usize;
            let blob = bytes.get(c..c + len).ok_or(crate::template::TemplateError::UnexpectedEof)?;
            c += len;
            views.push(Template::from_blob(blob)?);
        }
        Ok(EnrolledTemplate { views })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::Minutia;

    /// A synthetic template with `n` minutiae seeded by `seed` (distinct descriptors/positions).
    fn synth_template(n: usize, seed: u32) -> Template {
        let minutiae: Vec<Minutia> = (0..n)
            .map(|i| {
                let h = (i as u32).wrapping_mul(2_654_435_761).wrapping_add(seed.wrapping_mul(40_503));
                let mut descriptor = [0u8; 8];
                for (k, b) in descriptor.iter_mut().enumerate() {
                    *b = ((h >> (k * 4)) & 0xff) as u8;
                }
                Minutia {
                    descriptor,
                    x: ((h >> 3) % 144) as u8,
                    y: ((h >> 11) % 56) as u8,
                    angle_deg: ((h >> 17) % 180) as u16,
                }
            })
            .collect();
        Template { descriptor: [seed as u8; 8], split: (n / 2) as u8, field_0c: 0, minutiae }
    }

    #[test]
    fn dll_defaults_match_engine_cfg() {
        let p = EnrollParams::default();
        assert_eq!(p.quality_denom, 18);
        assert_eq!(p.required_samples, 24);
        assert_eq!(p.required_minutiae, 1);
        assert_eq!(p.redundancy_threshold, 150);
        assert_eq!(p.redundancy_budget, 6);
        assert_eq!(p.reject_streak_max, 4);
    }

    #[test]
    fn quality_scales_with_accepted_views() {
        assert_eq!(quality_from_views(0, 18), 0);
        assert_eq!(quality_from_views(9, 18), 50);
        assert_eq!(quality_from_views(18, 18), 100);
        assert_eq!(quality_from_views(20, 18), 100);
    }

    #[test]
    fn quality_early_completes_before_sample_gate() {
        let params = EnrollParams {
            quality_denom: 2, // two accepts → quality 100
            required_samples: 24,
            redundancy_threshold: u32::MAX, // isolate quality gate from matcher noise
            ..Default::default()
        };
        let mut acc = EnrollAccumulator::with_params(params);
        assert!(matches!(
            acc.add_sample(synth_template(16, 1)),
            SampleOutcome::Accepted { quality: 50, .. }
        ));
        assert!(!acc.is_complete());
        assert!(matches!(
            acc.add_sample(synth_template(16, 2)),
            SampleOutcome::Accepted { quality: 100, .. }
        ));
        assert!(acc.is_complete(), "quality 100 must complete without 24 samples");
        assert_eq!(acc.samples(), 2);
    }

    #[test]
    fn samples_advance_on_redundant_skip() {
        // Force redundancy via threshold 0: any positive score skips; identical templates score > 0
        // under ValidFlag more often than not — if score is 0, assert samples still advance on accept.
        let params = EnrollParams { redundancy_threshold: 0, quality_denom: 64, ..Default::default() };
        let mut acc = EnrollAccumulator::with_params(params);
        let v = synth_template(16, 1);
        let first = acc.add_sample(v.clone());
        assert!(matches!(first, SampleOutcome::Accepted { .. }), "{first:?}");
        let samples_after_first = acc.samples();
        let second = acc.add_sample(v);
        assert_eq!(acc.samples(), samples_after_first + 1, "redundant/accept still counts a touch");
        // With thr=0, a positive score is redundant; score 0 still accepted as a second view.
        assert!(
            matches!(second, SampleOutcome::Redundant { .. } | SampleOutcome::Accepted { views: 2, .. }),
            "{second:?}"
        );
    }

    #[test]
    fn sample_and_minutiae_gate_completes_without_full_quality() {
        let params = EnrollParams {
            quality_denom: 100, // quality stays low
            required_samples: 2,
            required_minutiae: 20,
            ..Default::default()
        };
        let mut acc = EnrollAccumulator::with_params(params);
        acc.add_sample(synth_template(12, 1));
        assert!(!acc.is_complete());
        acc.add_sample(synth_template(12, 2));
        assert!(acc.is_complete());
        assert!(acc.quality() < 100);
    }

    #[test]
    fn too_few_minutiae_rejected_then_hard_fail() {
        let mut acc = EnrollAccumulator::new(0x2449);
        for _ in 0..(REJECT_STREAK_MAX - 1) {
            assert!(matches!(
                acc.add_sample(synth_template(3, 1)),
                SampleOutcome::Rejected { reason: RejectReason::TooFewMinutiae }
            ));
        }
        assert!(matches!(acc.add_sample(synth_template(3, 1)), SampleOutcome::Failed));
        assert_eq!(acc.last_stats().last_subcode, Some(SUBCODE_REJECT_STREAK));
    }

    #[test]
    fn multiview_blob_roundtrips() {
        let canon = |t: Template| Template::from_blob(&t.to_blob().unwrap()).unwrap();
        let enrolled = EnrolledTemplate {
            views: vec![canon(synth_template(12, 1)), canon(synth_template(14, 2))],
        };
        let blob = enrolled.to_blob().unwrap();
        let back = EnrolledTemplate::from_blob(&blob).unwrap();
        assert_eq!(enrolled, back);
    }

    #[test]
    fn enrolled_snapshot_is_non_consuming_and_matches_finalize() {
        // never skip on synthetic noise
        let params = EnrollParams { redundancy_threshold: u32::MAX, ..Default::default() };
        let mut acc = EnrollAccumulator::with_params(params);
        for s in 0..4u32 {
            acc.add_sample(synth_template(16, s + 1));
        }
        let snapshot = acc.enrolled().expect("views accepted");
        assert_eq!(snapshot.view_count(), acc.view_count());
        let finalized = acc.finalize().unwrap();
        assert_eq!(snapshot.views, finalized.views);
    }

    #[test]
    fn identify_diagnostic_agrees_with_identify() {
        let params = EnrollParams { redundancy_threshold: u32::MAX, ..Default::default() };
        let mut acc = EnrollAccumulator::with_params(params);
        for s in 0..4u32 {
            acc.add_sample(synth_template(16, s + 1));
        }
        let enrolled = acc.finalize().unwrap();
        let probe = synth_template(16, 3);
        let by_score = enrolled.identify(&probe, MatchLevel::Level1);
        let by_diag = enrolled.identify_diagnostic(&probe, MatchLevel::Level1, 144, 56);
        match (by_score, by_diag) {
            (Some((i, _)), Some((j, _))) => assert_eq!(i, j, "same winning view"),
            (None, None) => {}
            _ => panic!("identify / identify_diagnostic disagree on presence"),
        }
    }
}
