//! Detector tuning config — the stack struct `syna_qm_probe_extract_core@0x180004bc0` builds and
//! passes to `syna_qm_detect_minutiae@0x18000aa00`. Kept as a **subtype-keyed table** (AGENTS.md #6):
//! a sibling silicon subtype is one row away from being supported. Every field is a named constant
//! with its DLL cfg-struct offset (AGENTS.md #5).
//!
//! Ground truth: the inline immediates in `syna_qm_probe_extract_core` (see
//! `../../docs/qm/qm-minutiae-detector.md`).

/// Detector configuration (mirror of the DLL cfg struct at `probe_extract_core`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectConfig {
    /// cfg+0x00 — passed to `syna_qm_emit_candidates@0x18000d290` as `param_5` (NMS `max_out =
    /// param_5 >> 2`). For 0x2449 this is **500** → per-call NMS budget **125**. Not the NMS
    /// response gate (`thr1` is [`Self::nms_thr1`] / `geom_p14`).
    pub score_threshold: i32,
    /// cfg+0x04 — maximum minutiae kept (candidate-array capacity; the post-sort cap).
    pub max_minutiae: u32,
    /// cfg+0x08 — kernel radius `R` (halo/overlap in pixels; per-tile padding).
    pub radius: i32,
    /// cfg+0x0c — emit-pass parameter (feeds `syna_qm_emit_candidates`).
    pub emit_p0c: i32,
    /// cfg+0x10 — geometry scale, in Q10 pixels. Copied to `SynaQmDetectCtx+0x14` and consumed as
    /// **the DoH Gaussian scale** ([`Self::gaussian_ksize`]) and as the NMS min-distance
    /// ([`Self::nms_mindist_raw`]).
    pub geom_p10: i32,
    /// cfg+0x14 — the NMS strict threshold `thr1` ([`Self::nms_thr1`]). Despite the historical
    /// "geometry parameter" name it is a *response* threshold and is never used as a length scale.
    pub geom_p14: i32,
    /// cfg+0x18 — emit-pass parameter.
    pub emit_p18: i32,
    /// cfg+0x1c — box-filter scale (`>>6` / `<<6` in `syna_qm_boxfilter_normalize`).
    pub boxfilter_scale: i32,
    /// cfg+0x20 — mode flag.
    pub flag_p20: i32,
}

impl DetectConfig {
    /// The 3×3 tile grid the detector always uses (`syna_qm_detect_minutiae` loops `i,j` in `0..3`).
    pub const TILE_GRID: usize = 3;
    /// Candidate/minutia record stride in the DLL array (bytes) — informational; our Rust record is
    /// a struct. `syna_qm_detect_minutiae` uses `0x20`.
    pub const RECORD_STRIDE: usize = 0x20;
    /// Halo fill value for out-of-tile pixels: mid-gray `128` in Q16.16 (`128 << 16`).
    /// `syna_qm_detect_minutiae` passes `0x800000` to `FUN_180009ea0`.
    pub const HALO_FILL_Q16: i32 = 0x0080_0000;
    // --- DoH Gaussian pre-smooth (`syna_qm_gaussian_select_ksize@0x180010110`, reached from
    //     `syna_qm_boxfilter_normalize@0x18000f1a0`). ---

    /// Scale offset subtracted before the ksize fit (`scale - 0x333` in the DLL).
    const KSIZE_SCALE_BIAS: i32 = 0x333;
    /// Q16 multiplier applied to the biased scale (`0x35555 >> 16` = 10/3, i.e. ~3.33 σ per unit).
    const KSIZE_SCALE_MUL_Q16: i64 = 0x3_5555;
    /// Rounding/floor term added after doubling the radius (`+0xbff` ≈ +3 in Q10, the "+3σ" tail).
    const KSIZE_ROUND_Q10: i32 = 0xbff;
    /// Q10 fractional bits the ksize fit works in.
    const KSIZE_Q10_SHIFT: u32 = 10;

    /// DoH Gaussian pre-smooth kernel size, exactly as `syna_qm_gaussian_select_ksize@0x180010110`
    /// derives it:
    ///
    /// ```text
    /// k = ((((geom_p10 - 0x333) * 0x35555) >> 16) * 2 + 0xbff) >> 10, rounded up to odd
    /// ```
    ///
    /// For `0x2449` (`geom_p10 = 0x466`) this is **5** — the classic `2·⌈3σ⌉+1` at σ ≈ 1 px.
    ///
    /// The scale argument is `SynaQmDetectCtx+0x14`, which `detect_kernel_params@0x18000a070` fills
    /// from **cfg+0x10**. Reading that struct offset as a *cfg* offset (i.e. using `geom_p14`
    /// = `0x15d8`, the NMS threshold) yields `35` and was this port's long-standing error — see
    /// `docs/qm/doh-whole-field-validation.md`.
    pub const fn gaussian_ksize(&self) -> usize {
        let biased = (self.geom_p10 - Self::KSIZE_SCALE_BIAS) as i64;
        let radius = ((biased * Self::KSIZE_SCALE_MUL_Q16) >> 16) as i32;
        let k = (radius * 2 + Self::KSIZE_ROUND_Q10) >> Self::KSIZE_Q10_SHIFT;
        (k | 1) as usize
    }

    /// Sub-pixel offset reject bound in `syna_qm_refine_subpixel_hessian` (`|δ| > 0x80` ⇒ drop).
    pub const SUBPIXEL_REJECT: i32 = 0x80;
    /// Border margin (px) enforced by `FUN_18000a8b0`: a minutia must satisfy `2 < c < dim-3`.
    pub const BORDER_MARGIN_LO: i32 = 2;
    /// See [`Self::BORDER_MARGIN_LO`]; the high guard is `dim - BORDER_MARGIN_HI`.
    pub const BORDER_MARGIN_HI: i32 = 3;

    // --- NMS engine thresholds (`syna_qm_detect_peaks_nms@0x18000cee0` reads these off the
    //     `SynaQmDetectCtx` that `detect_kernel_params@0x18000a070` populates — validated bit-exact
    //     against the DLL via `tools/qm-dll-oracle`, golden/nms.txt). For 0x2449: thr1=0x15d8=5592,
    //     thr2=0xa8=168, min-dist raw=0x11980 → exclusion on dx²+dy² = 1 (~1px, near no-op). ---

    /// NMS strict threshold `thr1` (`engine+0x20`, `v > thr1`) = `geom_p14` (copied by
    /// `detect_kernel_params`). For 0x2449: `0x15d8` (5592).
    pub const fn nms_thr1(&self) -> i32 {
        self.geom_p14
    }
    /// NMS `>=` threshold `thr2` (`engine+0x24`, `v >= thr2`) — a hardcoded `0xa8` (168) in
    /// `detect_kernel_params`, not from cfg. (Subsumed by `thr1` for 0x2449, but applied faithfully.)
    pub const NMS_THR2: i32 = 0xa8;
    /// `syna_qm_emit_candidates@0x18000d290` shifts `param_5` (cfg+0) right by this to get NMS
    /// `max_out`. For 0x2449: `500 >> 2` = **125** peaks per tile emit call.
    pub const NMS_EMIT_BUDGET_SHIFT: u32 = 2;
    /// Per-tile NMS output cap — `cfg.score_threshold >> NMS_EMIT_BUDGET_SHIFT`.
    pub const fn nms_max_out(&self) -> usize {
        let thr = if self.score_threshold < 0 { 0 } else { self.score_threshold as usize };
        thr >> Self::NMS_EMIT_BUDGET_SHIFT
    }
    /// NMS scan margin — `emit_candidates` passes cfg+8 (`radius`) as `param_6`. Equals the tile
    /// halo, so NMS runs on the proper rect (halo excluded). Port used to hardcode `1`.
    pub const fn nms_margin(&self) -> i32 {
        self.radius
    }
    /// NMS min-distance raw value (`engine+0x48`) = `(geom_p10 << 10) >> 4`. For 0x2449: `0x11980`.
    pub const fn nms_mindist_raw(&self) -> i32 {
        (self.geom_p10 << 10) >> 4
    }
    /// NMS exclusion threshold on `dx²+dy²`: the DLL computes `((engine+0x48 >> 6)²) >> 20`. For 0x2449
    /// this is `1` — i.e. only exactly-adjacent peaks suppress (a near no-op, since the strict 3×3
    /// local-max test already excludes adjacent maxima).
    pub const fn nms_min_dist_sq(&self) -> i32 {
        let r = self.nms_mindist_raw() >> 6;
        (r * r) >> 20
    }
}

/// Silicon subtype this config row is for (the `0x75` silicon-id low16). Detection is data-driven by
/// subtype, never PID-hardcoded (AGENTS.md #6).
pub type Subtype = u16;

/// Our reference device.
pub const SUBTYPE_2449: Subtype = 0x2449;

/// Config for silicon subtype `0x2449` — immediates from `syna_qm_probe_extract_core@0x180004bc0`.
pub const CONFIG_2449: DetectConfig = DetectConfig {
    score_threshold: 500,
    max_minutiae: 250, // 0xfa
    radius: 10,
    emit_p0c: 7,
    geom_p10: 0x466,
    geom_p14: 0x15d8,
    emit_p18: 16, // 0x10
    boxfilter_scale: 64, // 0x40
    flag_p20: 1,
};

/// Subtype → config lookup table. Add a row to support a sibling silicon (AGENTS.md #6).
const CONFIG_TABLE: &[(Subtype, DetectConfig)] = &[(SUBTYPE_2449, CONFIG_2449)];

/// Look up the detector config for a silicon subtype. Falls back to the `0x2449` row for unknown
/// subtypes (the only one reversed so far) so detection still runs, data-driven not PID-gated.
pub fn config_for(subtype: Subtype) -> DetectConfig {
    CONFIG_TABLE
        .iter()
        .find(|(s, _)| *s == subtype)
        .map(|(_, c)| *c)
        .unwrap_or(CONFIG_2449)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_subtype_resolves() {
        assert_eq!(config_for(SUBTYPE_2449), CONFIG_2449);
    }

    #[test]
    fn unknown_subtype_falls_back_to_2449() {
        assert_eq!(config_for(0xffff), CONFIG_2449);
    }

    #[test]
    fn nms_engine_values_match_dll() {
        // From detect_kernel_params@0x18000a070; validated against tools/qm-dll-oracle golden/nms.txt.
        assert_eq!(CONFIG_2449.nms_thr1(), 0x15d8);
        assert_eq!(DetectConfig::NMS_THR2, 0xa8);
        assert_eq!(CONFIG_2449.nms_mindist_raw(), 0x11980);
        assert_eq!(CONFIG_2449.nms_min_dist_sq(), 1);
    }

    #[test]
    fn gaussian_ksize_matches_dll() {
        // syna_qm_gaussian_select_ksize@0x180010110 on ctx+0x14 = cfg+0x10 = 0x466.
        // Cross-checked bit-exact on a real frame: tools/qm-dll-oracle golden/doh_field.txt.
        assert_eq!(CONFIG_2449.gaussian_ksize(), 5);
        // The mis-read that produced the old ksize-35 default, kept as a regression tripwire.
        assert_ne!(CONFIG_2449.gaussian_ksize(), 35);
    }

    #[test]
    fn cfg_2449_immediates_match_dll() {
        // Values transcribed from syna_qm_probe_extract_core@0x180004bc0.
        assert_eq!(CONFIG_2449.score_threshold, 500);
        assert_eq!(CONFIG_2449.max_minutiae, 0xfa);
        assert_eq!(CONFIG_2449.radius, 10);
        assert_eq!(CONFIG_2449.boxfilter_scale, 0x40);
        // emit_candidates@0x18000d290: max_out = cfg+0 >> 2; margin = cfg+8.
        assert_eq!(CONFIG_2449.nms_max_out(), 125);
        assert_eq!(CONFIG_2449.nms_margin(), 10);
    }
}
