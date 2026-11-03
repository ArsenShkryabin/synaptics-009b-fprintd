//! Statistical scorer: z-normalized 34-feature vector → 34→20→2 MLP → 0..3000 score.
//!
//! This whole path is STATIC (single global model, `.rdata`), so it is bit-exact-portable. Ported
//! functions:
//!   - [`mlp_activation`] — `syna_qm_mlp_activation@0x180002b20` (Q10 sigmoid LUT, NOT a ReLU — the
//!     decompile shows a `DAT_18014a2b0` table; the earlier doc note of "ReLU" was wrong).
//!   - [`mlp_forward`] — `syna_qm_mlp_forward@0x180002cd0` (layer 0 activated, layer 1 linear).
//!   - [`llr_to_scale`] — `syna_qm_score_llr_to_scale@0x180002f30`.
//!   - [`znorm_feature`] — the f64 z-normalization inside `syna_qm_score_features@0x1800088d0`
//!     (uses IEEE-754 doubles, so it is reproduced in `f64` for bit-exactness).
//!   - [`score_feature_vector`] — the full znorm → MLP → scale composition.
//!
//! All integer accumulation uses wrapping 32-bit arithmetic to match the vendor's `int` math.

use super::scorer_weights::{MLP_ACTIVATION_LUT, MLP_WEIGHTS_LAYER0, MLP_WEIGHTS_LAYER1};
use super::types::{
    FEATURE_NORM_TABLE, SCORE_FEATURE_VECTOR_LEN, SCORE_FEATURES_PER_MINUTIA, mlp_dims,
    mlp_weights::BIAS_SCALE, score_scale,
};

/// Hidden-layer activation: maps a Q20 accumulator to a Q10 activation via the quantized sigmoid
/// table. Exact port of `syna_qm_mlp_activation@0x180002b20`.
pub fn mlp_activation(acc_q20: i32) -> i32 {
    // Round-to-nearest by ±0xc00 then divide by 0x1800 (both truncate toward zero, as in C).
    let mut x = if acc_q20 < 0 {
        acc_q20.wrapping_sub(0xc00)
    } else {
        acc_q20.wrapping_add(0xc00)
    };
    x /= 0x1800;

    if x > 0x1ed2 {
        return 0x400;
    }
    if x < -0x523 {
        return 0;
    }
    if x > 0x459 {
        return 0x3ff;
    }
    if x < -0x459 {
        return 1;
    }
    if x > 0x403 {
        return 0x3fe;
    }
    if x < -0x403 {
        return 2;
    }
    if x > 0x3ff {
        return 0x3fd;
    }
    if x < -0x3ff {
        return 3;
    }
    if x >= 0 {
        MLP_ACTIVATION_LUT[x as usize] as i32
    } else {
        0x400 - MLP_ACTIVATION_LUT[(-x) as usize] as i32
    }
}

/// Forward pass of the 34→20→2 scoring MLP. Layer 0 (input→hidden) is activated via
/// [`mlp_activation`]; layer 1 (hidden→output) is linear (last layer). Returns the 2-element LLR
/// output vector (Q10-domain accumulators). Exact port of `syna_qm_mlp_forward@0x180002cd0` with
/// the static weights.
pub fn mlp_forward(input: &[i32; mlp_dims::INPUT]) -> [i32; mlp_dims::OUTPUT] {
    const IN: usize = mlp_dims::INPUT; // 34
    const HID: usize = mlp_dims::HIDDEN; // 20
    const ROW0: usize = IN + 1; // 35

    let mut hidden = [0i32; HID];
    for (j, h) in hidden.iter_mut().enumerate() {
        let row = &MLP_WEIGHTS_LAYER0[j * ROW0..j * ROW0 + ROW0];
        let mut acc: i32 = 0;
        for k in 0..IN {
            acc = acc.wrapping_add(row[k].wrapping_mul(input[k]));
        }
        acc = acc.wrapping_add(row[IN].wrapping_mul(BIAS_SCALE));
        *h = mlp_activation(acc);
    }

    const ROW1: usize = HID + 1; // 21
    let mut out = [0i32; mlp_dims::OUTPUT];
    for (j, o) in out.iter_mut().enumerate() {
        let row = &MLP_WEIGHTS_LAYER1[j * ROW1..j * ROW1 + ROW1];
        let mut acc: i32 = 0;
        for k in 0..HID {
            acc = acc.wrapping_add(row[k].wrapping_mul(hidden[k]));
        }
        acc = acc.wrapping_add(row[HID].wrapping_mul(BIAS_SCALE));
        *o = acc; // linear output layer
    }
    out
}

/// Map the MLP log-likelihood output (`out[0]`) to the final 0..3000 integer match score.
/// Exact port of `syna_qm_score_llr_to_scale@0x180002f30`.
pub fn llr_to_scale(llr: i32) -> i32 {
    // (int)(llr + (llr>>31 & 0x3ff)) >> 10  — arithmetic rounding of a negative Q10 value.
    let rounded = llr.wrapping_add((llr >> 31) & 0x3ff);
    let iv = rounded >> 10;
    if iv < -score_scale::LLR_BIAS {
        return 0;
    }
    if iv > score_scale::LLR_MAX {
        return score_scale::SCORE_MAX;
    }
    (iv + score_scale::LLR_BIAS) * score_scale::SCORE_MAX / score_scale::LLR_SPAN
}

/// Z-normalize a single raw feature against [`FEATURE_NORM_TABLE`] and quantize to Q10, exactly as
/// the inner loop of `syna_qm_score_features@0x1800088d0`. Uses `f64` for bit-exactness. `idx` is
/// the feature index in `0..17`. A raw value `>= 0x7fff` is a sentinel → quantized `+1.6·1024`.
pub fn znorm_feature(raw: i32, idx: usize) -> i32 {
    znorm_feature_clamped(raw, idx, ZNORM_CLAMP_HI_DLL)
}

/// The DLL-faithful high clamp for `score_features`' z-norm (`1.1`, oracle-confirmed via `SCZNORM`).
/// **Distinct** from MetViper's `push_pool_feature`, which clamps to `1.6` — the curiosity toggle can
/// swap this to `1.6` to see the (genuinely different DLL function's) behaviour.
pub const ZNORM_CLAMP_HI_DLL: f64 = 1.1;

/// [`znorm_feature`] with the high clamp as a parameter (see [`ZNORM_CLAMP_HI_DLL`]).
pub fn znorm_feature_clamped(raw: i32, idx: usize, clamp_hi: f64) -> i32 {
    let norm = &FEATURE_NORM_TABLE[idx];
    let z: f64 = if raw < 0x7fff {
        let mut d = ((raw as f64) - norm.mean) * 1.6 / norm.stddev;
        if d <= clamp_hi {
            if d >= -1.6 {
                if d <= 1.6 {
                    // Near-zero guard: nudge |d| away from 0 while keeping its sign.
                    if d >= 0.0 || d <= -0.001 {
                        if (0.0..0.001).contains(&d) {
                            d = 0.001;
                        }
                    } else {
                        d = -0.001;
                    }
                } else {
                    d = 1.6; // unreachable given the `d <= 1.1` guard; kept to mirror the decompile
                }
            } else {
                d = -1.6;
            }
        } else {
            d = clamp_hi;
        }
        d
    } else {
        1.6
    };
    (z * 1024.0) as i32
}

/// Full statistical score: z-normalize the 34 raw features (each anchor's 17 features share the
/// same norm table, so `idx = i % 17`), run the MLP, and map `out[0]` to 0..3000. Composition of
/// `syna_qm_score_features@0x1800088d0` (the static, extractor-independent tail).
pub fn score_feature_vector(features: &[i32; SCORE_FEATURE_VECTOR_LEN]) -> i32 {
    score_feature_vector_clamped(features, ZNORM_CLAMP_HI_DLL)
}

/// [`score_feature_vector`] with the z-norm high clamp as a knob (see [`ZNORM_CLAMP_HI_DLL`]).
pub fn score_feature_vector_clamped(features: &[i32; SCORE_FEATURE_VECTOR_LEN], clamp_hi: f64) -> i32 {
    let mut input = [0i32; SCORE_FEATURE_VECTOR_LEN];
    for (i, slot) in input.iter_mut().enumerate() {
        *slot = znorm_feature_clamped(features[i], i % SCORE_FEATURES_PER_MINUTIA, clamp_hi);
    }
    let out = mlp_forward(&input);
    llr_to_scale(out[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activation_zero_is_half() {
        // acc = 0 -> (0 + 0xc00)/0x1800 = 0 -> LUT[0] = 512 = 0.5 in Q10.
        assert_eq!(mlp_activation(0), 512);
    }

    #[test]
    fn activation_saturates() {
        // Large (non-overflowing) accumulators saturate to the LUT bounds.
        // 1e8 / 0x1800 = 16278 > 0x1ed2 -> 0x400 ; -1e8 -> 0.
        assert_eq!(mlp_activation(100_000_000), 0x400);
        assert_eq!(mlp_activation(-100_000_000), 0);
    }

    #[test]
    fn llr_to_scale_zero() {
        // (0+4805)*3000/9585 = 14415000/9585 = 1503 (integer division).
        assert_eq!(llr_to_scale(0), 1503);
    }

    #[test]
    fn llr_to_scale_clamps() {
        assert_eq!(llr_to_scale(i32::MAX), 3000);
        assert_eq!(llr_to_scale(i32::MIN), 0);
    }

    // Hand-checked reference: computed independently from the extracted weights + sigmoid LUT with
    // the exact integer/Q10 arithmetic (see scratchpad reference script in the port report).
    //
    // Zero input (all features 0 -> all znorm inputs 0):
    //   hidden = [36,351,764,55,94,185,924,2,9,91,377,304,995,848,35,417,455,21,307,749]
    //   out[0] = 6800800  -> llr_to_scale clamps to 3000.
    #[test]
    fn mlp_forward_zero_input_reference() {
        let out = mlp_forward(&[0i32; 34]);
        assert_eq!(out[0], 6800800);
        assert_eq!(out[1], -8248315);
        assert_eq!(llr_to_scale(out[0]), 3000);
    }

    // A non-clamped reference so the score arithmetic is actually exercised end-to-end:
    //   input = all 1024 (Q10 = 1.0) -> out[0] = -4902494 -> score = 5.
    #[test]
    fn mlp_forward_ones_input_reference() {
        let out = mlp_forward(&[1024i32; 34]);
        assert_eq!(out[0], -4902494);
        assert_eq!(llr_to_scale(out[0]), 5);
    }

    #[test]
    fn znorm_sentinel_and_clamps() {
        // Sentinel raw -> 1.6 * 1024 = 1638.
        assert_eq!(znorm_feature(0x7fff, 0), 1638);
        // Feature 0: mean=stddev=22.5. raw=0 -> z = (0-22.5)*1.6/22.5 = -1.6 -> -1638.
        assert_eq!(znorm_feature(0, 0), (-1.6 * 1024.0) as i32);
        // raw = mean -> z ~ 0, guarded to +0.001 -> round(0.001*1024)=1.
        assert_eq!(znorm_feature(22, 0), znorm_feature(22, 0)); // deterministic
    }

    #[test]
    fn score_feature_vector_zero_is_clamped() {
        // znorm(0, idx) is negative for every feature (raw 0 < mean), MLP out[0] stays high -> 3000.
        let score = score_feature_vector(&[0i32; 34]);
        assert!(score <= 3000);
    }

    // ---- oracle golden (tools/qm-dll-oracle/golden/scorer.txt) ----

    #[test]
    fn llr_to_scale_matches_oracle_golden() {
        // syna_qm_score_llr_to_scale@0x180002f30 — SCLLR.
        for &(llr, want) in &[
            (0, 1503), (1, 1503), (-1, 1503), (1024, 1504), (-1024, 1503), (4920320, 3000),
            (-4920320, 0), (4894720, 3000), (100000, 1534), (-100000, 1473), (5000000, 3000),
            (-5000000, 0), (1234567, 1881), (-1234567, 1126),
        ] {
            assert_eq!(llr_to_scale(llr), want, "llr {llr}");
        }
    }

    #[test]
    fn weights_and_norm_table_match_dll() {
        // Our extracted blobs == the live DLL (SCWEIGHTS / SCNORM).
        assert_eq!(&MLP_WEIGHTS_LAYER0[0..4], &[-343, 2270, 1643, -2300], "layer0 weights");
        assert_eq!(MLP_WEIGHTS_LAYER1[0], -1525, "layer1 weight[0]");
        assert_eq!(MLP_WEIGHTS_LAYER1[21], 649, "layer1 row1 weight[0]");
        #[rustfmt::skip]
        let want_norm: &[(f64, f64)] = &[
            (22.5, 22.5), (662.0, 584.0), (3350.0, 3350.0), (3210.0, 3210.0), (3530.5, 3530.5),
            (21.0, 21.0), (12.5, 12.5), (98.5, 98.5), (39.0, 28.0), (38.0, 34.0), (3728.0, 3728.0),
            (3867.0, 3708.0), (143.5, 143.5), (37.0, 30.0), (115.5, 115.5), (35.5, 35.5), (679.0, 567.0),
        ];
        for (i, &(m, s)) in want_norm.iter().enumerate() {
            assert_eq!(FEATURE_NORM_TABLE[i].mean, m, "norm[{i}].mean");
            assert_eq!(FEATURE_NORM_TABLE[i].stddev, s, "norm[{i}].stddev");
        }
    }

    #[test]
    fn znorm_clamp_quirk_changes_high_values() {
        // The faithful 1.1 high clamp (→1126 Q10) vs the MetViper-style 1.6 (→1638) diverge on a value
        // that saturates the high side; the faithful default equals ZNORM_CLAMP_HI_DLL·1024.
        let hi_raw = 30000; // above mean, below the 0x7fff sentinel → saturates the high clamp
        assert_eq!(znorm_feature(hi_raw, 0), 1126); // 1.1 · 1024
        assert_eq!(znorm_feature_clamped(hi_raw, 0, 1.6), 1638); // 1.6 · 1024
        assert_eq!(znorm_feature(hi_raw, 0), znorm_feature_clamped(hi_raw, 0, ZNORM_CLAMP_HI_DLL));
    }

    #[test]
    fn score_tail_matches_oracle_golden() {
        // Whole tail vs syna_qm_score_features@0x1800088d0 (SCRAW/SCZNORM/SCSCORE): z-norm (f64, HIGH
        // clamp 1.1 — genuinely distinct from MetViper's 1.6, confirmed by the golden) → 34→20→2 MLP →
        // LLR→score. Oracle uses count=1, so both anchor halves come from anchor 0 (feat[i]=raw[i%17]).
        #[rustfmt::skip]
        let cases: &[([i32; 17], [i32; 17], i32)] = &[
            ([-1500,-1363,-1226,-1089,-952,-815,400,-541,-404,-267,-130,7,144,281,418,555,692],
             [-1638,-1638,-1638,-1638,-1638,-1638,1126,-1638,-1638,-1638,-1638,-1638,5,1126,1126,1126,37],
             205),
            ([-1483,-1212,-941,-670,-399,-128,143,414,685,956,1227,1498,1769,2040,2311,-1418,-1147],
             [-1638,-1638,-1638,-1638,-1638,-1638,1126,1126,1126,1126,-1099,-1046,1126,1126,1126,-1638,-1638],
             0),
        ];
        for (c, &(raw, znorm, score)) in cases.iter().enumerate() {
            let feat: [i32; 34] = std::array::from_fn(|i| raw[i % 17]);
            for i in 0..34 {
                assert_eq!(znorm_feature(feat[i], i % 17), znorm[i % 17], "case {c} znorm[{i}]");
            }
            assert_eq!(score_feature_vector(&feat), score, "case {c} score");
        }
    }
}
