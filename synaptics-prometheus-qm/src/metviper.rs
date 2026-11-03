//! MetViper ASP post-match path — distinct from QuantumMatcher extraction.
//!
//! Call chain: `syna_asp_dev_extract_template@0x180104350` →
//! `syna_metviper_extract_wrap@0x18010c880` → `syna_metviper_run_qm_nnet@0x18010db20`.
//!
//! Static default model `"7fbMetViper_QM"`: weights @ `0x1801f3ce0` (677→36→2),
//! mask @ `0x1801f27a0`, scaling LUT @ `0x1801f27b0`.

use crate::metviper_weights::{MetViperModel, METVIPER_BIAS_SCALE, ScalingPair};
use crate::scorer::mlp_activation;

/// Model selector context offsets. syna_get_embedded_fw_manifest_nnet@0x180117430.
pub mod ctx_off {
    /// Firmware nnet config pointer.
    pub const FW_NNET_CFG: u64 = 0x1a70;
    /// Firmware nnet config length/aux.
    pub const FW_NNET_AUX: u64 = 0x1a78;
    /// Static model name buffer.
    pub const MODEL_NAME: u64 = 0x1a60;
    /// Second network descriptor used by second matrix multiply.
    pub const SECOND_NET: u64 = 0x1be0;
}

/// Static embedded model name. g_anSynaMetViperQmWeights_default@0x1801f3ce0.
pub const DEFAULT_MODEL_NAME: &str = "7fbMetViper_QM";

/// Static `NNET_INPUT_FLAGS` for the default model. SynaNnetConfig+0x24.
pub const DEFAULT_INPUT_FLAGS: u32 = 0x7fbefffd;

/// Topology for the static MetViper final-score sub-net.
pub mod topology {
    pub const INPUT_POOL: usize = 677;
    pub const HIDDEN: usize = 36;
    pub const OUTPUT: usize = 2;
    pub const WEIGHT_COUNT: usize = (INPUT_POOL + 1) * HIDDEN + (HIDDEN + 1) * OUTPUT;
}

/// Normalize one raw pool slot via the scaling LUT — bit-exact port of the `uVar1 < param_8` (valid-LUT)
/// path of `syna_qm_push_pool_feature@0x180117740`: `d = (raw − mean)·1.6/stddev` in IEEE-754 doubles
/// (`mean`/`stddev` are `f32` promoted to `f64`, `raw` is `i32→f64`), clamped to `[−1.6, 1.6]`, with tiny
/// non-zero magnitudes snapped away from zero to `±0.001`, then `(int)(d·1024)` (truncate toward zero).
///
/// NOTE the DLL upper clamp is **1.6** (an earlier port used 1.6 as the LOWER limit only and clamped the
/// high side to 1.1, and checked it first — both wrong; validated against `MVNORM` golden).
#[allow(clippy::manual_range_contains)] // mirror the DLL's exact comparison branch structure
pub fn normalize_pool_value(raw: i32, pair: &ScalingPair) -> i32 {
    let mut d = ((raw as f64) - f64::from(pair.mean)) * 1.6 / f64::from(pair.stddev);
    if d < -1.6 {
        d = -1.6;
    } else if d <= 1.6 {
        if d < 0.0 && d > -0.001 {
            d = -0.001;
        } else if d >= 0.0 && d < 0.001 {
            d = 0.001;
        }
    } else {
        d = 1.6;
    }
    (d * 1024.0) as i32
}

/// Apply input mask + scaling LUT to a raw feature pool, producing Q10 MLP inputs.
pub fn apply_input_mask_and_scaling(
    raw: &[i32],
    model: &MetViperModel,
) -> Vec<i32> {
    let n = topology::INPUT_POOL.min(raw.len());
    let mut out = vec![0i32; n];
    for i in 0..n {
        if model.input_mask.get(i).copied().unwrap_or(0) == 0 {
            out[i] = 0;
        } else {
            out[i] = normalize_pool_value(raw[i], &model.scaling_lut[i]);
        }
    }
    out
}

/// Two-layer forward pass. syna_qm_matrix_multiply_simd@0x18010eca0.
pub fn mlp_forward_q10(input: &[i32], model: &MetViperModel) -> [i32; topology::OUTPUT] {
    const IN: usize = topology::INPUT_POOL;
    const HID: usize = topology::HIDDEN;
    const ROW0: usize = IN + 1;
    const ROW1: usize = HID + 1;

    let w = &model.weights;
    let mut hidden = [0i32; HID];
    for (j, h) in hidden.iter_mut().enumerate() {
        let row = &w[j * ROW0..j * ROW0 + ROW0];
        let mut acc: i32 = 0;
        for k in 0..IN {
            acc = acc.wrapping_add(row[k].wrapping_mul(input[k]));
        }
        acc = acc.wrapping_add(row[IN].wrapping_mul(METVIPER_BIAS_SCALE));
        *h = mlp_activation(acc);
    }

    let base1 = HID * ROW0;
    let mut out = [0i32; topology::OUTPUT];
    for (j, o) in out.iter_mut().enumerate() {
        let row = &w[base1 + j * ROW1..base1 + j * ROW1 + ROW1];
        let mut acc: i32 = 0;
        for k in 0..HID {
            acc = acc.wrapping_add(row[k].wrapping_mul(hidden[k]));
        }
        acc = acc.wrapping_add(row[HID].wrapping_mul(METVIPER_BIAS_SCALE));
        // Last layer linear: syna_qm_matrix_multiply_simd with param_6 != 0.
        let rounded = acc.wrapping_add((acc >> 31) & 0x3ff);
        *o = rounded >> 10;
    }
    out
}

/// MetViper 677→36→2 runner on a raw (pre-LUT) input pool.
pub fn run_qm_nnet(raw_pool: &[i32]) -> Result<[i32; topology::OUTPUT], MetViperError> {
    if raw_pool.len() < topology::INPUT_POOL {
        return Err(MetViperError::InputTooShort);
    }
    let model = MetViperModel::embedded_default();
    let q10 = apply_input_mask_and_scaling(raw_pool, &model);
    Ok(mlp_forward_q10(&q10, &model))
}

/// Convenience wrapper when the caller already has Q10-normalized inputs.
pub fn run_qm_nnet_q10(input_q10: &[i32; topology::INPUT_POOL]) -> [i32; topology::OUTPUT] {
    let model = MetViperModel::embedded_default();
    mlp_forward_q10(input_q10, &model)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MetViperError {
    #[error("MetViper input pool too short")]
    InputTooShort,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_raw_pool_runs() {
        let raw = vec![0i32; topology::INPUT_POOL];
        let out = run_qm_nnet(&raw).unwrap();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn normalize_clamps_small_positive() {
        let pair = ScalingPair {
            mean: 0.0,
            stddev: 1.0,
        };
        assert_eq!(normalize_pool_value(0, &pair), 1);
    }

    // ---- oracle golden (tools/qm-dll-oracle/golden/metviper.txt) ----

    #[test]
    fn activation_matches_oracle_golden() {
        // The hidden activation FUN_18010ebe0 (which the port reuses via scorer::mlp_activation) —
        // MVACT lines. Confirms the two Q10 sigmoid LUTs (DAT_1801f1be0 == DAT_18014a2b0) agree.
        use crate::scorer::mlp_activation;
        for &(acc, want) in &[
            (0, 512), (1, 512), (-1, 512), (3072, 513), (-3072, 511), (6144, 513), (-6144, 511),
            (4194304, 1006), (-4194304, 18), (1193046, 775), (-1193046, 249), (8191, 513),
            (-8191, 511), (100000, 536), (-100000, 488),
        ] {
            assert_eq!(mlp_activation(acc), want, "activation({acc})");
        }
        // Spot-check the LUT the port carries against DAT_1801f1be0 (MVLUT16, indices 0,64,128,…).
        let lut = crate::scorer_weights::MLP_ACTIVATION_LUT;
        let spot = [512, 607, 695, 773, 837, 888, 926, 955, 975, 990, 1000, 1008, 1013, 1016, 1019, 1020];
        for (n, &v) in spot.iter().enumerate() {
            assert_eq!(lut[n * 64] as i32, v, "LUT[{}]", n * 64);
        }
    }

    #[test]
    fn embedded_weights_match_dll() {
        // Our extracted metviper_weights.bin == the live g_abSynaMetViperQmWeights_default (MVWEIGHTS).
        let m = MetViperModel::embedded_default();
        assert_eq!(&m.weights[0..8], &[68, 344, 0, 327, -168, 279, 197, 21], "layer0 weights[0..8]");
        const ROW0: usize = topology::INPUT_POOL + 1; // 678
        const ROW1: usize = topology::HIDDEN + 1; // 37
        assert_eq!(m.weights[topology::HIDDEN * ROW0], -2160, "layer1 weight[0]");
        assert_eq!(m.weights[topology::HIDDEN * ROW0 + ROW1], 2122, "layer1 row1 weight[0]");
    }

    #[test]
    fn normalize_matches_oracle_golden() {
        // syna_qm_push_pool_feature valid-LUT path (MVNORM). mean/stddev given as their f32 bit patterns.
        for &(raw, mb, sb, want) in &[
            (0i32, 0u32, 1065353216u32, 1i32),
            (100, 0, 1065353216, 1638),
            (1000, 1140457472, 1120403456, 1638),
            (-1000, 0, 1065353216, -1638),
            (5, 0, 1176256512, 1),
            (-5, 0, 1176256512, -1),
            (12345, 1120403456, 1080033280, 1638),
            (-12345, 3267887104, 1080033280, -1638),
            (700, 1143111680, 1109393408, 1638),
        ] {
            let pair = ScalingPair { mean: f32::from_bits(mb), stddev: f32::from_bits(sb) };
            assert_eq!(normalize_pool_value(raw, &pair), want, "normalize({raw}, {mb}, {sb})");
        }
    }

    /// The oracle's two deterministic Q10 input pools (case 0/1).
    fn mlp_input(cse: i32) -> [i32; topology::INPUT_POOL] {
        std::array::from_fn(|i| ((i as i32 * if cse != 0 { 977 } else { 613 } + cse * 41) % 3277) - 1638)
    }

    #[test]
    fn mlp_forward_matches_oracle_golden() {
        // Full 677→36→2 forward vs syna_qm_matrix_multiply_simd on the LIVE weights (MVMLP).
        let model = MetViperModel::embedded_default();
        for &(cse, want) in &[(0i32, [4397i32, -4918]), (1, [-9826, 9406])] {
            assert_eq!(mlp_forward_q10(&mlp_input(cse), &model), want, "mlp case {cse}");
        }
    }
}
