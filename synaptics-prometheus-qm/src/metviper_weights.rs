//! Static MetViper `7fbMetViper_QM` model blobs — `g_anSynaMetViperQmWeights_default@0x1801f3ce0`,
//! `g_abSynaMetViperQmInputMask@0x1801f27a0`, `g_adSynaMetViperQmScalingLUT@0x1801f27b0`.
//!
//! Topology: 677 → 36 → 2 (see `docs/qm/metviper-nnet-config.md`).

use crate::metviper::topology;

/// Embedded weight blob (24482 × i32 LE). syna_get_embedded_fw_manifest_nnet@0x180117430.
pub static WEIGHTS_BYTES: &[u8] = include_bytes!("../data/metviper_weights.bin");

/// Per-input enable mask (678 bytes; index 677 is guard). g_abSynaMetViperQmInputMask@0x1801f27a0.
pub static INPUT_MASK_BYTES: &[u8] = include_bytes!("../data/metviper_mask.bin");

/// Per-input `{mean, stddev}` scaling pairs (677 × f64 × 2 LE). g_adSynaMetViperQmScalingLUT@0x1801f27b0.
pub static SCALING_LUT_BYTES: &[u8] = include_bytes!("../data/metviper_lut.bin");

/// Expected on-disk sizes (sanity-checked at load time).
pub mod blob_sizes {
    use super::topology;

    pub const WEIGHTS: usize = topology::WEIGHT_COUNT * 4;
    pub const INPUT_MASK: usize = topology::INPUT_POOL + 1;
    pub const SCALING_LUT: usize = topology::INPUT_POOL * 8;
}

/// Bias accumulation scale — same Q10 convention as the match scorer MLP.
/// syna_qm_matrix_multiply_simd@0x18010eca0 (`bias * 0x400`).
pub const METVIPER_BIAS_SCALE: i32 = 0x400;

/// One `{mean, stddev}` pair from the scaling LUT. syna_qm_push_pool_feature@0x180117740 (LUT path).
#[derive(Debug, Clone, Copy)]
pub struct ScalingPair {
    pub mean: f32,
    pub stddev: f32,
}

/// Parsed static MetViper model.
#[derive(Debug, Clone)]
pub struct MetViperModel {
    pub weights: Vec<i32>,
    pub input_mask: Vec<u8>,
    pub scaling_lut: Vec<ScalingPair>,
}

impl MetViperModel {
    /// Load the embedded default model; panics in debug if blob sizes drift.
    pub fn embedded_default() -> Self {
        assert_eq!(WEIGHTS_BYTES.len(), blob_sizes::WEIGHTS);
        assert_eq!(INPUT_MASK_BYTES.len(), blob_sizes::INPUT_MASK);
        assert_eq!(SCALING_LUT_BYTES.len(), blob_sizes::SCALING_LUT);
        Self::from_bytes(WEIGHTS_BYTES, INPUT_MASK_BYTES, SCALING_LUT_BYTES)
    }

    pub fn from_bytes(weights: &[u8], mask: &[u8], lut: &[u8]) -> Self {
        let weights = bytes_to_i32_vec(weights);
        assert_eq!(weights.len(), topology::WEIGHT_COUNT);
        let input_mask = mask.to_vec();
        assert!(input_mask.len() >= topology::INPUT_POOL);
        let scaling_lut = parse_scaling_lut(lut);
        assert_eq!(scaling_lut.len(), topology::INPUT_POOL);
        Self {
            weights,
            input_mask,
            scaling_lut,
        }
    }

    /// Layer-0 row width: input + bias.
    pub const fn layer0_row_len() -> usize {
        topology::INPUT_POOL + 1
    }

    /// Layer-1 row width: hidden + bias.
    pub const fn layer1_row_len() -> usize {
        topology::HIDDEN + 1
    }
}

fn bytes_to_i32_vec(bytes: &[u8]) -> Vec<i32> {
    bytes
        .chunks_exact(4)
        .map(|c| i32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

fn parse_scaling_lut(bytes: &[u8]) -> Vec<ScalingPair> {
    bytes
        .chunks_exact(8)
        .map(|c| ScalingPair {
            mean: f32::from_le_bytes([c[0], c[1], c[2], c[3]]),
            stddev: f32::from_le_bytes([c[4], c[5], c[6], c[7]]),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_blobs_parse() {
        let m = MetViperModel::embedded_default();
        assert_eq!(m.weights.len(), topology::WEIGHT_COUNT);
        assert_eq!(m.scaling_lut.len(), topology::INPUT_POOL);
        assert!(m.input_mask.iter().any(|&b| b != 0));
    }
}
