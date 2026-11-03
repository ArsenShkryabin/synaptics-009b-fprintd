//! 677-wide MetViper input pool — port of `syna_qm_extract_feature_vector@0x1801178d0`
//! (Ghidra entry; also reachable at interior `0x180119e50`).
//!
//! CORRECTED 2026-07-21 (see `docs/qm/metviper-nnet-config.md` §CORRECTION): the DLL pool is **not**
//! per-site image features — it is a **query-vs-gallery MATCH feature vector**. For each ASP field
//! enabled by `NNET_INPUT_FLAGS` (`asp_ctx+0x1a44`), the DLL pushes either
//!   * a scalar diff `image_stat[off] − gallery_stat[off]` / a `[lo ≤ x ≤ hi]` range test, or
//!   * the 1-D Earth-Mover distance between the normalized query histogram and the normalized
//!     gallery histogram (`syna_qm_normalize_histogram@0x180119fe0` +
//!     `syna_qm_histogram_emd_distance@0x180117360`), optionally plus the per-bin diffs.
//!
//! The per-image ASP statistics are precomputed by the firmware/ASP engine; the host only reads and
//! diffs them against an enrolled gallery template. With no gallery, every feature is 0.
//!
//! This module ports `push_pool_feature` (`syna_qm_push_pool_feature@0x180117740`, the mask + Q10
//! scaling-LUT push) exactly. [`extract_feature_vector`] below is a **degenerate non-DLL stub**:
//! it fabricates a few image-only scalars because we have neither a populated ASP-context stat
//! struct nor a gallery template (golden vectors). It does NOT mirror the DLL's field layout and is
//! used only to keep the diagnostic grid-scan in `extractor.rs` runnable.

use crate::metviper::{normalize_pool_value, topology, DEFAULT_INPUT_FLAGS};
use crate::metviper_weights::{MetViperModel, ScalingPair};

/// Result of filling an input pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureVectorResult {
    pub count: u32,
    pub enabled: u32,
}

/// Push one raw value into the pool with optional Q10 normalization.
/// syna_qm_push_pool_feature@0x180117740.
pub fn push_pool_feature(
    raw: i32,
    pool: &mut [i32],
    count: &mut u32,
    lut_index: &mut u32,
    scaling: Option<&ScalingPair>,
    mask: Option<&[u8]>,
    use_mask: bool,
) {
    let idx = *count as usize;
    if idx < pool.len() {
        pool[idx] = raw;
    }
    *count += 1;

    let li = *lut_index as usize;
    let masked_ok = !use_mask
        || mask
            .and_then(|m| m.get(li))
            .copied()
            .unwrap_or(0) != 0;
    if masked_ok {
        *lut_index += 1;
        if let Some(pair) = scaling
            && idx < pool.len()
        {
            pool[idx] = normalize_pool_value(raw, pair);
        }
    }
}

/// Minimal image-side context for extraction (no gallery template).
#[derive(Debug, Clone)]
pub struct ExtractImageContext {
    pub width: u16,
    pub height: u16,
    pub mean: u32,
    pub stddev: u32,
    pub min: u8,
    pub max: u8,
    pub input_flags: u32,
}

impl ExtractImageContext {
    pub fn from_pixels(pixels: &[u8], width: u16, height: u16) -> Self {
        let n = pixels.len().max(1) as u64;
        let sum: u64 = pixels.iter().map(|&p| p as u64).sum();
        let mean = (sum / n) as u32;
        let var: u64 = pixels
            .iter()
            .map(|&p| {
                let d = p as i64 - mean as i64;
                (d * d) as u64
            })
            .sum();
        let stddev = ((var / n) as f64).sqrt().round() as u32;
        Self {
            width,
            height,
            mean,
            stddev: stddev.max(1),
            min: *pixels.iter().min().unwrap_or(&0),
            max: *pixels.iter().max().unwrap_or(&0),
            input_flags: DEFAULT_INPUT_FLAGS,
        }
    }
}

struct PoolBuilder<'a> {
    pool: &'a mut [i32],
    count: u32,
    lut_index: u32,
    model: &'a MetViperModel,
}

impl<'a> PoolBuilder<'a> {
    fn push(&mut self, raw: i32) {
        let scaling = self.model.scaling_lut.get(self.lut_index as usize);
        push_pool_feature(
            raw,
            self.pool,
            &mut self.count,
            &mut self.lut_index,
            scaling,
            Some(&self.model.input_mask),
            true,
        );
    }

    fn finish(self) -> FeatureVectorResult {
        FeatureVectorResult {
            count: self.count,
            enabled: self.lut_index,
        }
    }
}

/// Build a 677-wide pool from image context. **Degenerate non-DLL stub** — the real
/// `syna_qm_extract_feature_vector@0x1801178d0` diffs precomputed ASP histograms against a gallery
/// template (see module docs); with neither available host-side this fabricates image-only scalars
/// so the diagnostic grid-scan can run. Not bit-exact with the DLL and not intended to be.
pub fn extract_feature_vector(
    ctx: &ExtractImageContext,
    local_patch: Option<&[u8]>,
    model: &MetViperModel,
) -> (Vec<i32>, FeatureVectorResult) {
    let mut pool = vec![0i32; topology::INPUT_POOL];
    let mut b = PoolBuilder {
        pool: pool.as_mut_slice(),
        count: 0,
        lut_index: 0,
        model,
    };

    if (ctx.input_flags & 1) != 0 {
        b.push(ctx.height as i32);
        b.push(ctx.width as i32);
        b.push(0);
        b.push(ctx.mean as i32);
        b.push(ctx.stddev as i32);
        b.push(ctx.min as i32);
        b.push(ctx.max as i32);
    }

    if (ctx.input_flags & 2) != 0 {
        b.push(ctx.width as i32 * ctx.height as i32);
        b.push(ctx.mean as i32);
        b.push(ctx.stddev as i32);
    }

    if (ctx.input_flags & 4) != 0 {
        if let Some(patch) = local_patch {
            for chunk in patch.chunks(4).take(0x3b) {
                let v: i32 = chunk.iter().map(|&b| b as i32).sum();
                b.push(v);
            }
        } else {
            for _ in 0..0x3b {
                b.push(0);
            }
        }
    }

    while (b.count as usize) < topology::INPUT_POOL && b.lut_index < topology::INPUT_POOL as u32 {
        b.push(0);
    }

    let meta = b.finish();
    (pool, meta)
}

/// Convenience: build pool with the embedded default model.
pub fn build_raw_pool(ctx: &ExtractImageContext, local_patch: Option<&[u8]>) -> Vec<i32> {
    let model = MetViperModel::embedded_default();
    extract_feature_vector(ctx, local_patch, &model).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_produces_full_pool() {
        let ctx = ExtractImageContext::from_pixels(&[128u8; 144 * 56], 144, 56);
        let pool = build_raw_pool(&ctx, None);
        assert_eq!(pool.len(), topology::INPUT_POOL);
    }
}
