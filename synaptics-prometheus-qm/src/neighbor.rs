//! Per-minutia local neighborhood construction and candidate pairing.
//!
//! Ports: `syna_qm_build_neighbor_candidates@0x180003830`.

use crate::descriptor::{
    build_candidates_from_indices, build_candidates_from_indices_into, NeighborCandidate,
};
use crate::template::Minutia;

/// Runtime neighbor context for one minutia — mirrors `SynaQmMinutiaNeighbors`.
#[derive(Debug, Clone)]
pub struct MinutiaNeighbors {
    pub indices: Vec<u8>,
    /// Split between near `[0..primary_count)` and far `[primary_count..]`.
    pub primary_count: u8,
}

impl MinutiaNeighbors {
    pub fn from_all(minutiae: &[Minutia], self_idx: usize, primary_count: u8) -> Self {
        let mut order: Vec<(u32, u8)> = minutiae
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != self_idx)
            .map(|(i, m)| {
                let dx = m.x as i32 - minutiae[self_idx].x as i32;
                let dy = m.y as i32 - minutiae[self_idx].y as i32;
                ((dx * dx + dy * dy) as u32, i as u8)
            })
            .collect();
        order.sort_by_key(|(d, _)| *d);
        let indices: Vec<u8> = order.into_iter().map(|(_, i)| i).collect();
        Self {
            primary_count: primary_count.min(indices.len() as u8),
            indices,
        }
    }
}

/// Build neighbor candidates using near/far split — `syna_qm_build_neighbor_candidates@0x180003830`.
pub fn build_neighbor_candidates(
    probe_ctx: &MinutiaNeighbors,
    gallery_ctx: &MinutiaNeighbors,
    probe: &[Minutia],
    gallery: &[Minutia],
) -> Vec<NeighborCandidate> {
    let probe_near: Vec<Minutia> = probe_ctx.indices[..probe_ctx.primary_count as usize]
        .iter()
        .map(|&i| probe[i as usize])
        .collect();
    let gallery_near: Vec<Minutia> = gallery_ctx.indices[..gallery_ctx.primary_count as usize]
        .iter()
        .map(|&i| gallery[i as usize])
        .collect();
    let mut out = build_candidates_from_indices(&probe_near, &gallery_near);
    if out.len() < 100 {
        let probe_far: Vec<Minutia> = probe_ctx.indices[probe_ctx.primary_count as usize..]
            .iter()
            .map(|&i| probe[i as usize])
            .collect();
        let gallery_far: Vec<Minutia> = gallery_ctx.indices[gallery_ctx.primary_count as usize..]
            .iter()
            .map(|&i| gallery[i as usize])
            .collect();
        build_candidates_from_indices_into(&probe_far, &gallery_far, &mut out);
    }
    out
}
