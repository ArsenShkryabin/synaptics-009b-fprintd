//! Local-neighbor descriptor matching: 64-bit Hamming distance + the neighbor-candidate pairing.
//!
//! Ports:
//!   - `syna_qm_descriptor_hamming_dist@0x180003490` — popcount(xor)·2 over the 64-bit descriptor.
//!   - `syna_qm_angle_diff_mod180@0x1800045d0` — undirected orientation distance mod 180°.
//!   - `syna_qm_pair_neighbor_candidates@0x1800035f0` — best/2nd-best neighbor pairing with the
//!     Lowe-ratio / spatial acceptance gate.
//!   - `syna_qm_neighbor_cand_cmp_by_dist@0x1800045b0` — the ascending-by-distance sort, top ≤25.

use super::template::Minutia;
use super::types::{
    DESCRIPTOR_ACCEPT_MAX_DIST, MAX_CANDIDATE_PAIRS, MAX_NEIGHBOR_CANDIDATES,
    NEIGHBOR_RATIO_TEST_PCT, NEIGHBOR_SPATIAL_DIST2_MAX,
};

/// Initial best/2nd-best distance seed used by `syna_qm_pair_neighbor_candidates@0x1800035f0`
/// (`uVar8 = uVar7 = 0x40`). Acts as a prefilter: a neighbor must beat 64 to become "best".
const HAMMING_SEED: u32 = 0x40;

/// Hamming distance between two 64-bit binary descriptors, matching
/// `syna_qm_descriptor_hamming_dist@0x180003490`: it XORs the words, sums the set bits via a
/// 256-entry popcount LUT (`g_abSynaQmPopcountTable@0x18014e1a0`), and returns `popcount·2`.
/// Range 0..=128; lower = more similar. (`u8::count_ones` is bit-identical to the LUT sum.)
pub fn hamming(a: &[u8; 8], b: &[u8; 8]) -> u32 {
    a.iter()
        .zip(b)
        .map(|(x, y)| (x ^ y).count_ones())
        .sum::<u32>()
        * 2
}

/// Undirected orientation distance, `syna_qm_angle_diff_mod180@0x1800045d0`. Angles are ridge
/// orientations in degrees (read as bytes). Uses C-style truncated remainder (matched by Rust's
/// `%` on `i32`).
pub fn angle_diff_mod180(a: u8, b: u8) -> i32 {
    let modulus = super::types::ANGLE_MODULUS_DEG as i32; // 0xb4 = 180
    let fold = super::types::ANGLE_FOLD_DEG as i32; // 0x5a = 90
    let d = b as i32 - a as i32;
    let i1 = (d - fold) % modulus;
    let i2 = d % modulus;
    i1.min(i2)
}

/// One candidate neighbor correspondence (Ghidra `SynaQmNeighborCandidate`, stride 0x1c).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeighborCandidate {
    pub probe_x: i32,
    pub probe_y: i32,
    pub gallery_x: i32,
    pub gallery_y: i32,
    pub probe_angle: u32,
    pub gallery_angle: u32,
    /// Descriptor Hamming distance (0..=128) — the sort key, lower = better.
    pub hamming_dist: i32,
}

/// For each probe neighbor, find its best + 2nd-best gallery neighbor by descriptor Hamming
/// distance and accept the pair per the vendor gate, appending to `out`. Bit-faithful port of
/// `syna_qm_pair_neighbor_candidates@0x1800035f0`.
///
/// Acceptance: `(lowe_ratio > 116% OR spatial_dist² < 36) AND best < 96`, where `lowe_ratio =
/// (2nd·100)/(best+1)` and `spatial_dist²` is the squared coordinate distance between the best and
/// 2nd-best *gallery* neighbours. Caps the output at [`MAX_CANDIDATE_PAIRS`] (100).
pub fn pair_neighbor_candidates(
    out: &mut Vec<NeighborCandidate>,
    probe: &[Minutia],
    gallery: &[Minutia],
) {
    if gallery.is_empty() {
        return;
    }
    for p in probe {
        let mut best = HAMMING_SEED;
        let mut second = HAMMING_SEED;
        let mut best_idx = 0usize;
        let mut second_idx = 0usize;
        for (gi, g) in gallery.iter().enumerate() {
            let d = hamming(&p.descriptor, &g.descriptor);
            if d < best {
                second = best;
                second_idx = best_idx;
                best = d;
                best_idx = gi;
            } else if d < second {
                second = d;
                second_idx = gi;
            }
        }

        let dx = gallery[best_idx].x as i32 - gallery[second_idx].x as i32;
        let dy = gallery[best_idx].y as i32 - gallery[second_idx].y as i32;
        let spatial2 = (dx * dx + dy * dy) as u32;
        let lowe = (second * 100) / (best + 1);

        if (lowe > NEIGHBOR_RATIO_TEST_PCT || spatial2 < NEIGHBOR_SPATIAL_DIST2_MAX)
            && best < DESCRIPTOR_ACCEPT_MAX_DIST
        {
            out.push(NeighborCandidate {
                probe_x: p.x as i32,
                probe_y: p.y as i32,
                gallery_x: gallery[best_idx].x as i32,
                gallery_y: gallery[best_idx].y as i32,
                probe_angle: p.angle_deg as u32,
                gallery_angle: gallery[best_idx].angle_deg as u32,
                hamming_dist: best as i32,
            });
            if out.len() == MAX_CANDIDATE_PAIRS {
                return;
            }
        }
    }
}

/// Build the neighbor-candidate list between two minutia sets, sorted ascending by Hamming
/// distance and truncated to the top [`MAX_NEIGHBOR_CANDIDATES`] (25).
pub fn build_candidates(probe: &[Minutia], gallery: &[Minutia]) -> Vec<NeighborCandidate> {
    let mut v = Vec::new();
    pair_neighbor_candidates(&mut v, probe, gallery);
    sort_and_truncate(&mut v);
    v
}

/// Like [`build_candidates`] but caller supplies pre-indexed neighbor subsets.
pub fn build_candidates_from_indices(probe: &[Minutia], gallery: &[Minutia]) -> Vec<NeighborCandidate> {
    let mut v = Vec::new();
    build_candidates_from_indices_into(probe, gallery, &mut v);
    sort_and_truncate(&mut v);
    v
}

/// Append pairings into `out` without sorting/truncating (for near+far merge).
pub fn build_candidates_from_indices_into(
    probe: &[Minutia],
    gallery: &[Minutia],
    out: &mut Vec<NeighborCandidate>,
) {
    pair_neighbor_candidates(out, probe, gallery);
}

fn sort_and_truncate(v: &mut Vec<NeighborCandidate>) {
    v.sort_by_key(|c| c.hamming_dist);
    v.truncate(MAX_NEIGHBOR_CANDIDATES);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(desc: [u8; 8], x: u8, y: u8, a: u16) -> Minutia {
        Minutia {
            descriptor: desc,
            x,
            y,
            angle_deg: a,
        }
    }

    #[test]
    fn hamming_identical_is_zero() {
        let d = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67];
        assert_eq!(hamming(&d, &d), 0);
    }

    #[test]
    fn hamming_is_popcount_times_two() {
        let a = [0u8; 8];
        let b = [0xffu8; 8]; // 64 differing bits
        assert_eq!(hamming(&a, &b), 64 * 2);
        let c = [0b1010_1010u8, 0, 0, 0, 0, 0, 0, 0]; // 4 bits
        assert_eq!(hamming(&a, &c), 4 * 2);
        // one differing byte with 3 set bits -> 6
        let e = [0b0000_0111u8, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(hamming(&a, &e), 3 * 2);
    }

    #[test]
    fn angle_diff_matches_decompile() {
        // Faithful to syna_qm_angle_diff_mod180 (C truncated `%`, so it is NOT symmetric and can be
        // negative — the kernel consumes it accordingly).
        // Even equal orientations fold to -90 via the -0x5a offset: min((0-90)%180, 0%180) = -90.
        assert_eq!(angle_diff_mod180(90, 90), -90);
        assert_eq!(angle_diff_mod180(10, 170), 70); // d=160: min((160-90)%180, 160%180)=70
        assert_eq!(angle_diff_mod180(170, 10), -160); // d=-160: min(-70,-160)=-160
    }

    #[test]
    fn pairing_accepts_close_descriptor() {
        // probe neighbor exactly matches gallery[0]; gallery[1] is far -> strong Lowe ratio.
        let probe = vec![m([0xaa; 8], 5, 5, 0)];
        let gallery = vec![m([0xaa; 8], 9, 9, 0), m([0x55; 8], 40, 40, 90)];
        let cands = build_candidates(&probe, &gallery);
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].hamming_dist, 0);
        assert_eq!((cands[0].gallery_x, cands[0].gallery_y), (9, 9));
    }

    #[test]
    fn pairing_rejects_on_weak_ratio_and_spread() {
        // Two moderately-close gallery neighbors at distant coords: best=40, second=44 ->
        // lowe = 44*100/41 = 107 (<= 116), and spatial² between them is 200 (>= 36) -> rejected.
        // (20 set bits -> hamming 40; 22 set bits -> 44.)
        let probe = vec![m([0x00; 8], 5, 5, 0)];
        let gallery = vec![
            m([0xff, 0xff, 0x0f, 0, 0, 0, 0, 0], 0, 0, 0),
            m([0xff, 0xff, 0x3f, 0, 0, 0, 0, 0], 10, 10, 0),
        ];
        let mut out = Vec::new();
        pair_neighbor_candidates(&mut out, &probe, &gallery);
        assert!(out.is_empty());
    }
}
