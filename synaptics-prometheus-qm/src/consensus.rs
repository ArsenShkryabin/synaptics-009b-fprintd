//! Geometric consensus gate: a 120×120 Hough translation vote grid over per-minutia Q16
//! similarity transforms.
//!
//! Ports (the vote-grid **mechanics** are bit-exact + oracle-validated — `golden/consensus.txt`):
//!   - [`apply_xform_q16`] — `syna_qm_apply_xform_q16@0x180006b10`. Bit-exact (`CXFORM`).
//!   - [`vote_grid_build`] — `syna_qm_vote_grid_build@0x18000bf20`: grid marking + per-transform `+0x9d`
//!     normalization. Bit-exact cell-for-cell (`CVOTE`). The gate is `has_match_result@0x18000bf00` =
//!     **`tx != 0 || ty != 0`** ([`VoteGate::Translation`], the faithful default) — an earlier port
//!     gated on a `valid_flag`, which is wrong (kept as the [`VoteGate::ValidFlag`] quirk toggle).
//!   - [`count_occupied`] — `syna_qm_vote_grid_count_occupied@0x18000c190`. Bit-exact (`CVOTE occ`).
//!
//! The **decision wrapper** `syna_qm_geometric_consensus@0x18000c5f0` (multi-level state machine over
//! `vote_grid_add_reference` / `consensus_pick_transform@0x18000c460` / `_finalize@0x18000bd40` /
//! `consensus_hash_grid` / `_update_point`) operates on the live matcher work-buffer + a level counter,
//! so it is **context-heavy, not a static leaf** — [`geometric_consensus_pick`] keeps a peak-support
//! stand-in for it, to be pinned alongside the Stage-5 live-matcher fixture.

use super::types::{
    SynaQmXformRecord, VOTE_GRID_BYTES, VOTE_GRID_CENTER, VOTE_GRID_SIDE, VOTE_MARK_STEP,
    VOTE_TRANSLATION_BIN_PX, XFORM_Q16_ROUND,
};

/// Apply a Q16 similarity transform to an integer point. Exact port of
/// `syna_qm_apply_xform_q16@0x180006b10`:
/// `x' = (cos·x − sin·y + 0x8000 + tx) >> 16`, `y' = (cos·y + 0x8000 + ty + sin·x) >> 16`.
pub fn apply_xform_q16(x: i32, y: i32, xf: &SynaQmXformRecord) -> (i32, i32) {
    let cos = xf.cos_q16;
    let sin = xf.sin_q16;
    let xp = ((cos * x - sin * y) + XFORM_Q16_ROUND + xf.tx) >> 16;
    let yp = ((cos * y + XFORM_Q16_ROUND + xf.ty) + sin * x) >> 16;
    (xp, yp)
}

/// The translation vote grid: 120×120 bytes, one vote count per translation bin.
pub struct VoteGrid {
    pub cells: Box<[u8; VOTE_GRID_BYTES]>,
}

impl Default for VoteGrid {
    fn default() -> Self {
        VoteGrid {
            cells: Box::new([0u8; VOTE_GRID_BYTES]),
        }
    }
}

impl VoteGrid {
    fn idx(bin_x: i32, bin_y: i32) -> usize {
        bin_y as usize * VOTE_GRID_SIDE + bin_x as usize
    }
}

/// Which predicate decides a transform votes — the gate `syna_qm_vote_grid_build` applies per record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteGate {
    /// **DLL-faithful** (`has_match_result@0x18000bf00` = `tx != 0 || ty != 0`): a transform with zero
    /// translation (e.g. the identity) has no match result and is skipped.
    Translation,
    /// The port's earlier (wrong) behaviour: gate on the struct's `valid_flag`. Kept as a curiosity
    /// toggle — an identity transform votes under this gate but not the faithful one.
    ValidFlag,
}

/// Build the translation vote grid from the candidate per-minutia transforms over a `w×h` sample
/// region — bit-exact port of `syna_qm_vote_grid_build@0x18000bf20` with the DLL-faithful
/// [`VoteGate::Translation`] gate. Returns `true` if at least one transform voted.
pub fn vote_grid_build(grid: &mut VoteGrid, xforms: &[SynaQmXformRecord], w: i32, h: i32) -> bool {
    vote_grid_build_gated(grid, xforms, w, h, VoteGate::Translation)
}

/// [`vote_grid_build`] with the vote gate selectable (see [`VoteGate`]).
///
/// Each voting transform marks each landing bin once (`+VOTE_MARK_STEP`, capped), then a
/// per-transform normalization pass (`+0x9d`, u8-wrapping) converts a just-marked cell (value 100)
/// into an incremented running count — so a cell's final value is the number of transforms that
/// voted that translation.
pub fn vote_grid_build_gated(
    grid: &mut VoteGrid,
    xforms: &[SynaQmXformRecord],
    w: i32,
    h: i32,
    gate: VoteGate,
) -> bool {
    grid.cells.fill(0);
    let mut any_valid = false;

    for xf in xforms {
        // has_match_result@0x18000bf00 gates on the record's translation (record+0xc = tx, +0x10 = ty).
        let votes = match gate {
            VoteGate::Translation => xf.tx != 0 || xf.ty != 0,
            VoteGate::ValidFlag => xf.valid_flag != 0,
        };
        if !votes {
            continue;
        }
        any_valid = true;

        // Mark every 8-px grid sample's landing bin, once per transform.
        let mut sy = 0;
        while sy < h {
            let mut sx = 0;
            while sx < w {
                let (xp, yp) = apply_xform_q16(sx, sy, xf);
                let bin_x = (VOTE_GRID_CENTER - (w / 2) / VOTE_TRANSLATION_BIN_PX)
                    + xp / VOTE_TRANSLATION_BIN_PX;
                let bin_y = yp / VOTE_TRANSLATION_BIN_PX
                    + (VOTE_GRID_CENTER - (h / 2) / VOTE_TRANSLATION_BIN_PX);
                if (bin_x as u32) < VOTE_GRID_SIDE as u32 && (bin_y as u32) < VOTE_GRID_SIDE as u32
                {
                    let cell = &mut grid.cells[VoteGrid::idx(bin_x, bin_y)];
                    if *cell < VOTE_MARK_STEP {
                        *cell += VOTE_MARK_STEP;
                    }
                }
                sx += VOTE_TRANSLATION_BIN_PX;
            }
            sy += VOTE_TRANSLATION_BIN_PX;
        }

        // Normalize: a marked cell (>= 100) wraps by +0x9d, turning 100 -> 1 (one vote), and a
        // previously-counted cell +100 -> +0x9d -> +1 more (running transform count).
        for cell in grid.cells.iter_mut() {
            if *cell >= VOTE_MARK_STEP {
                *cell = cell.wrapping_add(0x9d);
            }
        }
    }
    any_valid
}

/// Count the nonzero (occupied) cells of the vote grid — the consensus support size.
/// `syna_qm_vote_grid_count_occupied@0x18000c190`.
pub fn count_occupied(grid: &VoteGrid) -> usize {
    grid.cells.iter().filter(|&&c| c != 0).count()
}

/// The maximum vote count in any single translation bin (peak support).
pub fn peak_support(grid: &VoteGrid) -> u8 {
    grid.cells.iter().copied().max().unwrap_or(0)
}

/// Result of the geometric-consensus gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Consensus {
    /// Whether a globally-consistent alignment was found (the gate's boolean return).
    pub found: bool,
    /// Number of occupied translation bins (consensus support).
    pub occupied: usize,
    /// Peak vote count in a single bin.
    pub peak: u8,
}

/// Geometric-consensus gate with peak-selection refinement.
///
/// Ports `syna_qm_geometric_consensus@0x18000c5f0` structure:
/// vote grid build, occupancy/peak measurement, and `syna_qm_consensus_pick_transform@0x18000c460`
/// peak selection (simplified to max-peak bin when refinement helpers are unavailable).
pub fn geometric_consensus_pick(
    xforms: &[SynaQmXformRecord],
    w: i32,
    h: i32,
) -> Consensus {
    geometric_consensus_pick_gated(xforms, w, h, VoteGate::Translation)
}

/// [`geometric_consensus_pick`] with the vote gate selectable (see [`VoteGate`]). The matcher's 1:N
/// path uses [`VoteGate::Translation`] (faithful); enroll's same-view redundancy check uses
/// [`VoteGate::ValidFlag`] until the upstream per-minutia transform `tx`/`ty` are ported faithfully.
pub fn geometric_consensus_pick_gated(
    xforms: &[SynaQmXformRecord],
    w: i32,
    h: i32,
    gate: VoteGate,
) -> Consensus {
    let mut grid = VoteGrid::default();
    let any_valid = vote_grid_build_gated(&mut grid, xforms, w, h, gate);
    let occupied = count_occupied(&grid);
    let peak = peak_support(&grid);
    let found = any_valid && peak >= 2 && pick_transform_support(&grid, peak);
    Consensus {
        found,
        occupied,
        peak,
    }
}

/// Legacy peak-support gate (kept for unit tests).
pub fn geometric_consensus(
    xforms: &[SynaQmXformRecord],
    w: i32,
    h: i32,
    min_peak: u8,
) -> Consensus {
    let mut grid = VoteGrid::default();
    let any_valid = vote_grid_build(&mut grid, xforms, w, h);
    let occupied = count_occupied(&grid);
    let peak = peak_support(&grid);
    Consensus {
        found: any_valid && peak >= min_peak,
        occupied,
        peak,
    }
}

/// Whether the peak bin has sufficient support — stand-in for full finalize graph scoring.
fn pick_transform_support(grid: &VoteGrid, peak: u8) -> bool {
    peak >= 2 && grid.cells.contains(&peak)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xform(cos: i32, sin: i32, tx: i32, ty: i32) -> SynaQmXformRecord {
        SynaQmXformRecord { cos_q16: cos, sin_q16: sin, tx, ty, valid_flag: 1 }
    }
    fn identity() -> SynaQmXformRecord {
        xform(0x10000, 0, 0, 0)
    }
    fn translation(tx: i32, ty: i32) -> SynaQmXformRecord {
        xform(0x10000, 0, tx, ty)
    }

    #[test]
    fn apply_identity_is_noop() {
        assert_eq!(apply_xform_q16(30, 40, &identity()), (30, 40));
    }

    #[test]
    fn apply_translation() {
        assert_eq!(apply_xform_q16(10, 20, &translation(5 << 16, 7 << 16)), (15, 27));
    }

    #[test]
    fn apply_xform_matches_oracle_golden() {
        // CXFORM: apply_xform_q16@0x180006b10 (x, y, cos, sin, tx, ty) -> (x', y').
        // `(x, y, cos, sin, tx, ty, want_x, want_y)` — the golden line, in order.
        type Case = (i32, i32, i32, i32, i32, i32, i32, i32);
        #[rustfmt::skip]
        let cases: &[Case] = &[
            (30, 40, 0x10000, 0, 0, 0, 30, 40),
            (10, 20, 0x10000, 0, 5 << 16, 7 << 16, 15, 27),
            (25, 25, 46341, 46341, 0, 0, 0, 35),
            (50, 12, 56756, 32768, -3 << 16, 2 << 16, 34, 37),
            (0, 0, 0x10000, 0, 100 << 16, -40 << 16, 100, -40),
            (100, 100, -65536, 0, 0, 0, -100, -100),
        ];
        for &(x, y, cos, sin, tx, ty, wx, wy) in cases {
            assert_eq!(apply_xform_q16(x, y, &xform(cos, sin, tx, ty)), (wx, wy), "xform {x},{y}");
        }
    }

    #[test]
    fn vote_grid_matches_oracle_golden() {
        // CVOTE: two agreeing translations + an identity (tx=ty=0, SKIPPED by the faithful gate) + a
        // distinct translation over a 40×24 region → any=1, occ=17, peak=3.
        let xforms = [
            translation(5 << 16, 7 << 16),
            translation(5 << 16, 7 << 16),
            identity(), // tx=ty=0 → has_match_result false → skipped
            translation(13 << 16, -6 << 16),
        ];
        let mut grid = VoteGrid::default();
        assert!(vote_grid_build(&mut grid, &xforms, 40, 24));
        assert_eq!(count_occupied(&grid), 17, "occupied");
        assert_eq!(peak_support(&grid), 3, "peak");
        // exact nonzero cells (CVOTECELLS).
        #[rustfmt::skip]
        let want: &[(usize, u8)] = &[
            (7138,2),(7139,3),(7140,3),(7141,3),(7142,3),(7143,1),
            (7258,2),(7259,3),(7260,3),(7261,3),(7262,3),(7263,1),
            (7378,2),(7379,2),(7380,2),(7381,2),(7382,2),
        ];
        let got: Vec<(usize, u8)> =
            grid.cells.iter().enumerate().filter(|&(_, &c)| c != 0).map(|(i, &c)| (i, c)).collect();
        assert_eq!(got, want, "nonzero cells");
    }

    #[test]
    fn identity_is_skipped_by_faithful_gate_but_not_valid_flag() {
        // The gate quirk toggle: identity (tx=ty=0) votes under ValidFlag, is skipped under Translation.
        let mut grid = VoteGrid::default();
        assert!(!vote_grid_build(&mut grid, &[identity()], 40, 24), "faithful: no vote");
        assert_eq!(count_occupied(&grid), 0);
        assert!(
            vote_grid_build_gated(&mut grid, &[identity()], 40, 24, VoteGate::ValidFlag),
            "valid_flag quirk: identity votes"
        );
        assert!(count_occupied(&grid) > 0);
    }

    #[test]
    fn consensus_found_with_agreeing_transforms() {
        let c = geometric_consensus(&[translation(5 << 16, 7 << 16), translation(5 << 16, 7 << 16)], 40, 24, 2);
        assert!(c.found);
        assert_eq!(c.peak, 2);
    }
}
