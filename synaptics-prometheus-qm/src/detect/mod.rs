//! Host-side classical minutiae detector — port of `syna_qm_detect_minutiae@0x18000aa00` and its
//! kernel tree. On this SKU the sensor only images; this is where minutiae `(x, y, angle, class)`
//! actually come from. Full kernel map + record layout:
//! `../../docs/qm/qm-minutiae-detector.md`.
//!
//! Port status (phased, see the plan): this module currently provides the **primitives** tier —
//! config table, candidate record, tile geometry, sub-pixel coord de-offset, and the four sort keys.
//! The DSP response field, NMS detector, and PASS-2 descriptor land in later phases (`field`,
//! `emit`, `refine` sub-modules).
//!
//! Fixed-point: Q16.16 via raw `i32` shifts mirroring the decompile (AGENTS.md #5), never a
//! fixed-point crate (its rounding diverges from the DLL's truncating shifts).

pub mod config;
pub mod descriptor;
pub mod emit;
pub mod field;
pub mod fixedtrig;

pub use config::{config_for, DetectConfig, Subtype, SUBTYPE_2449};
pub use descriptor::{
    describe, describe_dll, descriptor_brief_dll, finalize_angle_deg, pair_geometry_dll, qm_cos_lut,
    qm_sin_lut, DescriptorGeometry, SamplePoint, DESCRIPTOR_BYTES, DESC_RADIUS_DLL, ORIENT_SCALE_DLL,
};
pub use emit::{
    adaptive_threshold, detect_peaks, interior_max, minutia_class, refine_and_reject, reject_border, NmsParams,
};
pub use field::{
    conditioned_to_u8, doh_response, gaussian_kernel_dll, gaussian_taps, orientation_deg,
    orientation_from_hessian, DohField, DohParams, CONDITIONED_DC_BIAS,
};

/// Q16.16 fractional bits — the detector works in 16.16 fixed point (`px << 16`, `v >> 0x10`).
pub const Q16_SHIFT: u32 = 16;

/// One detector candidate/minutia — the Rust mirror of the DLL's stride-`0x20` record
/// (`syna_qm_detect_minutiae` array element). Field offsets in the doc's record table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Candidate {
    /// +0x00 — packed 64-bit neighbor descriptor (filled in PASS-2; zero until then).
    pub descriptor: [u8; 8],
    /// +0x08 — class/polarity byte: `0` = class A (ridge ending), `≠0` = class B (bifurcation).
    pub class: u8,
    /// +0x09 — source tile index `row*3 + col` (0..8).
    pub tile: u8,
    /// +0x0c — orientation (set in PASS-2; the emit pass clears it after sub-pixel refine).
    pub angle: i32,
    /// +0x10 — detector response / quality score (`|v|` at the peak).
    pub score: i32,
    /// +0x14 — x. Q16.16 tile-local during detection; integer global after [`refine_xy`].
    pub x: i32,
    /// +0x18 — y. Same lifecycle as [`Self::x`].
    pub y: i32,
    /// +0x1c — aux (copied verbatim by compaction; semantics unresolved in the DLL).
    pub aux: i32,
}

/// Which sides of the 3×3 grid a tile touches — `syna_qm_tile_bounds@0x18000a830` output (4 bools).
/// A touched side gets `R` px of halo padding (no real neighbour pixels to gather there).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TileEdges {
    /// Tile is on the left image boundary (`col < 1`).
    pub left: bool,
    /// Tile is on the right image boundary (`col == cols-1`).
    pub right: bool,
    /// Tile is on the top image boundary (`row < 1`).
    pub top: bool,
    /// Tile is on the bottom image boundary (`row == rows-1`).
    pub bottom: bool,
}

/// Edge-touch booleans for tile `(row, col)` in a `cols × rows` grid.
/// Port of `syna_qm_tile_bounds@0x18000a830` (note the DLL's arg order: row, col, cols, rows).
pub fn tile_bounds(row: i32, col: i32, cols: i32, rows: i32) -> TileEdges {
    TileEdges {
        left: col < 1,
        right: col == cols - 1,
        top: row < 1,
        bottom: row == rows - 1,
    }
}

/// Padded working-field dims for a tile: grow by `radius` on each **touched** image edge (that side
/// has no neighbour pixels, so it is halo-filled). Port of `FUN_18000a030@0x18000a030`.
pub fn padded_dims(w: i32, h: i32, edges: TileEdges, radius: i32) -> (i32, i32) {
    let mut pw = w;
    let mut ph = h;
    if edges.left {
        pw += radius;
    }
    if edges.right {
        pw += radius;
    }
    if edges.top {
        ph += radius;
    }
    if edges.bottom {
        ph += radius;
    }
    (pw, ph)
}

/// Left/top border offset (px) that a tile's local coordinate frame is shifted by: `radius` when the
/// tile touches the left/top image edge (halo present there), else `0`. Used by [`refine_xy`] and the
/// border-reject pass — `x = edges.left ? R : 0`, `y = edges.top ? R : 0`.
pub fn tile_border(edges: TileEdges, radius: i32) -> (i32, i32) {
    let xb = if edges.left { radius } else { 0 };
    let yb = if edges.top { radius } else { 0 };
    (xb, yb)
}

/// Convert a tile-local Q16.16 coordinate back to a global integer pixel, removing the halo border
/// and adding the tile origin. Port of `syna_qm_minutia_refine_xy_angle@0x18000a860` (refines x,y
/// **only** — despite the DLL name it does not touch angle):
/// `g = ((tile0 - border) << 16 + raw_q16) >> 16 = (tile0 - border) + (raw_q16 >> 16)`.
pub fn refine_xy(raw_x_q16: i32, raw_y_q16: i32, tile_x0: i32, tile_y0: i32, xborder: i32, yborder: i32) -> (i32, i32) {
    let gx = ((tile_x0 - xborder) * 0x1_0000 + raw_x_q16) >> Q16_SHIFT;
    let gy = ((tile_y0 - yborder) * 0x1_0000 + raw_y_q16) >> Q16_SHIFT;
    (gx, gy)
}

/// Tile index tag written to `Candidate::tile` — `row*3 + col` (`syna_qm_detect_minutiae`).
pub fn tile_index(row: i32, col: i32) -> u8 {
    (row * DetectConfig::TILE_GRID as i32 + col) as u8
}

/// The four candidate-array sort keys, matching the DLL's quicksort comparators. Each returns an
/// `Ord` key; sort **ascending** by the returned tuple to reproduce the DLL order.
pub mod sort_key {
    use super::Candidate;

    /// `cmp_score@0x18000a710` — score descending (top-N selection before the cap).
    pub fn by_score_desc(c: &Candidate) -> i32 {
        -c.score
    }

    /// `cmp_tile@0x18000a760` — tile index descending, score ascending as tiebreak (regroup by tile).
    pub fn by_tile(c: &Candidate) -> (i32, i32) {
        (-(c.tile as i32), c.score)
    }

    /// `cmp_class@0x18000a730` — class byte descending, score descending tiebreak (partition classes).
    pub fn by_class(c: &Candidate) -> (i32, i32) {
        (-(c.class as i32), -c.score)
    }

    /// `cmp_angle@0x18000a890` — angle ascending (canonical within-class ordering).
    pub fn by_angle(c: &Candidate) -> i32 {
        c.angle
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tile_bounds_corners_and_center() {
        // 3×3 grid. Top-left corner touches left+top only.
        let tl = tile_bounds(0, 0, 3, 3);
        assert_eq!(tl, TileEdges { left: true, top: true, right: false, bottom: false });
        // Bottom-right corner touches right+bottom.
        let br = tile_bounds(2, 2, 3, 3);
        assert_eq!(br, TileEdges { left: false, top: false, right: true, bottom: true });
        // Center touches nothing.
        assert_eq!(tile_bounds(1, 1, 3, 3), TileEdges::default());
    }

    #[test]
    fn padded_dims_grows_per_edge() {
        let r = 10;
        // center tile: no growth.
        assert_eq!(padded_dims(48, 18, TileEdges::default(), r), (48, 18));
        // top-left corner: +R on left (w) and +R on top (h).
        let tl = tile_bounds(0, 0, 3, 3);
        assert_eq!(padded_dims(48, 18, tl, r), (58, 28));
    }

    #[test]
    fn refine_xy_deoffsets_q16_to_global() {
        // raw = 5.0 in Q16.16, tile origin (48, 18), no border -> global (53, 23).
        let (x, y) = refine_xy(5 << 16, 5 << 16, 48, 18, 0, 0);
        assert_eq!((x, y), (53, 23));
        // left/top-edge tile with R=10 border subtracts 10 from the origin.
        let (x, y) = refine_xy(5 << 16, 5 << 16, 10, 10, 10, 10);
        assert_eq!((x, y), (5, 5));
    }

    #[test]
    fn tile_index_is_row_major() {
        assert_eq!(tile_index(0, 0), 0);
        assert_eq!(tile_index(1, 2), 5);
        assert_eq!(tile_index(2, 2), 8);
    }

    #[test]
    fn sort_keys_order_as_dll() {
        let mut v = [Candidate { score: 10, tile: 1, class: 0, angle: 30, ..Default::default() },
            Candidate { score: 50, tile: 2, class: 1, angle: 10, ..Default::default() },
            Candidate { score: 20, tile: 0, class: 0, angle: 20, ..Default::default() }];
        v.sort_by_key(sort_key::by_score_desc);
        assert_eq!(v.iter().map(|c| c.score).collect::<Vec<_>>(), vec![50, 20, 10]);
        v.sort_by_key(sort_key::by_angle);
        assert_eq!(v.iter().map(|c| c.angle).collect::<Vec<_>>(), vec![10, 20, 30]);
    }
}
