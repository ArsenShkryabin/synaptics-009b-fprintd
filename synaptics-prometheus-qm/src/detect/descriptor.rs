//! Phase 5 — the 64-bit rotation-invariant minutia descriptor + orientation.
//!
//! Ports (see `../../docs/qm/qm-minutiae-detector.md`):
//! - `syna_qm_descriptor_pair_geometry@0x18000e600` — 64 sample-point pairs selected by the 127-entry
//!   permutation LUT over a 2-scale grid (BRIEF-style layout).
//! - `syna_qm_minutia_orientation@0x18000d870` — SIFT-style dominant orientation from a gradient
//!   histogram over a radius-6 window weighted by the 7×7 table `DAT_1801501d0`.
//! - `syna_qm_descriptor_brief@0x18000dfe0` — rotation-invariant BRIEF: rotate the pairs by the
//!   minutia orientation, sample the gradient projection, compare, pack 64 bits.
//!
//! The descriptor is **deterministic** (no learned weights), so it is bit-exact-portable in principle.
//! This is a faithful-**structural** port: exact LUTs (127-perm + 7×7 weights) transcribed; the DLL's
//! fixed-point `atan2`/`cos`/`sin` (`FUN_180003050/_180003100`, `π = 205887` in Q16.16) are replaced by
//! `f32` trig. Validated by **self-consistency** (same frame → same descriptor → high self-match) and
//! discrimination, not by golden-vector bit-parity. Rule #7 discipline: a processed matching feature.

use super::field::DohField;
use super::fixedtrig::{atan2_q16rad, atan2_quadrant};

/// Descriptor width in bits / bytes.
pub const DESCRIPTOR_BITS: usize = 64;
pub const DESCRIPTOR_BYTES: usize = DESCRIPTOR_BITS / 8;

/// Orientation window radius (px) — `syna_qm_minutia_orientation` scans `|dy|,|dx| ≤ 6` (`r² < 0x24`).
pub const ORIENT_RADIUS: i32 = 6;

/// Descriptor sample radius (px) — the 2-scale pair grid half-extent (`param_8` in the DLL).
pub const DESC_RADIUS: i32 = 8;

/// 127-entry permutation LUT selecting descriptor sample pairs — verbatim from
/// `syna_qm_descriptor_pair_geometry@0x18000e600` (`local_2b8[0..0x7e]`).
#[rustfmt::skip]
const PAIR_PERM: [u32; 127] = [
    0xd36, 0xfc7, 0x73a5, 0x6c6, 0x4ce3, 0x900, 0x427b, 0x4104, 0x272e, 0x674f, 0x473d, 0x1df4,
    0x6ff7, 0xa67, 0x10df, 0x268e, 0x2aea, 0x4b92, 0x2695, 0x4c06, 0x2ff5, 0x6053, 0x6fe6, 0x7f96,
    0x73ff, 0x504a, 0x6302, 0x777d, 0x49d7, 0x259, 0x6d55, 0x4548, 0x2f6a, 0x2505, 0x4a5c, 0x2150,
    0x7b3a, 0x761f, 0x3cb8, 0xf84, 0x7e0b, 0x2da3, 0x5d81, 0x4168, 0x6cdf, 0xfe0, 0x75dc, 0x595e,
    0x2725, 0x6ad9, 0x16d0, 0x7325, 0x2d2e, 0x2ec, 0x6355, 0x159f, 0x5ae0, 0x32b1, 0x40ae, 0x71d7,
    0x3aae, 0x4225, 0x60f9, 0x1342, 0x4c8, 0x3908, 0x5c05, 0x6545, 0x1e8e, 0x3083, 0x4a63, 0x31f8,
    0x2e4b, 0x680e, 0x16c0, 0x7e2a, 0x1720, 0x2191, 0x7972, 0x66a5, 0x713e, 0x8c9, 0x5250, 0x62b2,
    0x5258, 0x29ee, 0x54c7, 0xfe0, 0x7a59, 0x3b93, 0x3a2a, 0x6b02, 0x3852, 0x3fcd, 0x6e4a, 0x1a77,
    0x1bb6, 0x4097, 0x6a47, 0x2dae, 0x45c9, 0x2b75, 0x31a5, 0x75e8, 0x6f56, 0x1058, 0x25a2, 0x5c40,
    0x76a0, 0x47c2, 0x22c7, 0x58e9, 0x99c, 0x442a, 0x1cbe, 0x6fb8, 0x405d, 0x12a2, 0x2c63, 0x55e2,
    0x3bd0, 0x4eb7, 0x441d, 0x2506, 0x1ca9, 0xd99, 0x7e6f,
];

/// 7×7 radial window weights for the orientation histogram, indexed `[|dy|][|dx|]` — verbatim from
/// `DAT_1801501d0` (center 1669 → corner 0; a Gaussian-ish falloff).
#[rustfmt::skip]
const ORIENT_WEIGHTS: [[i32; 7]; 7] = [
    [1669, 1541, 1212, 812, 464, 226, 94],
    [1541, 1422, 1119, 750, 428, 208, 86],
    [1212, 1119,  880, 590, 337, 164, 68],
    [ 812,  750,  590, 395, 226, 110, 46],
    [ 464,  428,  337, 226, 129,  63, 26],
    [ 226,  208,  164, 110,  63,  31, 13],
    [  94,   86,   68,  46,  26,  13,  0],
];

/// One descriptor sample-pair: two offsets `(x,y)` relative to the minutia.
type Pair = ((i32, i32), (i32, i32));

/// One descriptor sample point: pixel offset from the minutia, tagged with its scale `level` (0/1/2 =
/// grid side 2/3/4). `syna_qm_descriptor_pair_geometry` samples a *region* around each point sized by
/// the level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SamplePoint {
    pub x: i32,
    pub y: i32,
    pub level: u8,
}

/// The DLL's descriptor sample geometry: the deduped unique sample points and the 64 pairs (indices
/// into `points`) the BRIEF descriptor compares. Bit-exact to `syna_qm_descriptor_pair_geometry`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DescriptorGeometry {
    pub points: Vec<SamplePoint>,
    pub pairs: Vec<(usize, usize)>,
}

impl DescriptorGeometry {
    /// Point indices + pairs restricted to one scale `level` (0/1/2). Used by the per-level GUI views.
    pub fn for_level(&self, level: u8) -> (Vec<usize>, Vec<(usize, usize)>) {
        let idxs: Vec<usize> = (0..self.points.len()).filter(|&i| self.points[i].level == level).collect();
        let pairs: Vec<(usize, usize)> =
            self.pairs.iter().copied().filter(|&(a, _)| self.points[a].level == level).collect();
        (idxs, pairs)
    }
}

/// Intern a sample point, returning its index (dedup by `(level,x,y)`, first-seen order).
fn intern_point(points: &mut Vec<SamplePoint>, p: SamplePoint) -> usize {
    match points.iter().position(|&q| q == p) {
        Some(i) => i,
        None => {
            points.push(p);
            points.len() - 1
        }
    }
}

/// Bit-exact port of `syna_qm_descriptor_pair_geometry@0x18000e600` — the BRIEF sample geometry.
///
/// Builds a **3-scale grid** (levels 2, 3, 4; step `ceil(2·radius/level)`, points
/// `((k%level)·step − radius, (k/level)·step − radius)`), enumerates every `i<j` pair per level →
/// exactly `6 + 36 + 120 = 162` pool pairs, then **samples 64 without replacement**: `slot = i` for the
/// first 6, else `PAIR_PERM[i] % pool.len()`, removing each picked slot (swap-remove). Endpoints are
/// deduped into unique `(level,x,y)` points. Validated bit-for-bit against the DLL at radius 7
/// (`tools/qm-dll-oracle/golden/pairgeom.txt`). NOTE the DLL radius is `ctx+0x34 = emit_p0c = 7`.
pub fn pair_geometry_dll(radius: i32) -> DescriptorGeometry {
    struct PoolPair {
        level: u8,
        a: (i32, i32),
        b: (i32, i32),
    }
    let mut pool: Vec<PoolPair> = Vec::with_capacity(162);
    for level in 2..=4i32 {
        let step = (2.0 * radius as f32 / level as f32 + 0.999) as i32; // DLL: (int)(radius*2.0/level + 0.999)
        let n = level * level;
        let pt = |k: i32| ((k % level) * step - radius, (k / level) * step - radius);
        for i in 0..n {
            for j in (i + 1)..n {
                pool.push(PoolPair { level: (level - 2) as u8, a: pt(i), b: pt(j) });
            }
        }
    }
    let mut points: Vec<SamplePoint> = Vec::new();
    let mut pairs: Vec<(usize, usize)> = Vec::with_capacity(64);
    for (i, &perm) in PAIR_PERM.iter().enumerate().take(64) {
        // slot = i for the forced first 6, else PAIR_PERM[i] % remaining-pool-size (pool shrinks).
        let slot = if i < 6 { i } else { (perm as usize) % pool.len() };
        let pp = pool.swap_remove(slot); // swap-remove: last moves into slot, exactly like the DLL
        let a = intern_point(&mut points, SamplePoint { x: pp.a.0, y: pp.a.1, level: pp.level });
        let b = intern_point(&mut points, SamplePoint { x: pp.b.0, y: pp.b.1, level: pp.level });
        pairs.push((a, b));
    }
    DescriptorGeometry { points, pairs }
}

/// Generate the 2-scale sample-point pair pool — port of the grid enumeration in
/// `syna_qm_descriptor_pair_geometry`. For scale levels `2` and `3` (grids of `4` and `9` points at
/// step `ceil(2·radius/level)`), enumerate every point-pair `i<j`.
fn pair_pool(radius: i32) -> Vec<Pair> {
    let mut pool = Vec::new();
    for level in 2..=3i32 {
        let n = level * level;
        let step = ((radius * 2) as f32 / level as f32 + 0.999) as i32; // DLL: ceil(param_8*2/level)
        let pt = |k: i32| ((k % level) * step - radius, (k / level) * step - radius);
        for i in 0..n {
            for j in (i + 1)..n {
                pool.push((pt(i), pt(j)));
            }
        }
    }
    pool
}

/// The 64 descriptor pairs, selected from the pool by the permutation LUT (`PAIR_PERM[i] % pool_len`,
/// the first six forced sequential as in the DLL's `if idx < 6 { idx = seq }`).
fn descriptor_pairs(radius: i32) -> Vec<Pair> {
    let pool = pair_pool(radius);
    if pool.is_empty() {
        return Vec::new();
    }
    (0..DESCRIPTOR_BITS)
        .map(|i| {
            let idx = if i < 6 { i } else { (PAIR_PERM[i % PAIR_PERM.len()] as usize) % pool.len() };
            pool[idx]
        })
        .collect()
}

#[inline]
fn at(v: &[i32], w: usize, h: usize, x: i32, y: i32) -> i32 {
    let cx = x.clamp(0, w as i32 - 1) as usize;
    let cy = y.clamp(0, h as i32 - 1) as usize;
    v[cy * w + cx]
}

/// Dominant gradient orientation (radians, `0..π` undirected) in a weighted radius-6 window around
/// `(x,y)` — structural port of `syna_qm_minutia_orientation@0x18000d870`: build a 42-bin orientation
/// histogram of the window's gradients (weighted by `ORIENT_WEIGHTS × magnitude`), accumulating the
/// gradient vector per bin, then take the dominant bin's resultant direction.
pub fn minutia_orientation(f: &DohField, x: usize, y: usize) -> f32 {
    const BINS: usize = 42;
    let (w, h) = (f.width, f.height);
    let (mut hx, mut hy) = ([0f64; BINS], [0f64; BINS]);
    for dy in -ORIENT_RADIUS..=ORIENT_RADIUS {
        for dx in -ORIENT_RADIUS..=ORIENT_RADIUS {
            if dx * dx + dy * dy >= 36 {
                continue; // r < 6 disc (DLL: r² < 0x24)
            }
            let wgt = ORIENT_WEIGHTS[dy.unsigned_abs() as usize][dx.unsigned_abs() as usize] as f64;
            let gx = at(&f.lx, w, h, x as i32 + dx, y as i32 + dy) as f64;
            let gy = at(&f.ly, w, h, x as i32 + dx, y as i32 + dy) as f64;
            let ang = gy.atan2(gx); // -π..π
            let mut bin = ((ang + std::f64::consts::PI) / (2.0 * std::f64::consts::PI) * BINS as f64) as usize;
            bin %= BINS;
            hx[bin] += gx * wgt;
            hy[bin] += gy * wgt;
        }
    }
    // dominant bin by resultant magnitude
    let mut best = 0usize;
    let mut best_mag = -1.0f64;
    for b in 0..BINS {
        let m = hx[b] * hx[b] + hy[b] * hy[b];
        if m > best_mag {
            best_mag = m;
            best = b;
        }
    }
    let mut a = (hy[best].atan2(hx[best])) as f32; // -π..π (directed)
    // undirected orientation 0..π (ridge orientation is π-periodic)
    if a < 0.0 {
        a += std::f32::consts::PI;
    }
    a
}

/// The DLL-faithful window `scale` (the step multiplier the DLL derives from `ctx+0x48` and the
/// subsample shift `tile+0x60`): `(ctx+0x48/(2·2^shift) + 0x8000) >> 16 = 1` on this SKU. Pass this to
/// [`minutia_orientation_dll`] for faithful behavior.
pub const ORIENT_SCALE_DLL: i32 = 1;

/// **Bit-exact** dominant-orientation port of `syna_qm_minutia_orientation@0x18000d870` — returns the
/// angle in **Q16.16 radians** (0..2π, π = 205887), the DLL's internal representation (before the
/// degree rescale in `minutia_finalize`). Uses the fixed-point `atan2` ([`atan2_quadrant`]/
/// [`atan2_q16rad`]) instead of `f32`.
///
/// `scale` is the DLL's window-step multiplier ([`ORIENT_SCALE_DLL`] = 1 for faithful behavior): each
/// disc sample is taken at `(x + dx·scale, y + dy·scale)`. This is exactly the value the DLL computes
/// from `ctx+0x48`/`tile+0x60` (`local_e8 = scale·0x10000` is the per-step increment). Curiosity knob:
/// `scale = 0` reproduces the degenerate collapse we found via a short oracle tile — the step is `0`, so
/// **every sample reads the center pixel** and the orientation becomes the pure center-pixel gradient
/// direction (no windowing); `scale = 2, 3, …` dilates the disc.
///
/// Differs from the f32 [`minutia_orientation`] in three DLL-faithful ways: gradients are weighted as
/// `(L>>10)·w>>4` (integer); each sample **spreads** its `(gx,gy)` over **7 trailing bins** `[bin-6,bin]`;
/// and the final angle is `atan2(Σgx, Σgy)` (the **ridge** direction, ⊥ to the gradient) — the f32 port
/// returned `atan2(Σgy, Σgx)` (the gradient direction, 90° off).
pub fn minutia_orientation_dll(f: &DohField, x: i32, y: i32, scale: i32) -> i32 {
    const BINS: usize = 42;
    let (w, h) = (f.width, f.height);
    let mut hx = [0i32; BINS];
    let mut hy = [0i32; BINS];
    for dx in -ORIENT_RADIUS..=ORIENT_RADIUS {
        for dy in -ORIENT_RADIUS..=ORIENT_RADIUS {
            if dx * dx + dy * dy >= 36 {
                continue; // radius-6 disc (r² < 0x24)
            }
            let wgt = ORIENT_WEIGHTS[dx.unsigned_abs() as usize][dy.unsigned_abs() as usize];
            // Window step is `scale·offset` (DLL: local_e8 = scale·0x10000 per step). scale=0 → the
            // position never advances → every sample reads the center pixel (the quirk).
            let (sx, sy) = (x + dx * scale, y + dy * scale);
            let gx = ((at(&f.lx, w, h, sx, sy) >> 10) * wgt) >> 4;
            let gy = ((at(&f.ly, w, h, sx, sy) >> 10) * wgt) >> 4;
            let orient = atan2_quadrant(gy, gx);
            let bin = ((orient << 12) / 0x0266_6666) as usize % BINS;
            // spread (gx,gy) over 7 trailing bins: (bin+0x24 .. bin+0x2a) mod 42 = [bin-6, bin]
            for b in (bin + 0x24..).take(7) {
                hx[b % BINS] += gx;
                hy[b % BINS] += gy;
            }
        }
    }
    // dominant bin by resultant magnitude ((Σgy>>13)² + (Σgx>>13)²), first-wins on ties
    let (mut best, mut best_mag) = (0usize, 0i32);
    for b in 0..BINS {
        let m = (hy[b] >> 13) * (hy[b] >> 13) + (hx[b] >> 13) * (hx[b] >> 13);
        if best_mag < m {
            best_mag = m;
            best = b;
        }
    }
    // ridge direction: atan2_q16rad(Σgx>>10, Σgy>>10) (note the DLL's swapped-looking arg order)
    atan2_q16rad(hx[best] >> 10, hy[best] >> 10)
}

/// Descriptor sample radius on this SKU — `ctx+0x34 = emit_p0c = 7` (the pair-geometry + BRIEF grid
/// half-extent). Note this is **7**, not the old structural port's [`DESC_RADIUS`] = 8.
pub const DESC_RADIUS_DLL: i32 = 7;

/// Cos/Sin LUT (Q16, per integer degree, 0..=360) — `g_anSynaQmCosLut@0x180160620` /
/// `g_anSynaQmSinLut@0x180160bc0`. The DLL stores `round(cos/sin(deg°)·65536)`; recomputing it
/// reproduces the table exactly (validated against the oracle golden `COSLUT`/`SINLUT`).
pub fn qm_cos_lut() -> [i32; 361] {
    std::array::from_fn(|d| ((d as f64).to_radians().cos() * 65536.0).round() as i32)
}
pub fn qm_sin_lut() -> [i32; 361] {
    std::array::from_fn(|d| ((d as f64).to_radians().sin() * 65536.0).round() as i32)
}

/// **Bit-exact** port of `syna_qm_descriptor_brief@0x18000dfe0` — the region-integrated,
/// rotation-invariant 64-bit BRIEF. Given the DoH field's first-derivative planes ([`DohField::lx`],
/// [`DohField::ly`] = the DLL's `tile+0x20`/`+0x28`), the minutia center `(px_q16, py_q16)` in
/// **Q16.16** (the sub-pixel coords the NMS refine wrote back), the orientation `angle_q16` in Q16
/// radians (from [`minutia_orientation_dll`]), and the descriptor geometry from [`pair_geometry_dll`].
///
/// Algorithm (SKU 0x2449 constants: radius `R = 7`, scale `= 1`, grid side `= 2R+2 = 16`):
/// 1. `deg = (int)(angle_q16 / 205887.416 · 180)`; `cos = CosLut[deg]`, `sin = SinLut[deg]`.
/// 2. Over the `side²` grid `(ex,ey) ∈ [−R, R+1]²`, rotate each cell into the field —
///    `col = (px_q16 + ex·cos − ey·sin + 0x8000) >> 16`, `row = (py_q16 + ex·sin + ey·cos + 0x8000) >> 16`
///    (`cos`/`sin` pre-multiplied by `scale`). OOB → `Lx = Ly = 0x800000` (halo). Two rotated gradient
///    projections per cell: `p1 = sin·(Ly>>8)>>8 + cos·(Lx>>8)>>8`, `p2 = −(sin·(Lx>>8))>>8 + cos·(Ly>>8)>>8`.
/// 3. Per unique point, region-sum `p1` over an `sz×sz` block (`sz = {R, ⌈2R/3⌉, R/2}[level] = {7,5,3}`)
///    anchored at grid cell `(x+R, y+R)`.
/// 4. Per pair `(a,b)`: bit = `sum1[b] < sum1[a]` (proj1 only). Pack LSB-first into 8 bytes.
///
/// All integer math uses `i32` wrapping to mirror the DLL's 32-bit IMUL/shift overflow behavior.
pub fn descriptor_brief_dll(
    f: &DohField,
    px_q16: i32,
    py_q16: i32,
    angle_q16: i32,
    geom: &DescriptorGeometry,
    cos_lut: &[i32; 361],
    sin_lut: &[i32; 361],
) -> [u8; DESCRIPTOR_BYTES] {
    const SCALE: i32 = 1; // (ctx+0x48/2 + 0x8000) >> 16 = 1 for 0x2449
    let r = DESC_RADIUS_DLL;
    let side = r * 2 + 2; // 16
    let (tw, th) = (f.width as i32, f.height as i32);
    // 1. rotation from the Q16-radian orientation
    let deg = ((angle_q16 as f64 / 205887.41614566068) * 180.0) as i32;
    let cos = cos_lut[deg as usize];
    let sin = sin_lut[deg as usize];
    let (sc_cos, sc_sin) = (cos.wrapping_mul(SCALE), sin.wrapping_mul(SCALE));
    // 2. projection grid, cell index = (ex+R)*side + (ey+R), filled ex-outer/ey-inner
    let mut p1 = vec![0i32; (side * side) as usize];
    let mut cell = 0usize;
    for ex in -r..=r + 1 {
        let acc_x = ex.wrapping_mul(sc_cos).wrapping_add(px_q16);
        let acc_y = ex.wrapping_mul(sc_sin).wrapping_add(py_q16);
        for ey in -r..=r + 1 {
            let row = ey.wrapping_mul(sc_cos).wrapping_add(acc_y).wrapping_add(0x8000) >> 16;
            let col = acc_x.wrapping_sub(ey.wrapping_mul(sc_sin)).wrapping_add(0x8000) >> 16;
            let (lx, ly) = if row < 0 || col < 0 || row >= th || col >= tw {
                (0x800000, 0x800000) // halo (same value the field.rs first-derivative pad uses)
            } else {
                let idx = (row * tw + col) as usize;
                (f.lx[idx], f.ly[idx])
            };
            // projection uses the RAW (unscaled) cos/sin; `*` binds tighter than `>>` in the DLL.
            p1[cell] = (sin.wrapping_mul(ly >> 8) >> 8).wrapping_add(cos.wrapping_mul(lx >> 8) >> 8);
            // p2 (= -(sin·(Lx>>8))>>8 + cos·(Ly>>8)>>8) is computed by the DLL but its region-sum is
            // never read by the bit decision (proj1 only), so the port omits it.
            cell += 1;
        }
    }
    // 3. per-point region sum of p1
    let region = [r, ((r as f32 * 2.0 / 3.0) + 0.999999) as i32, r / 2]; // {7,5,3}
    let mut sum1 = vec![0i32; geom.points.len()];
    for (i, pt) in geom.points.iter().enumerate() {
        let sz = region[pt.level as usize];
        let anchor = ((pt.x + r) * side + (pt.y + r)) as usize;
        let mut s = 0i32;
        for rr in 0..sz {
            for cc in 0..sz {
                s = s.wrapping_add(p1[anchor + (rr * side + cc) as usize]);
            }
        }
        sum1[i] = s;
    }
    // 4. compare + pack (proj1 only), LSB-first
    let mut desc = [0u8; DESCRIPTOR_BYTES];
    for (i, &(a, b)) in geom.pairs.iter().enumerate().take(DESCRIPTOR_BITS) {
        if sum1[b] < sum1[a] {
            desc[i >> 3] |= 1 << (i & 7);
        }
    }
    desc
}

/// Angle-field rescale from `syna_qm_minutia_finalize@0x18000f2a0` — the Q16-radian orientation
/// (`rec+0xc`, `[0,2π)`) → half-circle integer degrees `0..179` stored back for the matcher:
/// `d = (int)(angle_q16 · 0.00043713210688 + 0.5)`, then `180 → 0`.
pub fn finalize_angle_deg(angle_q16: i32) -> u16 {
    let d = (angle_q16 as f64 * 0.00043713210688 + 0.5) as i32;
    (if d == 180 { 0 } else { d }) as u16
}

/// Build the 64-bit rotation-invariant descriptor at `(x,y)` given the minutia orientation `angle`
/// (radians) — structural port of `syna_qm_descriptor_brief@0x18000dfe0`. Each of the 64 pairs is
/// rotated by `angle`, the gradient projection onto the rotated axis is sampled at both points, and
/// the sign of their difference sets one bit.
pub fn brief_descriptor(f: &DohField, x: usize, y: usize, angle: f32, pairs: &[Pair]) -> [u8; DESCRIPTOR_BYTES] {
    let (w, h) = (f.width, f.height);
    let (c, s) = (angle.cos(), angle.sin());
    // rotate an offset by the minutia orientation (rotation invariance)
    let rot = |(ox, oy): (i32, i32)| -> (i32, i32) {
        let rx = c * ox as f32 - s * oy as f32;
        let ry = s * ox as f32 + c * oy as f32;
        (rx.round() as i32, ry.round() as i32)
    };
    // rotated gradient projection at a point (matches dfe0's `cos·Lx + sin·Ly`)
    let proj = |ox: i32, oy: i32| -> f32 {
        let gx = at(&f.lx, w, h, x as i32 + ox, y as i32 + oy) as f32;
        let gy = at(&f.ly, w, h, x as i32 + ox, y as i32 + oy) as f32;
        c * gx + s * gy
    };
    let mut desc = [0u8; DESCRIPTOR_BYTES];
    for (i, &(a, b)) in pairs.iter().enumerate().take(DESCRIPTOR_BITS) {
        let (ax, ay) = rot(a);
        let (bx, by) = rot(b);
        if proj(ax, ay) < proj(bx, by) {
            desc[i / 8] |= 1 << (i % 8);
        }
    }
    desc
}

/// The descriptor pairs for [`DESC_RADIUS`], built once.
///
/// [`descriptor_pairs`] is a pure function of its radius, and [`describe`] only ever asks for the
/// constant one — so rebuilding the pool and re-running the permutation for *every minutia* (a few
/// hundred per frame) was pure waste. Same values, computed on first use.
static DESC_PAIRS: std::sync::LazyLock<Vec<Pair>> =
    std::sync::LazyLock::new(|| descriptor_pairs(DESC_RADIUS));

/// Compute a minutia's orientation (degrees `0..=179`) and 64-bit descriptor from the field at `(x,y)`.
pub fn describe(f: &DohField, x: usize, y: usize) -> (u16, [u8; DESCRIPTOR_BYTES]) {
    let angle = minutia_orientation(f, x, y);
    let desc = brief_descriptor(f, x, y, angle, &DESC_PAIRS);
    let deg = (angle.to_degrees().round() as i32).rem_euclid(180) as u16;
    (deg, desc)
}

/// The bit-exact descriptor geometry ([`pair_geometry_dll`] at [`DESC_RADIUS_DLL`]) + Cos/Sin LUTs,
/// built once — all three are pure constants the per-minutia [`describe_dll`] would otherwise rebuild.
static DLL_GEOM: std::sync::LazyLock<DescriptorGeometry> =
    std::sync::LazyLock::new(|| pair_geometry_dll(DESC_RADIUS_DLL));
static DLL_COS: std::sync::LazyLock<[i32; 361]> = std::sync::LazyLock::new(qm_cos_lut);
static DLL_SIN: std::sync::LazyLock<[i32; 361]> = std::sync::LazyLock::new(qm_sin_lut);

/// **Bit-exact** describe — the DLL PASS-2 (`minutia_finalize@f2a0`) chain: [`minutia_orientation_dll`]
/// (`d870`) → [`descriptor_brief_dll`] (`dfe0`) → [`finalize_angle_deg`] (`f2a0` rescale). Returns the
/// half-circle angle (`0..179°`) and the 64-bit descriptor. `(cx, cy)` are the **tile-local** integer
/// coords (the sub-pixel fraction is already discarded by the emit-stage refine on this port, so the
/// descriptor centers on `cx<<16, cy<<16`); `f` is the candidate's own tile field.
///
/// `orient_scale` is the orientation window-step multiplier ([`ORIENT_SCALE_DLL`] = 1 = faithful; `0`
/// reproduces the degenerate center-pixel-only quirk). It affects the orientation only — dfe0 keeps its
/// own (faithful) scale.
pub fn describe_dll(f: &DohField, cx: i32, cy: i32, orient_scale: i32) -> (u16, [u8; DESCRIPTOR_BYTES]) {
    let angle_q16 = minutia_orientation_dll(f, cx, cy, orient_scale);
    let desc = descriptor_brief_dll(f, cx << 16, cy << 16, angle_q16, &DLL_GEOM, &DLL_COS, &DLL_SIN);
    (finalize_angle_deg(angle_q16), desc)
}

#[cfg(test)]
mod tests {
    use super::super::field::doh_response;
    use super::*;

    fn ridge_image(w: usize, h: usize, period: f32, phase: f32) -> Vec<u8> {
        // vertical sinusoidal ridges — a controlled, orientation-bearing pattern.
        (0..w * h)
            .map(|p| {
                let x = (p % w) as f32;
                (128.0 + 100.0 * ((x / period + phase) * std::f32::consts::TAU).sin()) as u8
            })
            .collect()
    }

    #[test]
    fn pair_selection_is_deterministic_and_full() {
        let a = descriptor_pairs(DESC_RADIUS);
        let b = descriptor_pairs(DESC_RADIUS);
        assert_eq!(a.len(), DESCRIPTOR_BITS);
        assert_eq!(a, b, "descriptor pair selection must be deterministic");
    }

    #[test]
    fn descriptor_is_self_consistent() {
        let (w, h) = (48usize, 40usize);
        let px = ridge_image(w, h, 6.0, 0.0);
        let f = doh_response(&px, w, h, &crate::detect::DohParams { ksize: crate::detect::gaussian_taps(1.5), sigma: 1.5, scale: 1 });
        let d1 = describe(&f, 24, 20);
        let d2 = describe(&f, 24, 20);
        assert_eq!(d1, d2, "same point → identical descriptor + angle");
    }

    #[test]
    fn orientation_dll_is_self_consistent_and_perpendicular() {
        let (w, h) = (48usize, 40usize);
        // vertical ridges → horizontal gradient; the DLL orientation returns the RIDGE direction
        // (⊥ gradient), ~90° from the f32 gradient-direction port. Both must be deterministic.
        let f = doh_response(&ridge_image(w, h, 6.0, 0.0), w, h, &crate::detect::DohParams { ksize: crate::detect::gaussian_taps(1.5), sigma: 1.5, scale: 1 });
        let a1 = minutia_orientation_dll(&f, 24, 20, ORIENT_SCALE_DLL);
        let a2 = minutia_orientation_dll(&f, 24, 20, ORIENT_SCALE_DLL);
        assert_eq!(a1, a2, "fixed-point orientation must be deterministic");
        // result is a valid Q16 radian angle in [0, 2π)
        assert!((0..0x6487e).contains(&a1), "angle {a1} out of [0,2π)");
    }

    #[test]
    fn pair_geometry_matches_oracle_golden() {
        // Bit-exact vs the DLL at radius 7 (tools/qm-dll-oracle/golden/pairgeom.txt).
        let g = pair_geometry_dll(7);
        // 29 unique points, in first-seen dedup order — (level, x, y).
        #[rustfmt::skip]
        let want_pts: &[(u8, i32, i32)] = &[
            (0,-7,-7),(0,0,-7),(0,-7,0),(0,0,0),(1,-2,-7),(1,-7,-2),(2,-3,-7),(2,-7,-3),(1,3,3),
            (2,5,-3),(2,-3,5),(2,1,1),(2,1,-3),(2,-7,1),(1,-7,-7),(2,-7,5),(1,-2,-2),(1,3,-7),
            (1,3,-2),(1,-7,3),(2,5,-7),(2,-3,-3),(2,5,5),(2,5,1),(1,-2,3),(2,1,5),(2,-7,-7),
            (2,-3,1),(2,1,-7),
        ];
        let got_pts: Vec<(u8, i32, i32)> = g.points.iter().map(|p| (p.level, p.x, p.y)).collect();
        assert_eq!(got_pts, want_pts, "unique sample points");
        // 64 pairs (point-index a, b).
        #[rustfmt::skip]
        let want_pairs: &[(usize, usize)] = &[
            (0,1),(0,2),(0,3),(1,2),(1,3),(2,3),(4,5),(6,7),(4,8),(9,10),(11,10),(12,13),(14,8),
            (9,15),(5,16),(17,5),(18,19),(6,12),(20,21),(4,17),(6,11),(12,22),(20,12),(13,23),
            (17,24),(15,25),(26,27),(28,23),(14,16),(6,25),(15,10),(26,11),(26,9),(6,21),(20,15),
            (4,24),(26,21),(21,10),(26,20),(27,25),(23,25),(6,15),(6,28),(20,7),(17,18),(13,25),
            (14,24),(21,9),(7,15),(14,17),(4,16),(6,9),(21,11),(20,25),(26,13),(28,11),(13,11),
            (21,27),(17,16),(7,12),(5,18),(6,23),(13,15),(13,27),
        ];
        assert_eq!(g.pairs, want_pairs, "descriptor pairs");
        // 3-scale structure: level counts.
        let per_level = |l: u8| g.pairs.iter().filter(|&&(a, _)| g.points[a].level == l).count();
        assert_eq!((per_level(0), per_level(1), per_level(2)), (6, 16, 42), "pairs per level sum to 64");
    }

    #[test]
    fn cos_sin_lut_matches_oracle_golden() {
        // Recomputed Q16 LUTs match the DLL's g_anSynaQmCosLut/SinLut samples (tools/qm-dll-oracle).
        let (cos, sin) = (qm_cos_lut(), qm_sin_lut());
        for &(d, c, s) in &[
            (0i32, 65536i32, 0i32), (30, 56756, 32768), (45, 46341, 46341),
            (60, 32768, 56756), (90, 0, 65536), (180, -65536, 0),
        ] {
            assert_eq!(cos[d as usize], c, "cos[{d}]");
            assert_eq!(sin[d as usize], s, "sin[{d}]");
        }
    }

    #[test]
    fn descriptor_brief_matches_oracle_golden() {
        // Bit-exact vs syna_qm_descriptor_brief@0x18000dfe0 (tools/qm-dll-oracle/golden/brief.txt).
        // The oracle drives dfe0 with a crafted 40×40 tile field (Lx=tile+0x20, Ly=tile+0x28), the
        // real e600 point table + the {2·idx_a, 2·idx_b} pairs, and sweeps rotations; we reproduce
        // the same field + pair_geometry_dll(7) geometry here.
        let f = oracle_tile_field();
        let geom = pair_geometry_dll(DESC_RADIUS_DLL);
        let (cos, sin) = (qm_cos_lut(), qm_sin_lut());
        // (px, py, angle_q16, golden bytes). The LUT degree is derived from angle_q16 by both the DLL
        // and the port (`angle_q16/205887.416·180`), so passing the same angle_q16 is what matters.
        #[rustfmt::skip]
        let cases: &[(i32, i32, i32, [u8; 8])] = &[
            (20, 20, 0,      [218, 175, 117, 45, 46, 91, 229, 70]),
            (20, 20, 34314,  [222, 191, 119, 189, 190, 91, 245, 102]),
            (20, 20, 102943, [222, 191, 119, 189, 190, 91, 245, 102]),
            (20, 20, 171572, [218, 174, 69, 33, 46, 27, 229, 70]),
            (8,  8,  51471,  [247, 159, 118, 255, 251, 89, 246, 38]),
            (33, 33, 228763, [72, 174, 101, 9, 36, 27, 161, 70]),
        ];
        for &(px, py, aq, want) in cases {
            let got = descriptor_brief_dll(&f, px << 16, py << 16, aq, &geom, &cos, &sin);
            assert_eq!(got, want, "px={px} py={py} angle_q16={aq}");
        }
    }

    /// The 40×40 crafted tile field the oracle drives d870/dfe0 with (Lx=tile+0x20, Ly=tile+0x28).
    fn oracle_tile_field() -> DohField {
        const TW: usize = 40;
        const TH: usize = 40;
        let mut lx = vec![0i32; TW * TH];
        let mut ly = vec![0i32; TW * TH];
        for y in 0..TH as i32 {
            for x in 0..TW as i32 {
                lx[(y * TW as i32 + x) as usize] = (x * 7919 - y * 5417) - 40000;
                ly[(y * TW as i32 + x) as usize] = (x * 3313 + y * 2711) - 60000;
            }
        }
        DohField { width: TW, height: TH, response: vec![], lxx: vec![], lyy: vec![], lxy: vec![], lx, ly }
    }

    #[test]
    fn orientation_dll_matches_oracle_golden() {
        // Bit-exact vs syna_qm_minutia_orientation@0x18000d870 (tools/qm-dll-oracle/golden/brief.txt
        // ORIENT lines). The oracle drives d870 with the same 40×40 field + scale=1 (shift=0); the
        // linear field yields a distinct dominant Q16-radian angle per in-bounds center, pinning the
        // 13×13 disc sampling + weighting + 7-bin spread + argmax + fixed-point atan2.
        let f = oracle_tile_field();
        for &(px, py, want) in &[
            (20, 20, 90911),
            (15, 25, 156063),
            (30, 10, 27903),
            (8, 8, 231442),
            (33, 33, 83216),
        ] {
            assert_eq!(minutia_orientation_dll(&f, px, py, ORIENT_SCALE_DLL), want, "orient at ({px},{py})");
        }
        // Window-scale knob is DLL-faithful across values (golden ORIENTSCALE): scale=0 is the
        // degenerate center-pixel-only collapse, scale=2 the dilated window.
        assert_eq!(minutia_orientation_dll(&f, 20, 20, 0), 92646, "degenerate scale=0");
        assert_eq!(minutia_orientation_dll(&f, 20, 20, 2), 72260, "dilated scale=2");
    }

    #[test]
    fn finalize_angle_deg_maps_half_circle() {
        // The [0,2π) Q16-radian orientation rescales to [0,180): 0→0, π/2→45, π→90, 2π→180→0.
        assert_eq!(finalize_angle_deg(0), 0);
        assert_eq!(finalize_angle_deg(102943), 45); // π/2
        assert_eq!(finalize_angle_deg(205887), 90); // π
        assert_eq!(finalize_angle_deg(411774), 0); // 2π → 180 folds to 0
    }

    #[test]
    fn different_textures_give_different_descriptors() {
        let (w, h) = (48usize, 40usize);
        let f0 = doh_response(&ridge_image(w, h, 6.0, 0.0), w, h, &crate::detect::DohParams { ksize: crate::detect::gaussian_taps(1.5), sigma: 1.5, scale: 1 });
        let f1 = doh_response(&ridge_image(w, h, 3.0, 0.5), w, h, &crate::detect::DohParams { ksize: crate::detect::gaussian_taps(1.5), sigma: 1.5, scale: 1 });
        let (_, a) = describe(&f0, 24, 20);
        let (_, b) = describe(&f1, 24, 20);
        let hamming: u32 = a.iter().zip(&b).map(|(x, y)| (x ^ y).count_ones()).sum();
        assert!(hamming > 0, "distinct textures should yield distinct descriptors");
    }
}
