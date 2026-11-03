//! Phase 2 — the DoH (Determinant-of-Hessian) response field the NMS detector maximizes.
//!
//! Ground truth (`../../docs/qm/qm-minutiae-detector.md`; `FUN_18000a100` +
//! `syna_qm_boxfilter_normalize@0x18000f1a0` → `FUN_18000cb70`/`FUN_18000cdd0`):
//! ```text
//! I   = pixel << 16                     # Q16.16, halo-padded with 0x800000
//! L   = G_σ * I                         # separable unit-area GAUSSIAN pre-smooth (fe50, exp-LUT)
//! Lxx,Lxy,Lyy = 2nd derivatives of L    # central diff [+1,0,-1]·1024, 3-tap orthogonal smoother
//! R   = (Lxx>>12)*(Lyy>>12) - (Lxy>>12)^2   # determinant of Hessian  (FUN_18000cdd0)
//! ```
//! This is a scale-normalized SURF-family blob response — **not** smoothed intensity. Local maxima
//! of `R` are candidate minutiae; `sign(Lxx)`/`sign(Lyy)` give the ending-vs-bifurcation class.
//!
//! Fidelity: faithful-**structural** (i32 Q16.16 mirroring the decompile), validated by
//! finger-dependence (AGENTS.md #7). The per-tile scale is **`s = 1`** — resolved statically from
//! `detect_kernel_params@0x18000a070` (`ctx.scale_mul = 0x400`, single full-frame tile) so
//! `s = (0x466·0x400 + 0x80000)>>20 = 1` (see `docs/qm/doh-detector-faithful.md`). At `s=1` the exact
//! DLL kernels are the `FUN_18000fc50` special case (derivative `[0x400,0,-0x400]`, smoother
//! `[96,320,96]`), and both the pre-smooth and each derivative wrap their conv in the DLL's `x>>=6` /
//! `x<<=6` headroom. The only remaining data value is the Gaussian σ (DLL exp-LUT `DAT_180160550`),
//! approximated analytically here. Per AGENTS.md #7 this is a processed diagnostic field, never
//! asserted to "show ridges".

use super::config::DetectConfig;
use super::Q16_SHIFT;

/// Derivative scale `s` the DLL runs the DoH at. `detect_kernel_params@0x18000a070` builds a
/// **single** full-frame tile (`tile_rows = tile_cols = 1`), and `hessian_scale_derivatives@0x18000cb70`
/// evaluates `s = ((tile[+0x5c] * ctx[+0x18]) / (1<<tile[+0x60]) + 0x80000) >> 20` = `1` for row 0.
pub const DOH_DERIV_SCALE: i32 = 1;

/// Headroom shift applied to each second-derivative plane before multiplying, so `Lxx*Lyy` fits i32.
/// `FUN_18000cdd0`: `(Lyy>>0xc)*(Lxx>>0xc) - (Lxy>>0xc)^2`.
pub const DOH_HEADROOM_SHIFT: u32 = 12;

/// Unit gain the DLL derivative kernels are scaled by (`FUN_18000a070[6]=[7]=0x400`); central
/// difference is `[+0x400, 0, -0x400]`.
pub const DERIV_UNIT: i32 = 0x400;

/// The DoH response field plus the intermediate Hessian planes, for detection and visualization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohField {
    pub width: usize,
    pub height: usize,
    /// `R = det(Hessian)` — the plane NMS maximizes (`tile_desc+0x50`).
    pub response: Vec<i32>,
    /// `Lxx` — second x-derivative (`tile_desc+0x30`; polarity map 1).
    pub lxx: Vec<i32>,
    /// `Lyy` — second y-derivative (`tile_desc+0x40`; polarity map 2).
    pub lyy: Vec<i32>,
    /// `Lxy` — mixed second derivative (`tile_desc+0x38`).
    pub lxy: Vec<i32>,
    /// `Lx` — first x-derivative of the smoothed image (gradient plane the descriptor samples).
    pub lx: Vec<i32>,
    /// `Ly` — first y-derivative of the smoothed image.
    pub ly: Vec<i32>,
}

/// Convert an 8-bit image to the Q16.16 field the detector works in (`pixel << 16`).
pub fn to_q16(pixels: &[u8]) -> Vec<i32> {
    pixels.iter().map(|&p| (p as i32) << Q16_SHIFT).collect()
}

/// Build a normalized 1-D Gaussian kernel of `taps` samples for standard deviation `sigma` (pixels),
/// scaled to unit DC gain `1 << out_shift` fixed point. Structural port of
/// `syna_qm_gaussian_kernel@0x18000fe50` (which samples the same `exp(-x^2/2σ^2)` via the `DAT_180160550`
/// LUT and normalizes `Σ → 4096`). We evaluate `exp` in `f32` (allowed for the FP kernel spot); the
/// bit-exact LUT path is a later refinement.
pub fn gaussian_kernel(taps: usize, sigma: f32, out_shift: u32) -> Vec<i32> {
    let scale = (1i64 << out_shift) as f32;
    let center = (taps as f32 - 1.0) * 0.5;
    let raw: Vec<f32> = (0..taps)
        .map(|i| {
            let x = i as f32 - center;
            (-(x * x) / (2.0 * sigma * sigma)).exp()
        })
        .collect();
    let sum: f32 = raw.iter().sum();
    raw.iter().map(|&v| ((v / sum) * scale).round() as i32).collect()
}

/// Odd tap count covering `±3σ` — matches the DLL picking an odd kernel size from the scale.
pub fn gaussian_taps(sigma: f32) -> usize {
    let half = (3.0 * sigma).ceil() as usize;
    2 * half + 1
}

/// The DLL's fixed-point `exp` LUT (`DAT_180160550`), captured from the **live** mapped image via the
/// synaTudor relinker oracle (`tools/qm-dll-oracle`; Q16, `LUT[0]=exp(0)=65536`). Ghidra's static read
/// disagreed at index 4 (29989 vs live 30005) — the loaded image is authoritative.
const QM_EXP_LUT: [i32; 40] = [
    65536, 53908, 44344, 36476, 30005, 24681, 20302, 16700, 13737, 11300, 9295, 7646, 6289, 5173, 4256,
    3501, 2879, 2369, 1948, 1603, 1318, 1084, 892, 734, 604, 496, 408, 336, 276, 227, 187, 154, 127, 104,
    86, 70, 58, 48, 39, 32,
];

/// Bit-exact port of `syna_qm_exp_lut@0x18000fe10`: `idx = (((coeff·x>>2)·x>>8) / 25) >> 13`, returns
/// `LUT[-idx]`. The `/25` uses the DLL's magic-number division (`*0x51eb851f`, high word `>>3`, round
/// toward zero) so the truncation matches the hardware exactly. All products wrap in i32 as the DLL's
/// 32-bit `IMUL` does. Out-of-table indices (deep underflow) read 0.
fn dll_exp_lut(coeff: i32, x: i32) -> i32 {
    let c = coeff.wrapping_mul(x) >> 2;
    let c = c.wrapping_mul(x) >> 8;
    let hi = ((c as i64).wrapping_mul(0x51eb_851f) >> 32) as i32; // high word of the /25 magic product
    let mut q = hi >> 3;
    q = q.wrapping_add(((q as u32) >> 31) as i32); // round toward zero for negatives
    let k = (-(q >> 13)) as usize;
    QM_EXP_LUT.get(k).copied().unwrap_or(0)
}

/// Bit-exact port of `syna_qm_gaussian_kernel@0x18000fe50` — the Gaussian pre-smooth kernel the DLL
/// actually builds. σ is derived from `ksize` internally (`sigma_int = (ksize·0x26600 + 0x59acd) >> 10`),
/// `coeff = -0x20000000 / sigma_int²`; each tap `k[i] = exp_lut(coeff, x) >> 4` with `x` stepping `0x400`
/// from `-0x200·(ksize-1)`; then normalised to `Σ ≈ 4096` via `factor = (0x40000000 / Σ) >> 3`,
/// `k[i] = (k[i]·factor) >> 15`. Validated bit-for-bit against the DLL for ksize 7/11/35
/// (`tools/qm-dll-oracle/golden/doh_kernels.txt`).
pub fn gaussian_kernel_dll(ksize: usize) -> Vec<i32> {
    let ks = ksize as i32;
    let sigma_int = (ks.wrapping_mul(0x26600).wrapping_add(0x59acd)) >> 10;
    let coeff = -0x2000_0000i32 / (sigma_int * sigma_int);
    let mut k = vec![0i32; ksize];
    let mut sum = 0i32;
    for (i, slot) in k.iter_mut().enumerate() {
        // DLL: tap position x = 0x200 - (ksize<<9), stepping +0x400 (= -0x200·(ksize-1) at the centre 0).
        let x = 0x200 - ks * 512 + (i as i32) * 0x400;
        let e = dll_exp_lut(coeff, x) >> 4;
        *slot = e;
        sum = sum.wrapping_add(e);
    }
    let factor = (0x4000_0000i32 / sum) >> 3;
    for slot in &mut k {
        *slot = slot.wrapping_mul(factor) >> 15;
    }
    k
}

/// Halo/border fill for out-of-frame samples: `128 << 16` mid-grey in Q16.16. The DLL pads the field
/// with this (`FUN_180009ea0(buf, 0x800000, …)`) rather than replicating the edge pixel.
pub const HALO_FILL_Q16: i32 = 0x0080_0000;

/// Convert a **byte-domain conditioned field** (`reconstruct_roi` u8 carried as `f32` in 0..255)
/// into the `u8` image the DoH consumes.
///
/// `syna_qm_doh_build_field@0x18000a100` takes a plain byte buffer (`(uint)byte << 0x10`). The DLL
/// feeds it the output of `syna_ir_reconstruct_roi@0x1800b9430` directly — a normal-brightness
/// mid-grey image, not a signed zero-mean field. Our graph carries that same quantity as `f32`
/// for the Gray wire type, so the conversion is `clamp(round(v), 0, 255)`.
///
/// The old `+128` re-centre belonged to a host z-score signed carrier that is no longer on the QM
/// path (`docs/qm/conditioning-topology.md`).
pub fn conditioned_to_u8(field: &[f32]) -> Vec<u8> {
    field
        .iter()
        .map(|&v| v.round().clamp(0.0, u8::MAX as f32) as u8)
        .collect()
}

/// Historical DC bias of the SelectFrame scratch normalize (`syna_ir_normalize_frame` @ `0x80`).
/// Not used on the QM path — QM sees `reconstruct_roi` — kept only so older comments/tests that
/// name the constant still resolve.
pub const CONDITIONED_DC_BIAS: i32 = 0x80;

/// Separable convolution of a Q16.16 field with 1-D kernels `kx` (rows) then `ky` (cols), each in
/// `1<<shift` fixed point. Mirrors `syna_qm_convolve_separable@0x18000fd40`, which runs the row pass
/// (`FUN_18000f3b0`) then the column pass (`FUN_18000f790`) over the same buffer.
pub fn convolve_separable(field: &[i32], w: usize, h: usize, kx: &[i32], ky: &[i32], shift: u32) -> Vec<i32> {
    let tmp = convolve_axis(field, w, h, kx, shift, true);
    convolve_axis(&tmp, w, h, ky, shift, false)
}

/// One separable pass along rows (`horizontal=true`) or columns, bit-exact with `FUN_18000f3b0`:
///
/// - **True convolution, not correlation** — the DLL pairs `buf[k]` with `kernel[len-1-k]`, so the
///   kernel is applied reversed. Only the antisymmetric derivative kernel notices, and it flips the
///   sign of `Lx`/`Ly` (the second derivatives, and hence `R`, are unaffected).
/// - **Out-of-frame taps are dropped**, i.e. zero-padded: the DLL splits the line into a leading,
///   middle and trailing region and simply shortens the kernel span in the first and last `radius`
///   outputs. It does *not* read the buffer halo here — `syna_qm_halo_pad`'s `0x800000` ring only
///   exists where a tile has a neighbour, and the convolution truncates at the (padded) buffer edge
///   regardless.
/// - **32-bit arithmetic throughout**: `IMUL EAX,…` / `SAR EAX,CL` / `ADD` are all 32-bit, so each
///   tap is shifted before accumulating and every step wraps like the DLL's.
fn convolve_axis(field: &[i32], w: usize, h: usize, kernel: &[i32], shift: u32, horizontal: bool) -> Vec<i32> {
    let klen = kernel.len() as isize;
    let radius = klen / 2;
    let (iw, ih) = (w as isize, h as isize);
    let mut out = vec![0i32; w * h];
    for y in 0..h {
        for x in 0..w {
            let mut acc: i32 = 0;
            for k in 0..klen {
                let off = k - radius;
                let (sx, sy) = if horizontal { (x as isize + off, y as isize) } else { (x as isize, y as isize + off) };
                if sx < 0 || sx >= iw || sy < 0 || sy >= ih {
                    continue;
                }
                let sample = field[sy as usize * w + sx as usize];
                let coeff = kernel[(klen - 1 - k) as usize];
                acc = acc.wrapping_add(sample.wrapping_mul(coeff) >> shift);
            }
            out[y * w + x] = acc;
        }
    }
    out
}

/// The DLL's `x>>=6` / conv / `x<<=6` headroom wrapper shared by the pre-smooth
/// (`syna_qm_boxfilter_normalize@0x18000f1a0`) and each derivative pass
/// (`syna_qm_derivative_apply@0x1800102d0`): the field is pre-divided by 64 so the 32-bit `px*k`
/// products keep precision through the `>>shift`, then re-multiplied.
fn convolve_with_headroom(field: &[i32], w: usize, h: usize, kx: &[i32], ky: &[i32], shift: u32) -> Vec<i32> {
    let src: Vec<i32> = field.iter().map(|&x| x >> 6).collect();
    let mut out = convolve_separable(&src, w, h, kx, ky, shift);
    for v in &mut out {
        *v = v.wrapping_shl(6);
    }
    out
}

/// The `2s+1`-wide sparse derivative + smoother kernels the DLL builds. Both have exactly three
/// non-zero taps at `[0]`, `[w/2]`, `[w-1]`:
/// - derivative (order-1): `[+0x400, 0, -0x400]` — a central difference spanning `2s` pixels.
/// - smoother (order-0):   `[base, mid, base]` (the `[1, 3.33, 1]` shape).
///
/// **`s == 1`** takes the DLL's special-case `FUN_18000fc50`: derivative `[0x400, 0, -0x400]`,
/// smoother `[0xc00, 0x2800, 0xc00] · 1 >> 5 = [96, 320, 96]` (sum 512). **`s > 1`** uses the general
/// builder (`syna_qm_build_deriv_kernels`): `base = 0x100000/(s·0x2aaa)`, `mid = base·0xd55 >> 10`.
fn deriv_kernels(s: i32) -> (Vec<i32>, Vec<i32>) {
    let s = s.max(1);
    let width = (2 * s + 1) as usize;
    let (mid, last) = (width / 2, width - 1);
    let mut deriv = vec![0i32; width];
    deriv[0] = DERIV_UNIT;
    deriv[last] = -DERIV_UNIT;
    let mut smooth = vec![0i32; width];
    if s == 1 {
        // FUN_18000fc50: [0xc00, 0x2800, 0xc00] normalised ·1>>5.
        smooth[0] = 0xc00 >> 5; // 96
        smooth[mid] = 0x2800 >> 5; // 320
        smooth[last] = 0xc00 >> 5; // 96
    } else {
        let base = (0x100000i64 / (s as i64 * 0x2aaa)) as i32;
        smooth[0] = base;
        smooth[mid] = ((base as i64 * 0xd55) >> 10) as i32;
        smooth[last] = base;
    }
    (deriv, smooth)
}

/// Central-difference derivative along one axis, with the orthogonal smoother — the DLL's
/// `syna_qm_derivative_apply@0x1800102d0` operator: `x>>=6`, separable conv (deriv ⟂ smooth) at
/// conv-shift 10, `x<<=6`. `s` sets the kernel width (`2s+1`); `s=1` on this SKU.
fn derivative(field: &[i32], w: usize, h: usize, dx: bool, s: i32) -> Vec<i32> {
    const SHIFT: u32 = 10;
    let (deriv, smooth) = deriv_kernels(s);
    if dx {
        convolve_with_headroom(field, w, h, &deriv, &smooth, SHIFT)
    } else {
        convolve_with_headroom(field, w, h, &smooth, &deriv, SHIFT)
    }
}

/// Faithful DoH knobs. [`Default`] = the DLL's `0x2449` values (ksize `35` from `geom_p14`, per-tile
/// scale `s=1` — resolved statically, `cb70`/`a070`); every field is a knob. `sigma <= 0` derives σ
/// from `ksize` (~ksize/6). Only the exact σ (DLL exp-LUT) is fixture-pending — see
/// `docs/qm/doh-detector-faithful.md`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DohParams {
    /// Gaussian smoothing kernel size (odd). Derived by the DLL from the detect-context scale — see
    /// [`DetectConfig::gaussian_ksize`]. For `0x2449`: `5`.
    pub ksize: usize,
    /// Gaussian σ in pixels; `<= 0` ⇒ derive from `ksize`.
    pub sigma: f32,
    /// Derivative scale `s`: kernel width `2s+1` and the `s`/`s²` scale-normalisation. DLL default `1`.
    pub scale: i32,
}

impl Default for DohParams {
    /// The DLL's own parameters for our reference silicon, derived from the config table rather
    /// than hard-coded (AGENTS.md #6): `ksize` from `geom_p10`, `scale` `s = 1` from the single-tile
    /// grid (`detect_kernel_params@0x18000a070`), and `sigma = 0` meaning "use the DLL exp-LUT
    /// kernel". Use [`DohParams::for_config`] for a sibling subtype.
    fn default() -> Self {
        Self::for_config(&crate::detect::config::CONFIG_2449)
    }
}

impl DohParams {
    /// DoH field parameters for a given detector config row.
    pub const fn for_config(cfg: &DetectConfig) -> Self {
        Self { ksize: cfg.gaussian_ksize(), sigma: 0.0, scale: DOH_DERIV_SCALE }
    }
}

/// Compute the DoH response field from an 8-bit image. Faithful-structural port of the
/// `FUN_18000a100 → cb70 → cdd0` chain (Gaussian pre-smooth → 2nd derivatives → det Hessian).
///
/// `sigma` is the Gaussian smoothing scale in pixels (the DLL derives it from `cfg` via the exp-LUT
/// path; here it is an explicit knob so callers/tests can sweep it and validate finger-dependence).
pub fn doh_response(pixels: &[u8], w: usize, h: usize, p: &DohParams) -> DohField {
    let img = to_q16(pixels);
    // L = G_σ * I — Gaussian pre-smooth with the DLL's kernel size (misnamed "boxfilter"). σ is
    // derived from ksize when not given (~ksize/6, so a 35-tap kernel ≈ σ 5.8). The DLL wraps the
    // conv in `x>>=6` / `x<<=6` headroom (`syna_qm_boxfilter_normalize`); Σk = 4096, conv-shift 12 →
    // unit DC gain.
    let ksize = (p.ksize.max(1)) | 1; // odd
    // sigma <= 0 (the DLL default) => the bit-exact DLL kernel (σ derived from ksize via the exp LUT).
    // sigma > 0 is the port's tunable knob (analytic f32 Gaussian at that σ).
    let gk = if p.sigma > 0.0 {
        gaussian_kernel(ksize, p.sigma, 12)
    } else {
        gaussian_kernel_dll(ksize)
    };
    let smoothed = convolve_with_headroom(&img, w, h, &gk, &gk, 12);

    // First then second derivatives with the scale-`s` operator, in the DLL's own order
    // (`syna_qm_hessian_scale_derivatives@0x18000cb70`): Ly and Lx off the smoothed image, then
    // Lxy = d/dy(Lx), Lxx = d/dx(Lx), Lyy = d/dy(Ly).
    let s = p.scale.max(1);
    let lx0 = derivative(&smoothed, w, h, true, s);
    let ly0 = derivative(&smoothed, w, h, false, s);
    let lxx0 = derivative(&lx0, w, h, true, s);
    let lyy0 = derivative(&ly0, w, h, false, s);
    let lxy0 = derivative(&lx0, w, h, false, s);

    // Scale-normalisation (cb70): 1st derivatives × s, 2nd derivatives × s². A no-op at s=1.
    let (sf, s2) = (s as i64, (s as i64) * (s as i64));
    let scale = |v: &[i32], k: i64| -> Vec<i32> { v.iter().map(|&x| (x as i64 * k) as i32).collect() };
    let lx = scale(&lx0, sf);
    let ly = scale(&ly0, sf);
    let lxx = scale(&lxx0, s2);
    let lyy = scale(&lyy0, s2);
    let lxy = scale(&lxy0, s2);

    // R = (Lxx>>12)*(Lyy>>12) - (Lxy>>12)^2  — det(Hessian), FUN_18000cdd0.
    let sh = DOH_HEADROOM_SHIFT;
    let response: Vec<i32> = (0..w * h)
        .map(|i| {
            let a = (lxx[i] >> sh) as i64;
            let b = (lyy[i] >> sh) as i64;
            let c = (lxy[i] >> sh) as i64;
            (a * b - c * c) as i32
        })
        .collect();

    DohField { width: w, height: h, response, lxx, lyy, lxy, lx, ly }
}

/// Local structure orientation (undirected, `0..=179°`) from the Hessian principal axis at a pixel:
/// `θ = ½·atan2(2·Lxy, Lxx − Lyy)`. This is a **diagnostic** ridge-orientation estimate derived from
/// the finger-dependent field — NOT the DLL's minutia descriptor angle (that comes from the PASS-2
/// neighbor descriptor `FUN_18000e600`, ported in a later phase). Rule #7: report as processed
/// orientation, not an asserted ridge direction.
pub fn orientation_deg(field: &DohField, x: usize, y: usize) -> u16 {
    let idx = y * field.width + x;
    orientation_from_hessian(field.lxx[idx], field.lxy[idx], field.lyy[idx])
}

/// [`orientation_deg`] on loose Hessian components, so a whole-field diagnostic view can render the
/// same estimate without re-deriving the formula (or reshaping its planes into a [`DohField`]).
pub fn orientation_from_hessian(lxx: i32, lxy: i32, lyy: i32) -> u16 {
    let (a, b, d) = (lxx as f32, lxy as f32, lyy as f32);
    let mut deg = 0.5 * (2.0 * b).atan2(a - d) * 180.0 / std::f32::consts::PI;
    if deg < 0.0 {
        deg += 180.0;
    }
    (deg.round() as i32).rem_euclid(180) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gaussian_kernel_is_symmetric_and_unit_gain() {
        let k = gaussian_kernel(7, 1.0, 12);
        assert_eq!(k.len(), 7);
        // symmetric
        for i in 0..3 {
            assert_eq!(k[i], k[6 - i], "tap {i}");
        }
        // peak in the middle
        assert!(k[3] >= k[2] && k[3] >= k[4]);
        // ~unit DC gain (4096 = 1<<12), within rounding
        let sum: i32 = k.iter().sum();
        assert!((sum - 4096).abs() <= 8, "sum {sum}");
    }

    // Golden vectors captured from the REAL DLL via the synaTudor relinker oracle
    // (`tools/qm-dll-oracle`, golden/doh_kernels.txt). These validate the bit-exact port paths.
    #[test]
    fn gaussian_kernel_dll_matches_oracle_golden() {
        // 5 is the size the 0x2449 cfg actually selects (DetectConfig::gaussian_ksize).
        assert_eq!(gaussian_kernel_dll(5), [287, 927, 1666, 927, 287]);
        assert_eq!(gaussian_kernel_dll(7), [124, 400, 875, 1294, 875, 400, 124]);
        assert_eq!(gaussian_kernel_dll(11), [38, 101, 269, 485, 717, 871, 717, 485, 269, 101, 38]);
        assert_eq!(
            gaussian_kernel_dll(35),
            [
                2, 5, 9, 13, 20, 30, 44, 65, 80, 97, 143, 174, 212, 212, 258, 258, 258, 314, 258, 258,
                258, 212, 212, 174, 143, 97, 80, 65, 44, 30, 20, 13, 9, 5, 2
            ]
        );
        // DC gain targets 4096 (Q12) but the DLL's per-tap `k·factor>>15` truncation lands it a bit
        // under — Σ = 4074 for ksize 35. Pinned to the DLL's actual value.
        let sum: i32 = gaussian_kernel_dll(35).iter().sum();
        assert_eq!(sum, 4074, "gauss35 sum (DLL truncated normalization)");
    }

    #[test]
    fn deriv_kernels_match_oracle_golden() {
        // s=1 (FUN_18000fc50): deriv [1024,0,-1024], smoother [96,320,96].
        assert_eq!(deriv_kernels(1), (vec![1024, 0, -1024], vec![96, 320, 96]));
        // s=2/3 (build_deriv_kernels general path).
        assert_eq!(deriv_kernels(2), (vec![1024, 0, 0, 0, -1024], vec![48, 0, 159, 0, 48]));
        assert_eq!(deriv_kernels(3), (vec![1024, 0, 0, 0, 0, 0, -1024], vec![32, 0, 0, 106, 0, 0, 32]));
    }

    #[test]
    fn flat_image_has_zero_response() {
        // A constant field has zero curvature -> zero Hessian -> zero determinant.
        let (w, h) = (32usize, 24usize);
        let (ksize, s) = (gaussian_taps(1.2), 1i32);
        let px = vec![128u8; w * h];
        let f = doh_response(&px, w, h, &DohParams { ksize, sigma: 1.2, scale: s });
        // Only away from the border: the DLL's passes zero-pad (they shorten the kernel span at the
        // buffer edge, they do not clamp or reflect), so a flat image *does* have curvature there —
        // the smoother sees the image fall off to 0. The affected band is the Gaussian radius plus
        // one derivative radius per pass, and Lxx/Lyy are two passes deep.
        let m = ksize / 2 + 2 * (s as usize);
        for y in m..h - m {
            for x in m..w - m {
                assert_eq!(f.response[y * w + x], 0, "flat response at ({x},{y})");
            }
        }
        assert_ne!(f.response[0], 0, "the zero-pad edge should ring, else this test proves nothing");
    }

    #[test]
    fn blob_produces_positive_det_hessian_peak() {
        // A bright Gaussian-ish blob on a dark field is a det(Hessian) extremum at its center.
        let (w, h) = (33usize, 33usize);
        let mut px = vec![20u8; w * h];
        let (cx, cy) = (16i32, 16i32);
        for y in 0..h as i32 {
            for x in 0..w as i32 {
                let d2 = (x - cx) * (x - cx) + (y - cy) * (y - cy);
                let v = 20.0 + 200.0 * (-(d2 as f32) / 18.0).exp();
                px[(y as usize) * w + x as usize] = v.min(255.0) as u8;
            }
        }
        let f = doh_response(&px, w, h, &DohParams { ksize: gaussian_taps(1.5), sigma: 1.5, scale: 1 });
        let center = f.response[cy as usize * w + cx as usize];
        // center is a strong response and a local maximum vs a flat corner region.
        let corner = f.response[3 * w + 3];
        assert!(center > corner, "blob center {center} should exceed flat corner {corner}");
        assert!(center != 0, "blob center response must be non-zero");
    }
}
