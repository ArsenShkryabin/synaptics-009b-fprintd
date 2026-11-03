//! Image → template extraction (QuantumMatcher path).
//!
//! Active DLL path: `vcsmQuantumMatcher_1800ff610@0x1800ff610` → ASP slot `+0x78`
//! (`syna_sdk_180104130@0x180104130`) → cumulative ASP update → `syna_asp_serialize_template`.
//!
//! Image preconditions from `syna_qm_probe_setup@0x180001a30`:
//! - non-zero width/height at image `+0x04/+0x08`
//! - pixels at `+0x48`
//! - stride fields forced to `0x16b` (363) by the DLL
//! - rows copied in **reverse vertical order** into contiguous `width × height`

use crate::detect;
use crate::template::{Minutia, Template, TemplateError};
use crate::types::{ANGLE_BIN_STEP_DEG, ANGLE_TAIL_DEG, MIN_PROBE_MINUTIAE};

/// Snap the detector's fine Hessian orientation to the template's canonical 15° bin grid
/// (`{0,15,…,150,165}`, the `syna_qm_deserialize_minutiae@0x180005a00` reconstruction grid) so that
/// extracted templates already live on the serialized grid: store/reload is identity, and the live
/// MINUTIAE overlay shares the exact same orientation as the enrolled/gallery view stubs.
fn quantize_angle_grid(deg: u16) -> u16 {
    let step = ANGLE_BIN_STEP_DEG as u16;
    (deg.div_ceil(step) * step).min(ANGLE_TAIL_DEG as u16)
}

/// Conditioned grayscale frame for extraction — the shared neutral type (was a local clone).
pub use synaptics_biometric::ConditionedImage;

/// DLL stride written to image `+0x1c/+0x20`. syna_qm_probe_setup@0x180001a30.
pub const DLL_IMAGE_STRIDE: u16 = 0x16b;

/// VTML magic (`0x4c4d5456` little-endian). Intermediate template marker.
pub const VTML_MAGIC: u32 = 0x4c4d5456;

/// DoH Gaussian smoothing scale (px) for the probe scan. Provisional — the DLL derives σ from `cfg`
/// via the exp-LUT path (`syna_qm_gaussian_kernel@0x18000fe50`), deferred to the bit-exact pass.
const DETECT_SIGMA: f32 = 2.0;

/// Peak threshold as a fraction of the response max (our response scale ≠ the DLL's bit-exact scale;
/// see `detect::emit`). Stands in for the DLL's absolute `500`.
const DETECT_THRESHOLD_FRAC: f32 = 0.15;

/// Minimum pixel distance between kept peaks (`syna_qm_detect_peaks_nms` exclusion radius).
const DETECT_MIN_DISTANCE: i32 = 4;

/// Tunable minutiae-detection parameters. The DLL fixes these in the detector cfg struct
/// (`syna_qm_probe_extract_core@0x180004bc0`); here they are live knobs so the operating point can be
/// calibrated on hardware (our DoH field is structurally faithful but not bit-exact in scale, so the
/// absolute `score_threshold` is meant to be tuned — Rule #7). See [`Self::dll_baseline`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DetectParams {
    /// DoH field knobs (Gaussian ksize/σ + derivative scale `s`). DLL-faithful via [`detect::DohParams`].
    pub doh: detect::DohParams,
    /// Absolute strict NMS threshold `thr1` a peak must exceed (`engine+0x20`). For 0x2449 = `0x15d8`
    /// (5592). Used when [`Self::adaptive_frac`] is `None`.
    pub score_threshold: i32,
    /// Second NMS gate `thr2` (`engine+0x24`, `v >= thr2`). For 0x2449 = `0xa8`; `0` in the adaptive path.
    pub score_threshold2: i32,
    /// If `Some(frac)`, use `frac × max(response)` instead of the absolute threshold (the old
    /// scale-independent behavior). `None` = faithful absolute threshold.
    pub adaptive_frac: Option<f32>,
    /// Minimum pixel distance between kept peaks (NMS exclusion radius). For 0x2449 the DLL's exclusion
    /// is `((engine+0x48>>6)²)>>20 = 1` → `min_distance = 1`.
    pub min_distance: i32,
    /// On a min-distance replace, recompute the class byte (`true`) vs. reproduce the DLL's stale byte
    /// (`false`, the faithful default). See `emit::NmsParams::recompute_class_on_replace`.
    pub recompute_class_on_replace: bool,
    /// PASS-2 describe: `true` = the bit-exact DLL chain ([`detect::describe_dll`]:
    /// `minutia_orientation@d870` → `descriptor_brief@dfe0` → `finalize@f2a0`); `false` = the older f32
    /// structural [`detect::describe`]. Faithful default is `true`.
    pub dll_describe: bool,
    /// Orientation window-step multiplier ([`detect::ORIENT_SCALE_DLL`] = 1 = faithful). Curiosity knob:
    /// `0` reproduces the degenerate center-pixel-only orientation collapse; `2+` dilates the window.
    /// Only affects the bit-exact describe path (`dll_describe = true`).
    pub orient_scale: i32,
    /// Hard cap on kept minutiae, strongest first (DLL cfg+4 = `250`).
    pub max_minutiae: usize,
    /// Per-tile NMS `max_out` — `syna_qm_emit_candidates@0x18000d290` uses `cfg+0 >> 2`
    /// (= **125** on 0x2449). Distinct from the global [`Self::max_minutiae`] cap after sort.
    pub nms_max_out: usize,
    /// NMS scan margin — `emit_candidates` `param_6` = cfg+8 radius (**10** on 0x2449). Min 1.
    pub nms_margin: i32,
    /// Tile grid side: `1` = whole frame; `N` = `N×N` grid (`syna_qm_detect_minutiae` uses `3`).
    pub tiles: usize,
    /// Per-tile overlap/halo (px) giving the DoH kernel neighbour context at tile seams (DLL cfg+8
    /// kernel radius `R`).
    pub overlap: i32,
}

impl DetectParams {
    /// Non-faithful, easy-to-tune preset: a small σ=2 Gaussian, single tile, adaptive `0.15 × max`
    /// threshold (scale-independent, no tile seams). Use when a live operating point matters more than
    /// matching the DLL — the earlier extractor behavior.
    pub fn structural() -> Self {
        Self {
            doh: detect::DohParams { ksize: detect::gaussian_taps(DETECT_SIGMA), sigma: DETECT_SIGMA, scale: 1 },
            score_threshold: 0,
            score_threshold2: 0,
            adaptive_frac: Some(DETECT_THRESHOLD_FRAC),
            min_distance: DETECT_MIN_DISTANCE,
            recompute_class_on_replace: false,
            dll_describe: false, // structural preset keeps the f32 describe
            orient_scale: detect::ORIENT_SCALE_DLL,
            max_minutiae: 250,
            nms_max_out: 250,
            nms_margin: 1,
            tiles: 1,
            overlap: 10,
        }
    }

    /// **DLL-faithful defaults** for silicon subtype `0x2449` (`syna_qm_detect_minutiae` +
    /// `probe_extract_core@0x180004bc0`): Gaussian ksize `5`, derivative scale `s=1`, NMS `thr1`
    /// `0x15d8`, per-tile emit budget `cfg+0>>2` (=125), NMS margin = radius `10`, `3×3` tiling,
    /// global cap `250`. The target of the viewer's "reset to DLL defaults". The DoH field this
    /// produces is bit-exact against the DLL on a captured frame — see
    /// `docs/qm/doh-whole-field-validation.md` and `tests/doh_field_oracle.rs`.
    pub fn dll() -> Self {
        Self::dll_baseline(detect::SUBTYPE_2449)
    }

    /// DLL baseline for a silicon subtype: absolute `score_threshold` + cfg from the detector cfg,
    /// `3×3` tiling, the faithful [`detect::DohParams`] (ksize from `geom_p10`, s=1).
    pub fn dll_baseline(subtype: u16) -> Self {
        let cfg = detect::config_for(subtype);
        Self {
            doh: detect::DohParams::default(),
            score_threshold: cfg.nms_thr1(),
            score_threshold2: detect::DetectConfig::NMS_THR2,
            adaptive_frac: None,
            // ((engine+0x48>>6)²)>>20 = 1 for 0x2449 → min_distance 1 (min_dist_sq = 1).
            min_distance: {
                let mds = cfg.nms_min_dist_sq();
                if mds <= 1 { 1 } else { (mds as f64).sqrt() as i32 }
            },
            recompute_class_on_replace: false,
            dll_describe: true, // faithful: the bit-exact d870→dfe0→f2a0 chain
            orient_scale: detect::ORIENT_SCALE_DLL,
            max_minutiae: cfg.max_minutiae as usize,
            nms_max_out: cfg.nms_max_out(),
            nms_margin: cfg.nms_margin(),
            tiles: detect::DetectConfig::TILE_GRID,
            overlap: cfg.radius,
        }
    }
}

impl Default for DetectParams {
    fn default() -> Self {
        // NOTE: the DLL-faithful preset is [`Self::dll`] (the viewer's "reset to DLL defaults" target).
        // Its response magnitude is no longer unpinned — the field is bit-exact against the DLL on a real
        // frame (tests/doh_field_oracle.rs) — but whether the absolute `thr1` gate then fires at a useful
        // rate is a live-hardware question, so the scale-independent `structural()` preset stays the
        // `Default` until that is measured. See docs/qm/doh-whole-field-validation.md.
        Self::structural()
    }
}

/// Detect candidates on the whole frame or over a `tiles×tiles` grid (per the DLL's 3×3 detector),
/// then reject border candidates. Tiled: each tile is gathered with `overlap` px of real-pixel halo
/// for DoH context (`syna_qm_gather_tile_rows@0x18000a7a0`), detected independently, and a peak is kept
/// only by the tile whose *own* rect contains it (so overlap isn't double-counted).
/// The DoH field of one detector tile: the gathered window plus where it sits in the frame.
///
/// The DLL builds exactly this and nothing larger — `syna_qm_detect_minutiae@0x18000aa00` allocates
/// a single `(2R + h/3) x (2R + w/3)` buffer and reuses it for each of the 9 tiles, gathering the
/// tile plus an `R` halo (`syna_qm_gather_tile_rows@0x18000a7a0`) and running the field kernel over
/// that window. There is no whole-frame field anywhere in the detector.
pub struct TileField {
    /// Window origin in frame coordinates (tile origin minus the halo, clipped).
    pub x0: i32,
    pub y0: i32,
    /// The tile proper, inside the window — peaks outside it belong to a neighbour.
    pub tile_x0: i32,
    pub tile_y0: i32,
    pub tile_x1: i32,
    pub tile_y1: i32,
    /// Grid index, as the DLL tags each candidate at `rec+9`.
    pub tile: u8,
    pub field: detect::DohField,
}

/// Build the per-tile DoH fields for a frame, as the DLL does.
pub fn doh_response_tiles(
    pixels: &[u8],
    w: usize,
    h: usize,
    params: &DetectParams,
) -> Vec<TileField> {
    let grid = params.tiles.max(1) as i32;
    let (wi, hi) = (w as i32, h as i32);
    if grid == 1 {
        return vec![TileField {
            x0: 0,
            y0: 0,
            tile_x0: 0,
            tile_y0: 0,
            tile_x1: wi,
            tile_y1: hi,
            tile: 0,
            field: detect::doh_response(pixels, w, h, &params.doh),
        }];
    }
    let r = params.overlap.max(0);
    let mut out = Vec::with_capacity((grid * grid) as usize);
    for row in 0..grid {
        for col in 0..grid {
            let x0 = col * wi / grid;
            let x1 = if col == grid - 1 { wi } else { (col + 1) * wi / grid };
            let y0 = row * hi / grid;
            let y1 = if row == grid - 1 { hi } else { (row + 1) * hi / grid };
            let (wx0, wx1) = ((x0 - r).max(0), (x1 + r).min(wi));
            let (wy0, wy1) = ((y0 - r).max(0), (y1 + r).min(hi));
            let (ww, wh) = ((wx1 - wx0) as usize, (wy1 - wy0) as usize);
            if ww < 3 || wh < 3 {
                continue;
            }
            let mut win = vec![0u8; ww * wh];
            for yy in 0..wh {
                let src = (wy0 as usize + yy) * w + wx0 as usize;
                win[yy * ww..yy * ww + ww].copy_from_slice(&pixels[src..src + ww]);
            }
            out.push(TileField {
                x0: wx0,
                y0: wy0,
                tile_x0: x0,
                tile_y0: y0,
                tile_x1: x1,
                tile_y1: y1,
                tile: detect::tile_index(row, col),
                field: detect::doh_response(&win, ww, wh, &params.doh),
            });
        }
    }
    out
}

/// Peak detection over the per-tile fields: threshold and NMS inside each window, keep only peaks
/// that land in the tile proper, then the DLL's score sort and `max_minutiae` cap.
pub fn detect_peaks_in_tiles(
    tiles: &[TileField],
    w: usize,
    h: usize,
    params: &DetectParams,
) -> Vec<detect::Candidate> {
    // ONE threshold for the whole frame, not per tile. A per-tile adaptive threshold makes each tile
    // self-normalise to its own peak response, so detection sensitivity jumps at every tile boundary —
    // the tile SEAMS. The adaptive fraction is taken over the global max across all tiles (uniform), and
    // the absolute threshold is already uniform. (docs/qm/doh-detector-faithful.md, D6.)
    let threshold = match params.adaptive_frac {
        Some(frac) => {
            // Interior max (per tile), excluding the halo-inflated border — see `emit::interior_max`.
            let gmax = tiles.iter().map(|t| detect::interior_max(&t.field)).max().unwrap_or(0);
            ((gmax as f64) * frac as f64) as i32
        }
        None => params.score_threshold,
    };
    let mut out: Vec<detect::Candidate> = Vec::new();
    for t in tiles {
        let np = detect::NmsParams {
            thr1: threshold,
            thr2: params.score_threshold2,
            min_dist_sq: params.min_distance * params.min_distance,
            // Per-tile emit budget (`cfg+0 >> 2` on the DLL path), not the global max_minutiae cap.
            max_candidates: params.nms_max_out,
            // `syna_qm_emit_candidates@0x18000d290` passes cfg+8 radius as NMS margin.
            margin: params.nms_margin.max(1),
            recompute_class_on_replace: params.recompute_class_on_replace,
        };
        let peaks =
            detect::refine_and_reject(&t.field, detect::detect_peaks(&t.field, &np));
        for mut c in peaks {
            let (gx, gy) = (t.x0 + c.x, t.y0 + c.y);
            if gx >= t.tile_x0 && gx < t.tile_x1 && gy >= t.tile_y0 && gy < t.tile_y1 {
                c.x = gx;
                c.y = gy;
                c.tile = t.tile;
                out.push(c);
            }
        }
    }
    let mut cands = detect::reject_border(out, w, h);
    // DLL: quicksort by score, cap to cfg.max_minutiae (strongest kept).
    cands.sort_by_key(detect::sort_key::by_score_desc);
    cands.truncate(params.max_minutiae);
    cands
}

/// Describe candidates against the tile field each one came out of — the DLL's second 3x3 pass
/// re-gathers the same windows to refine, so the description samples tile-local planes too.
/// Returns `(minutia, detector_score, class)` per kept candidate, where `class` is the detector's
/// polarity byte (`0` = ridge ending, non-zero = bifurcation). `class` is diagnostic — the
/// descriptor-based matcher does not consume it — but it lets the overlay colour endings vs
/// bifurcations. Callers that don't need it (the `scan_minutiae_sites_scored*` wrappers) drop it.
pub fn describe_candidates_in_tiles(
    tiles: &[TileField],
    cands: &[detect::Candidate],
    dll_describe: bool,
    orient_scale: i32,
) -> Vec<(Minutia, i32, u8)> {
    cands
        .iter()
        .filter_map(|c| {
            let t = tiles.iter().find(|t| t.tile == c.tile).or_else(|| tiles.first())?;
            let (lx, ly) = (c.x - t.x0, c.y - t.y0);
            let cxi = lx.clamp(0, t.field.width as i32 - 1);
            let cyi = ly.clamp(0, t.field.height as i32 - 1);
            let (cx, cy) = (cxi as usize, cyi as usize);
            let (angle, descriptor) = if dll_describe {
                detect::describe_dll(&t.field, cxi, cyi, orient_scale) // bit-exact d870→dfe0→f2a0
            } else {
                detect::describe(&t.field, cx, cy)
            };
            Some((
                Minutia {
                    descriptor,
                    x: c.x.clamp(0, u8::MAX as i32) as u8,
                    y: c.y.clamp(0, u8::MAX as i32) as u8,
                    // Canonical 15° grid so live overlay == enrolled/gallery stubs.
                    angle_deg: quantize_angle_grid(angle),
                },
                c.score,
                c.class,
            ))
        })
        .collect()
}

/// Errors during extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExtractError {
    #[error("invalid image geometry")]
    InvalidGeometry,
    #[error("too few minutiae detected")]
    TooFewMinutiae,
    #[error("unsupported")]
    Unsupported,
}

/// Reverse vertical row order into contiguous buffer — probe_setup copy path.
pub fn flip_vertical_rows(pixels: &[u8], width: usize, height: usize, stride: usize) -> Vec<u8> {
    let mut out = vec![0u8; width * height];
    for row in 0..height {
        let src = (height - 1 - row) * stride;
        let dst = row * width;
        out[dst..dst + width].copy_from_slice(&pixels[src..src + width]);
    }
    out
}

/// Validate and normalize a conditioned image to DLL layout (flip + stride check).
pub fn normalize_image(img: ConditionedImage<'_>) -> Result<Vec<u8>, ExtractError> {
    let w = img.width as usize;
    let h = img.height as usize;
    let stride = img.stride as usize;
    if w == 0 || h == 0 || stride < w {
        return Err(ExtractError::InvalidGeometry);
    }
    let need = stride * (h - 1) + w;
    if img.pixels.len() < need {
        return Err(ExtractError::InvalidGeometry);
    }
    Ok(flip_vertical_rows(img.pixels, w, h, stride))
}

/// Pack detected minutiae into a template. syna_asp_metviper_extract@0x180103a10 path. Preserves each
/// site's position, 64-bit descriptor AND Hessian orientation (`angle_deg`) — the detector already
/// computes the orientation (`detect::describe`), so a template's minutiae carry the same angles as
/// the live-scan overlay rather than a zeroed placeholder.
pub fn sites_to_template(mut minutiae: Vec<Minutia>) -> Result<Template, ExtractError> {
    if minutiae.len() < MIN_PROBE_MINUTIAE as usize {
        return Err(ExtractError::TooFewMinutiae);
    }
    // Sort by orientation so each serialized angle group is monotonic — the exact-round-trip
    // precondition of `Template::serialize_body` (angles are reconstructed from cumulative bin
    // boundaries, which assume ascending angle within a group).
    minutiae.sort_by_key(|m| m.angle_deg);
    // `split` is the group-1/group-2 boundary. The serialize/deserialize round-trips any split
    // bit-exactly (oracle-validated), but the DLL's split is a class partition (the two groups are the
    // two minutia classes) — reproducing it needs the class byte threaded through `Minutia` + the
    // encoder's grouping confirmed. Until then this is a `len/2` content placeholder (not a fidelity gap).
    let split = (minutiae.len() / 2).min(u8::MAX as usize) as u8;
    let descriptor = minutiae.first().map(|m| m.descriptor).unwrap_or([0; 8]);
    Ok(Template {
        descriptor,
        split,
        field_0c: 0,
        minutiae,
    })
}

/// Detect minutiae candidates on a conditioned frame via the real host detector (no minimum count).
///
/// Used by live-view overlays to show partial detections before a full template can be packed.
pub fn scan_minutiae_sites(img: ConditionedImage<'_>) -> Result<Vec<Minutia>, ExtractError> {
    Ok(scan_minutiae_sites_scored(img)?.into_iter().map(|(m, _)| m).collect())
}

/// [`scan_minutiae_sites`] with explicit, tunable [`DetectParams`].
pub fn scan_minutiae_sites_with(
    img: ConditionedImage<'_>,
    params: &DetectParams,
) -> Result<Vec<Minutia>, ExtractError> {
    Ok(scan_minutiae_sites_scored_with(img, params)?.into_iter().map(|(m, _)| m).collect())
}

/// Like [`scan_minutiae_sites`] but returns each candidate's detector **score** (`|R|`, the DoH
/// response at the peak). Ports the single-tile detection path of `syna_qm_detect_minutiae@0x18000aa00`:
/// DoH response (`detect::doh_response`) → NMS local maxima (`detect::detect_peaks`) → sub-pixel
/// stability reject (`detect::refine_and_reject`) → border reject. **Positions are real** (peaks of the
/// finger-dependent response, not the old 8-px lattice). The angle is a diagnostic Hessian orientation
/// (`detect::orientation_deg`); the 64-bit descriptor is left empty until the PASS-2 neighbor
/// descriptor (`FUN_18000e600`) is ported. Rule #7: validated by finger-dependence, never asserted as
/// fingerprint minutiae.
pub fn scan_minutiae_sites_scored(
    img: ConditionedImage<'_>,
) -> Result<Vec<(Minutia, i32)>, ExtractError> {
    scan_minutiae_sites_scored_with(img, &DetectParams::default())
}

/// Like [`scan_minutiae_sites_scored`] but with explicit, tunable [`DetectParams`] (threshold,
/// tiling, min-distance, cap). Detects candidates (whole-frame or 3×3-tiled per the DLL), keeps the
/// strongest `max_minutiae` globally, then attaches the stand-in orientation + descriptor from the
/// whole-frame DoH field. Rule #7: validated by finger-dependence, never asserted as real minutiae.
pub fn scan_minutiae_sites_scored_with(
    img: ConditionedImage<'_>,
    params: &DetectParams,
) -> Result<Vec<(Minutia, i32)>, ExtractError> {
    let w = img.width as usize;
    let h = img.height as usize;
    let pixels = normalize_image(img)?;
    let tiles = doh_response_tiles(&pixels, w, h, params);
    let cands = detect_peaks_in_tiles(&tiles, w, h, params);
    // The public scored API is `(minutia, score)`; the class byte is only for the overlay path.
    Ok(describe_candidates_in_tiles(&tiles, &cands, params.dll_describe, params.orient_scale)
        .into_iter()
        .map(|(m, s, _class)| (m, s))
        .collect())
}



/// Extract a QM template from a conditioned image.
///
/// Runs the ported host detector (`scan_minutiae_sites` → `detect::detect_peaks`, the single-tile
/// path of `syna_qm_detect_minutiae@0x18000aa00`) and packs the survivors into a [`Template`]. On this
/// SKU minutiae ARE extracted host-side; the full DLL wrapper (`syna_qm_probe_setup@0x180001a30` →
/// `syna_qm_probe_extract_core@0x180004bc0` → 3×3-tiled detector → VTML via
/// `syna_qm_enroll_extract_vt90@0x1800ff610`) additionally does the two-pass tiling + the PASS-2
/// neighbor descriptor (`FUN_18000e600`) that fills the 64-bit `descriptor`/exact angle — not yet
/// ported, so `descriptor` is empty here and the angle is a diagnostic Hessian orientation. Rule #7:
/// positions are real (finger-dependent response peaks), but validate by finger-dependence and never
/// assert the output "shows ridges". The MetViper net (`feature_vector.rs`) is a separate *scoring*
/// sub-path, not the minutiae source. See `docs/qm/qm-minutiae-detector.md`.
pub fn extract_template(img: ConditionedImage<'_>) -> Result<Template, ExtractError> {
    sites_to_template(scan_minutiae_sites(img)?)
}

/// [`extract_template`] with explicit, tunable [`DetectParams`] — e.g. [`DetectParams::dll_baseline`]
/// for the 3×3-tiled, absolute-threshold detector, or a live-tuned set from the viewer.
pub fn extract_template_with(
    img: ConditionedImage<'_>,
    params: &DetectParams,
) -> Result<Template, ExtractError> {
    sites_to_template(scan_minutiae_sites_with(img, params)?)
}

/// Serialize a template to an ASP blob container.
pub fn template_to_blob(t: &Template) -> Result<Vec<u8>, TemplateError> {
    t.to_blob()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flip_vertical_matches_row_reversal() {
        let px = [1u8, 2, 0, 0, 3, 4, 0, 0];
        let out = flip_vertical_rows(&px, 2, 2, 4);
        assert_eq!(out, vec![3, 4, 1, 2]);
    }

    #[test]
    fn extract_uniform_image_returns_template_or_too_few() {
        let px = vec![128u8; 144 * 56];
        let img = ConditionedImage {
            pixels: &px,
            width: 144,
            height: 56,
            stride: 144,
        };
        match extract_template(img) {
            Ok(t) => assert!(t.minutiae.len() >= MIN_PROBE_MINUTIAE as usize),
            Err(ExtractError::TooFewMinutiae) => {}
            Err(e) => panic!("unexpected {e:?}"),
        }
    }

    /// Deterministic varied texture — distinct local neighbourhoods, like the integration tests'
    /// `varied_texture`. Hashed on **4×4 blocks** (not per-pixel) so the structure survives the σ=2
    /// pre-smooth, with strong contrast centred on mid-grey (64..191) so the `0x800000` halo pad
    /// equals the background band and injects no dominating border edge (see `field.rs` halo note).
    fn varied(seed: u32) -> Vec<u8> {
        (0..144 * 56)
            .map(|p| {
                let (bx, by) = (((p % 144) / 4) as u32, ((p / 144) / 4) as u32);
                let hh = bx
                    .wrapping_mul(2_654_435_761)
                    .wrapping_add(by.wrapping_mul(40_503))
                    .wrapping_add(seed.wrapping_mul(2_246_822_519));
                (64 + ((((hh >> 13) ^ (hh >> 7)) & 0xff) >> 1)) as u8
            })
            .collect()
    }

    fn scan_count(px: &[u8], params: &DetectParams) -> usize {
        let img = ConditionedImage { pixels: px, width: 144, height: 56, stride: 144 };
        scan_minutiae_sites_scored_with(img, params).map(|v| v.len()).unwrap_or(0)
    }

    #[test]
    fn detect_params_are_tunable_and_capped() {
        let px = varied(1);
        // Tiling toggles cleanly and both paths detect something on a varied texture.
        let mut single = DetectParams::structural();
        single.tiles = 1;
        let mut tiled = DetectParams::structural();
        tiled.tiles = 3;
        assert!(scan_count(&px, &single) > 0, "single-tile finds candidates");
        assert!(scan_count(&px, &tiled) > 0, "3×3-tiled finds candidates");

        // Raising the absolute threshold monotonically thins the candidate set (fewer, stronger).
        let base = DetectParams { adaptive_frac: None, score_threshold: 0, tiles: 1, ..DetectParams::structural() };
        let strict = DetectParams { score_threshold: 1 << 28, ..base };
        assert!(scan_count(&px, &strict) <= scan_count(&px, &base), "higher threshold ⇒ no more candidates");

        // The cap keeps at most `max_minutiae`.
        let capped = DetectParams { max_minutiae: 5, ..base };
        assert!(scan_count(&px, &capped) <= 5, "max_minutiae caps the count");
    }

    #[test]
    fn dll_baseline_reads_detector_cfg() {
        let cfg = detect::config_for(0x2449);
        let p = DetectParams::dll_baseline(0x2449);
        // The NMS gate is the engine thr1 (geom_p14 = 0x15d8), NOT cfg+0x00 = 500.
        assert_eq!(p.score_threshold, cfg.nms_thr1());
        assert_eq!(p.score_threshold2, detect::DetectConfig::NMS_THR2);
        assert_eq!(p.min_distance, 1); // ((engine+0x48>>6)²)>>20 = 1
        assert_eq!(p.max_minutiae, cfg.max_minutiae as usize);
        assert_eq!(p.nms_max_out, cfg.nms_max_out());
        assert_eq!(p.nms_max_out, 125, "0x2449: cfg+0=500 >> 2");
        assert_eq!(p.nms_margin, cfg.nms_margin());
        assert_eq!(p.tiles, detect::DetectConfig::TILE_GRID);
        assert!(p.adaptive_frac.is_none(), "baseline uses the absolute threshold");
    }
}
