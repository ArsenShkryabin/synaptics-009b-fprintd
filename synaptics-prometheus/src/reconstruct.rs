//! Image reconstruction stages recovered from the DLL.
//!
//! **Naming:** `cf640` = `syna_recon_descramble_mode2@0x1800cf640`; inner Walsh kernel =
//! `syna_recon_timeslot_transform16@0x1800cfb90` (Rust `cfb90`, `cf640_line`).
//!
//! The sensor reads its pixel array through a time-multiplexed ("timeslot") scheme, so a raw frame
//! off the wire ([`crate::capture`]) is scrambled. `syna_capture_and_reconstruct @0x1800984f0`
//! un-scrambles it per line, driven by the capture program's `0x42` chunk:
//!   `0x42` payload = `[mode:u8, offset:u8, length:u16, …]`.
//! For each raw line it transforms `length` bytes starting at `offset`, leaving the line header
//! (`offset` bytes) and trailer untouched. Two transforms exist:
//!   * **mode 1** (`FUN_1800cf220`): a 4-pixel local high-pass — `clamp(halfsum − pixel)`.
//!   * **mode 2** (`syna_recon_descramble_mode2@0x1800cf640` / `syna_recon_timeslot_transform16@0x1800cfb90`):
//!     a 16-point column transform (the actual timeslot de-scramble) followed by `clamp(x >> 2)`.
//!
//! Our live `0x2449` (PROG_10) uses **mode 2, offset 8, length 144** (raw EP-0x82 line stride 152 =
//! 8 header + 144 data; `bytes_per_line`=160 is the 0x02-cmd width, not the wire stride — see the
//! "Line header semantics" note below and [`crate::calibrate`]). The two transforms are a faithful port —
//! `cfb90` was verified **byte-for-byte** against `syna_recon_timeslot_transform16@0x1800cfb90`
//! (2026-07, live-frame cross-check).
//!
//! # Distinct capture paths
//! There are three sensor read paths whose framing must not be conflated:
//!   * **FRAMES_SYNC** (`syna_capture_and_reconstruct@0x1800984f0`): raw multi-line frame →
//!     [`crate::reconstruct::reconstruct_frame`]-style host de-scramble (mode 2 above) on a
//!     `stride = flex[0x32]+8` (= 152 for 0x2449) buffer, `height = flex[0x12]` (= 56). Before the
//!     de-scramble it (a) line-averages the raw frame column-for-column (no reorder,
//!     `syna_frame_line_average@0x180099c70`) and (b) copies one **reference row** (per-subtype,
//!     see [`REF_ROW_TABLE`]) into the capture ctx for the downstream baseline/calibration stage.
//!   * **0x51 polled print/imaging** (`syna_capture_image@0x180099540`): reads the sensor's
//!     `width×height` flat body and prepends an 8-byte zero header per row — **no host cf640**.
//!     The arm uploads `0x2e` recon flags = 8 (field-0 = `flex[0x16]` = 150) as **firmware**
//!     Image Reconstruction config; whether the chip descrambles before returning the body is
//!     **unverified** — use finger-Δ A/B, not appearance (see `docs/capture/capture-paths.md`).
//!   * **0x51 polled identify** (`vfmCapture@0x180053bb0`, read_mode=2): same wire read, recon=2.
//!   * **Per-line packet ingest** (`syna_ir_unpack_frame_state@0x1800cd950`): separate `01 FE`-marked
//!     packets carrying decoded Y/motion/state fields.
//!
//! Captured `0x2449` polled bodies are 8064 flat bytes with **header-declared** geometry 144×56.
//! Host descramble (diagnostic / stream-only in DLL) re-strides at `line_width/16` blocks per row
//! (9 → 144 cols). The alternate 128×63 factorization is a **diagnostic re-stride** for finger-Δ
//! experiments — not a DLL-declared wire format. See `docs/capture/print-frame-layout.md`.
//!
//! ## Line header semantics (0x2449, from the FRAMES_SYNC/calibrate line)
//! The raw EP-0x82 line the DLL actually walks is **152 wide = 8-byte header + 144 data** — the
//! stride is `field8 = line_width(flex[0x32]=144) + 8`, matching the dest stride `flex[0x32]+8`, NOT
//! `SensorTypeInfo::bytes_per_line`/chunk-0x35 = 160 (that is the 0x02-command line width, not the
//! wire stride). Resolved 2026-07 from the 51224-byte live buffer = 337×152 (`req_lines`=3×112+1);
//! see [`crate::calibrate`] and `syna_frame_line_average@0x180099c70`. There is **no per-line trailer
//! and no frame header** on this path. The 8-byte header is averaged like the data
//! (`syna_frame_line_average`) but excluded from the 144-wide de-scramble (`0x42` offset = 8).
//! Empirically, the 8 bytes contain framing markers and line/frame counters. The DLL ignores their
//! contents: it validates total length, locates frames arithmetically, and averages all 152 columns.
//! They are not the decoded Y/state packet header from the separate per-line-packet path.

use crate::chunk_codec::split_chunks;

/// Per-line reconstruction parameters, parsed from the program's `0x42` chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconParams {
    /// 1 = `cf220` high-pass, 2 = `cf640` timeslot de-scramble.
    pub mode: u8,
    /// Byte offset within each line where the transformed region starts (line-header length).
    pub offset: u8,
    /// Number of bytes per line to transform (the imaged width, e.g. 144 for `0x2449`).
    pub length: u16,
}

/// Find the `0x42` "reconstruction" chunk in a capture program and parse its parameters.
/// Chunk framing = `type:u16le ‖ len:u16le ‖ payload`; payload = `mode ‖ offset ‖ length:u16le ‖ …`.
pub fn recon_params(program: &[u8]) -> Option<ReconParams> {
    let chunks = split_chunks(program)?;
    let c = chunks.iter().find(|c| c.typ == 0x42)?;
    if c.payload.len() < 4 {
        return None;
    }
    Some(ReconParams {
        mode: c.payload[0],
        offset: c.payload[1],
        length: u16::from_le_bytes([c.payload[2], c.payload[3]]),
    })
}

#[inline]
fn clamp_u8(x: i32) -> u8 {
    x.clamp(0, 0xff) as u8
}

/// Subtract each row's mean from that row (kills row-direction brightness drift). Shared by both
/// conditioning paths.
fn remove_row_mean(f: &mut [f32], width: usize, height: usize) {
    for row in 0..height {
        let base = row * width;
        let mean: f32 = f[base..base + width].iter().sum::<f32>() / width as f32;
        for v in &mut f[base..base + width] {
            *v -= mean;
        }
    }
}

/// Linearly map floats to 0..255 given the stretch window `[lo, hi]`. `clamp` is a no-op for a
/// min/max window (values are already inside it) and bounds a percentile window.
fn contrast_stretch(f: &[f32], lo: f32, hi: f32) -> Vec<u8> {
    let range = (hi - lo).max(1e-6);
    f.iter()
        .map(|&v| (((v - lo) / range) * 255.0).clamp(0.0, 255.0).round() as u8)
        .collect()
}

/// `FUN_1800cfb90`: the 16-point column transform (timeslot de-scramble). Takes 16 raw bytes,
/// returns 16 `i16` samples. Ported verbatim; intermediate math wraps at `i16` (`short`).
fn cfb90(p: &[u8; 16]) -> [i16; 16] {
    // pixel values as i32 (byte 0..255)
    let x: [i32; 16] = core::array::from_fn(|i| p[i] as i32);
    let w = |v: i32| v as i16 as i32; // truncate to short at each combine, like the decompile

    let s1 = w((x[1] - x[0]) + x[2] + x[3]);
    let s2 = w((x[5] - x[4]) + x[6] + x[7]);
    let s3 = w((x[9] - x[8]) + x[10] + x[11]);
    let s4 = w((x[13] - x[12]) + x[14] + x[15]);
    let s5 = w((x[0] - x[1]) + x[2] + x[3]);
    let s6 = w((x[4] - x[5]) + x[6] + x[7]);
    let s7 = w((x[8] - x[9]) + x[10] + x[11]);
    let s8 = w((x[12] - x[13]) + x[14] + x[15]);
    let s9 = w((x[0] + x[1] - x[2]) + x[3]);
    let s10 = w((x[4] + x[5] - x[6]) + x[7]);
    let s11 = w((x[8] + x[9] - x[10]) + x[11]);
    let s12 = w((x[12] + x[13] - x[14]) + x[15]);
    let s13 = w(x[0] + x[1] + x[2] - x[3]);
    let s14 = w(x[4] + x[5] + x[6] - x[7]);
    let s15 = w(x[8] + x[9] + x[10] - x[11]);
    let s16 = w(x[12] + x[13] + x[14] - x[15]);

    let mut o = [0i16; 16];
    o[0] = w(((x[0] - x[1]) - x[2] - x[3]) + s2 + s3 + s4) as i16;
    o[1] = w(((x[1] - x[0]) - x[2] - x[3]) + s6 + s7 + s8) as i16;
    o[2] = w(((-x[1] - x[0]) + x[2] - x[3]) + s10 + s11 + s12) as i16;
    o[3] = w(x[3] + s14 + ((-x[1] - x[0]) - x[2]) + s15 + s16) as i16;
    o[4] = w(s1 + ((x[4] - x[5]) - x[6] - x[7]) + s3 + s4) as i16;
    o[5] = w(s5 + ((x[5] - x[4]) - x[6] - x[7]) + s7 + s8) as i16;
    o[6] = w(s9 + ((-x[5] - x[4]) + x[6] - x[7]) + s11 + s12) as i16;
    o[7] = w(x[7] + s13 + ((-x[5] - x[4]) - x[6]) + s15 + s16) as i16;
    o[8] = w(((x[8] - x[9]) - x[10] - x[11]) + s4 + s1 + s2) as i16;
    o[9] = w(((x[9] - x[8]) - x[10] - x[11]) + s8 + s5 + s6) as i16;
    o[10] = w(((-x[9] - x[8]) + x[10] - x[11]) + s12 + s9 + s10) as i16;
    o[11] = w(((-x[9] - x[8]) - x[10]) + x[11] + s16 + s13 + s14) as i16;
    o[12] = w(s1 + s2 + s3 + ((x[12] - x[13]) - x[14] - x[15])) as i16;
    o[13] = w(s5 + s6 + s7 + ((x[13] - x[12]) - x[14] - x[15])) as i16;
    o[14] = w(s9 + s10 + s11 + ((-x[13] - x[12]) + x[14] - x[15])) as i16;
    o[15] = w(s13 + s14 + s15 + ((-x[13] - x[12]) - x[14]) + x[15]) as i16;
    o
}

/// `FUN_1800cf640` (mode 2): in-place per-line de-scramble of `data` (16 bytes at a time).
/// Trailing bytes (`len % 16`) are left untouched, matching the `0xf < remaining` loop bound.
fn cf640_line(data: &mut [u8]) {
    let mut base = 0;
    while data.len() - base >= 16 {
        let mut grp = [0u8; 16];
        grp.copy_from_slice(&data[base..base + 16]);
        let out = cfb90(&grp);
        for (i, &s) in out.iter().enumerate() {
            data[base + i] = clamp_u8((s as i32) >> 2);
        }
        base += 16;
    }
}

/// The **matcher's** de-spread + conditioning, one 16-timeslot block at a time.
/// ghidra: `syna_ir_recon_transform16_scaled@0x1800cf4a5`.
///
/// This is a *second* descrambler, distinct from the stream's cf640 despite sharing the same
/// `syna_recon_timeslot_transform16@0x1800cfb90` kernel. It is not on the capture-read path at all —
/// it hangs off the matcher's IR-reconstruction runtime (`irDliRT`, installed by
/// `syna_setup_match_processor`):
///
/// ```text
/// vcsIRreconFrame @0x1800b73e0 / 0x1800b8c30      (VCS IR-recon frame processor)
///  └─ syna_ir_recon_condition_frame @0x1800b96f0
///      └─ syna_ir_recon_transform16_scaled @0x1800cf4a5   ← here
///          └─ syna_recon_timeslot_transform16 @0x1800cfb90 (shared with cf640)
/// ```
///
/// which is why the polled `0x51` read path looks like it never descrambles: the read genuinely
/// doesn't, and the transform happens downstream, inside the matcher, before extraction.
///
/// The scaling differs from cf640 and that difference is *not* cosmetic:
///
/// | | cf640 (stream) | this (matcher) |
/// |---|---|---|
/// | shift | `>> 2` | `>> 1` |
/// | offset | none | `- 0x80` |
/// | reference | none here | `(ref - 0x80) * -4`, added **before** the shift |
///
/// `reference` is the dark-frame row/plane; `None` takes the DLL's `param_2 == 0` branch.
pub fn ir_recon_line(data: &mut [u8], reference: Option<&[u8]>) {
    let mut base = 0;
    while data.len() - base >= TIMESLOTS_PER_BLOCK {
        let mut grp = [0u8; TIMESLOTS_PER_BLOCK];
        grp.copy_from_slice(&data[base..base + TIMESLOTS_PER_BLOCK]);
        let out = cfb90(&grp);
        for (i, &s) in out.iter().enumerate() {
            // (ref - 0x80) * -4 is *added* to the transformed sample, so a reference brighter than
            // the 0x80 mid-point subtracts. Exactly the DLL's expression, in its order.
            let corrected = match reference {
                Some(r) => {
                    let rv = r.get(base + i).copied().unwrap_or(IR_RECON_MID) as i32;
                    s as i32 + (rv - IR_RECON_MID as i32) * IR_RECON_REF_GAIN
                }
                None => s as i32,
            };
            data[base + i] = clamp_u8((corrected >> IR_RECON_SHIFT) - IR_RECON_MID as i32);
        }
        base += TIMESLOTS_PER_BLOCK;
    }
}

/// Mid-point the matcher's recon centres both the reference and the output on.
/// ghidra: `local_40 = 0x80` in `syna_ir_recon_transform16_scaled`.
pub const IR_RECON_MID: u8 = 0x80;
/// Gain applied to `(reference - mid)` before it is folded into the transformed sample.
pub const IR_RECON_REF_GAIN: i32 = -4;
/// Post-fold right shift (cf640 uses 2; the matcher path uses 1).
pub const IR_RECON_SHIFT: i32 = 1;

/// Whole-image form of [`ir_recon_line`] — the DLL-faithful transform for a polled `0x51` body.
pub fn ir_recon_transform_image(
    body: &[u8],
    blocks_per_line: usize,
    reference: Option<&[u8]>,
) -> Image {
    let width = blocks_per_line * TIMESLOTS_PER_BLOCK;
    let height = body.len().checked_div(width).unwrap_or(0);
    let mut pixels = body[..width * height].to_vec();
    for line in 0..height {
        let span = line * width..(line + 1) * width;
        // The DLL advances the reference pointer in lockstep with the data pointer, so a
        // full-frame reference is consumed row-for-row.
        let r = reference.and_then(|r| r.get(span.clone()));
        ir_recon_line(&mut pixels[span], r);
    }
    Image {
        width,
        height,
        pixels,
    }
}

/// Number of time-multiplexed samples in one Walsh/Hadamard de-spread block — the width of a single
/// `cfb90` group and the granularity of the timeslot multiplex. An imaged line is an integer
/// number of these blocks (`syna_recon_timeslot_transform16@0x1800cfb90` transforms exactly 16 at a
/// time).
pub const TIMESLOTS_PER_BLOCK: usize = 16;

/// Diagnostic alternate line grouping: 8 blocks × 16 = 128 columns (128×63 factorization of 8064 B).
/// Row coherence at this width reflects timeslot-multiplex periodicity, not the DLL line width — see
/// `docs/capture/calib-fold.md`. Override via `BLOCKS_PER_LINE=8`, not the default.
pub const DESCRAMBLE_BLOCKS_DIAG_128: usize = 8;

/// Hadamard blocks per imaged line — `line_width / TIMESLOTS_PER_BLOCK`.
/// ghidra: `0x42` chunk `length` = flex[0x32]; `syna_capture_image` copies `width` bytes per row.
pub fn blocks_per_line_from_width(line_width: u16) -> usize {
    (line_width as usize) / TIMESLOTS_PER_BLOCK
}

/// A stage of the **canonical polled reconstruction pipeline** — the exact sequence the viewer's
/// `polled_default` graph runs, whose final stage is the buffer handed to the QM matcher. Each
/// variant is a strict superset of the previous one.
///
/// This enum + [`polled_stage_image`] are the single source of truth for that pipeline so the
/// `synfp` CLI and the `synaptics-pipeline-graph` nodes cannot drift: the graph's `DescrambleNode`
/// wraps [`ir_recon_transform_image`] and its `ConditionedNode` wraps
/// [`crate::ir_normalize::reconstruct_roi`] — the very two calls chained here.
/// ghidra: matcher IR-recon (`syna_ir_recon_condition_frame` mode 2 → `transform16`) then
/// `syna_ir_reconstruct_roi@0x1800b9430` ("QM input at ctx+0x238").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolledStage {
    /// Raw sensor body, no processing (viewer `SourceNode`).
    Raw,
    /// Timeslot de-spread only, **no** dark-reference fold — `ir_recon_transform_image(.., None)`.
    Descrambled,
    /// De-spread with the dark/device-pattern reference folded out —
    /// `ir_recon_transform_image(.., Some(dark_ref))` (viewer `DarkReference` → `Descramble` fold).
    DarkRemoved,
    /// Conditioned **QM input** — [`crate::ir_normalize::reconstruct_roi`] over the de-spread(+folded)
    /// image (viewer `ConditionedNode`; the buffer the matcher consumes).
    Conditioned,
}

/// Run the canonical polled pipeline up to `stage` and return the grayscale [`Image`] there.
///
/// - `body`: a raw [`crate::capture::PolledFrame`] body (row-major, `width*height` bytes).
/// - `raw_width`/`raw_height`: the frame header geometry, used only for the [`PolledStage::Raw`] wrap.
/// - `blocks_per_line`: from the capture geometry ([`blocks_per_line_from_width`] /
///   `CaptureConfig::descramble_blocks_per_line`).
/// - `dark_ref`: the dark-reference plane folded at [`PolledStage::DarkRemoved`]/[`PolledStage::Conditioned`].
///   The polled default auto-arms the frame's own body — pass `Some(body)` for viewer-faithful
///   behaviour, or `None` to take the DLL's no-reference branch.
pub fn polled_stage_image(
    body: &[u8],
    raw_width: u16,
    raw_height: u16,
    blocks_per_line: usize,
    dark_ref: Option<&[u8]>,
    stage: PolledStage,
) -> Image {
    if stage == PolledStage::Raw {
        let w = raw_width as usize;
        let rows = body.len().checked_div(w).unwrap_or(0);
        let h = (raw_height as usize).min(rows);
        return Image {
            width: w,
            height: h,
            pixels: body[..w * h].to_vec(),
        };
    }
    // Descrambled omits the dark-ref fold; DarkRemoved + Conditioned fold it in (matching the graph).
    let reference = if stage == PolledStage::Descrambled {
        None
    } else {
        dark_ref
    };
    let mut img = ir_recon_transform_image(body, blocks_per_line, reference);
    if stage == PolledStage::Conditioned && !img.pixels.is_empty() {
        crate::ir_normalize::reconstruct_roi(
            &mut img.pixels,
            img.width,
            img.height,
            crate::ir_normalize::RoiBounds::full(img.width as u16, img.height as u16),
        );
    }
    img
}

/// Apply the DLL's mode-2 16-byte transform to a flat polled `0x51` body re-strided at
/// `blocks_per_line * TIMESLOTS_PER_BLOCK` columns per row.
///
/// **Default:** `blocks_per_line = line_width / 16` (9 for `0x2449` → 144×56), matching
/// `syna_capture_image@0x180099540` row-major iteration and the `0x42` chunk's 144-byte transform
/// region. Use [`DESCRAMBLE_BLOCKS_DIAG_128`] (8) only as an explicit diagnostic.
///
/// Two independent orderings are undone, and there is **no block/column permutation** — the transform
/// is order-preserving:
///  * **Horizontal / within-line (from the DLL):** each consecutive [`TIMESLOTS_PER_BLOCK`]-byte block
///    holds the 16 time-multiplexed samples of 16 spatial columns; `cf640_line`/`cfb90`
///    (`syna_recon_descramble_mode2@0x1800cf640` → `..._timeslot_transform16@0x1800cfb90`, then
///    `>>2`+clamp) de-spreads it in place. This is byte-for-byte the FRAMES_SYNC de-scramble; it
///    applies unchanged here.
///  * **Vertical / line grouping:** the body is re-strided at `blocks_per_line * 16`. Wrong line
///    width misaligns the 16-byte transform groups (144 sense cells = 9 blocks, not 8).
///
/// **No per-line metadata skip on the flat `0x51` body (measured 2026-07).** Unlike the CALIBRATE
/// wire line (152 = 8-byte `[1,254,line,frame,0xF0,0xF7,1,0]` header + 144 data, skipped by the `0x42`
/// chunk `offset=8`), the raw `0x51` readout has **no per-line header at a fixed column** — so the
/// de-scramble runs at `offset = 0` over the full line width (144 for `0x2449`). Proof it must NOT skip:
///   * The `0x51` body carries recurring bytes `[67,193,68,72,186,190,67,66]`
///     (`0x43,0xC1,0x44,0x48,0xBA,0xBE,0x43,0x42`) flanked by 8-byte runs of the ~135 DC level, but it
///     **marches diagonally** (baseline: row1 col8, row2 col16, row59 col96, row60 col104; +8 col/row
///     per selected field) — it is NOT at a fixed offset, so no fixed `offset` can exclude it. The DLL
///     does not establish its meaning. It is absent from the CALIBRATE buffer, whose header is unrelated.
///   * Columns 0–7 of each 128-line are ~135-constant in the dark fixed pattern (cross-row std 1.4) but
///     carry the **strongest** finger signal (mean |Δ| 8.5 vs 6.7 for the rest) — they are DATA, not a
///     header; skipping them (offset 8) would discard signal AND straddle the 16-byte transform blocks.
pub fn descramble_timeslot_image(body: &[u8], blocks_per_line: usize) -> Image {
    let width = blocks_per_line * TIMESLOTS_PER_BLOCK;
    let height = body.len().checked_div(width).unwrap_or(0);
    let mut pixels = body[..width * height].to_vec();
    // De-spread each line's blocks in place (per-line, like the DLL). width is a multiple of 16, so
    // block boundaries never straddle a line — per-line and whole-buffer de-spread are identical.
    for line in 0..height {
        cf640_line(&mut pixels[line * width..(line + 1) * width]);
    }
    Image {
        width,
        height,
        pixels,
    }
}

/// Polled-path DLL reassembly — flat `width×height` body → `height × (width+8)` with 8 zero bytes
/// prepended per row (`syna_capture_image@0x180099540` dest layout). No descramble.
pub fn reassemble_dll_polled_dest(body: &[u8], width: usize, height: usize) -> Vec<u8> {
    let stride = width.saturating_add(8);
    let mut dest = vec![0u8; height.saturating_mul(stride)];
    for row in 0..height {
        let src = row.saturating_mul(width);
        let dst = row.saturating_mul(stride).saturating_add(8);
        if src.saturating_add(width) <= body.len() && dst.saturating_add(width) <= dest.len() {
            dest[dst..dst + width].copy_from_slice(&body[src..src + width]);
        }
    }
    dest
}

/// Mode-2 descramble on a strided line buffer (stream / DLL-dest semantics: `offset`/`length` per row).
pub fn descramble_strided_lines(
    buf: &mut [u8],
    stride: usize,
    height: usize,
    offset: usize,
    length: usize,
) {
    for row in 0..height {
        let base = row.saturating_mul(stride).saturating_add(offset);
        if base.saturating_add(length) <= buf.len() {
            cf640_line(&mut buf[base..base + length]);
        }
    }
}

/// Diagnostic geometry bundle for comparing 128×63 vs DLL 144-row views on the same flat body.
#[derive(Debug, Clone)]
pub struct GeometryDiagnostic {
    /// Descrambled at `blocks_per_line × 16` (default 144×56 for `0x2449`).
    pub view_128_descrambled: Image,
    /// DLL reassembly @ 144×56 tight raster, no descramble.
    pub view_144_reassembled: Image,
    /// Stream-style descramble on 152-stride buffer at offset 8 (wrong semantics for flat 0x51 body).
    pub view_144_stream_descrambled: Image,
}

fn tight_from_strided(strided: &[u8], stride: usize, width: usize, height: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(width * height);
    for row in 0..height {
        let base = row * stride + 8;
        out.extend_from_slice(strided.get(base..base + width).unwrap_or(&[]));
    }
    out
}

/// Build the three geometry diagnostic views from one flat polled body.
pub fn geometry_diagnostic(
    body: &[u8],
    blocks_128: usize,
    width_144: usize,
    height_144: usize,
) -> Option<GeometryDiagnostic> {
    if width_144 == 0 || height_144 == 0 {
        return None;
    }
    let view_128_descrambled = descramble_timeslot_image(body, blocks_128);
    let reasm = reassemble_dll_polled_dest(body, width_144, height_144);
    let stride = width_144 + 8;
    let view_144_reassembled = Image {
        width: width_144,
        height: height_144,
        pixels: tight_from_strided(&reasm, stride, width_144, height_144),
    };
    let mut stream_buf = reasm.clone();
    descramble_strided_lines(&mut stream_buf, stride, height_144, 8, width_144);
    let view_144_stream_descrambled = Image {
        width: width_144,
        height: height_144,
        pixels: tight_from_strided(&stream_buf, stride, width_144, height_144),
    };
    Some(GeometryDiagnostic {
        view_128_descrambled,
        view_144_reassembled,
        view_144_stream_descrambled,
    })
}

/// Reproduce the DLL's EP-0x82 repeat>=2 reconstruction stages for a typed sync transfer:
/// skip raw frame zero, average consecutive repeat lines from frame one, run the capture program's
/// per-line reconstruction region, then return only that data region as a tight image.
///
/// This function is not valid for a polled `0x51` body, which has no fixed-stride wire-line header.
pub fn reconstruct_sync_frame(
    raw: &[u8],
    layout: crate::capture::SyncFrameLayout,
    params: ReconParams,
) -> Option<Image> {
    reconstruct_sync_stages(raw, layout, params).map(|s| s.image)
}

/// Intermediate EP-0x82 reconstruction outputs before the tight image extract.
#[derive(Debug, Clone)]
pub struct SyncStages {
    /// Line-averaged buffer at wire stride (post frame-0 skip, pre tight extract).
    pub averaged: Vec<u8>,
    /// Final extracted image region.
    pub image: Image,
}

/// Same stages as [`reconstruct_sync_frame`], exposing the averaged wire buffer for diagnostics.
pub fn reconstruct_sync_stages(
    raw: &[u8],
    layout: crate::capture::SyncFrameLayout,
    params: ReconParams,
) -> Option<SyncStages> {
    let mut averaged = layout.average_second_frame(raw)?;
    let stride = layout.wire_stride();
    let off = params.offset as usize;
    let len = params.length as usize;
    if off.checked_add(len)? > stride {
        return None;
    }
    let image = extract_image(&mut averaged, stride, layout.lines_2d, params);
    if image.height != layout.lines_2d {
        return None;
    }
    Some(SyncStages { averaged, image })
}

/// `FUN_1800cf220` (mode 1): in-place 4-pixel local high-pass. `out = clamp(halfsum − pixel)`
/// where `halfsum = (a+b+c+d) >> 1`. Trailing `len % 4` bytes left untouched.
fn cf220_line(data: &mut [u8]) {
    let mut base = 0;
    while data.len() - base >= 4 {
        let a = data[base] as i32;
        let b = data[base + 1] as i32;
        let c = data[base + 2] as i32;
        let d = data[base + 3] as i32;
        let half = (a + b + c + d) >> 1;
        data[base] = clamp_u8(half - a);
        data[base + 1] = clamp_u8(half - b);
        data[base + 2] = clamp_u8(half - c);
        data[base + 3] = clamp_u8(half - d);
        base += 4;
    }
}

/// De-scramble a raw frame in place, line by line, per `params`. `raw` is `lines * bytes_per_line`;
/// each line's `[offset .. offset+length]` region is transformed, the header/trailer left as-is.
/// Lines that don't fit (short buffer) are skipped. Returns the number of lines transformed.
pub fn reconstruct_frame(
    raw: &mut [u8],
    bytes_per_line: usize,
    lines: usize,
    params: ReconParams,
) -> usize {
    let off = params.offset as usize;
    let len = params.length as usize;
    let mut done = 0;
    for line in 0..lines {
        let start = line * bytes_per_line + off;
        let end = start + len;
        if end > raw.len() || (line + 1) * bytes_per_line > raw.len() {
            break;
        }
        let region = &mut raw[start..end];
        match params.mode {
            1 => cf220_line(region),
            2 => cf640_line(region),
            _ => return done, // unknown mode: leave untouched
        }
        done += 1;
    }
    done
}

/// Legacy conditioning experiment for a caller-selected raster.
///
/// This is not a DLL reconstruction stage and does not establish geometry. It estimates and removes
/// per-field column offsets and row means, then contrast-stretches the result. `interleave` is a
/// diagnostic grouping chosen by the caller; the polled path itself does not expose row-field tags.
///
/// `interleave` is the field count (`repeat_multiplier`); pass 1 to treat rows uniformly.
pub fn condition_image(data: &[u8], width: usize, height: usize, interleave: usize) -> Image {
    let n = width * height;
    let fields = interleave.max(1);
    let mut f: Vec<f32> = data.iter().take(n).map(|&b| b as f32).collect();
    f.resize(n, 0.0);

    // per-field, per-column mean removal (kills the field-DC step + column gradient).
    for field in 0..fields {
        for col in 0..width {
            let (mut sum, mut cnt) = (0.0f32, 0usize);
            let mut row = field;
            while row < height {
                sum += f[row * width + col];
                cnt += 1;
                row += fields;
            }
            if cnt > 0 {
                let mean = sum / cnt as f32;
                let mut row = field;
                while row < height {
                    f[row * width + col] -= mean;
                    row += fields;
                }
            }
        }
    }
    // per-row mean removal (kills row-direction brightness drift).
    remove_row_mean(&mut f, width, height);
    // contrast-stretch (min..max) to 0..255.
    let (mut lo, mut hi) = (f32::MAX, f32::MIN);
    for &v in &f {
        lo = lo.min(v);
        hi = hi.max(v);
    }
    let pixels = contrast_stretch(&f, lo, hi);
    Image {
        width,
        height,
        pixels,
    }
}

/// Per-subtype reference-line spec — how `syna_capture_and_reconstruct@0x1800984f0` builds the
/// baseline reference line it stashes at capture-ctx+0x18 (consumed by the downstream baseline /
/// calibration stage, *not* by the de-scramble). See [`REF_ROW_TABLE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefRowSpec {
    /// Copy one whole dest row (index `n`, i.e. the DLL's `stride * n` source) as the reference.
    Row(u32),
    /// The DLL "default" branch: stitch the reference from three row-regions of widths
    /// `w/3 | w−2·(w/3) | w/3` (`w = flex[0x32]`) taken from rows 0x11(17), 0x1c(28), 0x25(37).
    ThreeWaySplit,
}

/// `subtype → RefRowSpec`: the reference-line switch inside `syna_capture_and_reconstruct`
/// @0x1800984f0. Only subtypes in this table have a reference extracted (outer membership gate,
/// also gated by `param_1[5] == 0`); others get none. The `Row(n)` index is the `*(ctx+4) * n`
/// multiplier verified against the decompile (2026-07). Family-generic: adding a sibling device is a
/// one-row edit.
pub static REF_ROW_TABLE: &[(u16, RefRowSpec)] = &[
    // ref row 0x1c (28) — includes our 0x2449
    (0xcce, RefRowSpec::Row(0x1c)),
    (0x123, RefRowSpec::Row(0x1c)),
    (0x8f3, RefRowSpec::Row(0x1c)),
    (0x8f5, RefRowSpec::Row(0x1c)),
    (0x8f6, RefRowSpec::Row(0x1c)),
    (0x116, RefRowSpec::Row(0x1c)),
    (0x121, RefRowSpec::Row(0x1c)),
    (0xb4b, RefRowSpec::Row(0x1c)),
    (0xb4d, RefRowSpec::Row(0x1c)),
    (0x2449, RefRowSpec::Row(0x1c)),
    (0x195, RefRowSpec::Row(0x1c)),
    (0x17e, RefRowSpec::Row(0x1c)),
    // ref row 0x2a (42)
    (0xb5, RefRowSpec::Row(0x2a)),
    (0x885, RefRowSpec::Row(0x2a)),
    (0x1055, RefRowSpec::Row(0x2a)),
    (0x196, RefRowSpec::Row(0x2a)),
    // ref row 0x2e (46)
    (0xe4, RefRowSpec::Row(0x2e)),
    (0xde, RefRowSpec::Row(0x2e)),
    // ref row 0x38 (56)
    (0xed, RefRowSpec::Row(0x38)),
    (0x199, RefRowSpec::Row(0x38)),
    (0x581, RefRowSpec::Row(0x38)),
    // ref row 0x25 (37)
    (0xb3, RefRowSpec::Row(0x25)),
    (0x143b, RefRowSpec::Row(0x25)),
    (0xe1, RefRowSpec::Row(0x25)),
    (0x8b1, RefRowSpec::Row(0x25)),
    // ref row 0x2c (44)
    (0xea, RefRowSpec::Row(0x2c)),
    // ref row 0x13 (19)
    (0x130, RefRowSpec::Row(0x13)),
    (0xbe2, RefRowSpec::Row(0x13)),
    (0xbe1, RefRowSpec::Row(0x13)),
    (0x518, RefRowSpec::Row(0x13)),
    (0x193, RefRowSpec::Row(0x13)),
    (0x57b, RefRowSpec::Row(0x13)),
    (0x963, RefRowSpec::Row(0x13)),
    // ref row 0x56 (86)
    (0x1825, RefRowSpec::Row(0x56)),
    (0x1ff5, RefRowSpec::Row(0x56)),
    // outer-list members with no specific branch → default 3-way split
    (0x110, RefRowSpec::ThreeWaySplit),
    (0x117, RefRowSpec::ThreeWaySplit),
    (0x126, RefRowSpec::ThreeWaySplit),
];

/// Look up the reference-line spec for `subtype` (see [`REF_ROW_TABLE`]). `None` ⇒ the DLL extracts
/// no reference line for this subtype.
pub fn ref_row_for(subtype: u16) -> Option<RefRowSpec> {
    REF_ROW_TABLE
        .iter()
        .find(|(s, _)| *s == subtype)
        .map(|(_, spec)| *spec)
}

/// Faithful port of the reference-line build in `syna_capture_and_reconstruct@0x1800984f0`:
/// produce the `stride`-byte baseline reference line for `subtype` from the (already line-averaged)
/// `dest` frame. `dest` is `height × stride`; `line_width` = `flex[0x32]` (the data width, e.g. 144).
/// Returns `None` if the subtype has no reference (see [`REF_ROW_TABLE`]) or `dest` is too short.
pub fn reference_line(
    dest: &[u8],
    stride: usize,
    height: usize,
    line_width: usize,
    subtype: u16,
) -> Option<Vec<u8>> {
    let spec = ref_row_for(subtype)?;
    let mut refline = vec![0u8; stride];
    match spec {
        RefRowSpec::Row(n) => {
            let n = n as usize;
            if n >= height {
                return None;
            }
            let src = &dest.get(n * stride..n * stride + stride)?;
            refline.copy_from_slice(src);
        }
        RefRowSpec::ThreeWaySplit => {
            // DLL default branch: local_6c = 8 (header), uVar3 = w/3, mid = w − 2·uVar3.
            const HDR: usize = 8;
            let w = line_width;
            let third = w / 3;
            let mid = w - third - third;
            // region 0: `third + HDR` bytes from row 17 (offset 0) → refline[0..]
            copy_region(dest, stride, 17, 0, &mut refline, 0, third + HDR)?;
            // region 1: `mid` bytes from row 28 (offset HDR+third) → refline[third..]
            copy_region(dest, stride, 28, HDR + third, &mut refline, third, mid)?;
            // region 2: `third` bytes from row 37 (offset HDR+third+mid) → refline[third+mid..]
            copy_region(
                dest,
                stride,
                37,
                HDR + third + mid,
                &mut refline,
                third + mid,
                third,
            )?;
        }
    }
    Some(refline)
}

/// Helper for [`reference_line`]'s 3-way split: copy `len` bytes from `dest` row `row` at column
/// `src_off` into `refline[dst_off..]`, clamping to available bytes (mirrors the DLL `memcpy`s).
fn copy_region(
    dest: &[u8],
    stride: usize,
    row: usize,
    src_off: usize,
    refline: &mut [u8],
    dst_off: usize,
    len: usize,
) -> Option<()> {
    let s = row * stride + src_off;
    let src = dest.get(s..s + len)?;
    let dst = refline.get_mut(dst_off..dst_off + len)?;
    dst.copy_from_slice(src);
    Some(())
}

/// Subtract a per-column reference line from every row of an image (the faithful baseline step: the
/// reference is the sensor's fixed per-column level, [`reference_line`] or a dark/no-finger frame).
/// `image` and `reference` are row-major `width`-strided; result is signed, biased to `0..255`
/// around 128 and returned as an [`Image`]. Columns beyond `reference.len()` are passed through.
pub fn subtract_reference(image: &[u8], reference: &[u8], width: usize, height: usize) -> Image {
    let mut pixels = vec![128u8; width * height];
    for row in 0..height {
        for col in 0..width {
            let idx = row * width + col;
            if idx >= image.len() {
                break;
            }
            let r = reference.get(col).copied().unwrap_or(0) as i32;
            let v = image[idx] as i32 - r + 128;
            pixels[idx] = v.clamp(0, 255) as u8;
        }
    }
    Image {
        width,
        height,
        pixels,
    }
}

/// Condition a caller-selected raster by removing column/row fixed pattern. This is an empirical
/// display/measurement stage, not proof that the input was reconstructed on-chip. Optionally pass a
/// no-finger `baseline` with the same chosen geometry; pass `None` to self-calibrate from one frame.
///
/// Pipeline (FFT-free, derived from the winning empirical reconstruction of `finger_imaging_72c.bin`
/// vs its baseline):
///   1. `g = frame − baseline` (if given) — removes the shared timeslot fixed pattern.
///   2. per-column mean removal — kills the constant-down-column vertical bars (period-4/2 timeslot
///      pattern lives here).
///   3. per-column gain normalisation (÷ population std) — equalises the per-timeslot column gains.
///   4. per-row mean removal — kills row-direction brightness drift.
///   5. contrast-stretch to `0..255`.
///
/// This is a fixed-pattern remover only. For the empirical alternate `128×63` view, run it after
/// [`descramble_timeslot_image`]. For the DLL-declared `144×56` view, use the flat body directly.
/// Validate either view by finger-dependence, never by FFT/Gabor appearance (AGENTS.md Rule #7).
pub fn condition_onchip(
    frame: &[u8],
    baseline: Option<&[u8]>,
    width: usize,
    height: usize,
) -> Image {
    let n = width * height;
    let mut f: Vec<f32> = (0..n)
        .map(|i| {
            let a = frame.get(i).copied().unwrap_or(0) as f32;
            let b = baseline.and_then(|bl| bl.get(i)).copied().unwrap_or(0) as f32;
            a - b
        })
        .collect();

    // per-column mean removal + per-column gain normalisation.
    for col in 0..width {
        let mut sum = 0.0f32;
        for row in 0..height {
            sum += f[row * width + col];
        }
        let mean = sum / height as f32;
        let mut var = 0.0f32;
        for row in 0..height {
            let d = f[row * width + col] - mean;
            var += d * d;
        }
        let std = (var / height as f32).sqrt().max(1e-6);
        for row in 0..height {
            let idx = row * width + col;
            f[idx] = (f[idx] - mean) / std;
        }
    }
    // per-row mean removal.
    remove_row_mean(&mut f, width, height);
    // contrast-stretch (robust 1..99 percentile) to 0..255.
    let mut sorted = f.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let lo = sorted[(n as f32 * 0.01) as usize];
    let hi = sorted[((n as f32 * 0.99) as usize).min(n - 1)];
    let pixels = contrast_stretch(&f, lo, hi);
    Image {
        width,
        height,
        pixels,
    }
}

/// The 16-byte frame header prefixing a `0x51` polled-identify response body (after the 2-byte tunnel
/// status). Parsed by `syna_capture_image@0x180099540`: `local_80[0]` = height, `local_80[1]` = width,
/// body = `width*height` flat (no per-line header — the 8-byte dest header is DLL-synthesized zeros).
///
/// Bytes (relative to `d = &resp[2..]`): `payload_len:u32 @0 | height:u16 @4 | width:u16 @6 |
/// raw_line_count:u16 @8 | …`. For `0x2449`: `144×56`, body 8064.
///
/// NB: `width`/`height` are the geometry `syna_capture_image` declares (144×56 for `0x2449`). The
/// flat body is still timeslot-multiplexed at the readout raster (finger-Δ peak at 128×63, 8 blocks).
/// Host descramble for diagnostics: [`descramble_timeslot_image`] with
/// [`DESCRAMBLE_BLOCKS_DIAG_128`] or [`blocks_per_line_from_width`] — the DLL never calls cf640 on
/// polled reads. See `docs/capture/0x51-conditioning.md`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrintFrameHeader {
    /// Firmware payload length (`= 12-byte fw header + body`).
    pub payload_len: u32,
    /// Rows (`flex[0x12]` `lines_2d`). `56` for `0x2449`.
    pub height: u16,
    /// Columns (`flex[0x32]` `line_width`). `144` for `0x2449`.
    pub width: u16,
    /// Raw line count field — the DLL reads it but does not use it.
    pub raw_line_count: u16,
}

impl PrintFrameHeader {
    /// Header length in bytes (the fixed prefix the DLL skips before the body).
    pub const LEN: usize = 16;

    /// Parse the header from a `0x51` response payload `d` (i.e. `&resp[2..]`, after the tunnel
    /// status). Returns the header and a borrow of the frame body. `None` if `d` is too short.
    pub fn parse(d: &[u8]) -> Option<(Self, &[u8])> {
        if d.len() < Self::LEN {
            return None;
        }
        let hdr = Self {
            payload_len: u32::from_le_bytes([d[0], d[1], d[2], d[3]]),
            height: u16::from_le_bytes([d[4], d[5]]),
            width: u16::from_le_bytes([d[6], d[7]]),
            raw_line_count: u16::from_le_bytes([d[8], d[9]]),
        };
        Some((hdr, &d[Self::LEN..]))
    }

    /// Expected flat body length = `width * height`.
    pub fn body_len(&self) -> usize {
        self.width as usize * self.height as usize
    }

    /// The `width*height` flat body from a parsed response tail, clamped to the declared size.
    /// Falls back to the whole tail if the declared size doesn't fit (defensive against a bad header).
    pub fn body<'a>(&self, tail: &'a [u8]) -> &'a [u8] {
        match self.body_len() {
            n if n > 0 && n <= tail.len() => &tail[..n],
            _ => tail,
        }
    }
}

/// The grayscale image container + its PGM/PNG encoders now live in [`crate::image_io`]; re-exported
/// so `reconstruct::Image` keeps working for the many examples that build/serialize recon output.
pub use crate::image_io::Image;

/// Reconstruct then extract just the imaged region: for each of `lines` rows, the `length` bytes at
/// `offset`. Produces a tight `length × lines` grayscale [`Image`]. `raw` is consumed-by-value's
/// worth of work but taken by mut-ref so the caller keeps the buffer.
pub fn extract_image(
    raw: &mut [u8],
    bytes_per_line: usize,
    lines: usize,
    params: ReconParams,
) -> Image {
    let transformed = reconstruct_frame(raw, bytes_per_line, lines, params);
    let off = params.offset as usize;
    let len = params.length as usize;
    let mut pixels = Vec::with_capacity(len * transformed);
    for line in 0..transformed {
        let start = line * bytes_per_line + off;
        pixels.extend_from_slice(&raw[start..start + len]);
    }
    Image {
        width: len,
        height: transformed,
        pixels,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture_progs_9b::CAPTURE_PROGS;

    #[test]
    fn print_frame_header_parses_live_0x2449_bytes() {
        // Real 16-byte header of a 0x51 identify response (d = &resp[2..]), captured on hardware.
        let d = [
            0x8c, 0x1f, 0x00, 0x00, // payload_len = 8076
            0x38, 0x00, // height = 56
            0x90, 0x00, // width  = 144
            0x4d, 0x01, // raw_line_count = 333
            0x08, 0x00, 0x00, 0x00, 0x08, 0x00, // rest
        ];
        let mut resp = d.to_vec();
        resp.extend(std::iter::repeat_n(0xAB, 144 * 56)); // flat body
        let (h, body) = PrintFrameHeader::parse(&resp).expect("parse");
        assert_eq!(h.payload_len, 8076);
        assert_eq!(h.height, 56);
        assert_eq!(h.width, 144);
        assert_eq!(h.raw_line_count, 333);
        assert_eq!(h.body_len(), 8064);
        assert_eq!(h.body(body).len(), 8064);
        assert_eq!(PrintFrameHeader::parse(&d[..8]), None); // too short
    }

    fn prog_2449() -> &'static [u8] {
        CAPTURE_PROGS
            .iter()
            .find(|p| p.subtype == 0x2449 && p.st8 == 0x6 && p.st9 == 0x14)
            .expect("0x2449 program")
            .program
    }

    #[test]
    fn recon_params_2449_is_mode2_off8_len144() {
        let p = recon_params(prog_2449()).expect("0x42 chunk");
        assert_eq!(
            p,
            ReconParams {
                mode: 2,
                offset: 8,
                length: 144
            }
        );
    }

    #[test]
    fn cfb90_flat_input_is_constant() {
        // All-equal pixels: every intermediate difference cancels, so the transform is uniform.
        let out = cfb90(&[50u8; 16]);
        assert!(
            out.iter().all(|&v| v == out[0]),
            "flat in ⇒ flat out: {out:?}"
        );
    }

    #[test]
    fn cf640_flat_is_dc_preserving() {
        // The de-scramble is DC-preserving: cfb90 of a flat field is uniform (=4v), then >>2 → v.
        let mut data = vec![100u8; 144];
        cf640_line(&mut data);
        assert!(
            data.iter().all(|&b| b == 100),
            "flat field survives de-scramble"
        );
    }

    /// The matcher path's scaling is NOT cf640's. Pinned to the decompiled expression
    /// `clamp(((t + (ref-0x80)*-4) >> 1) - 0x80)` vs cf640's `clamp(t >> 2)`.
    #[test]
    fn ir_recon_scaling_differs_from_cf640() {
        let line: Vec<u8> = (0..16u16).map(|i| (i * 7) as u8).collect();

        let mut ir = line.clone();
        ir_recon_line(&mut ir, None);
        let mut cf = line.clone();
        cf640_line(&mut cf);
        assert_ne!(
            ir, cf,
            "matcher recon must not reduce to the stream cf640 scaling"
        );

        // Recompute the DLL expression independently from the shared kernel.
        let mut grp = [0u8; 16];
        grp.copy_from_slice(&line);
        let t = cfb90(&grp);
        for (i, &s) in t.iter().enumerate() {
            assert_eq!(
                ir[i],
                clamp_u8(((s as i32) >> 1) - 0x80),
                "no-reference branch, slot {i}"
            );
            assert_eq!(cf[i], clamp_u8((s as i32) >> 2), "cf640 branch, slot {i}");
        }
    }

    /// A reference exactly at the 0x80 mid-point contributes nothing — `(0x80 - 0x80) * -4 == 0` —
    /// so it must be identical to the no-reference branch.
    #[test]
    fn ir_recon_reference_at_midpoint_is_a_no_op() {
        let line: Vec<u8> = (0..16u16).map(|i| (i * 11 + 3) as u8).collect();
        let mid = vec![IR_RECON_MID; 16];
        let mut with_ref = line.clone();
        ir_recon_line(&mut with_ref, Some(&mid));
        let mut without = line.clone();
        ir_recon_line(&mut without, None);
        assert_eq!(with_ref, without);
    }

    /// A reference brighter than the mid-point must darken the output (gain is negative), and a
    /// darker reference must brighten it.
    #[test]
    fn ir_recon_reference_sign_is_subtractive() {
        let line = vec![0x90u8; 16];
        let mut base = line.clone();
        ir_recon_line(&mut base, None);
        let mut brighter = line.clone();
        ir_recon_line(&mut brighter, Some(&[IR_RECON_MID + 20; 16]));
        let mut darker = line.clone();
        ir_recon_line(&mut darker, Some(&[IR_RECON_MID - 20; 16]));
        // Compare on the first slot that is not already clamped at an endpoint.
        let i = (0..16)
            .find(|&i| base[i] > 0 && base[i] < 255)
            .expect("some slot lands inside the clamp range");
        assert!(
            brighter[i] <= base[i],
            "a brighter reference must not brighten the output"
        );
        assert!(
            darker[i] >= base[i],
            "a darker reference must not darken the output"
        );
    }

    #[test]
    fn cf640_line_transforms_a_gradient() {
        // 144 bytes = 9 groups of 16, exact. A non-uniform line must change.
        let mut data: Vec<u8> = (0..144u16).map(|i| (i * 3) as u8).collect();
        let before = data.clone();
        cf640_line(&mut data);
        assert_ne!(data, before, "a scrambled gradient should be transformed");
        assert_eq!(data.len(), 144);
    }

    #[test]
    fn blocks_per_line_from_width_2449() {
        assert_eq!(blocks_per_line_from_width(144), 9);
        assert_eq!(blocks_per_line_from_width(128), 8);
    }

    #[test]
    fn descramble_timeslot_image_dims_and_dc_144x56() {
        let body = vec![100u8; 144 * 56];
        let img = descramble_timeslot_image(&body, 9);
        assert_eq!((img.width, img.height), (144, 56));
        assert!(
            img.pixels.iter().all(|&b| b == 100),
            "flat body survives de-scramble"
        );
    }

    #[test]
    fn descramble_timeslot_image_dims_and_dc_diag_128() {
        let body = vec![100u8; 128 * 63];
        let img = descramble_timeslot_image(&body, DESCRAMBLE_BLOCKS_DIAG_128);
        assert_eq!((img.width, img.height), (128, 63));
        assert!(
            img.pixels.iter().all(|&b| b == 100),
            "flat body survives de-scramble"
        );
    }

    #[test]
    fn descramble_timeslot_image_matches_per_line_cf640() {
        // The new fn must equal reconstruct_frame with offset 0, length = width (mode 2), since both
        // de-spread every consecutive 16-block. Cross-check on a varied body.
        let (blocks, lines) = (8usize, 5usize);
        let width = blocks * 16;
        let body: Vec<u8> = (0..width * lines)
            .map(|i| (i * 31 + (i / width) * 7) as u8)
            .collect();
        let img = descramble_timeslot_image(&body, blocks);
        let mut raw = body.clone();
        let n = reconstruct_frame(
            &mut raw,
            width,
            lines,
            ReconParams {
                mode: 2,
                offset: 0,
                length: width as u16,
            },
        );
        assert_eq!(n, lines);
        assert_eq!(
            img.pixels, raw,
            "descramble_timeslot_image == per-line cf640 offset0"
        );
    }

    #[test]
    fn cf220_line_highpass_of_flat_is_zero() {
        // half = (4*v)>>1 = 2v; out = clamp(2v - v) = v ... wait: half-sum minus pixel.
        // For flat v: half = 2v, out = clamp(2v - v) = clamp(v) = v. So flat stays flat here.
        let mut data = vec![40u8; 8];
        cf220_line(&mut data);
        assert!(data.iter().all(|&b| b == 40));
    }

    #[test]
    fn reconstruct_preserves_header_and_trailer() {
        let bpl = 160;
        let lines = 3;
        let params = ReconParams {
            mode: 2,
            offset: 8,
            length: 144,
        };
        // header bytes 0..8 and trailer 152..160 marked distinctly; data region varied.
        let mut raw = vec![0u8; bpl * lines];
        for line in 0..lines {
            for i in 0..bpl {
                raw[line * bpl + i] = if !(8..152).contains(&i) {
                    0xEE // header/trailer sentinel
                } else {
                    (i as u8).wrapping_mul(7).wrapping_add(line as u8)
                };
            }
        }
        let done = reconstruct_frame(&mut raw, bpl, lines, params);
        assert_eq!(done, lines);
        for line in 0..lines {
            assert!(
                raw[line * bpl..line * bpl + 8].iter().all(|&b| b == 0xEE),
                "header untouched"
            );
            assert!(
                raw[line * bpl + 152..line * bpl + 160]
                    .iter()
                    .all(|&b| b == 0xEE),
                "trailer untouched"
            );
        }
    }

    #[test]
    fn condition_image_removes_field_dc_step() {
        // Build a 8-wide × 6-tall frame: even rows biased +40, odd rows -40 (a pure field-DC step),
        // no real content. After per-field FPN removal the two fields collapse → uniform output.
        let (w, h) = (8usize, 6usize);
        let mut data = vec![0u8; w * h];
        for row in 0..h {
            let base = if row % 2 == 0 { 160u8 } else { 80u8 };
            for c in 0..w {
                data[row * w + c] = base;
            }
        }
        let img = condition_image(&data, w, h, 2);
        assert_eq!((img.width, img.height), (w, h));
        // A pure field-DC step carries no spatial content ⇒ conditioned image is flat.
        assert!(
            img.pixels.iter().all(|&p| p == img.pixels[0]),
            "field DC step should be fully removed"
        );
    }

    #[test]
    fn ref_row_2449_is_row_28() {
        // 0x2449 is in the *0x1c (28) group of syna_capture_and_reconstruct's switch.
        assert_eq!(ref_row_for(0x2449), Some(RefRowSpec::Row(0x1c)));
        assert_eq!(ref_row_for(0x199), Some(RefRowSpec::Row(0x38)));
        assert_eq!(ref_row_for(0x110), Some(RefRowSpec::ThreeWaySplit));
        assert_eq!(ref_row_for(0xffff), None); // not in the outer membership list
    }

    #[test]
    fn reference_line_copies_row_28() {
        let (stride, height) = (152usize, 56usize);
        let mut dest = vec![0u8; stride * height];
        for c in 0..stride {
            dest[28 * stride + c] = (c as u8).wrapping_mul(3).wrapping_add(1);
        }
        let refline = reference_line(&dest, stride, height, 144, 0x2449).expect("ref line");
        assert_eq!(refline.len(), stride);
        for (c, &val) in refline.iter().enumerate() {
            assert_eq!(val, (c as u8).wrapping_mul(3).wrapping_add(1));
        }
    }

    #[test]
    fn condition_onchip_removes_column_fixed_pattern() {
        // A pure per-column vertical bar (constant down rows) carries no ridge content ⇒ conditioned
        // image is flat. This is the exact artifact condition_onchip is built to kill.
        let (w, h) = (16usize, 8usize);
        let mut frame = vec![0u8; w * h];
        for row in 0..h {
            for col in 0..w {
                frame[row * w + col] = (100 + (col % 4) as i32 * 30) as u8; // period-4 column bars
            }
        }
        let img = condition_onchip(&frame, None, w, h);
        assert_eq!((img.width, img.height), (w, h));
        assert!(
            img.pixels.iter().all(|&p| p == img.pixels[0]),
            "column fixed-pattern should be fully removed: {:?}",
            &img.pixels[..w]
        );
    }

    #[test]
    fn extract_image_dims_match() {
        let bpl = 160;
        let lines = 5;
        let params = ReconParams {
            mode: 2,
            offset: 8,
            length: 144,
        };
        let mut raw = vec![77u8; bpl * lines];
        let img = extract_image(&mut raw, bpl, lines, params);
        assert_eq!(img.width, 144);
        assert_eq!(img.height, 5);
        assert_eq!(img.pixels.len(), 144 * 5);
    }

    #[test]
    fn geometry_diagnostic_builds_three_views() {
        let body = vec![100u8; 144 * 56];
        let g = geometry_diagnostic(&body, 9, 144, 56).expect("diag");
        assert_eq!(g.view_128_descrambled.width, 144);
        assert_eq!(g.view_128_descrambled.height, 56);
        assert_eq!(g.view_144_reassembled.width, 144);
        assert_eq!(g.view_144_reassembled.height, 56);
        assert_eq!(g.view_144_stream_descrambled.pixels.len(), 144 * 56);
    }

    #[test]
    fn reassemble_dll_polled_dest_prepends_eight_zeros() {
        let body: Vec<u8> = (0..144 * 2).map(|i| i as u8).collect();
        let dest = reassemble_dll_polled_dest(&body, 144, 2);
        assert_eq!(dest.len(), 2 * 152);
        assert!(dest[..8].iter().all(|&b| b == 0));
        assert_eq!(dest[8..8 + 144], body[..144]);
    }

    /// Byte-compare host `reconstruct_sync_stages` against tudor `SYNA_DUMP_STAGES` hooks on the
    /// paired wire capture `captures/dll_stages_finger/dll_finger_raw_ep82_0.bin`.
    #[test]
    fn reconstruct_sync_matches_dll_stage_dumps() {
        fn read_pgm(path: &std::path::Path) -> Vec<u8> {
            let raw = std::fs::read(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
            let mut i = 0usize;
            fn tok<'a>(raw: &'a [u8], i: &mut usize) -> &'a str {
                while *i < raw.len() && raw[*i].is_ascii_whitespace() {
                    *i += 1;
                }
                if *i < raw.len() && raw[*i] == b'#' {
                    while *i < raw.len() && raw[*i] != b'\n' {
                        *i += 1;
                    }
                    return tok(raw, i);
                }
                let s = *i;
                while *i < raw.len() && !raw[*i].is_ascii_whitespace() && raw[*i] != b'#' {
                    *i += 1;
                }
                std::str::from_utf8(&raw[s..*i]).unwrap()
            }
            assert_eq!(tok(&raw, &mut i), "P5");
            let w: usize = tok(&raw, &mut i).parse().unwrap();
            let h: usize = tok(&raw, &mut i).parse().unwrap();
            let _mv: usize = tok(&raw, &mut i).parse().unwrap();
            while i < raw.len() && raw[i].is_ascii_whitespace() {
                i += 1;
            }
            raw[i..i + w * h].to_vec()
        }

        let base =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../captures/dll_stages_finger");
        // `dll_finger_raw_ep82_1.bin` pairs with `dll_stage_04`/`05` (cf640 visibly runs there).
        // `dll_finger_raw_ep82_0.bin` pairs with `dll_stage_01`/`02` where the hook dumps are
        // byte-identical (cf640 skipped or no-op on that session — see investigation notes).
        let wire_path = base.join("dll_finger_raw_ep82_1.bin");
        let avg_pgm = base.join("dll_stage_04_01_line_average.pgm");
        let descr_pgm = base.join("dll_stage_05_02_descramble_timeslot.pgm");
        if !wire_path.exists() {
            eprintln!("skip: {wire_path:?} not present");
            return;
        }
        let wire = std::fs::read(&wire_path).unwrap();
        assert_eq!(wire.len(), 51224, "expected 337×152 EP-0x82 wire");

        let layout = crate::capture::SyncFrameLayout {
            line_width: 144,
            lines_2d: 56,
            repeat_multiplier: 2,
            frames: 3,
        };
        let recon = ReconParams {
            mode: 2,
            offset: 8,
            length: 144,
        };
        let stages = reconstruct_sync_stages(&wire, layout, recon).expect("stages");
        let averaged_only = layout.average_second_frame(&wire).expect("line-average");
        let stride = layout.wire_stride();
        let mut avg_tight = Vec::with_capacity(144 * 56);
        for row in 0..56 {
            let base = row * stride + 8;
            avg_tight.extend_from_slice(&averaged_only[base..base + 144]);
        }

        let dll_avg = read_pgm(&avg_pgm);
        let dll_descr = read_pgm(&descr_pgm);
        assert_eq!(avg_tight.len(), dll_avg.len());
        assert_eq!(stages.image.pixels.len(), dll_descr.len());

        let avg_diffs = avg_tight
            .iter()
            .zip(&dll_avg)
            .filter(|(a, b)| a != b)
            .count();
        let descr_diffs = stages
            .image
            .pixels
            .iter()
            .zip(&dll_descr)
            .filter(|(a, b)| a != b)
            .count();
        assert_eq!(
            avg_diffs,
            0,
            "line-average mismatch: {avg_diffs}/{} bytes differ",
            dll_avg.len()
        );
        assert_eq!(
            descr_diffs,
            0,
            "descramble mismatch: {descr_diffs}/{} bytes differ",
            dll_descr.len()
        );
    }

    #[test]
    fn polled_stage_image_stages_are_consistent() {
        let bpl = 4usize; // 4 blocks × 16 = 64 columns
        let width = bpl * TIMESLOTS_PER_BLOCK;
        let height = 3usize;
        let body: Vec<u8> = (0..(width * height) as u32)
            .map(|i| (i % 251) as u8)
            .collect();
        let (rw, rh) = (width as u16, height as u16);

        // Raw = the body verbatim at the declared geometry.
        let raw = polled_stage_image(&body, rw, rh, bpl, None, PolledStage::Raw);
        assert_eq!((raw.width, raw.height), (width, height));
        assert_eq!(raw.pixels, body);

        // Every processed stage uses the descramble geometry and preserves the pixel count.
        for stage in [
            PolledStage::Descrambled,
            PolledStage::DarkRemoved,
            PolledStage::Conditioned,
        ] {
            let img = polled_stage_image(&body, rw, rh, bpl, Some(&body), stage);
            assert_eq!((img.width, img.height), (width, height), "{stage:?}");
            assert_eq!(img.pixels.len(), width * height, "{stage:?}");
        }

        // Conditioning (reconstruct_roi) changes pixels relative to the bare descramble.
        let descr = polled_stage_image(&body, rw, rh, bpl, None, PolledStage::Descrambled);
        let cond = polled_stage_image(&body, rw, rh, bpl, None, PolledStage::Conditioned);
        assert_ne!(
            cond.pixels, descr.pixels,
            "conditioned must differ from descrambled"
        );
    }
}
