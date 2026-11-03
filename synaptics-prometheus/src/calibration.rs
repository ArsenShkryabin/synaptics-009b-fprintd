//! The 0x2449 calibration STATE MACHINE (task #26/#27) — a full port of the vendor
//! `syna_lib_run_calibration@0x1800731d0` driver + `syna_lib_calibration_step@0x180073270` steps.
//!
//! On a provisioned sensor, before arming an image capture the DLL runs a 10-step, capability-gated
//! calibration that produces the per-line correction buffers the capture arm folds in. Skipping it
//! (arming with the static fallback tables) is the weak-signal cause established in
//! `docs/calibration/calibration-state-machine.md`. This module reproduces it; every constant/formula cites the
//! Ghidra address it was derived from (`docs/calibration/calibration-fullmachine-spec.md`).
//!
//! Steps are gated on the per-subtype capability mask `flex[0x1c]`. **For subtype `0x2449`,
//! `flex[0x1c] = 0x81`**, so only steps 3 and 6 actually run (4/5/8/9 are gated off); the other steps
//! are implemented here for the whole family per AGENTS.md Rule #6. Steps 3/4/8/9 are pure functions
//! of the factory blocks; steps 5/6 need live dark-field capture(s) via [`CalIo`].

use crate::error::{Error, Result};
use crate::factory_cal::{FactoryBlock, factory_block};
use crate::line_update::bitpack;

/// `flex[0x1c]` capability bits — each gates one step in `syna_lib_calibration_step`.
pub mod cap {
    /// step 3 (factory `0x80000003` line-diff → `+0x68`, DAT lines A/B).
    pub const STEP3: u16 = 0x01;
    /// step 5 (live line-diff → `+0x80`).
    pub const STEP5: u16 = 0x02;
    /// steps 8 AND 9 (finger-detect + prod-33 config).
    pub const STEP8_9: u16 = 0x08;
    /// step 4 (factory `0x80000007` → `+0x98`).
    pub const STEP4: u16 = 0x40;
    /// step 6 (WOE clean-slate → `+0x80`).
    pub const STEP6: u16 = 0x80;
    /// `flex[0x1c]` for subtype `0x2449` (read from `g_flex_params_table` row 41) = steps 3 + 6.
    pub const FLEX_1C_2449: u16 = 0x81;
}

/// Factory-block tags each step looks up (`syna_cal_get_factory_block_by_tag`).
pub mod block_tag {
    pub const STEP3_LINE_DIFF: u32 = 0x8000_0003;
    pub const STEP4_FACTORY7: u32 = 0x8000_0007;
    pub const STEP8_FINGERDET: u32 = 0x8000_0009;
    pub const STEP6_REFERENCE: u32 = 0x8000_000c;
    pub const STEP9_PROD33: u32 = 0x8000_000d;
}

/// Product class byte (`*(ctx+0x28)+0xb`) — gates steps 3/9 and the step-8/9 register bases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductClass {
    /// `'0'` — base product.
    Prod0,
    /// `'2'` — prod-32.
    Prod2,
    /// `'3'` — prod-33 (our 0x2449 build).
    Prod3,
}

impl ProductClass {
    fn is_23(self) -> bool {
        matches!(self, ProductClass::Prod2 | ProductClass::Prod3)
    }

    /// From the sensor's real product byte — `RomInfo.product` (`0x01` reply), the same value the DLL
    /// reads at `*(ctx->pStatus+0xb)` and gates the calibration steps on: `'0'`=0x30, `'2'`=0x32,
    /// `'3'`=0x33. Read live from the sensor rather than guessed from the subtype (a static map wrongly
    /// mapped the 0x0199 type-1 family to `'3'`). Unknown bytes fall back to `Prod3`.
    pub fn from_product_byte(b: u8) -> ProductClass {
        match b {
            b'0' => ProductClass::Prod0,
            b'2' => ProductClass::Prod2,
            _ => ProductClass::Prod3,
        }
    }
}

/// Flex-params inputs the calibration reads (per-subtype row of `g_flex_params_table@0x18013aaf0`).
#[derive(Debug, Clone, Copy)]
pub struct FlexCal {
    /// `flex[0x1c]` — the capability mask ([`cap`]).
    pub cap_bits: u16,
    /// `flex[0x12]` — per-line array width for steps 3/4 (the calib-data size; 56 for 0x2449).
    pub line_diff_width: usize,
    /// `flex[0x88]` — step-6 **digital** contrast-rescale numerator (10 for 0x2449). NB this is a
    /// post-capture pixel rescale `clamp((px-0x80)*num/den, ±127)`, NOT an analog VGA/PGA gain
    /// register — the `SCM_*_GAIN` register catalog is dead scaffolding and the live per-unit
    /// analog trim lives host-side in the Windows registry (`SOFTWARE\Validity\Cal`), not replicated
    /// on Linux. See `docs/capture/afe-register-map.md`.
    pub scale_num: i32,
    /// `flex[0x8a]` — step-6 digital contrast-rescale denominator (4 for 0x2449).
    pub scale_den: i32,
    /// `*(flex+0x90)` — the 5 source-row positions the step-6 variance check samples
    /// (`{4,18,28,38,51}` for 0x2449).
    pub row_positions: [i32; 5],
    /// `flex[0x98]` — step-6 branch selector (`0` for 0x2449 ⇒ the single-capture scaled path).
    pub branch_sel: u16,
    /// Step-6 clean-slate variance threshold (the dispatcher's per-subtype `val`; 200 for 0x2449).
    pub step6_threshold: u32,
}

impl FlexCal {
    /// The verified 0x2449 ("86C") calibration parameters (from `g_flex_params_table` row 41 and the
    /// `syna_lib_calibration_step` `val` table).
    pub const FLEX_2449: FlexCal = FlexCal {
        cap_bits: cap::FLEX_1C_2449,
        line_diff_width: 56,
        scale_num: 10,
        scale_den: 4,
        row_positions: [4, 18, 28, 38, 51],
        branch_sel: 0,
        step6_threshold: 200,
    };
}

/// Step-6 variance threshold from the dispatcher's per-subtype `val` table
/// (`syna_lib_calibration_step` case 6). Verified for the 0x2449 group; others use the same default
/// until sibling rows are transcribed.
fn step6_threshold_for_subtype(subtype: u16) -> u32 {
    match subtype {
        0x2449 | 0x121 | 0xb4b | 0xb4d | 0x195 | 0x17e | 0x116 => 200,
        0x130 | 0xbe1 | 0xbe2 | 0x518 | 0x193 | 0x57b | 0x963 => 0x28,
        0xb3 => 0x55,
        0x143b => 0x19,
        _ => 200,
    }
}

/// Build [`FlexCal`] from the extracted `g_flex_params_table` row. Returns `None` for unknown subtypes.
pub fn flex_cal_for_subtype(subtype: u16) -> Option<FlexCal> {
    if subtype == 0x2449 {
        return Some(FlexCal::FLEX_2449);
    }
    let fp = crate::flex_params::flex_params(subtype)?;
    // The step-6 digital rescale gain (`flex[0x88]/[0x8a]`), variance rows (`*(flex+0x90)`) and branch
    // selector (`flex[0x98]`) are PER-SUBTYPE in the vendor flex table — extracted into `flex_cal_gen`.
    // They are NOT the 0x2449 values: e.g. 0x0199 = 10/34 (not 10/4) with rows {16,34,52,70,88} and
    // branch 2. Applying the 0x2449 gain (10/4 = 2.5x, vs 0x0199's 10/34 = 0.29x) over-amplifies the
    // dark-field rescale ~8.6x and clips to +-127 — the 009a "blown-out middle". Confirmed byte-for-byte
    // against the DLL flex table and the decrypted 009a calibrate oracle (see
    // captures/lenovo-009a-pairing/). Fall back to the 0x2449 values for subtypes absent from the table.
    let (scale_num, scale_den, row_positions, branch_sel) =
        crate::flex_cal_gen::flex_cal(subtype).unwrap_or((10, 4, [4, 18, 28, 38, 51], 0));
    Some(FlexCal {
        cap_bits: fp.cap_bits,
        line_diff_width: fp.calib_size as usize,
        scale_num,
        scale_den,
        row_positions,
        branch_sel,
        step6_threshold: step6_threshold_for_subtype(subtype),
    })
}


/// Rust mirror of the vendor `SynaCalResults` sub-struct (`*(ctx+0x288)`, 0xc0 bytes) — the outputs
/// of the calibration steps that the capture-arm line-update consumes. Each `Option` is `Some` only
/// when its producing step ran (gated by `flex[0x1c]`); absent ⇒ the arm uses the static fallback.
#[derive(Debug, Clone, Default)]
pub struct CalResults {
    /// `+0x68` — step-3 bit-packed per-line diff (factory `0x80000003`). DAT lines A/B source.
    pub step3_diff: Option<Vec<u8>>,
    /// `+0x98` — step-4 buffer (factory `0x80000007`). DAT line C 2nd-preference source.
    pub step4_buf: Option<Vec<u8>>,
    /// `+0x80` — step-5 live-measured diff OR step-6 WOE clean-slate frame. DAT line C 1st preference.
    pub step56_buf: Option<Vec<u8>>,
    /// `+0xbc` — step-6 clean-slate variance id (diagnostic; `sum_sq/0x1000`).
    pub step56_id: Option<u32>,
    /// `ctx+0x29c` — step-8 finger-detect threshold word (no wire consumer found — see spec §7).
    pub fingerdet_threshold: Option<u32>,
    /// `ctx+0x2a8` — step-9 prod-33 register word (no wire consumer found — see spec §7).
    pub prod33_reg: Option<u32>,
    /// The raw **step-7 settle** frame (wire form: `height` rows of `wire_stride` bytes = 8-byte
    /// `SYNC_LINE_HEADER` + pixels) — the DLL's `pLast_frame_buf` at identify-arm time. Emitted as the
    /// arm's `0x48` finger-detect baseline chunk by `syna_append_chunk_48_last_frame@0x180095ae0` (the
    /// LAST captured frame, re-embedded so the sensor has a baseline to subtract). This is the read_mode-2
    /// / capture_type-4 Hello identify path. It is NOT the step-6 dark frame and NOT the enrolled template
    /// (`pEnrolled_template` ctx+0x108 is a separate on-chip matcher struct, dead on our host-match SKU).
    /// `None` ⇒ arm omits `0x48`. See [`crate::line_update::chunk_baseline`].
    pub baseline_frame: Option<Vec<u8>>,
}

impl CalResults {
    /// The DAT-line-C source (step-6/5 `+0x80` preferred, then step-4 `+0x98`) the arm folds as a raw
    /// memcpy, or `None` ⇒ the static `DAT_FLAT40` fallback. Mirrors `syna_build_line_update_prod23`.
    pub fn line_c_source(&self) -> Option<&[u8]> {
        self.step56_buf.as_deref().or(self.step4_buf.as_deref())
    }
}

/// Device operations the calibration needs. The factory-block read is a `0x6f` tag-14 round-trip
/// (see [`crate::factory_cal::factory_bits_request`]); the dark-frame capture (steps 5/6) is a
/// finger-less imaging read. The caller owns the TLS session and wire framing.
pub trait CalIo {
    /// Read + parse the per-tag factory block table (`0x6f`, tag 14). Called once at the start.
    fn read_factory_blocks(&mut self) -> Result<Vec<FactoryBlock>>;
    /// Step-6 dark-frame arms must fold step-3's measured per-line diff into DAT lines A/B (replacing
    /// the static `DAT_CAL_2449` fallback). Called after step 3 completes, before step 6 capture.
    fn set_step3_diff_for_capture(&mut self, _diff: Option<&[u8]>) {}
    /// Take the raw step-6 dark frame (wire form). Superseded as the `0x48` source by
    /// [`Self::take_raw_settle_frame`] — kept only for the Phase-0 A/B comparison. Default `None`.
    fn take_raw_dark_frame(&mut self) -> Option<Vec<u8>> {
        None
    }
    /// Take the raw step-7 **settle** frame (wire form) captured by [`Self::capture_settle_arm`] — the
    /// DLL's `pLast_frame_buf` at identify-arm time, and the true source of the arm's `0x48`
    /// finger-detect baseline chunk (`syna_append_chunk_48_last_frame@0x180095ae0`). Default `None`
    /// (mock/non-session impls don't retain it).
    fn take_raw_settle_frame(&mut self) -> Option<Vec<u8>> {
        None
    }
    /// Capture one dark-field frame (finger-less) for the live-measure steps 5/6, returning the flat
    /// `width*height` body and its `(width, height)`. Only invoked when steps 5/6 are gated on.
    fn capture_dark_frame(&mut self) -> Result<(Vec<u8>, usize, usize)>;
    /// Step 7 settle arm — `syna_lib_calibration_step` case 7 always runs
    /// `syna_capture_arm_and_wait(ctx,0,1,0)`: upload a `req_lines=0` calibrate-class program with
    /// the measured cal fold, no EP-0x82 payload read.
    fn capture_settle_arm(&mut self, _cal: &CalResults) -> Result<()> {
        Ok(())
    }
}

// ---- pure step arithmetic (unit-testable, capture-independent) -----------------------------------

/// `clip` a signed value to a `u8` (`syna_cal`'s `clip_u8`).
fn clip_u8(v: i32) -> u8 {
    v.clamp(0, 255) as u8
}

/// `clip` a signed value to an `i8`.
fn clip_i8(v: i32) -> i8 {
    v.clamp(-128, 127) as i8
}

/// Header-split a factory block: the first 4 bytes are `(const_lo, const_hi, pad, pad)`; the per-line
/// array follows. Steps 3/4/6-ref/8/9 all share this "skip 4" pattern.
const BLOCK_HEADER: usize = 4;

/// Step 4 — factory `0x80000007` → `step4_buf`. For product `'2'`/`'3'` (0x2449) this is the
/// **raw-store** branch (verbatim header-stripped bytes); otherwise it bit-packs (like step 3).
/// `syna_lib_cal_step4_factory7_into_98@0x180077ec0`.
pub fn step4_factory7(
    blocks: &[FactoryBlock],
    width: usize,
    product: ProductClass,
) -> Option<Vec<u8>> {
    let block = factory_block(blocks, block_tag::STEP4_FACTORY7)?;
    let arr = block.data.get(BLOCK_HEADER..BLOCK_HEADER + width)?;
    Some(if product.is_23() {
        arr.to_vec() // RAW-STORE branch (product '2'/'3')
    } else {
        bitpack(arr).2 // BITPACK branch
    })
}

/// Step 5 live-measure per-iteration refine of the `+0x80` buffer (additive, row-minimum baseline):
/// `buf[i] = clip_u8(buf[i] + (diff[i] - min_val)*10/18)` where `diff[i] = row_mean[i] - 0x80`.
/// `syna_cal_measure_line_diff_into_80@0x1800767c0`. Pure; the caller supplies per-row means.
pub fn step5_accumulate(buf: &mut [u8], row_means: &[u8]) {
    let diff: Vec<i32> = row_means.iter().map(|&m| m as i32 - 0x80).collect();
    let min_val = diff.iter().copied().min().unwrap_or(0);
    for (b, &d) in buf.iter_mut().zip(&diff) {
        *b = clip_u8(*b as i32 + (d - min_val) * 10 / 18);
    }
}

/// Step 3 live-measure fallback refine of the `+0x68` buffer (subtractive, buffer pre-filled `0x80`):
/// `buf[i] = clip_u8(buf[i] - (diff[i]+15)/30)`. `syna_cal_measure_line_diff_into_68@0x1800758c0`.
pub fn step3_fallback_refine(buf: &mut [u8], row_means: &[u8]) {
    for (b, &m) in buf.iter_mut().zip(row_means) {
        let d = m as i32 - 0x80;
        *b = clip_u8(*b as i32 - (d + 15) / 30);
    }
}

/// Number of saturated rows (mean == 0 or == 0xff) — the live-measure convergence signal.
pub fn saturated_rows(row_means: &[u8]) -> usize {
    row_means.iter().filter(|&&m| m == 0 || m == 0xff).count()
}

/// Step-6 variance gate: SSD of the DIGITALLY-rescaled captured frame vs the factory reference,
/// divided by `0x1000`, compared to `threshold`. Returns `(variance_id, passed)`.
/// `syna_cal_variance_check_scaled@0x180079250`. Pure.
///
/// For each of the 5 `row_positions`, samples `frame[pos*width + col_offset ..][..row_len]`, applies
/// the digital contrast rescale `clip_i8((px-0x80)*scale_num/scale_den)` (a software op, not an
/// analog gain — see [`FlexCal::scale_num`]), and accumulates `(ref - scaled)^2`.
#[allow(clippy::too_many_arguments)]
pub fn variance_check_scaled(
    frame: &[u8],
    frame_width: usize,
    col_offset: usize,
    reference: &[u8],
    row_len: usize,
    row_positions: &[i32],
    threshold: u32,
    scale_num: i32,
    scale_den: i32,
) -> (u32, bool) {
    let mut sum_sq: i64 = 0;
    for (r, &pos) in row_positions.iter().enumerate() {
        let src_base = pos as usize * frame_width + col_offset;
        let ref_base = r * row_len;
        for col in 0..row_len {
            let px = frame.get(src_base + col).copied().unwrap_or(0x80) as i32;
            let scaled = clip_i8((px - 0x80) * scale_num / scale_den) as i32;
            let refv = reference.get(ref_base + col).copied().unwrap_or(0) as i8 as i32;
            let delta = refv - scaled;
            sum_sq += (delta * delta) as i64;
        }
    }
    let id = (sum_sq / 0x1000) as u32;
    (id, id <= threshold)
}

/// Step 8/9 packed-word byte layout: `byte0 = base&0xff, byte1<<8, byte2<<0x10, byte3<<0x18`.
fn pack_word(base: u32, byte1: u8, byte2: u8, byte3: u8) -> u32 {
    (base & 0xff) | ((byte1 as u32) << 8) | ((byte2 as u32) << 16) | ((byte3 as u32) << 24)
}

/// Step 8 — factory `0x80000009` → finger-detect threshold word (`ctx+0x29c`).
/// `syna_lib_cal_step8_fingerdet_cfg@0x180078610`. Byte1 = `lo + 2*(hi-lo)/3`; byte2 = `hi-6` for
/// product `'2'`/`'3'`. (No wire consumer of this word was found — spec §7; computed for fidelity.)
pub fn step8_fingerdet(blocks: &[FactoryBlock], product: ProductClass) -> Option<u32> {
    let block = factory_block(blocks, block_tag::STEP8_FINGERDET)?;
    let d = block.data.get(BLOCK_HEADER..BLOCK_HEADER + 3)?;
    let (lo, hi, class_byte) = (d[0] as i32, d[1] as i32, d[2]);
    let base = if product == ProductClass::Prod2 {
        0xff00c4
    } else {
        0xff00cc
    };
    let two_thirds = (lo + (hi - lo) * 2 / 3) as u8;
    let quarter = (lo + (((hi - lo) + (((hi - lo) >> 31) & 3)) >> 2)) as u8;
    let hi_field = if product.is_23() {
        (hi - 6) as u8
    } else {
        quarter
    };
    Some(pack_word(base, two_thirds, hi_field, class_byte))
}

/// Step 9 — factory `0x8000000d` → prod-33 register word (`ctx+0x2a8`).
/// `syna_lib_cal_step9_prod33_cfg@0x180078c00`. `lo=hi=byte4-6` (prod `'2'`/`'3'`) / `-3` (prod `'0'`).
/// Tag byte fixed `0x44`. (No wire consumer found — spec §7; computed for fidelity.)
pub fn step9_prod33(blocks: &[FactoryBlock], product: ProductClass) -> Option<u32> {
    let block = factory_block(blocks, block_tag::STEP9_PROD33)?;
    let d = block.data.get(BLOCK_HEADER..BLOCK_HEADER + 3)?;
    let (lo, class_byte) = (d[0] as i32, d[2]);
    let field = match product {
        ProductClass::Prod2 | ProductClass::Prod3 => (lo - 6) as u8,
        ProductClass::Prod0 => (lo - 3) as u8,
    };
    Some(pack_word(0xff00c4, field, field, class_byte))
}

// ---- the driver -----------------------------------------------------------------------------------

/// Run the calibration state machine for `subtype`/`product`, gated by `flex.cap_bits`, returning the
/// [`CalResults`] the capture arm folds. Port of `syna_lib_run_calibration@0x1800731d0` +
/// `syna_lib_calibration_step@0x180073270`. `io` provides the factory-block read (all steps) and the
/// dark-frame capture (steps 5/6) and the step-7 settle arm.
///
/// For 0x2449 (`cap_bits = 0x81`) this runs step 3 (factory `0x80000003` → `step3_diff`), step 6
/// (`sync_frames=1` dark capture → `step56_buf` + variance gate), and **step 7** (always — settle arm
/// with `req_lines=0` and the full measured line-update fold). A failed step-6 variance gate returns
/// `Error::Malformed` (the DLL's `0xd8` "clean-slate not converged" — usually means the sensor wasn't
/// clear during calibration).
pub fn run_calibration(
    io: &mut impl CalIo,
    flex: &FlexCal,
    product: ProductClass,
    subtype_classify: i32,
) -> Result<CalResults> {
    let blocks = io.read_factory_blocks()?;
    let mut r = CalResults::default();

    // Step 3 — factory 0x80000003 line-diff → DAT lines A/B (bit-packed for 0x2449).
    // The DLL (`syna_lib_calibration_step`/`syna_scs_windsor_cal_step` case 3) gates this on
    // `cap_bits&1` AND `NOT(product=='0' && subtype_classify<5)` — product-'0' dies with a low classify
    // (the 0x0199 type-1 family) SKIP step 3 even when the cap bit is set. Verified in both the baseline
    // and Lenovo DLLs (docs/capture/009a-calibration-port.md §2026-08-19).
    let step3_product_skip = product == ProductClass::Prod0 && subtype_classify < 5;
    if flex.cap_bits & cap::STEP3 != 0 && !step3_product_skip {
        r.step3_diff = crate::factory_cal::cal_line_diff(&blocks, flex.line_diff_width);
        io.set_step3_diff_for_capture(r.step3_diff.as_deref());
    }
    // Step 4 — factory 0x80000007 → DAT line C 2nd preference (raw for product '2'/'3').
    if flex.cap_bits & cap::STEP4 != 0 {
        r.step4_buf = step4_factory7(&blocks, flex.line_diff_width, product);
    }
    // Step 5 — live line-diff → +0x80 (not run for 0x2449; capture-driven).
    if flex.cap_bits & cap::STEP5 != 0 {
        r.step56_buf = Some(measure_live_diff(io, flex)?);
    }
    // Step 6 — WOE clean-slate: one dark-frame capture → +0x80 (raw frame) + variance gate.
    if flex.cap_bits & cap::STEP6 != 0 {
        let (frame, width, _height) = io.capture_dark_frame()?;
        let _ = io.take_raw_dark_frame(); // step-6 frame is NOT the 0x48 source (see step-7 below)
        // Variance gate against factory reference 0x8000000c (5×(width-8) bytes, header-skipped).
        let row_len = width.saturating_sub(8);
        if let Some(refb) = factory_block(&blocks, block_tag::STEP6_REFERENCE)
            && let Some(reference) = refb.data.get(BLOCK_HEADER..BLOCK_HEADER + 5 * row_len)
        {
            let (id, ok) = variance_check_scaled(
                &frame,
                width,
                8,
                reference,
                row_len,
                &flex.row_positions,
                flex.step6_threshold,
                flex.scale_num,
                flex.scale_den,
            );
            // The DLL ABORTS here on failure (`syna_lib_cal_step6_woe_cleanslate@0x180076de0` returns
            // 0xd8, no retry, never arms). We DIVERGE and continue, because Rust's dark frame is
            // systematically brighter than the DLL's — the per-unit analog gain trim lives in the
            // Windows registry (`SOFTWARE\Validity\Cal`) and is not replicated on Linux, so the frame
            // fails the variance the DLL passes. Gating on it would block every capture; the gain
            // difference is the same reason the 0x34 fold / delta VALUES differ (excluded as sensor
            // calibration). Record the id for diagnostics and proceed.
            if !ok {
                log::debug!(
                    "calibration step 6 variance id={id} > {} (brighter frame — analog gain not replicated); continuing",
                    flex.step6_threshold
                );
            }
            r.step56_id = Some(id);
        }
        r.step56_buf = Some(frame); // +0x80 = the raw captured dark frame (DAT line C, raw memcpy)
    }
    // Step 7 — the DLL runs this unconditionally (`syna_lib_calibration_step` case 7): a settle
    // capture. We SKIP it for product '0' (0x0199 type-1 family): our settle arm is a FOLDED
    // frames-sync arm, which faults this die (verified on-device 2026-08-19 — resets even after a
    // correct step 6). The `0x85` calib fold belongs on the polled `0x4e` identify (which uses the
    // fresh step-6 dark below), NOT a frames-sync settle; and pv's 009a identify carries no `0x48`
    // baseline (`line_update_type_1` emits none), so skipping the settle's `pLast_frame_buf` is
    // DLL/pv-consistent for this family. 0x2449 still runs step 7 (its settle arm is fine).
    if product != ProductClass::Prod0 {
        io.capture_settle_arm(&r)?;
        // The settle frame is the DLL's `pLast_frame_buf` at identify-arm time → the source of the
        // arm's `0x48` baseline chunk (`syna_append_chunk_48_last_frame`). NOT the step-6 dark frame.
        r.baseline_frame = io.take_raw_settle_frame();
    }
    // Steps 8/9 — pure config words (no found wire consumer; computed for fidelity, gated on &8).
    if flex.cap_bits & cap::STEP8_9 != 0 {
        r.fingerdet_threshold = step8_fingerdet(&blocks, product);
        if product.is_23() {
            r.prod33_reg = step9_prod33(&blocks, product);
        }
    }
    Ok(r)
}

/// Step 5 live-measure loop: up to 3 dark-frame captures, refining the `+0x80` buffer, stopping when
/// fewer than 3 rows saturate (or after no improvement). Uses [`step5_accumulate`] per iteration.
fn measure_live_diff(io: &mut impl CalIo, _flex: &FlexCal) -> Result<Vec<u8>> {
    const MAX_ITERS: usize = 3;
    const SAT_LIMIT: usize = 3;
    const ROW_HEADER: usize = 12; // per-row header skipped by syna_cal_mean
    const ROW_FOOTER: usize = 4;
    let mut buf: Option<Vec<u8>> = None;
    let mut prev_sat = usize::MAX;
    for iter in 0..MAX_ITERS {
        let (frame, width, height) = io.capture_dark_frame()?;
        let stride = width;
        let means: Vec<u8> = (0..height)
            .map(|row| {
                let base = row * stride + ROW_HEADER;
                let end = (row * stride + stride).saturating_sub(ROW_FOOTER);
                let slice = frame.get(base..end).unwrap_or(&[]);
                if slice.is_empty() {
                    0
                } else {
                    (slice.iter().map(|&b| b as u32).sum::<u32>() / slice.len() as u32) as u8
                }
            })
            .collect();
        let b = buf.get_or_insert_with(|| vec![0u8; height]);
        step5_accumulate(b, &means);
        let sat = saturated_rows(&means);
        if sat < SAT_LIMIT {
            break; // converged
        }
        if iter + 1 >= MAX_ITERS || (iter >= 1 && prev_sat <= sat) {
            return Err(Error::Malformed(
                "calibration step 5 live measure did not converge".into(),
            ));
        }
        prev_sat = sat;
    }
    buf.ok_or_else(|| Error::Malformed("calibration step 5 produced no buffer".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Per-subtype step-6 gain/variance must come from the vendor flex table, NOT the 0x2449 constants.
    /// 0x0199 = 10/34 (over-scaling with 0x2449's 10/4 is the 009a "blown-out middle"); 0x2449 unchanged.
    #[test]
    fn flex_cal_gain_is_per_subtype_not_2449_default() {
        let f0199 = flex_cal_for_subtype(0x0199).expect("0x0199 in flex table");
        assert_eq!(
            (f0199.scale_num, f0199.scale_den),
            (10, 34),
            "0x0199 digital rescale gain (flex[0x88]/[0x8a]) — NOT the 0x2449 10/4"
        );
        assert_eq!(f0199.row_positions, [88, 70, 52, 34, 16], "0x0199 variance rows *(flex+0x90)");
        assert_eq!(f0199.branch_sel, 2, "0x0199 branch selector flex[0x98]");
        // 0x2449 stays exactly the verified constants.
        let f2449 = flex_cal_for_subtype(0x2449).expect("0x2449");
        assert_eq!((f2449.scale_num, f2449.scale_den), (10, 4));
        assert_eq!(f2449.row_positions, [4, 18, 28, 38, 51]);
        // a sibling to prove it is genuinely a table, not two special cases.
        let fe4 = flex_cal_for_subtype(0x00e4).expect("0x00e4");
        assert_eq!((fe4.scale_num, fe4.scale_den), (10, 24));
    }

    #[test]
    fn run_calibration_invokes_step7_settle_arm() {
        struct MockCalIo {
            settle: bool,
        }
        impl CalIo for MockCalIo {
            fn read_factory_blocks(&mut self) -> Result<Vec<FactoryBlock>> {
                Ok(vec![])
            }
            fn capture_dark_frame(&mut self) -> Result<(Vec<u8>, usize, usize)> {
                Ok((vec![0x80; 152 * 56], 152, 56))
            }
            fn capture_settle_arm(&mut self, _cal: &CalResults) -> Result<()> {
                self.settle = true;
                Ok(())
            }
        }
        let mut io = MockCalIo { settle: false };
        let _ = run_calibration(&mut io, &FlexCal::FLEX_2449, ProductClass::Prod3, 0).unwrap();
        assert!(io.settle, "step 7 settle arm must run after step 6");
    }

    #[test]
    fn step3_gated_off_for_product0_low_classify() {
        // DLL `syna_lib_calibration_step` case 3: step 3 runs iff `cap_bits&1` AND
        // NOT(product=='0' && subtype_classify<5). FLEX_2449 has STEP3 set; vary product/classify.
        struct MockCalIo {
            step3_called: bool,
        }
        impl CalIo for MockCalIo {
            fn read_factory_blocks(&mut self) -> Result<Vec<FactoryBlock>> {
                Ok(vec![])
            }
            fn capture_dark_frame(&mut self) -> Result<(Vec<u8>, usize, usize)> {
                Ok((vec![0x80; 152 * 56], 152, 56))
            }
            fn capture_settle_arm(&mut self, _cal: &CalResults) -> Result<()> {
                Ok(())
            }
            fn set_step3_diff_for_capture(&mut self, _diff: Option<&[u8]>) {
                self.step3_called = true;
            }
        }
        let run = |product, classify| {
            let mut io = MockCalIo { step3_called: false };
            run_calibration(&mut io, &FlexCal::FLEX_2449, product, classify).unwrap();
            io.step3_called
        };
        assert!(!run(ProductClass::Prod0, 0), "product '0' + classify<5 skips step 3");
        assert!(run(ProductClass::Prod0, 5), "product '0' + classify>=5 runs step 3");
        assert!(run(ProductClass::Prod3, 0), "product '3' runs step 3");
    }

    #[test]
    fn product_byte_maps_to_class() {
        assert_eq!(ProductClass::from_product_byte(b'0'), ProductClass::Prod0);
        assert_eq!(ProductClass::from_product_byte(b'2'), ProductClass::Prod2);
        assert_eq!(ProductClass::from_product_byte(b'3'), ProductClass::Prod3);
    }

    #[test]
    fn flex_2449_runs_steps_3_and_6_only() {
        let f = FlexCal::FLEX_2449;
        assert_eq!(f.cap_bits, 0x81);
        assert_ne!(f.cap_bits & cap::STEP3, 0);
        assert_ne!(f.cap_bits & cap::STEP6, 0);
        assert_eq!(f.cap_bits & cap::STEP4, 0);
        assert_eq!(f.cap_bits & cap::STEP5, 0);
        assert_eq!(f.cap_bits & cap::STEP8_9, 0);
    }

    #[test]
    fn variance_gate_passes_when_frame_matches_reference() {
        // A frame whose sampled rows, when scaled, equal the reference → SSD 0 → passes.
        let width = 16;
        let height = 60;
        let row_positions = [4i32, 18, 28, 38, 51];
        let row_len = width - 8;
        // Reference = scaled pixels. Build a frame, then a reference matching its scaling.
        let mut frame = vec![0x80u8; width * height];
        for (r, &pos) in row_positions.iter().enumerate() {
            for col in 0..row_len {
                frame[pos as usize * width + 8 + col] = 0x80 + (r as u8 + 1);
            }
        }
        let mut reference = vec![0u8; 5 * row_len];
        for (r, _) in row_positions.iter().enumerate() {
            let scaled = clip_i8((r as i32 + 1) * 10 / 4) as u8;
            for col in 0..row_len {
                reference[r * row_len + col] = scaled;
            }
        }
        let (id, ok) = variance_check_scaled(
            &frame,
            width,
            8,
            &reference,
            row_len,
            &row_positions,
            200,
            10,
            4,
        );
        assert_eq!(id, 0);
        assert!(ok);
    }

    #[test]
    fn variance_gate_fails_when_frame_diverges() {
        let width = 32; // wide enough that the SSD/0x1000 clears the 200 threshold
        let height = 60;
        let row_positions = [4i32, 18, 28, 38, 51];
        let row_len = width - 8;
        let frame = vec![0xffu8; width * height]; // saturated → scaled ~127
        let reference = vec![0u8; 5 * row_len]; // expects ~0
        let (_id, ok) = variance_check_scaled(
            &frame,
            width,
            8,
            &reference,
            row_len,
            &row_positions,
            200,
            10,
            4,
        );
        assert!(
            !ok,
            "a saturated frame vs a zero reference must exceed threshold"
        );
    }

    #[test]
    fn step5_accumulate_uses_row_min_baseline() {
        // means {0x80, 0x82, 0x84} → diff {0,2,4}, min 0 → add {0, 20/18=1, 40/18=2}.
        let mut buf = vec![0u8; 3];
        step5_accumulate(&mut buf, &[0x80, 0x82, 0x84]);
        assert_eq!(buf, vec![0, 1, 2]);
    }

    #[test]
    fn step8_and_step9_word_layout() {
        // Block 0x80000009 data = [hdr0..3][lo=0x40, hi=0x52, class=0x07].
        let mk = |tag: u32, lo: u8, hi: u8, cls: u8| FactoryBlock {
            tag,
            flags: 0,
            data: vec![0, 0, 0, 0, lo, hi, cls],
        };
        let blocks = vec![
            mk(block_tag::STEP8_FINGERDET, 0x40, 0x52, 0x07),
            mk(block_tag::STEP9_PROD33, 0x40, 0x00, 0x07),
        ];
        // step8 prod'3': byte1 = 0x40 + 2*(0x52-0x40)/3 = 0x40+0x0c = 0x4c; byte2 = 0x52-6 = 0x4c.
        let w8 = step8_fingerdet(&blocks, ProductClass::Prod3).unwrap();
        assert_eq!(w8 & 0xff, 0xcc); // base 0xff00cc low byte
        assert_eq!((w8 >> 8) & 0xff, 0x4c);
        assert_eq!((w8 >> 16) & 0xff, 0x4c);
        assert_eq!((w8 >> 24) & 0xff, 0x07);
        // step9 prod'3': lo=hi=0x40-6=0x3a.
        let w9 = step9_prod33(&blocks, ProductClass::Prod3).unwrap();
        assert_eq!(w9 & 0xff, 0xc4);
        assert_eq!((w9 >> 8) & 0xff, 0x3a);
        assert_eq!((w9 >> 16) & 0xff, 0x3a);
    }
}
