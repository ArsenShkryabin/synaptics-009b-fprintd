//! Calibration-line model + serialization — the `Line` type, product-0x33 delta/data line
//! generation (`calib_delta_lines_prod33`, `line_update_prod33`/`_type_2`), timeslot 2D folding,
//! `bitpack`, and `serialize_line_update`. Extracted from the `line_update` module (uses its `Mode`
//! + RECON/CAPTURE constants + the disasm decoder/patcher via `super`); re-exported by `mod.rs`.

use super::*;
// =====================================================================================
// Product-0x33 "line update" (subtype 0x2449, first capture / identify).
//
// This is a second, independent line_update path, ported from `syna_build_line_update_prod23`
// @0x1800a36c0 (the ALT branch taken when `status[8]==6 && status[9]>10`, which is true for our
// live sensor). It replaces the simpler 3-line/no-bitpack `line_update_type_2` above for this
// product family. See `docs/calibration/line-update-transcription-spec.md` for the derivation; the notes
// below record where the live decompile diverged from that spec during transcription.
// =====================================================================================

/// Port of python-validity `sensor.bitpack` / vendor `syna_bitpack_calib_diff`@0x180095d40
/// (single-array form — the DLL degrades to exactly this when the second array is absent, which
/// is always true on our path). Verified byte-for-byte against the DLL's helper trio
/// `FUN_180096f70` (min/max), `syna_count_delta_bits`@0x180097180 (bit width = bit-length of
/// `max-min`, 0 if they're equal) and `syna_pack_bits`@0x1800971d0 (LSB-first bit packing, value
/// `i` occupies bits `[i*u, i*u+u)`).
///
/// Returns `(u_bits, min, packed)`. `packed` is `ceil(u_bits * data.len() / 8)` bytes.
/// The DLL's two "diff" flag outputs (`local_118`/`local_114`, min-negative / is-diff) are
/// always `0` in this single-array form (confirmed from the decompile: both are hard-set to `0`
/// before the packing loop), so callers building product-0x33 lines never need to consult them.
pub fn bitpack(data: &[u8]) -> (u8, u8, Vec<u8>) {
    if data.is_empty() {
        return (0, 0, Vec::new());
    }
    let m = *data.iter().min().unwrap();
    let x = *data.iter().max().unwrap();
    let mut delta = x.wrapping_sub(m);
    let mut u: u8 = 0;
    while delta > 0 {
        delta >>= 1;
        u += 1;
    }
    let total_bits = u as usize * data.len();
    let mut packed = vec![0u8; total_bits.div_ceil(8)];
    for (i, &b) in data.iter().enumerate() {
        let v = b.wrapping_sub(m);
        let bitpos = i * u as usize;
        for bit in 0..u as usize {
            if (v >> bit) & 1 == 1 {
                let p = bitpos + bit;
                packed[p / 8] |= 1 << (p % 8);
            }
        }
    }
    (u, m, packed)
}

/// `DAT_180145320`: the embedded per-line calibration-diff table used for the "DAT line A/B"
/// entries of subtypes `{0x123,0x8f3,0x126,0x8f5,0x8f6,0x121,0xb4b,0xb4d,0x2449,0x195,0x17e}`
/// (same table for all of them — verified from the decompile's subtype-selection `if` chain,
/// `syna_build_line_update_prod23` lines ~186-194 and ~222-231). 56 bytes.
pub const DAT_CAL_2449: [u8; 56] = [
    123, 128, 130, 131, 130, 132, 131, 130, 129, 131, 130, 130, 128, 132, 130, 130, 129, 131, 131,
    129, 129, 130, 130, 128, 128, 129, 131, 128, 128, 129, 129, 128, 128, 130, 130, 130, 129, 131,
    130, 131, 129, 131, 129, 130, 128, 130, 130, 130, 130, 131, 131, 132, 131, 132, 128, 124,
];

/// `DAT_180145358`: the embedded "DAT line C" table, used raw (NOT bitpacked — see
/// [`line_update_prod33`]) for the same subtype set as [`DAT_CAL_2449`]. Flat `40`s, 56 bytes.
pub const DAT_FLAT40: [u8; 56] = [40; 56];

/// `DAT_180144f60` / `DAT_180144fe0`: the DLL's **static single-line calib fallback** for the
/// product-`'6'` / version-1 branch of `syna_build_line_update_prod0_a`@0x1800a03c0. This is the
/// `local_160 != 0` arm (the `0x2f` program *has* a `0x800020fc` register write) **and** no fresh
/// step-6 clean-slate buffer is present (`ctx+0x288 == NULL` or `+0x80 == NULL`): rather than the
/// 28-line `0x85` column transpose, the DLL emits a *single* 114-byte (`0x72`) calib line copied
/// verbatim from one of these tables, selected by `ctx+0x280` (`==3` → [`DAT_CALIB_FALLBACK_CTX280EQ3`],
/// else [`DAT_CALIB_FALLBACK_DEFAULT`]), for the subtype whitelist
/// `{0xb5,0x16f,0xe2,0x885,0xea,0xe1,0x8b1,0xe4,0xde,0x1055,0x196}`.
///
/// **Not the 0x0199/009a path.** Our 009a takes the `local_160 == 0` arm (no `0x800020fc` write),
/// which either folds the fresh step-6 dark into the 28-line `0x85` transpose (buffer present) or
/// emits *no* calib line at all (buffer absent) — it never reaches these fallback tables. They are
/// extracted here for the sibling family (Rule #6) and to document that the DLL's "no fresh buffer"
/// behaviour on the `0x800020fc` branch is a single static line, not an empty arm.
/// Values are pixel-domain (0..=160). Source: `read_memory` @0x180144f60 / @0x180144fe0.
pub const DAT_CALIB_FALLBACK_CTX280EQ3: [u8; 114] = [
    5, 40, 40, 77, 63, 63, 63, 37, 37, 85, 76, 76, 74, 70, 69, 99, 121, 122, 114, 123, 128, 125,
    126, 129, 135, 134, 129, 148, 148, 146, 133, 130, 150, 132, 146, 143, 140, 141, 130, 118, 110,
    112, 96, 146, 139, 121, 134, 137, 150, 146, 145, 160, 158, 144, 109, 113, 133, 137, 136, 149,
    145, 132, 130, 145, 125, 155, 156, 145, 152, 147, 138, 142, 136, 131, 135, 128, 121, 127, 124,
    120, 111, 96, 105, 105, 65, 81, 89, 62, 70, 70, 68, 62, 78, 86, 100, 111, 71, 60, 87, 87, 81,
    72, 63, 45, 49, 23, 15, 23, 11, 0, 3, 22, 3, 5,
];

/// See [`DAT_CALIB_FALLBACK_CTX280EQ3`] — the `ctx+0x280 != 3` (default) variant. `DAT_180144fe0`.
pub const DAT_CALIB_FALLBACK_DEFAULT: [u8; 114] = [
    45, 34, 54, 41, 23, 52, 30, 5, 46, 58, 44, 45, 50, 35, 80, 54, 85, 85, 72, 80, 94, 86, 84, 90,
    86, 90, 91, 98, 108, 102, 87, 85, 110, 87, 107, 108, 97, 92, 93, 73, 73, 82, 47, 104, 99, 73,
    95, 100, 109, 104, 112, 118, 127, 123, 84, 92, 113, 106, 105, 124, 122, 116, 118, 124, 113,
    132, 133, 124, 137, 128, 109, 122, 115, 105, 119, 112, 97, 119, 111, 106, 105, 90, 88, 90, 48,
    75, 92, 68, 73, 80, 70, 67, 79, 83, 102, 114, 72, 60, 90, 90, 82, 86, 70, 52, 62, 27, 22, 35,
    27, 0, 8, 25, 31, 32,
];

/// One product-0x33 "line" (ghidra: the 0x18-byte-per-entry array built in
/// `syna_build_line_update_prod23`). `mask`/`flags` are the 0x30-chunk header fields; `v0..v2`
/// and `data` are the extra fields carried in the 0x43 chunk for `group = (flags>>0x14)&0xf >= 2`
/// lines (see [`serialize_line_update`]).
#[derive(Debug, Clone)]
pub struct Line {
    pub mask: u32,
    pub flags: u32,
    pub v0: u8,
    pub v1: u8,
    pub v2: u16,
    pub data: Vec<u8>,
}

/// `flags` pc-anchor contribution: the DLL adds `+1` to the raw find-result before OR-ing it into
/// `flags` (seen directly for the opcode search in `syna_build_line_update_prod23` line 475:
/// `local_164 + 1U`; the register-write search's own `+1` is baked into the DLL's internal finder,
/// which our [`find_nth_regwrite`] does *not* replicate — so both primitives need the same `+1`
/// here, matching how `line_update_type_2` above already treats them).
pub(crate) fn pc_flag(pc: Option<usize>) -> u32 {
    pc.map(|p| (p + 1) as u32).unwrap_or(0)
}

/// The raw pc (no `+1`) for lines that embed `local_1a8`/`local_1a4` directly (ghidra: line 726/734
/// use `| local_1a8` with no increment, unlike the calib/DAT lines which use `pc+1`).
fn pc_raw(pc: Option<usize>) -> u32 {
    pc.map(|p| p as u32).unwrap_or(0)
}

/// Subtypes that share [`DAT_CAL_2449`]/[`DAT_FLAT40`] and the model-marker line (ghidra:
/// `syna_build_line_update_prod23`, the repeated `sVar1 == ...` chains). We only have the actual
/// table bytes for `0x2449`; the other DAT tables (`DAT_180145288`, `DAT_1801452c0`,
/// `DAT_1801452f8`, used by different subtype groups) are not extracted, so this list is scoped to
/// the group `0x2449` belongs to.
const DAT_2449_GROUP_SUBTYPES: [u16; 11] = [
    0x123, 0x8f3, 0x126, 0x8f5, 0x8f6, 0x121, 0xb4b, 0xb4d, 0x2449, 0x195, 0x17e,
];

/// Subset of [`DAT_2449_GROUP_SUBTYPES`] that also gets the trailing "model marker" line
/// (ghidra: lines ~744-747 / ~290-292 — `0x123`/`0x8f3`/`0x126` are notably absent here).
const MODEL_MARKER_SUBTYPES: [u16; 8] = [0x8f5, 0x8f6, 0x121, 0xb4b, 0xb4d, 0x2449, 0x195, 0x17e];

/// The prod-0x33 per-line **delta lines** — the `local_19c == 0` arm of
/// `syna_build_line_update_prod23` (the loop @0x1800a578c that the earlier port wrongly documented as
/// dead code). When the live `0x2f` program has NO `0x800020fc` register write (true for 0x2449), the
/// DLL expands the step-6 dark frame (`pCal_results->pStep5or6_buf_ptr`, `ctx+0x288+0x80`) into
/// `count = (stride - 8) / 4` group-0 lines, each `scanlines*4` bytes, applying the flex digital
/// rescale `clamp((px - 0x80) * num / den, ±127)` (the same op as [`crate::calibration`]'s fold).
///
/// Inputs (all runtime/data-driven — Rule #6, no fitted constants):
/// - `frame` = the step-6 dark frame as captured ([`crate::calibration::CalResults::line_c_source`]),
///   **incl. the 8-byte per-line header** — for 0x2449 `152 × 56 = 8512` B, the DLL's `pStep5or6_buf`
///   layout. (`SessionCalIo::capture_dark_frame` returns the averaged frames-sync frame, header kept.)
/// - `scanlines` = `local_1ac` = the `0x2f` "2D" chunk value (`= CaptureConfig::lines_2d`, 56 for
///   0x2449). Decompile-confirmed as `*(u32*)(0x2f_chunk_header + 4)` = the chunk's first payload word.
/// - `stride = frame.len() / scanlines` = the row width incl. the 8-byte header (`152` for 0x2449).
///   `count = (stride - 8) / 4 = line_width/4 = 36`.
///
/// Each line: `mask = 0xffffffff`, `flags = (4*d) | 0x85000000` (group nibble 0 ⇒ the `0x30` chunk),
/// `data[r*4+k] = clip_i8((frame[8 + 4*d + r*stride + k] - 0x80) * num / den)`. For 0x2449 → 36 lines
/// × 224 B, so the `0x30` chunk becomes 6 base + 36 delta = 42 lines, `36*224 + 4 + 42*8 = 8404` B.
/// Verified against the DLL decompile @0x1800a578c **and the live pcap** (`dll.pcap` LineUpdate = 8404).
pub fn calib_delta_lines_prod33(
    frame: &[u8],
    scanlines: usize,
    scale_num: i32,
    scale_den: i32,
) -> Vec<Line> {
    if scanlines == 0 || scale_den == 0 || frame.len() < scanlines {
        return Vec::new();
    }
    let stride = frame.len() / scanlines; // 152 (row width incl. 8-byte header)
    if stride <= 8 {
        return Vec::new();
    }
    let count = (stride - 8) / 4; // local_154 = line_width/4 = 36
    let mut lines = Vec::with_capacity(count);
    for d in 0..count {
        let mut data = vec![0u8; scanlines * 4];
        for r in 0..scanlines {
            for k in 0..4 {
                let idx = 8 + 4 * d + r * stride + k; // +8 skips the per-line header
                let px = frame.get(idx).copied().unwrap_or(0x80) as i32;
                let scaled = ((px - 0x80) * scale_num / scale_den).clamp(-128, 127);
                data[r * 4 + k] = scaled as i8 as u8;
            }
        }
        lines.push(Line {
            mask: 0xffff_ffff,
            flags: (4 * d as u32) | 0x8500_0000,
            v0: 0,
            v1: 0,
            v2: 0,
            data,
        });
    }
    lines
}

/// Per-subtype step-6 dark-frame rows sampled for the `0x34` timeslot fold — the 3 thirds of the
/// `line_width`-column correction table. Ghidra `syna_fold_timeslot_2d_measured@0x180092c70`:
/// `local_14c`/fixed `0x1c`/`local_14a`. `None` = the subtype's rows aren't extracted yet (skip fold).
pub fn timeslot_fold_rows(subtype: u16) -> Option<(usize, usize, usize)> {
    match subtype {
        0x2449 => Some((18, 28, 38)), // 0x12 / 0x1c / 0x26
        0x195 => Some((20, 28, 36)),  // 0x14 / 0x1c / 0x24
        _ => None,
    }
}

/// In-place port of `syna_fold_timeslot_2d_measured@0x180092c70` — fold the measured step-6 dark
/// frame's per-column dark level into the leading `data_width` bytes of the `0x34` timeslot payload.
/// The DLL runs this LAST in `syna_build_capture_cmd02` (after the line-update) when `capture_type != 5`;
/// it corrects the per-timeslot fixed pattern **at the sensor**, so the emitted frame is clean (proven
/// by the live pcap: DLL emitted-frame per-timeslot spread ≈ 0.3 vs ≈ 11 unfolded → the "stipple").
///
/// `frame` = the step-6 dark frame as captured (`stride = frame.len()/scanlines`, **incl. the 8-byte
/// per-line header** — 152 for 0x2449, same layout the DLL folds). The `line_width = stride-8`
/// destination columns split into three thirds — first `third = line_width/3` cols from `rows.0`, a
/// middle `line_width - 2*third` cols from `rows.1`, and a final `third` cols from `rows.2` — where the
/// **source column follows the destination index contiguously**: dst byte `d` reads data col `8 + d`
/// (NOT `8 + (d % third)`), only the row multiplier changing per third (Ghidra: `local_154` is the
/// contiguous dst index reused as the source column offset across all three loops). Each byte is
/// `clip_i8((px-0x80)*num/den)` with the DLL's "avoid-5" quirk (`5` is reserved in the 2D table → `4`).
pub fn fold_timeslot_2d(
    payload: &mut [u8],
    frame: &[u8],
    scanlines: usize,
    scale_num: i32,
    scale_den: i32,
    rows: (usize, usize, usize),
) {
    if scanlines == 0 || scale_den == 0 || frame.len() < scanlines {
        return;
    }
    let stride = frame.len() / scanlines; // 152 (row stride incl. 8-byte header)
    if stride <= 8 {
        return;
    }
    let line_width = stride - 8; // 144 (data columns per row)
    let third = line_width / 3; // 48 (local_10c)
    if third == 0 || payload.len() < line_width {
        return;
    }
    let mid = line_width - 2 * third; // local_e4: middle third absorbs the remainder (48 for 144)
    // (start, end, row): dst index `d` runs contiguously 0..line_width; only the row changes.
    let segments = [
        (0, third, rows.0),
        (third, third + mid, rows.1), // Ghidra hardcodes row 0x1c(28) here for every subtype
        (third + mid, line_width, rows.2),
    ];
    for (start, end, row) in segments {
        for (i, out) in payload[start..end].iter_mut().enumerate() {
            let dst = start + i; // contiguous dst index across all three thirds
            let idx = row * stride + 8 + dst; // src col = 8 + contiguous dst, after the 8-byte header
            let px = frame.get(idx).copied().unwrap_or(0x80) as i32;
            let mut v = ((px - 0x80) * scale_num / scale_den).clamp(-128, 127) as i8 as u8;
            if v == 5 {
                v = 4; // reserved value in the 2D table
            }
            *out = v;
        }
    }
}

/// Build the product-0x33 line list (ghidra: `syna_build_line_update_prod23`@0x1800a36c0, the
/// `local_11c != 0` ALT branch — taken when `status[8]==6 && status[9]>10`, true for our sensor).
/// **Post-calibration path.** After `syna_lib_run_calibration`, `ctx+0x288` (`pCal_results`) is
/// allocated and `+0x80` (`pStep5or6_buf_ptr`) holds the step-6 dark frame, so the DLL's per-line
/// delta loop (@0x1800a578c) runs — emitting `count = line_width/4` group-0 lines via
/// [`calib_delta_lines_prod33`]. (The earlier "dead code" note here was wrong: the loop's guard is
/// `local_19c == 0`, i.e. the live `0x2f` program has no `0x800020fc` write — TRUE for 0x2449 — not
/// `ctx+0x288 == NULL`.) `scanlines`/`scale_num`/`scale_den` feed that loop when `step6_dark` is
/// `Some`; when it is `None` (no measured frame) the delta lines are simply absent (weak-signal
/// fallback). The `p19c.is_some()` raw-line-C branch is the mutually-exclusive `local_19c != 0` arm.
///
/// `tst` is the **patched** Timeslot-Table-2D payload (`patch_timeslot_table` +
/// `patch_fingerdet_reg`); `calibration_blob` is `SensorTypeInfo::calibration_blob`; `subtype`
/// selects the DAT-table/model-marker subtype groups.
///
/// Differences found in the live decompile vs. the original spec draft:
/// - The "DAT line C" entry (`0x800020fc` register write) is **not** bitpacked — it's a raw
///   memcpy of [`DAT_FLAT40`] (ghidra lines ~686-719: no call to the bitpack helper on this
///   branch, unlike lines A/B). `v0/v1/v2` stay `0` (the `v0=0xf` override only fires when a
///   prior-frame field is set, which cannot happen on first capture).
/// - The running `seq` (`local_1e0`) is **not** a simple per-line counter: the calib-blob line
///   uses a hardcoded `flags` constant (`0x0720_0000`, embedding `group=2` directly) and force-sets
///   `seq=3` afterwards *only if that line was emitted*; the "1a8" line uses the *pre-increment*
///   `seq`, and (if present) "1a4" uses `seq+1`, with `seq` advancing by 2 only when both are
///   present. This function replicates that exact sequencing rather than a uniform `seq += 1`.
///
/// `step3_diff` is the measured step-3 per-line calibration diff (`factory_cal::cal_line_diff`, the
/// DLL's `pStep3_diff_ptr`). When `Some`, it replaces [`DAT_CAL_2449`] as the DAT line-A/B source, so
/// the arm folds the sensor's MEASURED correction instead of flat factory defaults (task #27). When
/// `None`, the static fallback is used. Either source is the RAW per-line array, bit-packed **once**
/// below (`syna_bitpack_calib_diff` single-array — step-3 stores raw, no earlier pack).
/// `step6_dark` is the measured DAT-line-C source — step 6's WOE clean-slate frame (or step 4's
/// buffer), the DLL's `pStep5or6_buf_ptr`/`pStep4_factory7_ptr`. When `Some`, line C carries it as a
/// **raw memcpy** with a fixed `v0 = 0x0f` header (NOT bit-packed, unlike A/B — see
/// docs/calibration/calibration-fullmachine-spec.md §7); when `None`, the static [`DAT_FLAT40`] fallback (`v0 = 0`).
#[allow(clippy::too_many_arguments)]
pub fn line_update_prod33(
    tst: &[u8],
    calibration_blob: &[u8],
    subtype: u16,
    step3_diff: Option<&[u8]>,
    step6_dark: Option<&[u8]>,
    scanlines: usize,
    scale_num: i32,
    scale_den: i32,
    // Older type-1 family: persisted `(calib_data, line_width, lines_per_calibration_data)` for the
    // `0x30` delta lines (raw copy — python-validity), instead of folding the live step-6 dark.
    calib_data: Option<(&[u8], usize, usize)>,
    // Older type-1 family: the raw `0x80000003` factory-bits block ([`factory_calibration_values`]),
    // bit-packed into the single `0x8000203c` DAT line exactly as python-validity `line_update_type_1`
    // (`bitpack(self.factory_calibration_values)`). `0x2449` uses the measured `step3_diff` instead.
    factory_calibration_values: &[u8],
) -> Vec<Line> {
    let rx = TimeslotOp::EnableRx.op();
    let p164 = find_nth_insn(tst, rx, 2); // 2nd "Enable Rx" -> calib_blob line anchor
    let p1a8 = find_nth_insn(tst, rx, 3);
    let p1a4 = find_nth_insn(tst, rx, 4);
    let p19c = find_nth_regwrite(tst, reg::LINE_UPDATE_C, 1);
    let p160 = find_nth_regwrite(tst, reg::LINE_UPDATE_A, 1);
    let p15c = find_nth_regwrite(tst, reg::LINE_UPDATE_B, 1);
    // The older type-1 family follows python-validity `line_update_type_1` exactly: `calibration_blob`
    // + a single `bitpack(factory_calibration_values)` DAT line at `0x8000203c` + the `0x85` calib_data
    // lines — no DAT-B, no line-C, no 1a8/1a4/model-marker. Key this on the *subtype*
    // (`key_calibration_line`, matching `capture_prog::prod33_body`), NOT on `calib_data.is_some()`: pv
    // emits the factory `0x8000203c` line unconditionally for this family, so the UNFOLDED prime arm
    // (empty calib_data) must emit it too. The stock 009a DLL calibrate oracle confirms a 2-line prime
    // `0x30` (calib_blob + factory DAT-A); gating on calib_data dropped the DAT-A on the prime. This is a
    // no-op for the folded arms (calib_data present → both gates true) and for 0x2449 (still None here,
    // and `in_dat_group` keeps `emit_ab` true) — the 0x2449 KATs stay byte-exact.
    let older_family = key_calibration_line(subtype).is_some();
    // DAT line-A/B source: the older family bit-packs the RAW factory values (pv); 0x2449 uses the
    // measured step-3 diff when present, else the static factory fallback.
    let dat_src: &[u8] = if older_family {
        factory_calibration_values
    } else {
        step3_diff.unwrap_or(&DAT_CAL_2449)
    };

    let mut lines = Vec::new();
    let mut seq: u32 = 2;

    // 1. calib_blob line.
    if p164.is_some() && !calibration_blob.is_empty() {
        lines.push(Line {
            mask: 0xff,
            flags: pc_flag(p164) | line_flag::CALIB_BLOB,
            v0: 0x0f,
            v1: 0,
            v2: 0,
            data: calibration_blob.to_vec(),
        });
        seq = 3;
    }

    let in_dat_group = DAT_2449_GROUP_SUBTYPES.contains(&subtype);
    // DAT lines are emitted per the program's regwrites (the DLL's real gate: DAT-A/B at
    // 0x8000203c/0x80002040 from step-3, DAT-C at 0x800020fc from step-6). The historical
    // `in_dat_group` whitelist wrongly excluded the older type-1 family (e.g. 0x0199), which also
    // needs DAT-A when step-3 ran — python-validity `line_update_type_1` line1 =
    // `bitpack(factory_calibration_values)` at the 0x8000203c regwrite. Emit when there is a measured
    // source, OR for the 0x2449 group which uses static fallbacks even without one.
    let emit_ab = older_family || in_dat_group || step3_diff.is_some();
    // DAT line C (0x800020fc raw memcpy of step-6 dark) is emitted by the 0x2449-class program only.
    // The older type-1 family (0x0199) has NO line-C — pv's line_update_type_1 folds the dark ONLY into
    // the 0x85 delta lines (via the `calib_data` param), never DAT line C. Emitting it here (because
    // the identify path passes step6_dark) produced a folded IDENTIFY arm that faults this die, where the
    // byte-exact calibrate arm (step6_dark=None, 0x85 only) does not. Gate it off for the older family.
    let emit_c = (in_dat_group || step6_dark.is_some()) && !older_family;

    // 2. DAT line A (bitpacked).
    if p160.is_some() && emit_ab {
        let (u, min, packed) = bitpack(dat_src);
        lines.push(Line {
            mask: 0xff,
            flags: (seq << 0x14) | line_flag::DAT | pc_flag(p160),
            v0: u.wrapping_sub(1) | line_flag::V0_PACKED,
            v1: min,
            v2: 0, // both bitpack diff-flags are always 0 in single-array form (see `bitpack`)
            data: packed,
        });
        seq += 1;
    }

    // 3. DAT line B (bitpacked, same source table as A). The older type-1 family has no DAT-B
    //    (python-validity `line_update_type_1` writes only the one `0x8000203c` factory line).
    if p15c.is_some() && emit_ab && !older_family {
        let (u, min, packed) = bitpack(dat_src);
        lines.push(Line {
            mask: 0xff,
            flags: (seq << 0x14) | line_flag::DAT | pc_flag(p15c),
            v0: u.wrapping_sub(1) | line_flag::V0_PACKED,
            v1: min,
            v2: 0,
            data: packed,
        });
        seq += 1;
    }

    // 4. Line C (raw memcpy) — ONLY when the 0x2f program has the `0x800020fc` write (`local_19c != 0`).
    //    For 0x2449 `local_19c == 0`, so this is skipped and the per-line delta expansion runs LAST
    //    (step 7), matching the DLL's `0x30` line order (deltas after the 1a8/1a4/marker lines).
    if p19c.is_some() && emit_c {
        // Measured step-6 clean-slate (raw memcpy, v0=0x0f) if present, else the static flat fallback.
        let (v0_c, data_c) = match step6_dark {
            Some(c) => (0x0f, c.to_vec()),
            None => (0, DAT_FLAT40.to_vec()),
        };
        lines.push(Line {
            mask: 0xff,
            flags: (seq << 0x14) | line_flag::DAT | pc_flag(p19c),
            v0: v0_c,
            v1: 0,
            v2: 0,
            data: data_c,
        });
        seq += 1;
    }

    // 5. "1a8"/"1a4" lines: empty data, mask 0xffff. 1a4 only appears alongside 1a8. The older
    //    type-1 family omits these (python-validity `line_update_type_1` emits none).
    if p1a8.is_some() && !older_family {
        lines.push(Line {
            mask: 0xffff,
            flags: (seq << 0x14) | line_flag::EMPTY_1A | pc_raw(p1a8),
            v0: 0,
            v1: 0,
            v2: 0,
            data: Vec::new(),
        });
        if p1a4.is_some() {
            lines.push(Line {
                mask: 0xffff,
                flags: ((seq + 1) << 0x14) | line_flag::EMPTY_1A | pc_raw(p1a4),
                v0: 0,
                v1: 0,
                v2: 0,
                data: Vec::new(),
            });
            seq += 2;
        } else {
            seq += 1;
        }
    }

    // 6. Model-marker line (empty data). Not emitted for the older type-1 family.
    if MODEL_MARKER_SUBTYPES.contains(&subtype) && !older_family {
        lines.push(Line {
            mask: 0xff,
            flags: (seq << 0x14) | line_flag::MODEL_MARKER,
            v0: 0,
            v1: 0x0c,
            v2: 0,
            data: Vec::new(),
        });
    }

    // 7. Per-line delta expansion — the `local_19c == 0` arm (TRUE for 0x2449). The DLL emits these 36
    //    group-0 lines LAST, after the 1a8/1a4/model-marker lines (verified byte-exact vs the DLL's
    //    `0x30` line-header order). Each carries its own `flags = (4*d)|0x85000000`; absent when there
    //    is no measured dark frame (weak-signal fallback → the 6-base-line output).
    // EXPERIMENT (SYNA_NO_DELTA=1): skip the 0x85 0x30 calib-delta lines half of the fold — bisecting
    // whether the reset is those calibration-RAM writes or the 0x34 key-line.
    let skip_delta = std::env::var_os("SYNA_NO_DELTA").is_some();
    if p19c.is_none() && !skip_delta {
        if let Some((cd, line_width, lpc)) = calib_data {
            // Older family: raw persisted calib_data copy (already scaled at calibration time).
            lines.extend(calib_data_lines(cd, line_width, lpc));
        } else if let Some(frame) = step6_dark {
            // 0x2449 path: fold the live step-6 dark.
            lines.extend(calib_delta_lines_prod33(frame, scanlines, scale_num, scale_den));
        }
    }

    lines
}

pub(crate) fn pad4(n: usize) -> usize {
    n.div_ceil(4) * 4
}

/// The `calib_data` row used as the `0x34` timeslot-table **key line** (python-validity
/// `key_calibration_line`, `sensor.py:231`). The older type-1 family (`0x0199` etc.) fills the
/// leading `line_width` bytes of the `0x34` chunk from this persisted-calibration row; `0x2449` folds
/// a live step-6 dark instead (returns `None`). Value `0x38` matches [`super::fingerdet_cal_offset`]
/// for these subtypes.
pub fn key_calibration_line(subtype: u16) -> Option<usize> {
    match subtype {
        0xed | 0x1ff5 | 0xb5 | 0x1055 | 0x196 | 0x199 | 0x581 => Some(0x38),
        _ => None,
    }
}

/// The `0x34` timeslot-table **key line** from persisted `calib_data` — python-validity
/// `get_key_line` (`sensor.py:400`): row `key_line` of the per-line calibration data, sliced to
/// `line_width`, with the vendor `i == 5 → 4` tweak (5 collides with a timeslot-program opcode). All
/// zeros when `calib_data` is empty (matches pv's uncalibrated branch).
pub fn calib_data_key_line(
    calib_data: &[u8],
    lines_per_calibration_data: usize,
    line_width: usize,
    key_line: usize,
) -> Vec<u8> {
    if calib_data.is_empty() || lines_per_calibration_data == 0 {
        return vec![0u8; line_width];
    }
    let bpcl = calib_data.len() / lines_per_calibration_data;
    let off = 8 + bpcl * key_line;
    let mut kl = calib_data
        .get(off..off + line_width)
        .map(<[u8]>::to_vec)
        .unwrap_or_else(|| vec![0u8; line_width]);
    for b in kl.iter_mut() {
        if *b == 5 {
            *b = 4;
        }
    }
    kl
}

/// Serialize a product-0x33 line list into the wire chunks (ghidra:
/// `syna_serialize_line_update`@0x1800a6080, transcribed field-for-field). Splits lines by
/// `group = (flags >> 0x14) & 0xf`: `group < 2` lines go in the **0x30** "Line Update" chunk
/// (`[mask,flags]` headers + their data, each entry 4-byte-padded); `group >= 2` lines go in the
/// **0x43** "Line Update Transform" chunk (`[v0,v1,v2:u16]` + unpadded data).
///
/// `interleave` is the "Line Update InterLeave" value (**0x44** chunk, `[u32]`); it's only
/// emitted when non-zero, mirroring the DLL's `if (param_3 != 0)`. In the DLL this comes from
/// `ctx+0x294 - 1`, opaque per-session runtime state we cannot resolve statically.
/// TODO(verify-live): confirm what value (if any) is actually needed here; `0` (omit) is the
/// conservative default used by [`crate::capture_prog::CaptureConfig::upload_cmd_prod33`].
/// Runtime-calibration lines appended to a capture line-update once `calib_data` exists
/// (python-validity `line_update_type_1`, `sensor.py:480-492`): one [`Line`] per 4-byte column of
/// the per-line calibration data, each gathering `lines_per_calibration_data` 4-byte slices. The
/// flags (`i | 0x85<<24`) put these in group 0 → the `0x30` chunk.
///
/// python-validity hardcodes `112` for both loop bounds (it is *both* `line_width` and
/// `lines_per_calibration_data` for its only supported type `0x199`); we parametrize by the real
/// geometry. ⚠️ For 0x2449 this is a BEST-EFFORT port — the vendor prod33 path bitpacks a calib
/// *diff* (`syna_build_line_update_prod23`, uses `syna_bitpack_calib_diff@0x180095d40`) rather than
/// this raw insertion, so this needs live validation (and may need replacing with the bitpacked
/// form). `None`-equivalent (empty vec) when there is no `calib_data`.
pub fn calib_data_lines(
    calib_data: &[u8],
    line_width: usize,
    lines_per_calibration_data: usize,
) -> Vec<Line> {
    let mut lines = Vec::new();
    if calib_data.is_empty() || lines_per_calibration_data == 0 {
        return lines;
    }
    let bytes_per_calibration_line = calib_data.len() / lines_per_calibration_data;
    let mut i = 0usize;
    while i < line_width {
        let mut data = Vec::with_capacity(lines_per_calibration_data * 4);
        for j in 0..lines_per_calibration_data {
            let p = 8 + j * bytes_per_calibration_line + i;
            match calib_data.get(p..p + 4) {
                Some(s) => data.extend_from_slice(s),
                None => data.extend_from_slice(&[0u8; 4]),
            }
        }
        lines.push(Line {
            mask: 0xffff_ffff,
            flags: (i as u32) | (0x85 << 24),
            v0: 0,
            v1: 0,
            v2: 0,
            data,
        });
        i += 4;
    }
    lines
}

pub fn serialize_line_update(lines: &[Line], interleave: u32) -> Vec<u8> {
    let mut out = Vec::new();
    if interleave != 0 {
        out.extend_from_slice(&ChunkType::Interleave.id().to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&interleave.to_le_bytes());
    }

    let group = |f: u32| (f >> 0x14) & 0xf;
    let (lo, hi): (Vec<&Line>, Vec<&Line>) = lines.iter().partition(|l| group(l.flags) < 2);

    let lo_data_len: usize = lo.iter().map(|l| pad4(l.data.len())).sum();
    let len30 = 4 + lines.len() * 8 + lo_data_len;
    out.extend_from_slice(&ChunkType::LineUpdate.id().to_le_bytes());
    out.extend_from_slice(&(len30 as u16).to_le_bytes());
    out.extend_from_slice(&(lines.len() as u32).to_le_bytes());
    for l in lines {
        out.extend_from_slice(&l.mask.to_le_bytes());
        out.extend_from_slice(&l.flags.to_le_bytes());
    }
    for l in &lo {
        out.extend_from_slice(&l.data);
        out.extend(std::iter::repeat_n(0u8, pad4(l.data.len()) - l.data.len()));
    }

    if !hi.is_empty() {
        // The 0x43 chunk writes each group≥2 line raw (`[v0][v1][v2][data]`, NOT 4-padded per line —
        // `syna_serialize_line_update@0x1800a6080`), then pads the WHOLE data region ONCE:
        // `len = count*4 + round4(Σ data)`. For 0x2449 Σ = 56+35+35 = 126 → round4 = 128 ⇒ 2 trailing
        // pad bytes after the last line (per-line padding would shift DAT-B and corrupt the interior).
        let raw_data: usize = hi.iter().map(|l| l.data.len()).sum();
        let padded_data = pad4(raw_data);
        let hi_len = 4 * hi.len() + padded_data;
        out.extend_from_slice(&ChunkType::LineUpdateTransform.id().to_le_bytes());
        out.extend_from_slice(&(hi_len as u16).to_le_bytes());
        for l in &hi {
            out.push(l.v0);
            out.push(l.v1);
            out.extend_from_slice(&l.v2.to_le_bytes());
            out.extend_from_slice(&l.data);
        }
        out.extend(std::iter::repeat_n(0u8, padded_data - raw_data));
    }

    out
}
