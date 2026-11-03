//! Flex `0x2e` "Image Reconstruction" chunk builders + the finger-detect (`0x15` / `0x230`) chunks —
//! per-subtype `Flex2eParams` and the wire-buffer assembly for the capture command. Extracted from
//! the `line_update` module (uses its `Mode` + `RECON_*` / `CAPTURE_*` flag constants via `super`);
//! re-exported by `mod.rs` so `line_update::{chunk_2e, Flex2eParams, …}` paths are unchanged.

use super::*;
/// Product-0x33 "Image Reconstruction" (`0x2e`) chunk fields not carried by
/// [`crate::capture_progs_9b::SensorTypeInfo`] (ghidra: `g_flex_params_table`@0x18013aaf0, 0xa8-byte
/// records; `0x2449` is record index 41 / byte offset `0x1ae8`). Field offsets are relative to the
/// per-subtype flex-params record; `recon_cfg` is the 3×u16 prefix of the table pointed to by the
/// record's `+0x78` field.
#[derive(Debug, Clone, Copy)]
pub struct Flex2eParams {
    /// flex `+0x32` (== `SensorTypeInfo::line_width` — kept separately here so this struct is
    /// self-contained).
    pub line_width: u16,
    /// flex `+0x12` (calibration-blob size; equals `SensorTypeInfo::lines_per_calibration_data`).
    pub calib_size: u16,
    /// flex `+0xe`.
    pub flex_e: u16,
    /// flex `+0x9c`.
    pub flex_9c: u16,
    /// flex `+0x14` (low byte only is used).
    pub flex_14: u16,
    /// flex `+0x16` — the alternate source for reconstruction field 0 when the `0x2e` flags word has
    /// bit `RECON_FLAG_ALT_FIELD0` set (ghidra: `syna_recon_substruct_build`@0x1800ae110's
    /// `(flex != 0 && alt_field0 != 0)` branch, `*param_1 = *(flex + 0x16)`). Read live from
    /// `g_flex_params_table` record `0x2449`.
    pub flex_16: u16,
    /// `*(flex+0x78)` dereferenced: `[recon_cfg0, recon_cfg1, recon_cfg2]`. `recon_cfg[0]` is field 0
    /// only when the alt-field-0 flag is CLEAR.
    pub recon_cfg: [u16; 3],
}

/// Bits of the **capture-flags** word — `param_5` of `syna_build_capture_cmd02`@0x180086110, the
/// `local_84` word assembled in `syna_capture_identify_enroll`@0x180053400, and the literal `0xa0030`
/// in `syna_capture_image`@0x180099540. Each bit gates a chunk or behaviour in the `0x02` program
/// builder. Ghidra enum `syna_capture_flags_t`. (All bits verified from the builder's `param_5 & X`
/// tests; `RECON_DOWNSTREAM` is the one bit the builder does not itself decode.)
pub mod capture_flag {
    /// `0x4` — emit the `FUN_180092710` processing chunk.
    pub const EMIT_PROC_CHUNK: u32 = 0x4;
    /// `0x10` — emit an empty `0x17` ReplyConfig chunk (`syna_append_empty_chunk`).
    pub const EMIT_REPLY_CONFIG: u32 = 0x10;
    /// `0x20` — **not** decoded by the cmd02 builder; `param_5` is stored at descriptor+4 and this
    /// bit is consumed by the frame-read / reconstruction path (`syna_capture_recon_setup`).
    pub const RECON_DOWNSTREAM: u32 = 0x20;
    /// `0x800` — force the static-calib-data fold decision on (`local_c0 = 1`).
    pub const FORCE_CALIB_FOLD: u32 = 0x800;
    /// `0x10000` — reconstruction MODE 4 (enroll): `local_c8 |= 4`. Set for request mode 3.
    pub const RECON_MODE4_ENROLL: u32 = 0x10000;
    /// `0x20000` — **SKIP** the finger-detect (`0x26`/`0x4e`) chunk (`FUN_180094420` is emitted only
    /// when this bit is CLEAR). Set ⇒ polled / no-WOE imaging.
    pub const SKIP_FINGER_DETECT: u32 = 0x20000;
    /// `0x40000` — emit the extra processing chunks (`FUN_180094e30` + conditional siblings).
    pub const EXTRA_PROC: u32 = 0x40000;
    /// `0x80000` — reconstruction MODE 8 (provisioned polled-imaging; alt field-0 = `flex[0x16]`):
    /// `local_c8 |= 8`. Set **only** by `syna_capture_image`.
    pub const RECON_MODE8_IMAGE: u32 = 0x80000;
    /// `0x100000` — peripheral reconstruction bit → `local_c8 |= 0x10` (error if set with `0x200000`).
    pub const RECON_PERIPH10: u32 = 0x100000;
    /// `0x200000` — peripheral reconstruction bit → `local_c8 |= 0x20`.
    pub const RECON_PERIPH20: u32 = 0x200000;
    /// `0x400000` — extra processing chunk B (`FUN_180094fb0`, within [`EXTRA_PROC`]).
    pub const EXTRA_PROC_B: u32 = 0x400000;
    /// `0x800000` — extra processing chunk C (`FUN_1800954f0`, within [`EXTRA_PROC`]).
    pub const EXTRA_PROC_C: u32 = 0x800000;
    /// `0x1000000` — peripheral reconstruction bit → `local_c8 |= 0x40`.
    pub const RECON_PERIPH40: u32 = 0x1000000;
    /// `0x2000000` — peripheral reconstruction bit → `local_c8 |= 0x80`.
    pub const RECON_PERIPH80: u32 = 0x2000000;
}

/// The `syna_capture_image`@0x180099540 provisioned-polled-imaging capture-flags word (`0xa0030`).
/// = ReplyConfig chunk + the downstream-recon bit + skip-finger-detect + recon-mode-8. This is the
/// only DLL call site that sets [`capture_flag::RECON_MODE8_IMAGE`]. Renamed from the earlier
/// opaque literal; see [`CAPTURE_FLAGS_IDENTIFY`] / [`CAPTURE_FLAGS_ENROLL`] for the other arms.
pub const CAPTURE_FLAGS_IMAGE: u32 = capture_flag::EMIT_REPLY_CONFIG
    | capture_flag::RECON_DOWNSTREAM
    | capture_flag::SKIP_FINGER_DETECT
    | capture_flag::RECON_MODE8_IMAGE;

/// The `syna_capture_identify_enroll` base capture-flags (`local_84 | 0xc0b0`) for a **verify/identify**
/// request (request mode 2, DLL capture-type 4). Neither `0x10000` nor `0x80000` ⇒ recon MODE 2.
pub const CAPTURE_FLAGS_IDENTIFY: u32 = 0xc0b0 | 0x840;

/// The `syna_capture_identify_enroll` base capture-flags for an **enroll** request (request mode 3,
/// DLL capture-type 6). Adds [`capture_flag::RECON_MODE4_ENROLL`] ⇒ recon MODE 4.
pub const CAPTURE_FLAGS_ENROLL: u32 = 0xc0b0 | capture_flag::RECON_MODE4_ENROLL;

/// Bits of the **`0x2e` reconstruction-flags** word — `local_c8` in `syna_build_capture_cmd02`,
/// passed to `syna_append_chunk_2e_image_recon` as `param_4` and written verbatim into the chunk
/// (`*local_68 = param_4`) so the on-chip reconstructor reads the whole word. Ghidra enum
/// `syna_recon_flags_t`. The low bits `{2,4,8}` are a **mutually-exclusive MODE select**; the only
/// DLL-visible difference between the modes is reconstruction field-0's source (see
/// [`RECON_FLAG_ALT_FIELD0`]) — we deliberately do NOT label the on-chip algorithm (unobservable
/// from the DLL; AGENTS.md Rule #7).
/// The `0x2e`-chunk recon-flags word is assembled verbatim in `syna_build_capture_cmd02@0x180086110`
/// and tunnelled into the sensor firmware — the host reads back **only** bit `0x8`
/// ([`MODE_ALT_FIELD0`]). The word is `mode | transform2d | peripheral`, where the mode nibble and the
/// peripheral pair are selected by the WinBio **operation** (via `session->dwSession_flags` +
/// `session->field_0x14`, set host-side from the WinBio purpose byte — enroll `0x04` vs identify
/// `0x02`), NOT by the subtype/flex table. See the plate on
/// `syna_capture_identify_enroll@0x180053400` for the full session-flags decode.
pub mod recon_flag {
    /// `0x1` — 2D transform. `session->field_0x14` → `syna_build_capture_cmd02`'s `param_6 == 1`.
    /// Set for the **enroll** capture (WinBio purpose byte `& 0x1c != 0`), clear for identify/verify.
    pub const TRANSFORM2D: u32 = 1;
    /// `0x2` — DEFAULT reconstruction mode (identify/verify, AND host-match enroll). Field-0 =
    /// `recon_cfg[0]`. Selected when neither capture-flag `0x10000` nor `0x80000` is set — which is
    /// **always** on the read_mode-2 (host-match EOH/MOH) path our SKU takes.
    pub const MODE_DEFAULT: u32 = 2;
    /// `0x4` — **match-on-chip (MOC) enroll** mode (capture-flag `0x10000`, `RECON_MODE4_ENROLL`).
    /// Reached only on the **read_mode-3 (capture_type 6)** MOC storage class — NOT on our host-match
    /// read_mode-2 SKU, where enroll uses [`MODE_DEFAULT`] + [`PERIPH_ENROLL`] instead (see
    /// [`crate::line_update::RECON_FLAGS_ENROLL`]). Renamed from the misleading `MODE_ENROLL`.
    pub const MODE_MOC_ENROLL: u32 = 4;
    /// `0x8` — ALT-FIELD0 reconstruction: the provisioned-polled-imaging arm (`syna_capture_image`,
    /// capture-flag `0x80000`). Field-0 = `flex[0x16]`. Alias [`crate::line_update::RECON_FLAG_ALT_FIELD0`].
    /// The one recon bit the host itself reads (`syna_append_chunk_2e_image_recon` `param_4 & 8`).
    pub const MODE_ALT_FIELD0: u32 = 8;
    /// `0x10` — sensor "peripheral recon mode" for the **finger-lift** capture
    /// (`syna_wbdi_force_finger_up@0x18001c5ec` sets `dwSession_flags=8` → capture-flag `0x100000`).
    /// Mutually exclusive with [`PERIPH_ENROLL`] (`syna_build_capture_cmd02` errors `0x6f` if both set).
    /// Renamed from `PERIPH_10`.
    pub const PERIPH_FINGER_UP: u32 = 0x10;
    /// `0x20` — sensor "peripheral recon mode" for the **enroll** capture (host-match). Set via
    /// `dwSession_flags` bit 2 → capture-flag `0x200000`. Sensor-tunnelled (the host never inspects it;
    /// firmware-facing meaning is unknown — Rule #7). Renamed from `PERIPH_20`.
    pub const PERIPH_ENROLL: u32 = 0x20;
    /// `0x40`/`0x80` — further peripheral recon bits (capture-flags `0x1000000`/`0x2000000`).
    /// `PERIPH_80` is additionally set when `flex[0x9a] == 1` (subtype-gated); neither fires on 0x2449.
    pub const PERIPH_40: u32 = 0x40;
    pub const PERIPH_80: u32 = 0x80;
}

/// `0x2e`-chunk recon-flags bit that swaps reconstruction field 0 from `recon_cfg[0]` (400 on
/// `0x2449`) to `flex[0x16]` (150) — i.e. the mode-8 selector. Ghidra: `syna_append_chunk_2e_image_recon`
/// tests `param_4 & 8` → sets `local_4c = 1` → `syna_recon_substruct_build`@0x1800ae110's
/// `(flex != 0 && local_4c != 0)` branch writes `*param_1 = *(flex + 0x16)`. Set by
/// `syna_build_capture_cmd02` when capture-flag [`capture_flag::RECON_MODE8_IMAGE`] is set and
/// [`capture_flag::RECON_MODE4_ENROLL`] is clear. Alias of [`recon_flag::MODE_ALT_FIELD0`].
pub const RECON_FLAG_ALT_FIELD0: u32 = recon_flag::MODE_ALT_FIELD0;

/// The `0x2e` recon-flags word for the **provisioned polled-imaging** capture (`syna_capture_image`
/// path, [`CAPTURE_FLAGS_IMAGE`] = `0xa0030`). `= 8` ([`recon_flag::MODE_ALT_FIELD0`]) ⇒ field-0 =
/// `flex[0x16]` = 150. VERIFIED against the DLL (`syna_recon_substruct_build`): 150 is correct for
/// this arm — this is NOT the identify arm (which is [`RECON_FLAGS_DEFAULT`]). Renamed from the
/// earlier misnomer `RECON_FLAGS_IDENTIFY`.
///
/// NB the imaging arm that uses this must ALSO omit the finger-detect (`0x26`) chunk
/// ([`CAPTURE_FLAGS_IMAGE`] sets [`capture_flag::SKIP_FINGER_DETECT`], which gates it off) — else the
/// sensor rejects the arm (status 0x0537).
pub const RECON_FLAGS_IMAGE: u32 = recon_flag::MODE_ALT_FIELD0;

/// The `0x2e` recon-flags "default branch" (`= 2`, [`recon_flag::MODE_DEFAULT`]): the identify/verify
/// arm (`0x80000` and `0x10000` both clear). Field-0 = `recon_cfg[0]` = 400. Used by the
/// finger-detect / interrupt-style arm, which empirically the sensor accepts alongside the `0x26`
/// chunk.
pub const RECON_FLAGS_DEFAULT: u32 = recon_flag::MODE_DEFAULT;

/// The `0x2e` recon-flags for the **enroll** capture on our **host-match (read_mode-2) SKU**:
/// `MODE_DEFAULT | TRANSFORM2D | PERIPH_ENROLL` = `0x23`. Field-0 = `recon_cfg[0]` = 400 (bit `0x8`
/// clear). **VERIFIED byte-exact** vs the DLL enroll arm across a full 13-sample enrollment (all
/// samples identical; `resolve_arm` reproduces it modulo `0x48` — see
/// `tests/dll_arm_parity.rs::enroll_arm_is_identify_with_recon_0x23_vs_dll`).
///
/// This is NOT [`recon_flag::MODE_MOC_ENROLL`] (`= 4`): that MOC mode bit is only set via capture-flag
/// `0x10000` on the read_mode-3 storage class, which our SKU never takes. On read_mode-2 the enroll
/// capture is the identify arm (default mode) plus the enroll operation's `TRANSFORM2D` + `PERIPH_ENROLL`
/// recon bits (both host-selected from the WinBio purpose byte). Family note (Rule #6): this holds for
/// any read_mode-2 sibling; a subtype with `flex[0x9a] == 1` would additionally OR in
/// [`recon_flag::PERIPH_80`] (0x2449 does not).
pub const RECON_FLAGS_ENROLL: u32 =
    recon_flag::MODE_DEFAULT | recon_flag::TRANSFORM2D | recon_flag::PERIPH_ENROLL;

/// Flex-params values for subtype `0x2449`, read live from `synaWudfBioUsb.dll` (record index 41
/// of `g_flex_params_table`, and its `+0x78` pointee) rather than re-running the table extractor.
pub const FLEX_2E_2449: Flex2eParams = Flex2eParams {
    line_width: 144,
    calib_size: 56,
    flex_e: 0x14d,
    flex_9c: 0,
    flex_14: 2,
    flex_16: 150,
    recon_cfg: [400, 380, 25650],
};

impl Flex2eParams {
    /// Build the `0x2e` reconstruction params for any subtype from the extracted
    /// [`crate::flex_params`] table (the DLL's `g_flex_params_table`) — the generic, family-wide
    /// path. `None` if the subtype isn't in the table.
    pub fn for_subtype(subtype: u16) -> Option<Flex2eParams> {
        let f = crate::flex_params::flex_params(subtype)?;
        Some(Flex2eParams {
            line_width: f.line_width,
            calib_size: f.calib_size,
            flex_e: f.flex_e,
            flex_9c: f.flex_9c,
            flex_14: f.flex_14,
            flex_16: f.flex_16,
            recon_cfg: f.recon_cfg,
        })
    }
}

/// Build the `0x2e` "Image Reconstruction" chunk (ghidra: `syna_append_chunk_2e_image_recon`
/// @0x180094990's `mode != 1` branch, feeding `syna_recon_substruct_build`@0x1800ae110's 14-byte
/// sub-struct into it — both transcribed field offset-by-offset). `mode` is `2` for our sensor (it
/// has a `0x2f` "2D" chunk); `mode == 1` uses a wholly different hardcoded payload and is not
/// implemented here.
///
/// `flags` is the chunk-level recon-flags word (`local_c8` in `syna_build_capture_cmd02`, derived
/// from the capture-flags via bit tests; see the [`recon_flag`] module). For the provisioned
/// polled-imaging path use [`RECON_FLAGS_IMAGE`] (`8`, field-0 = `flex[0x16]` = 150); the
/// identify/verify arm is [`RECON_FLAGS_DEFAULT`] (`2`, field-0 = `recon_cfg[0]` = 400); enroll is
/// [`RECON_FLAGS_ENROLL`] (`0x23`, also 400 — the `0x8` alt-field-0 bit is clear). Only reconstruction
/// field 0 depends on this (see [`RECON_FLAG_ALT_FIELD0`]); all other fields are flag-independent.
pub fn chunk_2e(p: &Flex2eParams, mode: u16, flags: u32) -> Vec<u8> {
    let local_7a: u16 = if mode == 2 { 0x18 } else { 0x14 };
    let mut data = Vec::with_capacity(28);
    data.extend_from_slice(&mode.to_le_bytes());
    data.extend_from_slice(&local_7a.to_le_bytes());
    data.extend_from_slice(&flags.to_le_bytes());
    data.extend_from_slice(&p.line_width.to_le_bytes());
    data.extend_from_slice(&p.calib_size.to_le_bytes());
    data.extend_from_slice(&p.flex_e.to_le_bytes());
    data.extend_from_slice(&p.flex_9c.to_le_bytes());
    // Reconstruction field 0 (`local_28` / `syna_recon_substruct_build`'s `*param_1`): sourced from
    // `flex[0x16]` (150) when the alt-field-0 flag (recon-flags bit 8) is set — the provisioned
    // polled-imaging path — else `recon_cfg[0]` (400). Verified against the DLL @0x1800ae110.
    let field0 = if flags & RECON_FLAG_ALT_FIELD0 != 0 {
        p.flex_16
    } else {
        p.recon_cfg[0]
    };
    data.extend_from_slice(&field0.to_le_bytes());
    data.extend_from_slice(&p.recon_cfg[1].to_le_bytes());
    data.push(0x3c);
    data.push(0x32);
    data.push(0x32);
    data.push((p.recon_cfg[2] & 0xff) as u8);
    data.push(((p.recon_cfg[2] >> 8) & 0xff) as u8);
    data.push(0x0a);
    data.push(0x02);
    data.push((p.flex_14 & 0xff) as u8);
    debug_assert_eq!(data.len(), 28);

    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&0x2eu16.to_le_bytes());
    out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    out.extend_from_slice(&data);
    out
}

/// The `0x15` "BW Reduction" chunk (ghidra: `syna_append_chunk_15_bwreduction`@0x1800924f0 +
/// `FUN_1800968f0` — the payload is a fixed `[0, 0x2820]` pair regardless of the caller's
/// `param_3`, so this is unconditionally the same 12 bytes for every call site we've seen).
pub fn chunk_15() -> [u8; 12] {
    [
        0x15, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x28, 0x00, 0x00,
    ]
}

/// The `0x48` **finger-detect baseline reference frame** chunk (see [`super::ChunkType::Baseline`]).
/// Emitted by the DLL as `syna_append_chunk_48_last_frame@0x180095ae0` for the read_mode-2 /
/// capture-type-4 Hello identify path (provisioned): `[0x48][len][width:u16][height:u16] ‖ frame`,
/// giving the sensor a baseline to subtract. NOT the step-6 dark frame and NOT the enrolled template.
///
/// This fn produces the correct **FRAMING**: the DLL's `0x48` is the **odd line-number field**
/// (headers `01 fe {1,3,5,…} 02 …`, 56 of 113 lines); it extracts that (even-index source lines = odd
/// line numbers; field byte→`0x02`). Verified header-exact vs the live DLL arm (chunk `0x48`, 152 × 56
/// → 8516 B) and pinned by `chunk_baseline_framing_matches_dll_0x48`. The emitter is
/// `syna_append_chunk_48_last_frame@0x180095ae0` — a verbatim `[0x48][len=w*h+4][w][h][w*h frame]`
/// wrapping `pLast_frame_buf`; that buffer is filled by a plain `memmove` (no conditioning on the
/// 0x2449 path) in `syna_capture_store_last_frame@0x1800ad800`. So the DLL captures its 56 odd-numbered
/// lines DIRECTLY (the arm's line-update requests them) and copies them verbatim — our 113→56
/// even-index decimation is a *workaround* for our settle capturing 113 progressive lines, not the
/// DLL's own step. Output format is identical either way; the CONTENT differs (see below).
///
/// CONTENT CAVEAT (RE cross-check 2026-07-24, see `docs/capture/last-frame-baseline.md`): `raw_frame`
/// is our **stream step-7 settle** (raw/scrambled, std ~24.7). The DLL's real `pLast_frame_buf` is a
/// **recon=8 firmware-reconstructed FLAT frame** (std ~1.8), stored verbatim. So the pixel CONTENT here
/// is the wrong pipeline stage — the framing matches but the frame is inert as a finger-detect baseline
/// (device 2026-07-24: no `0x51` frame, no touch). Correct source is a recon=8 imaging capture, blocked
/// pending the `capture_flags 0xa0030` plumbing.
pub fn chunk_baseline(raw_frame: &[u8], stride: u16) -> Vec<u8> {
    const HDR: usize = crate::capture_prog::SYNC_LINE_HEADER; // 8-byte per-line wire header
    let stride = stride as usize;
    let line_width = stride.saturating_sub(HDR); // 144 for 0x2449
    let total = raw_frame.len() / stride.max(1);
    // The DLL's `0x48` is the **odd line-number field** of the dark capture (headers
    // `01 fe {1,3,5,…} 02 f0 f7 01 00`), which is our EVEN-index lines (our line number = index+1),
    // exactly `total/2` lines (113 progressive → 56). Stamp the field byte `0x02` to match the DLL.
    let max_lines = (total / 2) as u16;
    let mut frame = Vec::with_capacity(max_lines as usize * stride);
    let mut idx = 0usize;
    let mut out = 0u16;
    while idx < total && out < max_lines {
        let base = idx * stride;
        // Copy the line's 8-byte header verbatim, then force byte[3] (field/frame) = 0x02.
        let mut hdr = [0u8; HDR];
        hdr.copy_from_slice(&raw_frame[base..base + HDR]);
        hdr[3] = 0x02;
        frame.extend_from_slice(&hdr);
        frame.extend_from_slice(&raw_frame[base + HDR..base + HDR + line_width]);
        idx += 2; // even-index lines = odd line numbers (the DLL's field)
        out += 1;
    }
    let payload_len = 4 + frame.len();
    let mut c = Vec::with_capacity(4 + payload_len);
    c.extend_from_slice(&0x0048u16.to_le_bytes()); // ChunkType::Baseline
    c.extend_from_slice(&(payload_len as u16).to_le_bytes());
    c.extend_from_slice(&(stride as u16).to_le_bytes()); // width = wire stride (152)
    c.extend_from_slice(&out.to_le_bytes()); // height = emitted line count
    c.extend_from_slice(&frame);
    c
}

/// The **finger-detect** config chunk. This is the chunk that arms the sensor's WOE ("wait on
/// event") finger-detect path so it raises an **EP-`0x83` interrupt** on a touch instead of imaging
/// immediately. The vendor emits it only in *identify/enroll* mode (ghidra: `FUN_180094420`, gated on
/// `(flags & 0x20000) == 0`); the synchronous frame-dump path (`syna_capture_image`, flags `0xa0030`)
/// omits it. Content is `FUN_180096a90`@0x180096a90.
///
/// The chunk **type and timeouts depend on the mode** (ghidra: `FUN_180094420` emits `0x4e` when
/// `flags & 0x4000000` is set, else `0x26`; that same bit is `FUN_180096a90`'s `param_6`):
/// - `Mode::Identify` → type `0x4e` ("WTF"), short timeouts (10000/6000) — completes a single scan.
/// - `Mode::Enroll` → type `0x26` ("Finger Detect"), long timeouts (50000/60000) — multi-frame.
///
/// `g230`/`g234`/`g238` are the live session-context fields `ctx+0x230`/`ctx+0x234`/`ctx+0x238`
/// that `FUN_180096a90`@0x180096a90 reads to compute the finger-detect threshold
/// `ivar1 = (100 - g238)*(g234 - g230)/100 + g230`. On our sensor `open`
/// (`syna_open_init_decide_format`@0x18006f400, step 12) copies `ctx+0x230 = flex[0x18]` and
/// `ctx+0x234 = flex[0x1a]` from the flex-params record; `ctx+0x238` is **not** touched by `open`
/// and stays at the ctx-allocator default `100` (`FUN_1800843f0`@0x1800843f0 sets `ctx+0x238 = 100`,
/// and `FUN_180065aa0` only ever caps it to `min(requested_sensitivity, 100)`), so `g238 = 100` —
/// **not** `0` — is the vendor's effective default. `g238 = 100` makes the `(g234 - g230)` term
/// vanish and pins the threshold at the more-sensitive `ivar1 = g230`.
pub fn chunk_finger_detect(g230: u32, g234: u32, g238: u32, mode: Mode) -> Vec<u8> {
    chunk_finger_detect_timed(g230, g234, g238, mode, FDET_IDENTIFY_TIMEOUTS_2449)
}

/// Identify-mode finger-detect scan timeouts `(d[0x20], d[0x22])`, in the sensor's tick unit.
/// **Family-specific:** the 0x2449 DLL emits `(10000, 6000)`; the older type-1 family (0x0199,
/// python-validity `line_update_type_1`) hard-codes `(5000, 3000)` in its identify `0x4e` blob
/// (`fbb2…8813b80b…`). Enroll uses `(50000, 60000)` on both families, so only identify diverges.
pub const FDET_IDENTIFY_TIMEOUTS_2449: (u16, u16) = (10000, 6000);
/// Older type-1 family (0x0199) identify finger-detect timeouts — see [`FDET_IDENTIFY_TIMEOUTS_2449`].
pub const FDET_IDENTIFY_TIMEOUTS_TYPE1: (u16, u16) = (5000, 3000);
/// Enroll-mode finger-detect scan timeouts (both families).
pub const FDET_ENROLL_TIMEOUTS: (u16, u16) = (50000, 60000);

/// [`chunk_finger_detect`] with an explicit identify-timeout pair so the older type-1 family can
/// supply its own `(5000, 3000)` while 0x2449 keeps `(10000, 6000)`.
pub fn chunk_finger_detect_timed(
    g230: u32,
    g234: u32,
    g238: u32,
    mode: Mode,
    identify_timeouts: (u16, u16),
) -> Vec<u8> {
    let identify = mode == Mode::Identify;
    let (to0, to1) = if identify { identify_timeouts } else { FDET_ENROLL_TIMEOUTS };
    let ivar1 = (100 - g238 as i32) * (g234 as i32 - g230 as i32) / 100 + g230 as i32;
    let mut d = [0u8; 40];
    let put16 = |d: &mut [u8], o: usize, v: u16| d[o..o + 2].copy_from_slice(&v.to_le_bytes());
    let put32 = |d: &mut [u8], o: usize, v: u32| d[o..o + 4].copy_from_slice(&v.to_le_bytes());
    put16(&mut d, 0x00, 0xb2fb);
    d[0x02] = 0x0f;
    d[0x06] = 0x0f;
    put16(&mut d, 0x04, 0); // param_2[2] = 0 (the non-calibrate branch)
    put32(&mut d, 0x08, 0x30);
    put32(&mut d, 0x0c, (ivar1 + 0x20000) as u32); // param_2[6]
    put32(&mut d, 0x10, (ivar1 + 0x9ffe0) as u32); // param_2[8]
    put32(&mut d, 0x14, 0x8001);
    put32(&mut d, 0x18, 0x20a);
    put32(&mut d, 0x1c, 0x190b);
    put16(&mut d, 0x20, to0);
    put16(&mut d, 0x22, to1);
    d[0x24] = 1;
    d[0x25] = 9;
    d[0x26] = 0x10;
    let typ = if identify {
        ChunkType::Wtf
    } else {
        ChunkType::FingerDetect
    };
    let mut out = Vec::with_capacity(44);
    out.extend_from_slice(&typ.id().to_le_bytes());
    out.extend_from_slice(&(d.len() as u16).to_le_bytes());
    out.extend_from_slice(&d);
    out
}

/// Finger-detect chunk for subtype `0x2449`.
///
/// `ctx+0x230 = flex[0x18] = 160`, `ctx+0x234 = flex[0x1a] = 260` (copied from the flex-params
/// record by `open`), and `ctx+0x238 = 100` (the ctx-allocator default that `open` leaves in place —
/// see [`chunk_finger_detect`]). With `g238 = 100` the interpolation collapses to the more-sensitive
/// threshold base `ivar1 = g230 = 160`.
///
/// This corrects the earlier `g238 = 0` (→ `ivar1 = 260`, the *least*-sensitive endpoint), which
/// raised the finger-down threshold so high that a touch often failed to cross it — the intermittent
/// "type-2 never fires" symptom. If finger detection is still unreliable live, sweep `g238` upward
/// toward `100` is already the max; to go *more* sensitive would require a firmware/flex change, so
/// tuning room here is `g238 ∈ {100 (=160), 50 (=210), 0 (=260, old)}` — lower `ivar1` = more
/// sensitive.
pub fn chunk_finger_detect_2449(mode: Mode) -> Vec<u8> {
    chunk_finger_detect(160, 260, 100, mode)
}

/// Finger-detect chunk for **any** subtype, data-driven from the extracted flex table
/// (`ctx+0x230 = flex[0x18]`, `ctx+0x234 = flex[0x1a]`, `ctx+0x238 = 100` allocator default).
/// Falls back to the `0x2449` values if the subtype isn't in the table.
pub fn chunk_finger_detect_for_subtype(subtype: u16, mode: Mode) -> Vec<u8> {
    // Older type-1 family (0x0199, python-validity `line_update_type_1`) uses `(5000, 3000)` identify
    // timeouts; 0x2449 (and unknown subtypes) use the DLL's `(10000, 6000)`. Keyed off the same
    // older-family predicate as the rest of the type-1 arm (`key_calibration_line`).
    let ident_timeouts = if super::key_calibration_line(subtype).is_some() {
        FDET_IDENTIFY_TIMEOUTS_TYPE1
    } else {
        FDET_IDENTIFY_TIMEOUTS_2449
    };
    match crate::flex_params::flex_params(subtype) {
        Some(f) => {
            chunk_finger_detect_timed(f.flex_18 as u32, f.flex_1a as u32, 100, mode, ident_timeouts)
        }
        None => chunk_finger_detect_2449(mode),
    }
}

// ---------------------------------------------------------------------------
// Arm-lab typed codecs — decode/encode the small editable chunk payloads.
// Offsets match [`chunk_2e`] / [`chunk_finger_detect`] byte-for-byte.
// ---------------------------------------------------------------------------

/// Wire size of the `0x2e` ImageReconstruction payload (no type/len header).
pub const CHUNK_2E_PAYLOAD_LEN: usize = 28;

/// Byte offsets into the `0x2e` payload (`syna_append_chunk_2e_image_recon@0x180094990`).
pub mod chunk_2e_off {
    pub const MODE: usize = 0;
    pub const LOCAL_7A: usize = 2;
    pub const FLAGS: usize = 4;
    pub const LINE_WIDTH: usize = 8;
    pub const CALIB_SIZE: usize = 10;
    pub const FLEX_E: usize = 12;
    pub const FLEX_9C: usize = 14;
    pub const FIELD0: usize = 16;
    pub const RECON_CFG1: usize = 18;
    pub const FIXED_3C32: usize = 20; // three bytes `0x3c 0x32 0x32`
    pub const RECON_CFG2: usize = 23;
    pub const FIXED_0A02: usize = 25; // two bytes `0x0a 0x02`
    pub const FLEX_14_LO: usize = 27;
}

/// Editable fields of a decoded `0x2e` ImageReconstruction payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk2eFields {
    pub mode: u16,
    pub local_7a: u16,
    pub flags: u32,
    pub line_width: u16,
    pub calib_size: u16,
    pub flex_e: u16,
    pub flex_9c: u16,
    pub field0: u16,
    pub recon_cfg1: u16,
    pub recon_cfg2: u16,
    pub flex_14_lo: u8,
}

impl Chunk2eFields {
    /// Parse a 28-byte `0x2e` payload. Returns `None` if the length is wrong.
    pub fn parse(payload: &[u8]) -> Option<Self> {
        if payload.len() != CHUNK_2E_PAYLOAD_LEN {
            return None;
        }
        let u16le = |o: usize| u16::from_le_bytes([payload[o], payload[o + 1]]);
        let u32le = |o: usize| {
            u32::from_le_bytes([payload[o], payload[o + 1], payload[o + 2], payload[o + 3]])
        };
        Some(Self {
            mode: u16le(chunk_2e_off::MODE),
            local_7a: u16le(chunk_2e_off::LOCAL_7A),
            flags: u32le(chunk_2e_off::FLAGS),
            line_width: u16le(chunk_2e_off::LINE_WIDTH),
            calib_size: u16le(chunk_2e_off::CALIB_SIZE),
            flex_e: u16le(chunk_2e_off::FLEX_E),
            flex_9c: u16le(chunk_2e_off::FLEX_9C),
            field0: u16le(chunk_2e_off::FIELD0),
            recon_cfg1: u16le(chunk_2e_off::RECON_CFG1),
            recon_cfg2: u16le(chunk_2e_off::RECON_CFG2),
            flex_14_lo: payload[chunk_2e_off::FLEX_14_LO],
        })
    }

    /// Encode back to a 28-byte payload, preserving the fixed mid-payload literals from
    /// [`chunk_2e`] (`0x3c 0x32 0x32` / `0x0a 0x02`).
    pub fn encode(self) -> [u8; CHUNK_2E_PAYLOAD_LEN] {
        let mut data = [0u8; CHUNK_2E_PAYLOAD_LEN];
        let put16 = |d: &mut [u8], o: usize, v: u16| d[o..o + 2].copy_from_slice(&v.to_le_bytes());
        let put32 = |d: &mut [u8], o: usize, v: u32| d[o..o + 4].copy_from_slice(&v.to_le_bytes());
        put16(&mut data, chunk_2e_off::MODE, self.mode);
        put16(&mut data, chunk_2e_off::LOCAL_7A, self.local_7a);
        put32(&mut data, chunk_2e_off::FLAGS, self.flags);
        put16(&mut data, chunk_2e_off::LINE_WIDTH, self.line_width);
        put16(&mut data, chunk_2e_off::CALIB_SIZE, self.calib_size);
        put16(&mut data, chunk_2e_off::FLEX_E, self.flex_e);
        put16(&mut data, chunk_2e_off::FLEX_9C, self.flex_9c);
        put16(&mut data, chunk_2e_off::FIELD0, self.field0);
        put16(&mut data, chunk_2e_off::RECON_CFG1, self.recon_cfg1);
        data[chunk_2e_off::FIXED_3C32] = 0x3c;
        data[chunk_2e_off::FIXED_3C32 + 1] = 0x32;
        data[chunk_2e_off::FIXED_3C32 + 2] = 0x32;
        put16(&mut data, chunk_2e_off::RECON_CFG2, self.recon_cfg2);
        data[chunk_2e_off::FIXED_0A02] = 0x0a;
        data[chunk_2e_off::FIXED_0A02 + 1] = 0x02;
        data[chunk_2e_off::FLEX_14_LO] = self.flex_14_lo;
        data
    }
}

/// Wire size of the `0x26`/`0x4e` finger-detect payload (no type/len header).
pub const CHUNK_FINGER_DETECT_PAYLOAD_LEN: usize = 40;

/// Byte offsets into the finger-detect (`0x26`/`0x4e`) payload (`FUN_180096a90`@0x180096a90).
pub mod chunk_fdet_off {
    pub const MAGIC: usize = 0x00;
    pub const PARAM2_2: usize = 0x04;
    pub const WORD_08: usize = 0x08;
    pub const THRESH_LO: usize = 0x0c;
    pub const THRESH_HI: usize = 0x10;
    pub const WORD_14: usize = 0x14;
    pub const WORD_18: usize = 0x18;
    pub const WORD_1C: usize = 0x1c;
    pub const TIMEOUT_A: usize = 0x20;
    pub const TIMEOUT_B: usize = 0x22;
}

/// Editable fields of a decoded `0x26`/`0x4e` finger-detect payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkFingerDetectFields {
    pub magic: u16,
    pub param2_2: u16,
    pub word_08: u32,
    pub thresh_lo: u32,
    pub thresh_hi: u32,
    pub word_14: u32,
    pub word_18: u32,
    pub word_1c: u32,
    pub timeout_a: u16,
    pub timeout_b: u16,
    /// Trailing three bytes at `0x24..0x27` (identify/enroll literals `01 09 10`).
    pub trailer: [u8; 3],
}

impl ChunkFingerDetectFields {
    /// Parse a 40-byte finger-detect payload. Returns `None` if the length is wrong.
    pub fn parse(payload: &[u8]) -> Option<Self> {
        if payload.len() != CHUNK_FINGER_DETECT_PAYLOAD_LEN {
            return None;
        }
        let u16le = |o: usize| u16::from_le_bytes([payload[o], payload[o + 1]]);
        let u32le = |o: usize| {
            u32::from_le_bytes([payload[o], payload[o + 1], payload[o + 2], payload[o + 3]])
        };
        Some(Self {
            magic: u16le(chunk_fdet_off::MAGIC),
            param2_2: u16le(chunk_fdet_off::PARAM2_2),
            word_08: u32le(chunk_fdet_off::WORD_08),
            thresh_lo: u32le(chunk_fdet_off::THRESH_LO),
            thresh_hi: u32le(chunk_fdet_off::THRESH_HI),
            word_14: u32le(chunk_fdet_off::WORD_14),
            word_18: u32le(chunk_fdet_off::WORD_18),
            word_1c: u32le(chunk_fdet_off::WORD_1C),
            timeout_a: u16le(chunk_fdet_off::TIMEOUT_A),
            timeout_b: u16le(chunk_fdet_off::TIMEOUT_B),
            trailer: [payload[0x24], payload[0x25], payload[0x26]],
        })
    }

    /// Encode back to a 40-byte payload. Preserves the fixed bytes at `0x02`/`0x06` (`0x0f`)
    /// that [`chunk_finger_detect`] writes.
    pub fn encode(self) -> [u8; CHUNK_FINGER_DETECT_PAYLOAD_LEN] {
        let mut d = [0u8; CHUNK_FINGER_DETECT_PAYLOAD_LEN];
        let put16 = |d: &mut [u8], o: usize, v: u16| d[o..o + 2].copy_from_slice(&v.to_le_bytes());
        let put32 = |d: &mut [u8], o: usize, v: u32| d[o..o + 4].copy_from_slice(&v.to_le_bytes());
        put16(&mut d, chunk_fdet_off::MAGIC, self.magic);
        d[0x02] = 0x0f;
        put16(&mut d, chunk_fdet_off::PARAM2_2, self.param2_2);
        d[0x06] = 0x0f;
        put32(&mut d, chunk_fdet_off::WORD_08, self.word_08);
        put32(&mut d, chunk_fdet_off::THRESH_LO, self.thresh_lo);
        put32(&mut d, chunk_fdet_off::THRESH_HI, self.thresh_hi);
        put32(&mut d, chunk_fdet_off::WORD_14, self.word_14);
        put32(&mut d, chunk_fdet_off::WORD_18, self.word_18);
        put32(&mut d, chunk_fdet_off::WORD_1C, self.word_1c);
        put16(&mut d, chunk_fdet_off::TIMEOUT_A, self.timeout_a);
        put16(&mut d, chunk_fdet_off::TIMEOUT_B, self.timeout_b);
        d[0x24] = self.trailer[0];
        d[0x25] = self.trailer[1];
        d[0x26] = self.trailer[2];
        d
    }
}

