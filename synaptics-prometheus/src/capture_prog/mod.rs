//! SensorCaptureProg selection + `0x02` capture-command construction.
//!
//! A Prometheus sensor will not image until a **capture program** (a "timeslot" register-write
//! program) has been uploaded via command `0x02`. The vendor stack picks the program with a
//! two-step lookup that we reproduce here from the DLL:
//!
//! 1. read the silicon id (cmd `0x35`) → `(major, minor)`;
//! 2. `syna_silicon_table_lookup`@0x18006dbb0 maps it to a **subtype** via the embedded
//!    `g_silicon_subtype_table` ([`crate::capture_prog::subtype_for_silicon`]);
//! 3. `syna_capture_prog_build`@0x18009ab80 selects the matching [`crate::capture_progs_9b::CaptureProg`] from
//!    `g_fw_module_table_cat1` by `(subtype, status[8], status[9], 0x18, 0x19)`
//!    ([`crate::capture_prog::select_prog`]);
//! 4. `syna_scs_init_config`@0x180069240 stores it; `FUN_18005ecc0`(cmd-index 9) then uploads it
//!    to the sensor as `02 ‖ bytes_per_line:u16 ‖ req_lines:u16 ‖ program` — python-validity
//!    `sensor.py build_cmd_02` (identical wire form; verified against the DLL builder
//!    `FUN_180086110`).
//!
//! The tables live in [`crate::capture_progs`] (alias [`crate::capture_progs_9b`]), extracted from
//! `synaWudfBioUsb.dll` by `tools/syna-driver-extract`. **This machine's sensor** (`06cb:009b`, silicon `0x190/0x4b`)
//! resolves to subtype `0x2449` ("86C TM-3368-001") → a 1688-byte, 200×152 program.
//!
//! ## Non-destructive
//! Uploading a capture program does not persist anything — it only enables imaging for the session
//! (`syna_scs_init_config` sets `ctx+0x168=1`). We build in **identify** mode (`req_lines = 0`); the
//! *calibrate* path is the one python-validity follows with flash writes (`persist_clean_slate`),
//! which we deliberately do not do.

/// Windsor recon-config (`tag 0x30000288`) parser — the coefficient table returned in the `0x02`
/// arm reply and unpacked host-side by `syna_capture_recon_setup@0x1800681e0`.
pub mod windsor;

/// Capture-spec abstraction: canonical per-mode arms + typed `ArmProgram` (Stage 1, additive).
/// NB `capture_spec::CaptureMode` (the new canonical modes) shadows the legacy narrow `CaptureMode`
/// used by `build_cmd_02`; it is intentionally *not* re-exported here to avoid the name clash —
/// reference it as `capture_spec::CaptureMode`. Stage 5 unifies the two.
pub mod capture_spec;
pub use capture_spec::{ArmChunk, ArmOverrides, ArmProgram, ArmSpec, FoldSource};

use crate::capture_progs_9b::{
    CAPTURE_PROGS, CaptureProg, SENSOR_TYPE_INFO, SILICON_TABLE, SensorTypeInfo,
};
use crate::line_update::{self, ChunkType, Mode};

/// The vendor "capture / image-reconstruction" USB command opcode (`0x02`); its body is
/// `bytes_per_line:u16 ‖ req_lines:u16 ‖ <timeslot chunks>`.
const CAPTURE_CMD: u8 = 0x02;

/// Resolve a silicon id `(major, minor)` to a sensor *subtype* via the vendor table.
///
/// Match rule (ghidra: `syna_silicon_table_lookup`): `major` must equal, then an exact minor match
/// (`(minor_val & minor_mask) == (minor & minor_mask)`) wins; a wildcard row
/// (`minor_val & minor_mask == 0`) is kept as a fallback. Returns `None` if `major` is unknown.
pub fn subtype_for_silicon(major: u16, minor: u16) -> Option<u16> {
    let mut wildcard = None;
    for row in SILICON_TABLE.iter() {
        if row.major != major {
            continue;
        }
        if (row.minor_val & row.minor_mask) == 0 || minor == 0 {
            wildcard = Some(row.subtype);
        } else if (row.minor_val & row.minor_mask) == (minor & row.minor_mask) {
            return Some(row.subtype);
        }
    }
    wildcard
}

/// Select the best capture program for a `subtype` and the live sensor status bytes.
///
/// Scoring mirrors `syna_capture_prog_build`: among entries for this subtype, prefer an exact
/// `status[8]` match (weight 2) then `status[9]` (weight 1). With one program per subtype (the
/// common case, e.g. `0x2449`) the status bytes don't matter. Returns `None` if the subtype has no
/// program in the family table (regenerate the table for a different family/driver).
pub fn select_prog(subtype: u16, st8: u16, st9: u16) -> Option<&'static CaptureProg> {
    CAPTURE_PROGS
        .iter()
        .filter(|p| p.subtype == subtype)
        .max_by_key(|p| u8::from(p.st8 == st8) * 2 + u8::from(p.st9 == st9))
}

/// The vendor flex-params geometry ([`SensorTypeInfo`]) for a subtype. `None` if not in the table.
pub fn type_info(subtype: u16) -> Option<&'static SensorTypeInfo> {
    SENSOR_TYPE_INFO.iter().find(|t| t.subtype == subtype)
}

use crate::chunk_codec::{Chunk, merge_chunks, split_chunks};

/// Split a program into OWNED `(type, payload)` chunk pairs (the mutable form the `line_update`
/// builders patch in place). `None` if the program is malformed.
fn owned_chunks(program: &[u8]) -> Option<Vec<(u16, Vec<u8>)>> {
    Some(
        split_chunks(program)?
            .into_iter()
            .map(|c| (c.typ, c.payload.to_vec()))
            .collect(),
    )
}

/// Merge owned `(type, payload)` chunk pairs back into a program body (inverse of [`owned_chunks`]).
fn merge_owned_chunks(chunks: &[(u16, Vec<u8>)]) -> Vec<u8> {
    merge_chunks(
        &chunks
            .iter()
            .map(|(t, p)| Chunk {
                typ: *t,
                payload: p,
            })
            .collect::<Vec<_>>(),
    )
}

/// The number of image lines per frame encoded in the program's `0x2f` ("2D") chunk (`u32`).
/// The vendor multiplies this by a per-type `repeat_multiplier` (from the flex-params table, not
/// yet extracted) to get `lines_per_frame`; the raw value is what `sensor.py open()` reads.
pub fn lines_2d(program: &[u8]) -> Option<u32> {
    let chunks = split_chunks(program)?;
    let c = chunks.iter().find(|c| c.typ == ChunkType::TwoD.id())?;
    if c.payload.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([
        c.payload[0],
        c.payload[1],
        c.payload[2],
        c.payload[3],
    ]))
}

/// The `error` word in a `0x51` (`get_prg_status2`) result.
///
/// The type-1 capture engine is **host-clocked**: after the `0x02` upload and the finger-down
/// interrupt, the host must repeatedly issue `0x51` reads to advance/pull the frame (ghidra:
/// `syna_read_frame_chunk`@0x18005cf00 loops on the not-ready codes `0x192`/`0x193`). Until a frame
/// is ready `0x51` reports [`CaptureStatus::InProgress`] — this is **not** a failure and must be
/// retried, not aborted. Our early runs mistook the single `0x51`→`0x00080000` for an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureStatus {
    /// `0` — frame ready / capture finished.
    Ok,
    /// `0x00080000` — capture still running (internal `0x192`/`0x193` "not ready"); poll again.
    InProgress,
    /// Any other `error` value (a real scanning problem).
    Other(u32),
}

impl CaptureStatus {
    /// The "capture in progress / not ready" sentinel (internal `0x192`/`0x193`).
    pub const IN_PROGRESS: u32 = 0x0008_0000;

    pub fn from_error(v: u32) -> CaptureStatus {
        match v {
            0 => CaptureStatus::Ok,
            Self::IN_PROGRESS => CaptureStatus::InProgress,
            other => CaptureStatus::Other(other),
        }
    }

    /// True while the capture should keep being polled with `0x51`.
    pub fn is_in_progress(self) -> bool {
        matches!(self, CaptureStatus::InProgress)
    }
}

/// A parsed `0x51 get_prg_status2` result: `len:u32, x:u16, y:u16, w1:u16, w2:u16, error:u32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureResult {
    pub len: u32,
    pub x: u16,
    pub y: u16,
    pub w1: u16,
    pub w2: u16,
    pub status: CaptureStatus,
}

impl CaptureResult {
    /// Parse the payload **after** the 2-byte wire status word. `None` if too short.
    pub fn parse(d: &[u8]) -> Option<CaptureResult> {
        if d.len() < 16 {
            return None;
        }
        let u16a = |o: usize| u16::from_le_bytes([d[o], d[o + 1]]);
        let u32a = |o: usize| u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]]);
        Some(CaptureResult {
            len: u32a(0),
            x: u16a(4),
            y: u16a(6),
            w1: u16a(8),
            w2: u16a(10),
            status: CaptureStatus::from_error(u32a(12)),
        })
    }
}

/// An event delivered on the **EP-`0x83` interrupt** endpoint during a capture/match, decoded from
/// the interrupt's first byte (the event type) — python-validity `sensor.capture()` /
/// `match_finger()`. The host observes these while the `0x51` read loop clocks the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureEvent {
    /// `0` — the capture program began executing (first lines produced).
    Started,
    /// `2` — a finger was detected on the sensor (WOE "finger down").
    FingerDown,
    /// `3` with `byte[2] & 4` — the capture/match finished.
    Complete,
    /// `3` without the completion bit — an intermediate progress tick.
    Progress,
    /// Any other interrupt-type byte.
    Other(u8),
}

impl CaptureEvent {
    /// The `byte[2]` bit that distinguishes a *complete* type-3 event from a progress tick.
    pub const COMPLETE_FLAG: u8 = 4;

    /// Decode a raw EP-`0x83` interrupt transfer. `None` if the buffer is empty.
    pub fn parse(b: &[u8]) -> Option<CaptureEvent> {
        Some(match *b.first()? {
            0 => CaptureEvent::Started,
            2 => CaptureEvent::FingerDown,
            3 => {
                if b.get(2).is_some_and(|&x| x & Self::COMPLETE_FLAG != 0) {
                    CaptureEvent::Complete
                } else {
                    CaptureEvent::Progress
                }
            }
            other => CaptureEvent::Other(other),
        })
    }
}

/// Capture intent for the `0x02` framing (`req_lines`). The full capture *mode* taxonomy
/// (calibrate/identify/enroll) is [`crate::line_update::Mode`]; this narrower enum only distinguishes
/// what `req_lines` to send, and only the non-destructive [`CaptureMode::Identify`] is wired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    /// Image for matching. `req_lines = 0`. No flash writes.
    Identify,
}

impl CaptureMode {
    fn req_lines(self) -> u16 {
        match self {
            CaptureMode::Identify => 0,
        }
    }
}

/// Build the `0x02` capture command: `02 ‖ bytes_per_line:u16 ‖ req_lines:u16 ‖ program`.
///
/// (ghidra: cmd-index 9 via `FUN_18005ecc0`→`FUN_180086110`; python-validity `build_cmd_02`.)
/// `program` is uploaded verbatim here — the per-product/subtype "line_update" chunk patching
/// (`line_update_type_1/2`, product `0x33`-specific, uses factory bits from `0x6f`) is **not**
/// applied yet; for a first identify pass the unpatched program is what we send.
pub fn build_cmd_02(program: &[u8], bytes_per_line: u16, mode: CaptureMode) -> Vec<u8> {
    frame_cmd_02(program, bytes_per_line, mode.req_lines())
}

/// Frame a prebuilt `0x02` body with an explicit `req_lines`: `02 ‖ bytes_per_line:u16 ‖
/// req_lines:u16 ‖ body`. `CALIBRATE` needs `req_lines = calibration_frames*lines_per_frame + 1`
/// (python-validity `build_cmd_02`), which the narrow [`CaptureMode`] can't express.
pub fn frame_cmd_02(body: &[u8], bytes_per_line: u16, req_lines: u16) -> Vec<u8> {
    let mut cmd = Vec::with_capacity(5 + body.len());
    cmd.push(CAPTURE_CMD);
    cmd.extend_from_slice(&bytes_per_line.to_le_bytes());
    cmd.extend_from_slice(&req_lines.to_le_bytes());
    cmd.extend_from_slice(body);
    cmd
}

/// Per-line header prepended to each EP-0x82 wire line in the frames-sync/calibrate stream
/// (`[valid, 0xFE, line_no, frame_no, 0xF0, 0xF7, …]`). The wire stride is `line_width + this`,
/// NOT [`SensorTypeInfo::bytes_per_line`] (the 0x02-command width). See
/// `syna_capture_frames_sync@0x18006ae20` / `syna_frame_line_average@0x180099c70`.
pub const SYNC_LINE_HEADER: usize = 8;

/// Step-6 WOE dark capture — `syna_lib_cal_step6_woe_cleanslate` → `syna_capture_arm_and_wait(..., 1)`.
/// The 0x2449 default (single frame, byte-exact vs the DLL). The older type-1 family uses
/// [`OLDER_FAMILY_CALIBRATION_FRAMES`]; see [`CaptureConfig::calibration_frames`].
pub const CAL_STEP6_SYNC_FRAMES: u32 = 1;
/// python-validity `calibration_frames` for the 0x0199 type-1 family (`open()`: `= 3` for type 0x199).
/// Drives `req_lines = frames * lines_per_frame + 1` (= 673 on the 009a) and the frame average.
pub const OLDER_FAMILY_CALIBRATION_FRAMES: u32 = 3;
/// Step-7 settle arm — `syna_lib_calibration_step` case 7 calls
/// `syna_capture_arm_and_wait(ctx,0,1,0)` (one frames-sync batch, not `req_lines=0`).
pub const CAL_STEP7_SETTLE_SYNC_FRAMES: u32 = 1;
/// Default EP-0x82 stream capture frame count (`stream:3:1`, live_viewer, `FrameCapturer`).
pub const STREAM_DEFAULT_SYNC_FRAMES: u32 = 3;

/// The **measured** calibration blobs folded into a polled arm's line-update — the outputs of
/// `syna_lib_run_calibration` that the static `DAT_CAL_*` fallbacks stand in for when absent.
///
/// Grouped into one struct rather than passed as three adjacent `Option<&[u8]>` parameters:
/// same-typed positional slots are trivially transposed at a call site, and a transposed
/// line-update silently arms the sensor with the wrong correction (see
/// [`docs/capture/last-frame-baseline.md`](../../docs/capture/last-frame-baseline.md)).
/// [`Default`] is "no measured cal" — every field `None`, i.e. the static-fallback arm.
#[derive(Debug, Clone, Copy, Default)]
pub struct MeasuredCal<'a> {
    /// Step-3 measured per-line diff, bit-packed into DAT lines A/B.
    pub step3_diff: Option<&'a [u8]>,
    /// Step-6 WOE dark-frame clean slate, folded into DAT line C.
    pub step6_dark: Option<&'a [u8]>,
    /// The `0x48` last-captured-frame chunk finger-detect compares against
    /// (`syna_append_chunk_48_last_frame@0x180095ae0`).
    pub baseline_frame: Option<&'a [u8]>,
}

/// The resolved per-session capture configuration — the port of `syna_scs_init_config`: given the
/// sensor's silicon id and status bytes, hold the selected program + derived geometry and hand back
/// the ready-to-tunnel `0x02` upload command.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub subtype: u16,
    pub prog: &'static CaptureProg,
    /// Per-subtype geometry from the vendor flex-params table (authoritative `bytes_per_line` etc.).
    pub type_info: &'static SensorTypeInfo,
    /// `bytes_per_line` for the `0x02` framing (from [`SensorTypeInfo`], e.g. 160 for `0x2449`).
    pub bytes_per_line: u16,
    /// The `0x2f` "2D" line count (before `repeat_multiplier`).
    pub lines_2d: u32,
    /// Line-update interleave chunk value (`0x44`): `flex[0x14] - 1` per
    /// `syna_build_line_update_prod23@0x1800a36c0` (`ctx+0x294 - 1`).
    pub line_update_interleave: u32,
}

impl CaptureConfig {
    /// Resolve everything from a live silicon id + status bytes. `st8`/`st9` are
    /// `SensorStatus` bytes `[8]`/`[9]`; pass `0` if unknown (single-program subtypes ignore them).
    /// `None` if the subtype has no capture program *or* no flex-params row (regenerate the table).
    pub fn for_silicon(major: u16, minor: u16, st8: u16, st9: u16) -> Option<CaptureConfig> {
        let subtype = subtype_for_silicon(major, minor)?;
        let prog = select_prog(subtype, st8, st9)?;
        let ti = type_info(subtype)?;
        let line_update_interleave = crate::flex_params::flex_params(subtype)
            .map(|f| u32::from(f.flex_14.saturating_sub(1)))
            .unwrap_or(0);
        Some(CaptureConfig {
            subtype,
            prog,
            type_info: ti,
            bytes_per_line: ti.bytes_per_line,
            lines_2d: lines_2d(prog.program).unwrap_or(0),
            line_update_interleave,
        })
    }

    /// The bare `0x02` upload (program **unpatched**). Arms a capture but will not detect a finger —
    /// use [`CaptureConfig::resolve_arm`](Self::resolve_arm) (or the `upload_cmd_*` builders) with
    /// live factory bits for a working capture. Kept for the "does the sensor accept the program"
    /// smoke test.
    pub fn upload_cmd(&self) -> Vec<u8> {
        build_cmd_02(
            self.prog.program,
            self.bytes_per_line,
            CaptureMode::Identify,
        )
    }

    /// The full `0x02` capture command via the **product-0x33** `line_update` path (ghidra:
    /// `syna_build_line_update_prod23`@0x1800a36c0's ALT branch — taken when
    /// `status[8]==6 && status[9]>10`, which is our live sensor's status). Unlike the simpler type-2
    /// `0x30`-only [`line_update::line_update_type_2`] path, this bitpacks calibration
    /// diffs into a `0x43` "Line Update Transform" chunk (python-validity `line_update_type_1`
    /// family, ported from the live decompile rather than python-validity directly — `0x2449`
    /// isn't in python-validity's `line_update_type1_devices`).
    ///
    /// `factory_calibration_values` = `0x6f` factory-bits subtag 3 (`[4:]`), read live from the
    /// sensor (same input `patch_fingerdet_reg` needs). Non-destructive (identify mode,
    /// `req_lines = 0`).
    ///
    /// Currently only wired for subtype `0x2449` — [`crate::line_update::FLEX_2E_2449`] and
    /// `DAT_2449_GROUP_SUBTYPES`-equivalent gating are hardcoded to that
    /// sensor's flex-params values (see `line_update.rs` doc comments for how to extend).
    /// `lines_per_frame = lines_2d * repeat_multiplier` (python-validity `open()`), needed for the
    /// `CALIBRATE` `req_lines`.
    pub fn lines_per_frame(&self) -> u32 {
        self.lines_2d * self.type_info.repeat_multiplier as u32
    }

    /// Number of frames a CALIBRATE / frames-sync capture requests, feeding
    /// `req_lines = calibration_frames * lines_per_frame + 1` and the multi-frame average.
    /// python-validity `open()` hardcodes this per sensor type: `3` for the 0x0199 type-1 family,
    /// `6` for type 0xdb. Our 0x2449 step-6 dark is a single frame ([`CAL_STEP6_SYNC_FRAMES`]),
    /// validated byte-exact vs the DLL. Keyed on the same per-subtype signal as the calib fold
    /// (`key_calibration_line`), so a sibling device is a data row away (Rule #6).
    pub fn calibration_frames(&self) -> u32 {
        if crate::line_update::key_calibration_line(self.subtype).is_some() {
            OLDER_FAMILY_CALIBRATION_FRAMES
        } else {
            CAL_STEP6_SYNC_FRAMES
        }
    }

    /// Override a register value in a `0x32` [`ChunkType::RegisterList16`] chunk payload
    /// (`[base:u32][ (off:u16, val:u16) … ]`, where `off = reg & 0xffff`). Returns the previous
    /// value if the offset was present. Used to retune the AFE analog gain (`SCM_AFE_LPF_VGA` etc.)
    /// that the static capture program bakes in — the program is uploaded verbatim otherwise.
    fn patch_reglist16_value(payload: &mut [u8], target_off: u16, new_val: u16) -> Option<u16> {
        if payload.len() < 4 {
            return None;
        }
        let mut i = 4; // skip the base u32
        while i + 4 <= payload.len() {
            let off = u16::from_le_bytes([payload[i], payload[i + 1]]);
            if off == target_off {
                let old = u16::from_le_bytes([payload[i + 2], payload[i + 3]]);
                payload[i + 2..i + 4].copy_from_slice(&new_val.to_le_bytes());
                return Some(old);
            }
            i += 4;
        }
        None
    }

    /// Build the prod33 `0x02` body: program chunks (`0x34` timeslot patched), `0x17` reply config,
    /// `0x15`, an optional `0x26` finger-detect, `0x2e` recon, and the line-update (with runtime
    /// `calib_data` transform lines appended when present). Shared by identify/calibrate arms.
    #[allow(clippy::too_many_arguments)] // internal capture-arm assembler; each arg is a distinct knob
    fn prod33_body(
        &self,
        factory_calibration_values: &[u8],
        calib_data: &[u8],
        calibrate: bool,
        recon_flags: u32,
        finger_detect: bool,
        measured: MeasuredCal<'_>,
        include_chunk_2e: bool,
    ) -> Option<Vec<u8>> {
        let MeasuredCal { step3_diff, step6_dark, baseline_frame } = measured;
        let mut chunks = owned_chunks(self.prog.program)?;

        // Flex digital rescale (flex[0x88]/[0x8a] = 10/4 for 0x2449) — shared by the 0x34 timeslot
        // fold and the line-update delta lines. Data-driven per subtype (Rule #6).
        let (scale_num, scale_den) = crate::calibration::flex_cal_for_subtype(self.subtype)
            .map(|f| (f.scale_num, f.scale_den))
            .unwrap_or((1, 1));

        // Older type-1 family (0x0199 etc.): fold the PERSISTED `calib_data` for the `0x34` key-line
        // and `0x30` deltas (python-validity `get_key_line` + `calib_data_lines`), instead of the live
        // step-6 dark (which saturates without the Windows-registry analog trim). `calib_data` comes
        // from the caller (`&[]` = none) or `SYNA_CALIB_DATA` (bring-up); the key-line row is per-subtype.
        let key_line = line_update::key_calibration_line(self.subtype);
        let cd_env;
        let calib_data: &[u8] = if !calib_data.is_empty() {
            calib_data
        } else if finger_detect && key_line.is_some() && step6_dark.is_some() {
            // Use the FRESH in-session step-6 dark (the DLL's `pStep5or6_buf`) as the older-family fold
            // source for the polled `0x4e` identify — the DLL `0x85`-transposes this fresh clean-slate,
            // never a persisted file. `capture_dark_frame`'s averaged buffer is `lines_2d × stride` =
            // 13440 B on the 009a, matching the calib_data layout. Gated on `finger_detect` so the fold
            // lands ONLY on the polled identify/enroll arm — the no-finger frames-sync arm (and step 6's
            // own dark) stay UNFOLDED (a folded frames-sync arm resets this die).
            step6_dark.unwrap()
        } else if let Some(p) = std::env::var_os("SYNA_CALIB_DATA") {
            cd_env = std::fs::read(p).unwrap_or_default();
            &cd_env
        } else {
            &[]
        };
        let lw = self.type_info.line_width as usize;
        let lpc = self.type_info.lines_per_calibration_data as usize;
        // The older type-1 family folds `calib_data` into the `0x30` deltas + `0x34` key-line for BOTH
        // the CALIBRATE and the capture (identify/image) arm — python-validity's `line_update_type_1`
        // adds the `0x85` calib_data lines and the `get_key_line()` splice mode-independently. Byte-diffed
        // vs the live pv CALIBRATE arm (`captures/009a-arm-golden/pv_arms.log`): with the fold the arm is
        // 13665B and byte-exact; without it (the old `!calibrate` gate) the arm was 897B and the sensor
        // reset (missing `0x85` lines → on-chip recon reads calib rows that aren't there). `key_line.is_some()`
        // already scopes this to the 0x0199 family; 0x2449 has no key line and keeps its measured `0x34`
        // fold below. See docs/capture/009a-calibration-port.md.
        let use_calib_data =
            !calib_data.is_empty() && key_line.is_some() && lw > 0 && lpc > 0;

        let mut tst: Vec<u8> = Vec::new();
        for c in chunks.iter_mut() {
            if c.0 == ChunkType::TimeslotTable2d.id() {
                let mut t =
                    line_update::patch_timeslot_table(&c.1, true, self.type_info.repeat_multiplier);
                // The finger-detect-register default patch (DLL `syna_patch_fingerdet_reg_from_calresults`
                // @0x18008c360). On 0x2449 it is a no-op: the DLL's guard needs a MEASURED fingerdet
                // cal (ctx+0x288+0x68/+0x70, a step5/6 output) which 0x2449 never produces (step3 only),
                // so reg 0x8000203c keeps its base 0x80 — proven byte-exact vs the DLL identify+image
                // arms. Hence `None` (no measured cal). Kept behind `!calibrate` for family subtypes
                // that DO run step5/6 and would pass their measured cal here.
                if !calibrate {
                    // Older type-1 family (0x0199): python-validity `patch_timeslot_again`
                    // (`sensor.py:295`) injects `factory_calibration_values[key_calibration_line]` into
                    // the `0x8000203c` reg-write reachable from the last Call — for IDENTIFY/ENROLL,
                    // never CALIBRATE. `patch_fingerdet_reg` runs the *identical* walk, and
                    // `fingerdet_cal_offset(0x199) == key_calibration_line(0x199) == 0x38`, so feeding it
                    // the factory block (guard holds) reproduces `patch_timeslot_again` exactly. Without
                    // it the reg keeps its base value; combined with the `0x85` dark fold + `0x2e` recon
                    // that faults the 0x0199 die (fold alone/recon alone both arm fine — it's the
                    // combination that needs this per-identify factory-cal injection). 0x2449 keeps
                    // `None` → the guard fails → no-op, preserving the byte-exact DLL identify/image arms.
                    let fdet_cal =
                        key_line.is_some().then_some(factory_calibration_values);
                    t = line_update::patch_fingerdet_reg(&t, fdet_cal, self.subtype);
                }
                // `tst` (line-update anchor source) stays UNFOLDED; the BODY copy gets the measured
                // 0x34 fold (`syna_fold_timeslot_2d_measured@0x180092c70`) — the DLL patches the leading
                // line_width bytes of the 0x34 payload with the step-6 dark-field per-column correction,
                // which cancels the per-timeslot fixed pattern AT THE SENSOR (fixes the reconstruction
                // stipple; verified vs the DLL's clean emitted frame). Runs last, when the measured
                // frame is present.
                tst = t.clone();
                // EXPERIMENT (SYNA_NO_KEYLINE=1): skip the 0x34 key-line splice half of the fold — bisecting
                // whether the reset is the timeslot key-line or the 0x85 0x30 delta lines.
                let skip_keyline = std::env::var_os("SYNA_NO_KEYLINE").is_some();
                if use_calib_data && !skip_keyline {
                    // python-validity `c[1] = get_key_line() + tst[line_width:]`: fill the leading
                    // `line_width` bytes (the zero placeholder) with the persisted-calib key line.
                    let kl =
                        line_update::calib_data_key_line(calib_data, lpc, lw, key_line.unwrap());
                    if t.len() >= lw {
                        t.splice(0..lw, kl);
                    }
                } else if let (Some(frame), Some(rows)) =
                    (step6_dark, line_update::timeslot_fold_rows(self.subtype))
                {
                    line_update::fold_timeslot_2d(
                        &mut t,
                        frame,
                        self.lines_2d as usize,
                        scale_num,
                        scale_den,
                        rows,
                    );
                }
                c.1 = t;
            } else if c.0 == ChunkType::RegisterList16.id()
                && Self::patch_reglist16_value(&mut c.1.clone(), 0x203c, 0).is_some()
            {
                // AFE analog-gain retune — only the AFE `0x32` chunk (the one carrying `SCM_AFE_LPF_VGA`
                // = off 0x203c). The static capture program bakes the pre-ADC gain here
                // (`SCM_AFE_LPF_VGA=0x80`, `SCM_AFE_LNA2=1`), uploaded verbatim otherwise. Env overrides
                // let us sweep it on-device (no-finger) to find where clipping stops; once pinned it
                // becomes a per-subtype data field. `off = reg & 0xffff`.
                for (env, reg) in [
                    ("SYNA_AFE_LPF_VGA", crate::scm_regs::ScmReg::ScmAfeLpfVga),
                    ("SYNA_AFE_LNA2", crate::scm_regs::ScmReg::ScmAfeLna2),
                    ("SYNA_AFE_VGA", crate::scm_regs::ScmReg::ScmAfeVga),
                ] {
                    let ov = std::env::var(env).ok().and_then(|s| {
                        let s = s.trim();
                        u16::from_str_radix(s.strip_prefix("0x").unwrap_or(s), if s.starts_with("0x") { 16 } else { 10 }).ok()
                    });
                    if let Some(v) = ov {
                        let off = (reg.addr() & 0xffff) as u16;
                        match Self::patch_reglist16_value(&mut c.1, off, v) {
                            Some(old) => log::info!("AFE override {}: {old:#06x} -> {v:#06x}", reg.scm_name()),
                            None => {
                                // Register not in the program's 0x32 chunk (silicon default) — APPEND the
                                // (off, val) pair so we can test knobs the program leaves unset (e.g. VGA).
                                c.1.extend_from_slice(&off.to_le_bytes());
                                c.1.extend_from_slice(&v.to_le_bytes());
                                log::info!("AFE override {}: appended = {v:#06x}", reg.scm_name());
                            }
                        }
                    }
                }
            }
        }

        let mut body = merge_owned_chunks(&chunks);
        body.extend_from_slice(&ChunkType::ReplyConfig.id().to_le_bytes()); // Reply Config chunk
        body.extend_from_slice(&0u16.to_le_bytes()); // ...with empty payload
        // BwReduction (0x15) — DISABLED. The live DLL **identify** arm captured on our own sensor (via
        // the synaTudor relink + a kernel usbmon trace, 2026-07) has NO `0x15` chunk: it goes
        // ReplyConfig(0x17) → FingerDetect(0x26) directly (verified chunk-for-chunk vs `/tmp/dll_arm`).
        // We had emitted it from a stale reading of `dll.pcap`; the DLL's `syna_append_chunk_15_bwreduction`
        // is evidently gated off for this arm/subtype.
        // CAVEAT: this `!calibrate` branch is SHARED by the identify AND image (`upload_cmd_image*`) arms.
        // We have only captured a DLL *identify* arm, so `0x15`'s absence on the *image* arm is unconfirmed.
        // If a DLL image capture shows `0x15`, re-enable it gated on the arm class rather than `!calibrate`.
        // if !calibrate {
        //     body.extend_from_slice(&line_update::chunk_15());
        // }
        // Finger-detect + image-reconstruction (0x2e) are IDENTIFY/ENROLL only, NOT CALIBRATE
        // (python-validity `line_update_type_1`: the 0x4e/0x26 finger-detect and the 0x2e recon are
        // added only for non-calibrate modes). CALIBRATE is a finger-less RAW-frame capture — with
        // 0x2e the sensor waits to reconstruct an image that never comes (0x51 stalls at status
        // 0x0001/no frame, observed live); without it, it streams raw calibration frames.
        if !calibrate {
            // Finger-detect (0x26) arms the WOE interrupt path. The vendor's POLLED imaging path
            // (`syna_capture_image`, capture-flags 0xa0030) OMITS it — it's gated on `0x20000`, which
            // 0xa0030 sets (`syna_build_capture_cmd02` skips `FUN_180094420`). Including it alongside
            // recon flags=8 makes the sensor reject the arm (status 0x0537). So the imaging arm
            // passes `finger_detect=false`.
            if finger_detect {
                // Finger-detect chunk MODE must match the capture mode (python-validity
                // `line_update_type_1`: IDENTIFY→`0x4e`, ENROLL→`0x26`). On the older type-1 family
                // (0x0199) the folded `0x85` calib arm **faults the sensor firmware** when paired with
                // the `0x26` (Enroll) finger-detect config, but is ACCEPTED with `0x4e` (Identify) —
                // verified on-device 2026-08-19 (T480 009a): `0x26`+fold → device reset (`-108`),
                // `0x4e`+fold → armed OK. This was the entire fold-reset root cause. 0x2449 keeps its
                // DLL-byte-exact behavior (the `0x4e`/`0x26`-by-mode distinction is scoped to the older
                // family, which pv's `line_update_type_1` covers and the 0x2449 KATs pin).
                let older_family = line_update::key_calibration_line(self.subtype).is_some();
                let fd_mode = if recon_flags == line_update::RECON_FLAGS_ENROLL {
                    Mode::Enroll
                } else if older_family {
                    Mode::Identify
                } else {
                    Mode::Enroll
                };
                body.extend_from_slice(&line_update::chunk_finger_detect_for_subtype(
                    self.subtype,
                    fd_mode,
                ));
            }
            // 0x2e reconstruction params are looked up PER-SUBTYPE from the extracted flex table
            // (generic, family-wide), falling back to the `0x2449` constant. recon_flags: the
            // provisioned polled-imaging arm derives 8 (RECON_FLAGS_IMAGE, alt field-0=flex[0x16]);
            // the `2` default (identify) branch reconstructs with field-0=recon_cfg[0].
            let flex2e = line_update::Flex2eParams::for_subtype(self.subtype)
                .unwrap_or(line_update::FLEX_2E_2449);
            if include_chunk_2e {
                body.extend_from_slice(&line_update::chunk_2e(&flex2e, 2, recon_flags));
                // Empty `0x47` companion chunk — the DLL's `syna_append_chunk_2e_image_recon` emits
                // `[0x47][len=0]` (`syna_append_chunk_47_recon_marker@0x180095660`) after `0x2e` on the
                // 0x2449 class. The older type-1 family (0x0199) does NOT: pv's `line_update_type_1`
                // adds `0x44` interleave after `0x2e`, never `0x47`. Emitting the stray `0x47` on the
                // folded 0x0199 IDENTIFY arm FAULTS this die (the folded arm is otherwise byte-exact to
                // pv's calibrate arm) — so gate it to 0x2449 (the identify/image KATs pin it there).
                if line_update::key_calibration_line(self.subtype).is_none() {
                    body.extend_from_slice(&ChunkType::Empty47.id().to_le_bytes());
                    body.extend_from_slice(&0u16.to_le_bytes());
                }
            }
        }

        // The calib-blob line sends the **static** per-line blob `flex+0x58` (= [`SensorTypeInfo::
        // calibration_blob`], `[12..67]` for 0x2449) — verified byte-exact against the DLL's 0x43 chunk
        // (`syna_build_line_update_prod23` copies `*(flex+0x58)`). The measured factory `0x80000003`
        // block (`factory_calibration_values`) is NOT this line: it is the step-3 per-line diff that
        // feeds DAT lines A/B (`ctx+0x288+0x68`, via `step3_diff`/`step3_diff`). The earlier note here had
        // these two swapped, sending the measured block as the calib-blob line.
        let calib_blob: &[u8] = self.type_info.calibration_blob;
        // On 0x2449 `factory_calibration_values` feeds only the (no-op) fingerdet-reg patch and the
        // caller-derived `step3_diff`; on the older type-1 family it is bit-packed into the single DAT
        // line by `line_update_prod33` (python-validity `bitpack(factory_calibration_values)`), so it is
        // passed through below.
        // `step3_diff` (step-3 measured per-line diff → DAT lines A/B) and `step6_dark` (step-6 WOE
        // clean-slate → DAT line C) come from the calibration state machine (crate::calibration); when
        // both `None` the arm uses the static `DAT_CAL_2449`/`DAT_FLAT40` fallbacks (the weak-signal
        // path). See docs/calibration/calibration-fullmachine-spec.md.
        // `scanlines` = the 0x2f "2D" count (`local_1ac`); `scale_num`/`scale_den` (computed above)
        // feed the step-6 dark-frame delta expansion (`calib_delta_lines_prod33`) when `step6_dark` is
        // present — the same measured fold the 0x34 patch uses.
        let lines = line_update::line_update_prod33(
            &tst,
            calib_blob,
            self.subtype,
            step3_diff,
            step6_dark,
            self.lines_2d as usize,
            scale_num,
            scale_den,
            use_calib_data.then_some((calib_data, lw, lpc)),
            factory_calibration_values,
        );
        body.extend_from_slice(&line_update::serialize_line_update(
            &lines,
            self.line_update_interleave,
        ));
        // `0x48` finger-detect baseline reference frame — the DLL's last identify/verify chunk
        // (`syna_append_matcher_template_chunk`). Width = wire stride (line_width + 8), height = the
        // captured dark-frame line count. Without it the sensor reads a spurious finger at arm.
        if let Some(frame) = baseline_frame {
            let stride = self.type_info.line_width as usize + SYNC_LINE_HEADER;
            body.extend_from_slice(&line_update::chunk_baseline(frame, stride as u16));
        }
        Some(body)
    }

    /// Identify arm (finger-detect on, no runtime calib_data). `req_lines = 0`. `0x2e` flags =
    /// default branch (`2`) — the combo the sensor accepts alongside the `0x26` finger-detect chunk.
    pub fn upload_cmd_prod33(&self, factory_calibration_values: &[u8]) -> Option<Vec<u8>> {
        let body = self.prod33_body(
            factory_calibration_values,
            &[],
            false,
            line_update::RECON_FLAGS_DEFAULT,
            true,
            MeasuredCal::default(),
            true,
        )?;
        Some(frame_cmd_02(&body, self.bytes_per_line, 0))
    }

    /// Calibrated identify arm (finger-detect on, `0x2e` flags = default `2`). The empirically-working
    /// polled-capture arm; the sensor returns a frame but its own reconstruction is the "default"
    /// branch (spatially-correct but only lightly conditioned).
    pub fn upload_cmd_prod33_calibrated(
        &self,
        factory_calibration_values: &[u8],
        calib_data: &[u8],
    ) -> Option<Vec<u8>> {
        let body = self.prod33_body(
            factory_calibration_values,
            calib_data,
            false,
            line_update::RECON_FLAGS_DEFAULT,
            true,
            MeasuredCal::default(),
            true,
        )?;
        Some(frame_cmd_02(&body, self.bytes_per_line, 0))
    }

    /// **Imaging arm** — a faithful match to `syna_capture_image @0x180099540` (capture-flags
    /// [`line_update::CAPTURE_FLAGS_IMAGE`] = `0xa0030`): finger-detect (`0x26`) OMITTED and `0x2e`
    /// reconstruction flags = 8 ([`line_update::RECON_FLAGS_IMAGE`], field 0 = `flex[0x16]` = 150 —
    /// verified against the DLL's `syna_recon_substruct_build`@0x1800ae110). This asks the sensor to
    /// do its full on-chip reconstruction, so the frame should come back as a clean image rather than
    /// the lightly-conditioned "default" one. NON-destructive (identify framing, no writes).
    pub fn upload_cmd_image(
        &self,
        factory_calibration_values: &[u8],
        calib_data: &[u8],
    ) -> Option<Vec<u8>> {
        self.upload_cmd_polled_imaging(
            factory_calibration_values,
            calib_data,
            line_update::RECON_FLAGS_IMAGE,
            false,
            MeasuredCal::default(),
        )
    }

    /// **Calibrated imaging arm** (task #27) — [`Self::upload_cmd_image`] plus the sensor's MEASURED
    /// per-line correction folded into the line-update: the factory `0x80000003` block's per-line diff
    /// (bit-packed) replaces the static `DAT_CAL_2449` fallback, reproducing what `syna_capture_image`
    /// arms *after* `syna_lib_run_calibration`. `factory_calibration_values` must be the `0x6f` tag-14
    /// / subtag-3 block (4-byte header already stripped). Pair with [`Self::upload_cmd_image`] for the
    /// static-vs-measured A/B that validates the weak-signal fix (finger-gated — AGENTS.md Rule #1).
    pub fn upload_cmd_image_calibrated(
        &self,
        factory_calibration_values: &[u8],
    ) -> Option<Vec<u8>> {
        // Step-3 measured diff (DAT lines A/B) from the factory `0x80000003` block. No DAT line C
        // (step 6 needs a live dark-frame capture — use [`Self::upload_cmd_image_with_cal`] for the
        // full state-machine fold).
        let step3_diff = crate::factory_cal::cal_diff_from_line_array(
            factory_calibration_values,
            self.type_info.lines_per_calibration_data as usize,
        );
        self.upload_cmd_polled_imaging(
            factory_calibration_values,
            &[],
            line_update::RECON_FLAGS_IMAGE,
            false,
            MeasuredCal { step3_diff: step3_diff.as_deref(), ..MeasuredCal::default() },
        )
    }

    /// **Full-calibration imaging arm** (task #27) — folds BOTH state-machine outputs: step-3's
    /// measured per-line diff into DAT lines A/B **and** step-6's WOE clean-slate into DAT line C.
    /// `cal` comes from [`crate::calibration::run_calibration`] (which does the step-6 dark-frame
    /// capture). This is the complete `syna_capture_image`-after-`syna_lib_run_calibration`
    /// reproduction. Pair with [`Self::upload_cmd_image`] for the static-vs-measured A/B (finger-gated).
    pub fn upload_cmd_image_with_cal(
        &self,
        factory_calibration_values: &[u8],
        cal: &crate::calibration::CalResults,
    ) -> Option<Vec<u8>> {
        self.upload_cmd_polled_imaging(
            factory_calibration_values,
            &[],
            line_update::RECON_FLAGS_IMAGE,
            false,
            MeasuredCal {
                step3_diff: cal.step3_diff.as_deref(),
                step6_dark: cal.line_c_source(),
                baseline_frame: None,
            },
        )
    }

    /// Identify/enroll arm with full vendor-cal fold — [`Self::upload_cmd_prod33_calibrated_recon`]
    /// plus measured step-3/step-6 line-update deltas. Uses identify-class recon flags (`2`) and
    /// finger-detect (`0x26`), matching `syna_capture_identify_enroll` polled `0x51` on 0x2449.
    pub fn upload_cmd_identify_with_cal(
        &self,
        factory_calibration_values: &[u8],
        cal: &crate::calibration::CalResults,
    ) -> Option<Vec<u8>> {
        // The `0x48` finger-detect baseline chunk (`syna_append_chunk_48_last_frame`) is emitted
        // UNCONDITIONALLY, matching the DLL which appends it for `capture_type==4 && provisioned`.
        // `cal.baseline_frame` is the step-7 SETTLE frame: line-averaged to `lines_2d` (56) and kept in
        // timeslot order (NOT descrambled), exactly the DLL's `pLast_frame_buf`. The step-6 dark-fold
        // fix (`session_cal.rs`, 2026-08-05 — fold the RAW dark, not the cf640-descrambled one) means
        // the sensor dark-corrects this settle on-chip to a FLAT field (std ~1.85 on device, matching
        // the DLL's `0x48` std ~1.9). The old "sending `0x48` resets the sensor" gate was disproven on
        // device (2026-08-07): the reset was the *deduped pre-arm* (`ctx+0x2d0`/calibration pre-arm),
        // NOT the `0x48` content — with the pre-arm fix the identify arm WITH `0x48` arms
        // `status=0x0000`. See `docs/capture/last-frame-baseline.md`.
        self.upload_cmd_polled_imaging(
            factory_calibration_values,
            &[],
            line_update::RECON_FLAGS_DEFAULT,
            true,
            MeasuredCal {
                step3_diff: cal.step3_diff.as_deref(),
                step6_dark: cal.line_c_source(),
                baseline_frame: cal.baseline_frame.as_deref(),
            },
        )
    }

    /// Polled still/identify arm with optional measured cal diffs folded into the line-update.
    /// `pub` for A/B probes (`examples/recon8_baseline_probe.rs`) that vary `recon_flags` /
    /// `finger_detect` independently to isolate what gates polled `0x51` body production.
    pub fn upload_cmd_polled_imaging(
        &self,
        factory_calibration_values: &[u8],
        calib_data: &[u8],
        recon_flags: u32,
        finger_detect: bool,
        measured: MeasuredCal<'_>,
    ) -> Option<Vec<u8>> {
        let body = self.prod33_body(
            factory_calibration_values,
            calib_data,
            false,
            recon_flags,
            finger_detect,
            measured,
            true,
        )?;
        Some(frame_cmd_02(&body, self.polled_imaging_bpl(), 0))
    }

    /// Calibrated arm with explicit `0x2e` reconstruction-flags + finger-detect toggle — for A/B
    /// validation of the reconstruction path.
    pub fn upload_cmd_prod33_calibrated_recon(
        &self,
        factory_calibration_values: &[u8],
        calib_data: &[u8],
        recon_flags: u32,
        finger_detect: bool,
    ) -> Option<Vec<u8>> {
        self.upload_cmd_polled_experimental(
            factory_calibration_values,
            calib_data,
            recon_flags,
            finger_detect,
            true,
        )
    }

    /// EXPT polled arm — optional `0x2e` chunk for on-chip recon A/B (`examples/recon_ab.rs`).
    pub fn upload_cmd_polled_experimental(
        &self,
        factory_calibration_values: &[u8],
        calib_data: &[u8],
        recon_flags: u32,
        finger_detect: bool,
        include_chunk_2e: bool,
    ) -> Option<Vec<u8>> {
        let body = self.prod33_body(
            factory_calibration_values,
            calib_data,
            false,
            recon_flags,
            finger_detect,
            MeasuredCal::default(),
            include_chunk_2e,
        )?;
        Some(frame_cmd_02(&body, self.bytes_per_line, 0))
    }

    /// EP-0x82 wire line stride for the frames-sync/calibrate path = `line_width + `[`SYNC_LINE_HEADER`]
    /// (152 for `0x2449`) — the stride `syna_capture_frames_sync` walks, NOT [`Self::bytes_per_line`]
    /// (the flex `bytes_per_line` width, 160). Polled imaging (`syna_capture_image`) uses the same
    /// field8 in the `0x02` header per live pcap parity (`dll-identify.pcap` step 24: bpl=152).
    pub fn sync_line_stride(&self) -> usize {
        self.type_info.line_width as usize + SYNC_LINE_HEADER
    }

    /// `0x02` header bytes-per-line for polled imaging arms (`syna_capture_image@0x180099540`).
    fn polled_imaging_bpl(&self) -> u16 {
        self.sync_line_stride() as u16
    }

    /// Mode-2 descramble blocks per line on a flat `0x51` body (= `line_width / 16`).
    /// ghidra: `syna_capture_image` row copy width = flex[0x32]; `0x42` chunk `length` matches.
    pub fn descramble_blocks_per_line(&self) -> usize {
        crate::reconstruct::blocks_per_line_from_width(self.type_info.line_width)
    }

    /// Expected flat `0x51` body length for a polled capture: `line_width × lines_2d`
    /// (8064 = 144×56 on `0x2449`).
    ///
    /// This is the Rust stand-in for the DLL's `session+0x20`. On read_mode 2
    /// (`vfmCapture@0x180053bb0`) there is **no header read**, so the reader cannot learn the size
    /// from the wire — the pump derives it from the capture geometry and passes it down, and
    /// [`crate::session::Session::capture_vfm_polled`] takes it from here for the same reason.
    /// The still path (`syna_capture_image@0x180099540`) parses it from its `0x10` header instead.
    pub fn polled_body_len(&self) -> usize {
        self.type_info.line_width as usize * self.lines_2d as usize
    }

    /// Polled `0x51` geometry declared by the DLL (header + flat body + dest stride).
    pub fn polled_layout(&self) -> crate::capture::PolledFrameLayout {
        crate::capture::PolledFrameLayout::from_type_info(self.type_info, self.lines_2d)
    }

    /// Mode-2 host reconstruct params for EP-0x82 (`syna_capture_and_reconstruct@0x1800984f0`).
    pub fn stream_recon_params(&self) -> crate::reconstruct::ReconParams {
        crate::reconstruct::ReconParams {
            mode: 2,
            offset: SYNC_LINE_HEADER as u8,
            length: self.type_info.line_width,
        }
    }

    /// Typed EP-0x82 geometry shared by arm sizing, receive sizing, and reconstruction.
    pub fn sync_layout(&self, frames: u32) -> crate::capture::SyncFrameLayout {
        crate::capture::SyncFrameLayout {
            line_width: self.type_info.line_width as usize,
            lines_2d: self.lines_2d as usize,
            repeat_multiplier: self.type_info.repeat_multiplier as usize,
            frames: frames as usize,
        }
    }

    /// `req_lines` a frames-sync/calibrate arm requests. The DLL adds one line only when the base
    /// transfer is 64-byte aligned, forcing a short terminating packet.
    pub fn stream_req_lines(&self, frames: u32) -> u16 {
        self.sync_layout(frames)
            .req_lines()
            .unwrap_or(usize::MAX)
            .min(u16::MAX as usize) as u16
    }

    /// Size of the EP-0x82 receive buffer the DLL allocates + reads in one blocking transfer for a
    /// frames-sync/calibrate capture: `req_lines × `[`Self::sync_line_stride`]. Mirrors
    /// `syna_capture_frames_sync@0x18006ae20` (`buffer = param_3 × param_2`); feed it to
    /// [`crate::capture::CaptureIo::read_frame`] to pre-size the read and length-validate.
    pub fn stream_buffer_size(&self, frames: u32) -> usize {
        self.stream_req_lines(frames) as usize * self.sync_line_stride()
    }

    /// Synchronous frames-sync arm — a faithful match to what the DLL pairs with
    /// `syna_capture_frames_sync @0x18006ae20` / `syna_capture_and_reconstruct @0x1800984f0`.
    ///
    /// **This is the CALIBRATE-class arm: no `0x2e` firmware reconstruction and no `0x26`/`0x4e`
    /// finger-detect chunk** (and no identify-only `patch_fingerdet_reg` anchor). That is required
    /// for fidelity: the DLL runs its host de-scramble (`syna_recon_descramble_mode2`, "cf640") in
    /// `syna_capture_and_reconstruct` **only** on raw frames armed *without* `0x2e` — the two are
    /// mutually exclusive (`0x2e` present ⇒ firmware reconstructs and host cf640 never runs; see
    /// `docs/capture/capture-paths.md` "`0x2e` vs host cf640"). Arming with `0x2e` here *and* running the
    /// host reconstruct (as an earlier version did) double-processes and matches no DLL path — plus
    /// with `0x2e` the sensor waits to reconstruct an image that never streams and `0x51` stalls at
    /// status `0x0001` (observed live).
    ///
    /// Framed with an explicit `req_lines` (= `frames*lines_per_frame` + the 64-byte USB alignment
    /// guard) instead of the identify `req_lines = 0`, so the sensor streams that many lines to
    /// EP-0x82 in one blocking read, independent of the finger-down/complete interrupts (broken on
    /// `0x2449`). Feed to [`crate::capture::FrameCapturer`] then reconstruct with
    /// [`crate::reconstruct::reconstruct_sync_frame`]. NON-destructive (no flash/DB writes).
    ///
    /// For the `0x2e`-on-chip A/B (identify-class recon over the stream) use
    /// [`Self::upload_cmd_prod33_calibrated_recon`] / `examples/recon_ab.rs`, not this arm.
    /// `calib_data` is accepted for API compatibility but superseded by the factory calibration.
    ///
    /// Uses static `DAT_CAL_2449` / `DAT_FLAT40` line-update fallbacks (no measured fold). After
    /// [`crate::calibration::run_calibration`], prefer [`Self::upload_cmd_prod33_sync_with_cal`].
    pub fn upload_cmd_prod33_sync(
        &self,
        factory_calibration_values: &[u8],
        calib_data: &[u8],
        frames: u32,
    ) -> Option<Vec<u8>> {
        self.upload_cmd_prod33_sync_body(
            factory_calibration_values,
            calib_data,
            frames,
            None,
            None,
        )
    }

    /// Frames-sync arm with measured calibration fold — mirrors
    /// `syna_build_line_update_prod23@0x1800a36c0` reading `ctx+0x288+{0x68,0x80}` after
    /// `syna_lib_run_calibration@0x1800731d0`. Same CALIBRATE-class semantics as
    /// [`Self::upload_cmd_prod33_sync`] (no `0x2e`, no finger-detect); differs only in the
    /// line-update DAT lines A/B/C sourced from [`crate::calibration::CalResults`].
    pub fn upload_cmd_prod33_sync_with_cal(
        &self,
        factory_calibration_values: &[u8],
        cal: &crate::calibration::CalResults,
        frames: u32,
    ) -> Option<Vec<u8>> {
        self.upload_cmd_prod33_sync_body(
            factory_calibration_values,
            &[],
            frames,
            cal.step3_diff.as_deref(),
            cal.line_c_source(),
        )
    }

    fn upload_cmd_prod33_sync_body(
        &self,
        factory_calibration_values: &[u8],
        calib_data: &[u8],
        frames: u32,
        step3_diff: Option<&[u8]>,
        step6_dark: Option<&[u8]>,
    ) -> Option<Vec<u8>> {
        // calibrate=true ⇒ prod33_body drops the 0x2e recon + finger-detect chunks (recon_flags /
        // finger_detect are then moot) — the frames-sync/CALIBRATE arm the host cf640 path expects.
        let body = self.prod33_body(
            factory_calibration_values,
            calib_data,
            true,
            line_update::RECON_FLAGS_DEFAULT,
            false,
            MeasuredCal { step3_diff, step6_dark, baseline_frame: None },
            false,
        )?;
        // Stream/CALIBRATE arm: the DLL writes field8 = line_width + 8 = 152 into the 0x02 header
        // (`syna_build_capture_cmd02@0x180086110`, proven by the EP-0x82 recv buffer = req_lines×152 =
        // 51224), NOT the flex `bytes_per_line` (160) the image arm uses.
        Some(frame_cmd_02(
            &body,
            self.sync_line_stride() as u16,
            self.stream_req_lines(frames),
        ))
    }

    /// `CALIBRATE`-mode arm: a finger-less blank capture (no `0x26`) with `req_lines =
    /// calibration_frames*lines_per_frame + 1`, carrying the accumulated `calib_data`. Drives the
    /// [`crate::calibrate::Calibrator`] loop. NON-destructive (no flash/DB writes).
    pub fn upload_cmd_calibrate(
        &self,
        factory_calibration_values: &[u8],
        calib_data: &[u8],
        calibration_frames: usize,
        step3_diff: Option<&[u8]>,
    ) -> Option<Vec<u8>> {
        // CALIBRATE omits the 0x2e + finger-detect chunks, so recon_flags/finger_detect are moot.
        // `step3_diff` is step-3's measured per-line array — without it DAT-A/B fall back to
        // `DAT_CAL_2449` (28 B packed each → 0x43 = 136 B); with it → ~35 B packed (152 B).
        let body = self.prod33_body(
            factory_calibration_values,
            calib_data,
            true,
            line_update::RECON_FLAGS_DEFAULT,
            false,
            MeasuredCal { step3_diff, ..MeasuredCal::default() },
            true,
        )?;
        // Same as the sync arm: CALIBRATE 0x02 header uses field8 = line_width + 8 = 152, not 160.
        Some(frame_cmd_02(
            &body,
            self.sync_line_stride() as u16,
            self.stream_req_lines(calibration_frames as u32),
        ))
    }

    /// Step-6 dark-field capture arm (`sync_frames=1` on 0x2449). Calibration bootstrap only —
    /// stream capture uses [`Self::upload_cmd_prod33_sync`] / [`Self::upload_cmd_prod33_sync_with_cal`]
    /// with [`STREAM_DEFAULT_SYNC_FRAMES`] or caller-provided `frames ≥ 1`.
    pub fn upload_cmd_cal_step6_dark(
        &self,
        factory_calibration_values: &[u8],
        step3_diff: Option<&[u8]>,
    ) -> Option<Vec<u8>> {
        // Frame count is per-subtype ([`Self::calibration_frames`]): 3 on the 0x0199 family (req_lines
        // 673), 1 on 0x2449. Must match the read budget in `session_cal::capture_dark_frame`.
        self.upload_cmd_calibrate(
            factory_calibration_values,
            &[],
            self.calibration_frames() as usize,
            step3_diff,
        )
    }

    /// Step-7 settle arm (`req_lines=0`, full measured line-update fold). Calibration bootstrap only.
    pub fn upload_cmd_cal_step7_settle(
        &self,
        factory_calibration_values: &[u8],
        cal: &crate::calibration::CalResults,
    ) -> Option<Vec<u8>> {
        self.upload_cmd_prod33_sync_with_cal(
            factory_calibration_values,
            cal,
            CAL_STEP7_SETTLE_SYNC_FRAMES,
        )
    }
}


#[cfg(test)]
mod tests;
