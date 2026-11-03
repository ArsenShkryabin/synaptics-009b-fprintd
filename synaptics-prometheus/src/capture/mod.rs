//! Frame capture — the vendor `CCaptureImage` read modes and their teardowns.
//!
//! The WBDI capture engine (`syna_wbdi_capture_start@0x18001addc`) picks a read path from two fields
//! on the capture context — the **mode** (`ctx+0x88`, 2/3) and the **WOF** flag (`ctx+0xa0`). Each
//! path clocks frames off the sensor differently and pairs with a specific teardown/dearm. This
//! module models all of them: [`ReadMode`] names them, [`FrameCapturer`] drives the streaming/sync
//! read, [`assemble_polled_frame`] drives the polled `0x51` read, [`run_wof`] drives SCM WOF only,
//! [`wait_capture_finger_detect`] drives capture IRQ finger-detect, and [`FrameCapturer`] drives
//! and [`teardown_steps`] emits the correct dearm sequence per mode (Rule #6: data-driven, not a
//! 0x2449 special-case). See the [`ReadMode`] docs for the per-mode Ghidra anchors.
//!
//! Ground truth for the streaming/sync read below: `syna_capture_frames_sync @0x18006ae20`. Per frame
//! the driver does exactly this, in a re-arming loop:
//!   1. **register a receive buffer** (`FUN_180067720`: `ctx+0x68 = buf`, `ctx+0x60 = size`) — posted
//!      *before* arming so the transfer is ready when the sensor streams;
//!   2. **arm the `0x02` capture program** (`syna_cmd02_upload_capture_prog`) — **re-armed every
//!      frame**; the `0x0450 "capture already armed"` we hit earlier was re-arming *without* the
//!      clean stop in step 0, not a "one capture per session" limit;
//!   3. **one blocking transfer** (`FUN_1800682f0`→`FUN_1800f1e50`→`FUN_1800f8ed0`, transport-vtable
//!      request id `0x938ae010`) that fills the pre-posted buffer and returns the actual size.
//!
//! So a frame is a *pre-posted buffer + a single blocking read per arm* — NOT `get_prg_status2`
//! polling and NOT an ad-hoc read-after-arm race. This module encodes that orchestration; the
//! [`CaptureIo`] impl owns the live protocol (stop/drain, tunnel the `0x02`, EP-0x82 read).
//!
//! This is the *raw* frame off the wire. Turning it into a de-scrambled image is [`crate::reconstruct`].

use crate::error::Result;
use crate::pre_arm::PreArmMode;

/// One capture cycle over a live session. Kept as a trait so the engine is unit-testable with a
/// mock and the transport/TLS details stay in the caller (mirrors [`crate::calibrate::CalibrateIo`]).
pub trait CaptureIo {
    /// Stop any in-flight capture (`0x04`) and drain stale interrupts, so the next [`Self::arm`]
    /// is accepted (else `0x0450`). Corresponds to the cleanup before each `frames_sync` iteration.
    fn stop(&mut self) -> Result<()>;
    /// Arm one capture by uploading the framed `0x02` program. Returns the sensor status word
    /// (`0x0000`/`0x0412` == armed OK). The command is built by the caller
    /// (e.g. [`crate::capture_prog::CaptureConfig::upload_cmd_prod33_calibrated`]).
    fn arm(&mut self, cmd: &[u8]) -> Result<u16>;
    /// Pre-arm ROM config (`Some`) → stop → arm. `None` skips the pre-arm entirely (stop → arm) —
    /// the DLL only pre-arms the identify/enroll/read-dispatch path, NEVER calibration frames
    /// (`syna_lib_calibration_step` never calls `syna_capture_send_pre_arm_rom_config`; sending it per
    /// calibration frame gets the sensor's second `0x06` rejected `0x04aa`). Default mock path skips
    /// pre-arm regardless. ghidra: `syna_capture_identify_enroll@0x180053400`.
    fn arm_with_pre(&mut self, cmd: &[u8], pre_arm: Option<PreArmMode>) -> Result<u16> {
        let _ = pre_arm;
        self.stop()?;
        self.arm(cmd)
    }
    /// Blocking read of one raw frame into the pre-sized buffer (vendor: EP-0x82, request
    /// `0x938ae010`). Returns the bytes actually transferred (may be empty on timeout).
    fn read_frame(&mut self, frame_size: usize) -> Result<Vec<u8>>;
}

/// Frame geometry + the capture orchestration. To match the DLL's EP-0x82 receive buffer (and pass
/// [`crate::capture::CaptureIo::read_frame`]'s length check), construct this from the **wire** geometry
/// — `bytes_per_line` = the wire stride ([`crate::capture_prog::CaptureConfig::sync_line_stride`], 152
/// for 0x2449) and `lines_per_frame` = the armed [`crate::capture_prog::CaptureConfig::stream_req_lines`]
/// (which includes the `+1` guard) — **not** the 0x02-command `bytes_per_line` (160) / `lines_2d`.
/// Then [`Self::frame_size`] equals [`crate::capture_prog::CaptureConfig::stream_buffer_size`].
#[derive(Debug, Clone, Copy)]
pub struct FrameCapturer {
    pub bytes_per_line: usize,
    pub lines_per_frame: usize,
}

/// A raw frame plus the status of the arm that produced it.
#[derive(Debug, Clone)]
pub struct RawFrame {
    pub arm_status: u16,
    pub bytes: Vec<u8>,
}

impl RawFrame {
    /// Whether the arm reported OK (`0x0000` or `0x0412`) and any bytes came back.
    pub fn is_ok(&self) -> bool {
        matches!(self.arm_status, 0x0000 | 0x0412 | 0x0450) && !self.bytes.is_empty()
    }
}

impl FrameCapturer {
    pub fn new(bytes_per_line: usize, lines_per_frame: usize) -> Self {
        Self {
            bytes_per_line,
            lines_per_frame,
        }
    }

    /// Expected raw frame size = `bytes_per_line * lines_per_frame`. This is the buffer the vendor
    /// registers at `ctx+0x60` before arming.
    pub fn frame_size(&self) -> usize {
        self.bytes_per_line * self.lines_per_frame
    }

    /// One capture cycle: (optional pre-arm) → stop → arm → blocking read (`frames_sync` inner body).
    /// `arm_cmd` is the framed `0x02` upload. `pre_arm = None` skips the pre-arm (calibration frames —
    /// see [`CaptureIo::arm_with_pre`]).
    pub fn capture_one<IO: CaptureIo>(
        &self,
        io: &mut IO,
        arm_cmd: &[u8],
        pre_arm: Option<PreArmMode>,
    ) -> Result<RawFrame> {
        let arm_status = io.arm_with_pre(arm_cmd, pre_arm)?;
        let bytes = if matches!(arm_status, 0x0000 | 0x0412 | 0x0450) {
            io.read_frame(self.frame_size())?
        } else {
            Vec::new()
        };
        Ok(RawFrame { arm_status, bytes })
    }

    /// Like [`Self::capture_one`] with [`PreArmMode::Standard`].
    pub fn capture_one_standard<IO: CaptureIo>(
        &self,
        io: &mut IO,
        arm_cmd: &[u8],
    ) -> Result<RawFrame> {
        self.capture_one(io, arm_cmd, Some(PreArmMode::Standard))
    }

    /// One capture cycle with NO `0x04` stop and NO pre-arm — just `arm` → blocking read. This matches
    /// python-validity's / the DLL step-6 calibrate loop, which sends the accumulate arms back-to-back
    /// with no teardown between them (a stop before a folded frames-sync CALIBRATE arm faults the 009a
    /// die — verified: byte-correct fold + stop → reset; no stop → accepted).
    pub fn capture_one_no_stop<IO: CaptureIo>(&self, io: &mut IO, arm_cmd: &[u8]) -> Result<RawFrame> {
        let arm_status = io.arm(arm_cmd)?;
        let bytes = if matches!(arm_status, 0x0000 | 0x0412 | 0x0450) {
            io.read_frame(self.frame_size())?
        } else {
            Vec::new()
        };
        Ok(RawFrame { arm_status, bytes })
    }

    /// Capture `n` frames, re-arming each (the `frames_sync` do-while). Stops on the first arm that
    /// reports an error status; returns whatever full frames were collected before that.
    pub fn capture_n<IO: CaptureIo>(
        &self,
        io: &mut IO,
        arm_cmd: &[u8],
        n: usize,
        pre_arm: Option<PreArmMode>,
    ) -> Result<Vec<RawFrame>> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let f = self.capture_one(io, arm_cmd, pre_arm)?;
            let armed_ok = matches!(f.arm_status, 0x0000 | 0x0412);
            out.push(f);
            if !armed_ok {
                break;
            }
        }
        Ok(out)
    }
}

/// DLL geometry for one EP-0x82 frames-sync/CALIBRATE transfer.
///
/// This layout is deliberately distinct from [`PolledFrameHeader`]: EP-0x82 has fixed-stride wire
/// lines and no frame header, while `0x51` has a frame header and a flat body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncFrameLayout {
    /// Pixel/data bytes after the fixed 8-byte wire-line header.
    pub line_width: usize,
    /// Destination rows after interleave averaging.
    pub lines_2d: usize,
    /// Consecutive raw lines averaged into one destination row.
    pub repeat_multiplier: usize,
    /// Complete raw frames requested from the sensor.
    pub frames: usize,
}

impl SyncFrameLayout {
    pub const USB_PACKET_SIZE: usize = 0x40;

    pub fn wire_stride(self) -> usize {
        self.line_width + crate::capture_prog::SYNC_LINE_HEADER
    }

    pub fn lines_per_frame(self) -> Option<usize> {
        self.lines_2d.checked_mul(self.repeat_multiplier)
    }

    pub fn base_req_lines(self) -> Option<usize> {
        self.lines_per_frame()?.checked_mul(self.frames)
    }

    /// DLL short-packet guard from `syna_capture_read_dispatch@0x18006de00`: append one wire line
    /// only when the unpadded transfer length is an exact multiple of the 64-byte USB packet size.
    /// Step-7 settle arms pass `frames=1` → same `req_lines` guard as step 6 (`113` on 0x2449).
    pub fn req_lines(self) -> Option<usize> {
        if self.frames == 0 {
            return Some(0);
        }
        let base = self.base_req_lines()?;
        let bytes = base.checked_mul(self.wire_stride())?;
        base.checked_add(usize::from(bytes % Self::USB_PACKET_SIZE == 0))
    }

    pub fn buffer_size(self) -> Option<usize> {
        self.req_lines()?.checked_mul(self.wire_stride())
    }

    /// Average `repeat_multiplier` consecutive wire lines into each destination row (column-wise).
    fn average_line_groups(self, frame: &[u8], stride: usize) -> Option<Vec<u8>> {
        if self.repeat_multiplier < 2 || self.lines_2d == 0 {
            return None;
        }
        let lines_per_frame = self.lines_per_frame()?;
        let need = lines_per_frame.checked_mul(stride)?;
        if frame.len() < need {
            return None;
        }
        let mut out = Vec::with_capacity(self.lines_2d.checked_mul(stride)?);
        for row in 0..self.lines_2d {
            let first_line = row.checked_mul(self.repeat_multiplier)?;
            for col in 0..stride {
                let mut sum = 0usize;
                for repeat in 0..self.repeat_multiplier {
                    let line = first_line.checked_add(repeat)?;
                    sum = sum.checked_add(
                        *frame.get(line.checked_mul(stride)?.checked_add(col)?)? as usize,
                    )?;
                }
                out.push((sum / self.repeat_multiplier) as u8);
            }
        }
        Some(out)
    }

    /// `syna_frame_line_average@0x180099c70`'s repeat>=2 branch: skip raw frame zero, then average
    /// each group of `repeat_multiplier` consecutive lines from frame one, column-for-column.
    /// The returned rows retain the 8-byte wire header because the DLL averages all stride columns;
    /// reconstruction excludes it later via the capture program's `0x42 offset=8`.
    pub fn average_second_frame(self, raw: &[u8]) -> Option<Vec<u8>> {
        if self.frames < 2 {
            return None;
        }
        let stride = self.wire_stride();
        let lines_per_frame = self.lines_per_frame()?;
        let frame_bytes = lines_per_frame.checked_mul(stride)?;
        let frame = raw.get(frame_bytes..frame_bytes.checked_mul(2)?)?;
        self.average_line_groups(frame, stride)
    }

    /// Step-6 dark capture (`sync_frames=1`): one frame in the buffer — average within it (no
    /// frame-zero skip). Matches `syna_frame_line_average` when `param_5==1` on 0x2449: the DLL
    /// returns early without skipping, so the single frame's line pairs are averaged in place.
    pub fn average_single_frame(self, raw: &[u8]) -> Option<Vec<u8>> {
        if self.frames != 1 {
            return None;
        }
        let stride = self.wire_stride();
        let lines_per_frame = self.lines_per_frame()?;
        let frame = raw.get(..lines_per_frame.checked_mul(stride)?)?;
        self.average_line_groups(frame, stride)
    }
}

/// DLL-declared polled `0x51` geometry (`syna_capture_image@0x180099540`).
///
/// Distinct from [`SyncFrameLayout`]: polled frames carry a firmware header and a flat
/// `line_width × lines_2d` body; the DLL re-lines into `dest_stride = line_width + 8` with
/// synthesized zero headers. All widths come from [`crate::capture_prog::SensorTypeInfo`] /
/// `g_flex_params_table` — never hard-coded per PID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolledFrameLayout {
    /// Imaged columns (`flex[0x32]` / frame-header `width`).
    pub line_width: usize,
    /// Destination rows (`flex[0x12]` / `0x2f` chunk / frame-header `height`).
    pub lines_2d: usize,
}

impl PolledFrameLayout {
    /// Build from the flex-params row + the selected program's `0x2f` line count.
    pub fn from_type_info(ti: &crate::capture_progs_9b::SensorTypeInfo, lines_2d: u32) -> Self {
        Self {
            line_width: ti.line_width as usize,
            lines_2d: lines_2d as usize,
        }
    }

    /// Flat body bytes the DLL reads (`width × height`).
    pub fn body_len(self) -> Option<usize> {
        self.line_width.checked_mul(self.lines_2d)
    }

    /// 152-stride dest row (`line_width + 8`); `syna_capture_image` prepends 8 zero bytes.
    pub fn dest_stride(self) -> usize {
        self.line_width + crate::capture_prog::SYNC_LINE_HEADER
    }

    /// Host cf640 blocks per line when applied to the flat body (`line_width / 16`).
    /// ghidra: `0x42` chunk `length` = `flex[0x32]`. The polled *read* never calls the stream cf640,
    /// but the DLL de-spreads the polled frame in the matcher IR-recon (`syna_ir_recon_condition_frame`
    /// mode 2 → `transform16`) — same kernel, downstream of the read. See `docs/capture/0x51-conditioning.md`.
    pub fn descramble_blocks_per_line(self) -> usize {
        crate::reconstruct::blocks_per_line_from_width(self.line_width as u16)
    }

    /// Descrambled raster width (`blocks × 16`); equals `line_width` when divisible by 16.
    pub fn descramble_width(self) -> usize {
        self.descramble_blocks_per_line() * crate::reconstruct::TIMESLOTS_PER_BLOCK
    }
}

// =================================================================================================
// Matcher submode (`nMatcher_submode`) — vfmCapture frame reader selection
// =================================================================================================

/// DLL `syna_eiv_config.nMatcher_submode` @ `dev+0x1e0` → `CCaptureImage+0x88` read_mode.
/// Drives `vfmCapture@0x180053bb0` reader fork (Ghidra decompile 2026-07-22).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u16)]
pub enum MatcherSubmode {
    /// EP-0x82 bulk via `syna_read_frame_blocking` (`read_mode==0/1` caps row).
    StreamEnroll = 1,
    /// `syna_read_frame_chunk@0x18005cf00` — wire `0x51` (identify default).
    #[default]
    PolledIdentify = 2,
    /// `syna_scs_read_frame_chunk_alt@0x18005d090` — SCS idx `0x31`, wire `0x78`.
    PolledEnrollAlt = 3,
}

impl MatcherSubmode {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::StreamEnroll),
            2 => Some(Self::PolledIdentify),
            3 => Some(Self::PolledEnrollAlt),
            _ => None,
        }
    }

    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Mirror `syna_eiv_set_matcher_submode@0x18001cde4` when `storage_mode == 1`.
    ///
    /// `caps_9` / `caps_10` are enroll-session status bytes (`param_2+9`, `+10`); on 0x2449 ROM
    /// status these are major/minor class bytes (`0x06`, `0x14`) — **not** the `caps[9]==6` gate,
    /// so this SKU always yields [`Self::PolledIdentify`] (`read_mode=2`).
    pub fn from_enroll_session_caps(
        storage_mode: u8,
        caps_9: u8,
        caps_10: u8,
        session_flags_33: u8,
    ) -> Self {
        if storage_mode != 1 {
            return Self::PolledIdentify;
        }
        const CAPS9_STREAM_ENROLL_CLASS: u8 = 6;
        const CAPS10_SUBMODE3_THRESHOLD: u8 = 10;
        const CAPS10_SUBMODE1_MAX: u8 = 7;
        const TABLE_BIT_SHIFT: u8 = 0x4a;
        const SESSION_FLAGS_WOF_MASK: u8 = 0x0a;

        if caps_9 == CAPS9_STREAM_ENROLL_CLASS
            && caps_10 < CAPS10_SUBMODE1_MAX
            && ((TABLE_BIT_SHIFT >> (caps_10 & 0x1f)) & 1) != 0
            && (session_flags_33 & SESSION_FLAGS_WOF_MASK) != SESSION_FLAGS_WOF_MASK
        {
            if caps_10 < CAPS10_SUBMODE3_THRESHOLD {
                Self::StreamEnroll
            } else {
                Self::PolledEnrollAlt
            }
        } else {
            Self::PolledIdentify
        }
    }

    /// Typical 0x2449 provisioned Hello path (`status bytes 8=0x06`, `9=0x14`).
    pub fn for_subtype_2449_provisioned() -> Self {
        Self::from_enroll_session_caps(1, 0x14, 0x00, 0x01)
    }
}

/// Capture-complete result byte from `syna_scs_query_capture_result@0x18005d970` (mapped in wrapper).
pub const CAPTURE_RESULT_DONE: u8 = 1;

/// Build wire command for SCS idx `0x31` / `syna_cmd_78_set_u32_param@0x18008bba0`.
pub const fn frame_chunk_alt_cmd(size: u32) -> [u8; 5] {
    let b = size.to_le_bytes();
    [
        crate::proto::Opcode::SetU32Param as u8,
        b[0],
        b[1],
        b[2],
        b[3],
    ]
}

/// Parse one alt-chunk (`0x78`) tunnel response per `syna_scs_alt_frame_chunk_recv_cb@0x180062cc0`.
///
/// On success returns `(copied_len, payload_after_u32_prefix)` within the sensor payload slice.
pub fn parse_alt_chunk_payload(reply: &[u8]) -> Option<(u32, &[u8])> {
    if polled_status(reply) != frame_status::WIRE_OK {
        return None;
    }
    let sp = reply.get(POLLED_SENSOR_PAYLOAD_OFF..)?;
    if sp.len() <= 4 {
        return Some((0, &[]));
    }
    let mut len = u32::from_le_bytes(sp[0..4].try_into().ok()?);
    let body = &sp[4..];
    if len as usize > body.len() {
        len = body.len() as u32;
    }
    Some((len, &body[..len as usize]))
}


mod polled;
pub use polled::*;

mod finger_detect;
pub use finger_detect::*;
mod control;
pub use control::*;

mod driver;
pub use driver::*;
#[cfg(test)]
mod tests;
