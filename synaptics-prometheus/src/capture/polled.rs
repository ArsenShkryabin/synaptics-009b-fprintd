//! Polled `0x51` frame read — assembles ONE frame that the sensor streams across MULTIPLE chunk
//! reads following a single arm: the frame header, the assemblers, and reference-cell scanning.
//! Extracted from the capture module; uses its `MatcherSubmode` + `parse_alt_chunk_payload` via
//! `super`, re-exported by `mod.rs` so `capture::{assemble_polled_frame, PolledFrame, …}` paths are
//! unchanged.
//!
//! # There are TWO `0x51` read contracts — do not conflate them
//!
//! `syna_read_frame_chunk@0x18005cf00` has exactly two callers in the DLL, and they disagree about
//! both the read sequence and which status codes are fatal:
//!
//! | | **still imaging** | **live identify/enroll** |
//! |---|---|---|
//! | function | `syna_capture_image@0x180099540` | `vfmCapture@0x180053bb0`, read_mode 2 |
//! | assembler | [`assemble_polled_frame_dll_faithful`] | [`assemble_polled_frame_vfm`] |
//! | disposition | [`frame_status::poll_disposition_still`] | [`frame_status::vfm_poll_event`] |
//! | retries on | `0x192`/`0x193` only; all else aborts | also `0x196`/`0x197`/`0x198`; `0x195` stops cleanly |
//! | frame size | parsed from a `0x10` header read | supplied by the caller (`session+0x20`) |
//!
//! Applying the still contract to the identify path is a real bug, not a nuance: it aborts on
//! `0x197 IMGPROC_FINGER_DETECTED`, which is exactly the state a finger arriving produces.
//! [`assemble_polled_frame_alt`] is a third, narrower shape for read_mode 3 (`0x31`/wire `0x78`),
//! which `syna_eiv_set_matcher_submode@0x18001cde4` can never select on this build.

use super::*;
// =================================================================================================
//
// Wire mechanics shared by both contracts: `syna_read_frame_chunk` sends `0x51 <u32 size>` and the
// sensor advances an INTERNAL CURSOR per read (there is no offset in the request) — so consecutive
// reads return consecutive slices of the same frame (re-polling without re-arming walks past the
// frame end, the "blocks jump" we observed live).
//
// Host-tunnel wire framing of each `0x51` response: `[status:u16][payload_len:u16][rsvd:u16][payload]`.
// The FIRST response's payload begins with the 12-byte frame header `[height:u16, width:u16,
// raw_lines:u16, 8, 0, 8]`; continuation responses (cursor past the header) carry pure body.

/// Byte offset of the sensor payload within a `0x51` host-tunnel response: `status(2)+payload_len(2)
/// +rsvd(2)`. (`syna_capture_image` measured framing, live 0x2449 2026-07.)
pub const POLLED_SENSOR_PAYLOAD_OFF: usize = 6;
/// Length of the frame header that prefixes the FIRST response's payload: `height,width,raw_lines,8,
/// 0,8` = 6×u16. Body starts after it. (`syna_read_frame_chunk` delivers this as its 16-byte read;
/// the host tunnel splits the 4-byte len/rsvd off, leaving 12.)
pub const POLLED_FRAME_HEADER_LEN: usize = 12;
/// Upper bound on a plausible frame dimension. A cursor-drifted / non-frame-aligned `0x51` read
/// (e.g. polling without re-arming) parses garbage `width`/`height` from mid-stream bytes; anything
/// beyond this is rejected so the assembler never returns a shifted/garbage frame.
pub const MAX_POLLED_FRAME_DIM: usize = 4096;

/// Maximum bytes requested per `0x51` body chunk (`syna_capture_image@0x180099540`).
pub const FRAME_CHUNK_MAX: usize = 0x2000;
/// DLL header read size: 16 bytes (`local_80` in `syna_capture_image@0x180099540`); only the first
/// 12 are the fw header — bytes 12–15 overlap `body[0..4]`.
pub const DLL_HEADER_READ_BYTES: u32 = 0x10;
/// Build a `0x51` frame-chunk command with an arbitrary size argument.
pub const fn frame_chunk_cmd(size: u32) -> [u8; 5] {
    let b = size.to_le_bytes();
    [
        crate::proto::Opcode::GetPrgStatus as u8,
        b[0],
        b[1],
        b[2],
        b[3],
    ]
}

/// Poll-until-ready chunk command (alias).
pub const POLL_FRAME_CHUNK: [u8; 5] = frame_chunk_cmd(0);
/// DLL header-read chunk command.
pub const HEADER_FRAME_CHUNK: [u8; 5] = frame_chunk_cmd(DLL_HEADER_READ_BYTES);

/// The frame-chunk read command: `GetPrgStatus <u32 size = 0x2000>` — one polled read of up to
/// `0x2000` stream bytes from the sensor's advancing cursor (`syna_read_frame_chunk@0x18005cf00`).
pub const READ_FRAME_CHUNK: [u8; 5] = frame_chunk_cmd(FRAME_CHUNK_MAX as u32);

/// Wire-level `0x51` poll status words (first u16 of the host-tunnel reply) and their decode to the
/// firmware result enum.
///
/// The tunnel reads the **wire** word (`0x0000`, `0x0001`, …); the DLL runs it through
/// `syna_wire_status_to_code@0x180087610` before the matcher sees the **internal** code. Those
/// internal codes are exactly [`VcsResult`] (base-100, IMGPROC group) — so what the poll loop calls
/// "busy" is really a sequence of distinct image-pipeline / finger-acquisition states
/// (`0x192 IMGPROC_IN_PROGRESS`, `0x193 IMGPROC_FINGER_SETTLED`, `0x195..0x198` finger states).
/// [`poll_result`] reproduces that wire→internal mapping so the loop classifies by *meaning*
/// (`VcsResult::is_ok` / `is_benign` / `is_error`) rather than by a bare `u16`.
pub mod frame_status {
    use crate::proto::VcsResult;

    /// Wire OK (`syna_wire_status_to_code` → internal `0`).
    pub const WIRE_OK: u16 = 0x0000;
    /// Second wire OK (`0x0412` → internal `0`).
    pub const WIRE_OK_ALT: u16 = 0x0412;
    /// Third wire code mapping to internal `0`: "nothing to commit", treated as success.
    pub const WIRE_OK_NOTHING_TO_COMMIT: u16 = 0x0491;
    /// Fourth wire code mapping to internal `0` (type-1 sibling of `0x05cb`).
    pub const WIRE_OK_TYPE1: u16 = 0x05cc;
    /// `0x0537` → internal `0x194 IMGPROC_NO_IMAGE_CAPTURED`. Terminal on **every** path; the
    /// recon=8 still arm settles here forever with no finger.
    pub const WIRE_NO_IMAGE_CAPTURED: u16 = 0x0537;

    /// Wire codes the **still** poll loop retries on (`0x0001`→`0x192 IMGPROC_IN_PROGRESS`,
    /// `0x0002`→`0x193 IMGPROC_FINGER_SETTLED`). See [`poll_disposition_still`]. The identify path
    /// has a wider set — see [`vfm_poll_event`].
    pub const WIRE_RETRY: &[u16] = &[0x0001, 0x0002];

    /// Decode a `0x51`-poll **wire** status word to its internal firmware result ([`VcsResult`]),
    /// reproducing `syna_wire_status_to_code@0x180087610`. Returns `None` for a wire word outside
    /// the known set (the DLL's `default:` arm, which yields internal `0xca`). NOTE the mapping uses
    /// the **later-revision** `VcsResult` naming (see `VcsResult` provenance caveat); the
    /// wire→internal pairing itself is verified in the 009b DLL.
    ///
    /// Decoding a code here does NOT tell you what the loop does with it — that is path-dependent:
    /// [`poll_disposition_still`] for `syna_capture_image`, [`vfm_poll_event`] for the identify
    /// pump. There is deliberately **no wire `0x0003`**: the DLL switch has no `case 3`.
    pub fn poll_result(wire: u16) -> Option<VcsResult> {
        use VcsResult::*;
        Some(match wire {
            WIRE_OK | WIRE_OK_ALT | WIRE_OK_NOTHING_TO_COMMIT | WIRE_OK_TYPE1 => Ok,
            0x0001 => ImgprocInProgress,           // internal 0x192
            0x0002 => ImgprocFingerSettled,        // internal 0x193
            0x0004 => ImgprocFingerRemoved,        // internal 0x195
            0x0005 => ImgprocFingerOnSensor,       // internal 0x196
            0x0006 => ImgprocFingerDetected,       // internal 0x197
            0x0007 => ImgprocAcquisitionNoImage,   // internal 0x198
            WIRE_NO_IMAGE_CAPTURED => ImgprocNoImageCaptured, // internal 0x194
            _ => return None,
        })
    }

    /// What the **still-imaging** poll loop should do with a `0x51` status — the explicit 3-way
    /// `syna_capture_image` branches on.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PollDisposition {
        /// Poll phase complete — proceed to the header/body reads.
        Ready,
        /// Still acquiring — sleep and poll again.
        Retry,
        /// Terminal for this arm — stop (do not keep polling).
        Abort,
    }

    /// Poll disposition for the **Path-1 still-imaging** read (`syna_capture_image@0x180099540`).
    ///
    /// `read_frame_chunk` returns the internal code; the loop is
    /// `if code==0 {ready} else if code!=0x192 && code!=0x193 {ABORT} else {retry}`. So **only**
    /// `IMGPROC_IN_PROGRESS` (0x192) and `IMGPROC_FINGER_SETTLED` (0x193) retry; every other code
    /// aborts, including the other IMGPROC states `0x194..0x198`.
    ///
    /// This is **narrower than the identify path on purpose** — do not generalise it. The live
    /// identify/enroll pump (`vfmCapture@0x180053bb0`, read_mode 2) treats `0x195..0x198` as
    /// non-fatal events; see [`vfm_poll_event`]. (The 6.0 "niseWrappers" build uses a frame-ready
    /// callback instead of a status poll, so this is the usdk5Core/009b contract we port.)
    pub fn poll_disposition_still(wire: u16) -> PollDisposition {
        match poll_result(wire) {
            Some(VcsResult::Ok) => PollDisposition::Ready,
            Some(VcsResult::ImgprocInProgress) | Some(VcsResult::ImgprocFingerSettled) => {
                PollDisposition::Retry
            }
            _ => PollDisposition::Abort,
        }
    }

    /// Still-path poll loop: keep polling only on `0x192`/`0x193`.
    pub fn is_poll_busy(s: u16) -> bool {
        poll_disposition_still(s) == PollDisposition::Retry
    }

    /// Still-path poll phase complete (result `Ok`) — proceed to header/body reads.
    pub fn is_poll_ready(s: u16) -> bool {
        poll_disposition_still(s) == PollDisposition::Ready
    }

    /// The `*out_status` event word `vfmCapture@0x180053bb0` reports to its pump
    /// (`syna_wbdi_read_fp_data@0x18001a818`). Named because the bit values are load-bearing: the
    /// pump switches on them directly.
    pub mod vfm_status {
        /// Frame complete — the pump returns.
        pub const FRAME_DONE: u16 = 0x0002;
        /// `0x193` finger-settled, and the first successful (latching) read.
        pub const FINGER_SETTLED: u16 = 0x0004;
        /// `0x195` finger removed — the pump tears down and returns.
        pub const FINGER_REMOVED: u16 = 0x0010;
        /// `0x196` finger on sensor — the pump keeps going AND disables its timeout.
        pub const FINGER_ON_SENSOR: u16 = 0x0020;
        /// `0x197` finger detected.
        pub const FINGER_DETECTED: u16 = 0x0040;
        /// `0x198` acquisition produced no image — the pump latches touch and keeps going.
        pub const ACQUISITION_NO_IMAGE: u16 = 0x0100;
        /// `0x192` still acquiring — the generic "keep pumping" word.
        pub const IN_PROGRESS: u16 = 0x4000;
    }

    /// What `vfmCapture@0x180053bb0` read_mode 2 does with a `0x51` status — the **identify/enroll**
    /// contract, which is materially different from [`poll_disposition_still`].
    ///
    /// Every IMGPROC state below is turned into a non-error (`local_98 = 0` in the decompile,
    /// verified in disassembly at `0x180053f43`–`0x18005403f`) and reported to the pump as an event
    /// word instead. Only unrecognised codes — including `0x194` — propagate as errors.
    ///
    /// **Every non-zero code, event or error, also truncates the frame** (`desc->total =
    /// desc->copied` at `0x180053f34`, *before* this dispatch). See [`Self::truncates_frame`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum VfmPollEvent {
        /// Internal `0` — the read returned chunk data.
        Data,
        /// `0x192` — keep pumping.
        InProgress,
        /// `0x193` — keep pumping.
        FingerSettled,
        /// `0x195` — stop cleanly; the pump tears the capture down. NOT an error.
        FingerRemoved,
        /// `0x196` — keep pumping, and the pump cancels its deadline.
        FingerOnSensor,
        /// `0x197` — keep pumping. (This is the code that a still-path reader wrongly aborts on.)
        FingerDetected,
        /// `0x198` — keep pumping; the pump latches touch.
        AcquisitionNoImage,
        /// Anything else (notably `0x194` ← wire `0x0537`) — propagates to the caller as an error.
        Error(u16),
    }

    impl VfmPollEvent {
        /// The `*out_status` word the DLL writes for this event, or `None` for [`Self::Error`]
        /// (which propagates the code instead of writing a status).
        pub fn out_status(self) -> Option<u16> {
            Some(match self {
                VfmPollEvent::Data => return None, // caller decides FRAME_DONE vs IN_PROGRESS
                VfmPollEvent::InProgress => vfm_status::IN_PROGRESS,
                VfmPollEvent::FingerSettled => vfm_status::FINGER_SETTLED,
                VfmPollEvent::FingerRemoved => vfm_status::FINGER_REMOVED,
                VfmPollEvent::FingerOnSensor => vfm_status::FINGER_ON_SENSOR,
                VfmPollEvent::FingerDetected => vfm_status::FINGER_DETECTED,
                VfmPollEvent::AcquisitionNoImage => vfm_status::ACQUISITION_NO_IMAGE,
                VfmPollEvent::Error(_) => return None,
            })
        }

        /// True while the pump should keep issuing reads.
        pub fn keeps_pumping(self) -> bool {
            matches!(
                self,
                VfmPollEvent::Data
                    | VfmPollEvent::InProgress
                    | VfmPollEvent::FingerSettled
                    | VfmPollEvent::FingerOnSensor
                    | VfmPollEvent::FingerDetected
                    | VfmPollEvent::AcquisitionNoImage
            )
        }

        /// `0x196` alone makes the pump drop its deadline (`param_3 = 0xffffffff`).
        pub fn cancels_timeout(self) -> bool {
            matches!(self, VfmPollEvent::FingerOnSensor)
        }

        /// `0x198` alone makes the pump latch touch (`uVar8 = 1`).
        pub fn latches_touch(self) -> bool {
            matches!(self, VfmPollEvent::AcquisitionNoImage)
        }

        /// The DLL writes `desc->total = desc->copied` for any non-zero code (`0x180053f34`).
        ///
        /// Note this only *survives* when the code also stops the pump: `vfmCapture` re-seeds
        /// `desc->total` from `session+0x20` at the top of every call, and it performs exactly one
        /// read per call. So a mid-frame busy poll truncates and is immediately undone; a
        /// [`Self::FingerRemoved`] or an error is what actually shortens the delivered frame.
        pub fn truncates_frame(self) -> bool {
            !matches!(self, VfmPollEvent::Data)
        }
    }

    /// Classify a `0x51` wire status for the **identify/enroll** (read_mode 2) reader.
    pub fn vfm_poll_event(wire: u16) -> VfmPollEvent {
        match poll_result(wire) {
            Some(VcsResult::Ok) => VfmPollEvent::Data,
            Some(VcsResult::ImgprocInProgress) => VfmPollEvent::InProgress,
            Some(VcsResult::ImgprocFingerSettled) => VfmPollEvent::FingerSettled,
            Some(VcsResult::ImgprocFingerRemoved) => VfmPollEvent::FingerRemoved,
            Some(VcsResult::ImgprocFingerOnSensor) => VfmPollEvent::FingerOnSensor,
            Some(VcsResult::ImgprocFingerDetected) => VfmPollEvent::FingerDetected,
            Some(VcsResult::ImgprocAcquisitionNoImage) => VfmPollEvent::AcquisitionNoImage,
            _ => VfmPollEvent::Error(wire),
        }
    }

    /// Poll disposition for the **read_mode 3 alt** reader (`0x31`/wire `0x78`) inside `vfmCapture`.
    ///
    /// Narrower than both siblings: only `0x192` is non-fatal, and it reports
    /// `0x0001` when the session's `stream_busy_flag` (`session+0x70`) is set, else
    /// [`vfm_status::IN_PROGRESS`]. Everything else propagates as an error.
    ///
    /// NOTE this path is **unreachable on the baseline build** — `syna_eiv_set_matcher_submode@
    /// 0x18001cde4` can never select read_mode 3 (its `caps[10] < 7` gate implies the `< 10` arm),
    /// so it is ported for family-completeness, not because this SKU uses it.
    pub fn alt_poll_disposition(wire: u16, stream_busy: bool) -> PollDisposition {
        match poll_result(wire) {
            Some(VcsResult::Ok) => PollDisposition::Ready,
            Some(VcsResult::ImgprocInProgress) => {
                let _ = stream_busy; // selects the reported word, not the disposition
                PollDisposition::Retry
            }
            _ => PollDisposition::Abort,
        }
    }

    /// The `*out_status` word the read_mode-3 branch reports for `0x192`.
    pub fn alt_in_progress_status(stream_busy: bool) -> u16 {
        if stream_busy { 0x0001 } else { vfm_status::IN_PROGRESS }
    }

    /// Legacy test aliases (wire codes, not internal `0x192`/`0x193`).
    pub const READY: u16 = WIRE_OK;
    pub const BUSY_A: u16 = 0x0001;
    pub const BUSY_B: u16 = 0x0002;
}

/// The complete six-word firmware header at the start of the first polled `0x51` payload.
///
/// Only [`Self::height`] and [`Self::width`] are consumed by
/// `syna_capture_image@0x180099540`; the DLL copies the other four words but never branches on
/// them. In particular, their presence does not imply per-row metadata in [`PolledFrame::body`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolledFrameHeader {
    /// DLL-declared reconstructed row count (`56` on subtype `0x2449`).
    pub height: u16,
    /// DLL-declared reconstructed column count (`144` on subtype `0x2449`).
    pub width: u16,
    /// Firmware acquisition field (`333` on subtype `0x2449`); ignored by the DLL.
    pub raw_line_count: u16,
    /// Informational value (`8` on subtype `0x2449`); ignored by the DLL.
    pub field_6: u16,
    /// Reserved/unknown (`0` on subtype `0x2449`); ignored by the DLL.
    pub field_8: u16,
    /// Informational value (`8` on subtype `0x2449`); ignored by the DLL.
    pub field_a: u16,
}

impl PolledFrameHeader {
    pub fn parse(payload: &[u8]) -> Option<Self> {
        let b = payload.get(..POLLED_FRAME_HEADER_LEN)?;
        let word = |off: usize| u16::from_le_bytes([b[off], b[off + 1]]);
        Some(Self {
            height: word(0),
            width: word(2),
            raw_line_count: word(4),
            field_6: word(6),
            field_8: word(8),
            field_a: word(10),
        })
    }

    pub fn body_len(self) -> Option<usize> {
        usize::from(self.width).checked_mul(usize::from(self.height))
    }
}

/// One polled `0x51` frame. The body is exactly `header.width * header.height` flat bytes according
/// to the DLL contract. It contains no host-visible row headers; alternate rasters such as the
/// measured `128×63` interpretation are diagnostic views of these same bytes, not wire framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolledFrame {
    pub header: PolledFrameHeader,
    pub body: Vec<u8>,
}

pub(crate) fn polled_status(r: &[u8]) -> u16 {
    if r.len() >= 2 {
        u16::from_le_bytes([r[0], r[1]])
    } else {
        0xffff
    }
}

/// Assemble one full polled frame from the sensor's multi-read `0x51` stream (one arm → N chunk
/// reads). `read_chunk` performs a single `0x51 <size>` tunnel and returns the raw response
/// (`[status][payload_len][rsvd][payload]`), or `None` on transport error. `keep_going` is polled
/// before every read and should return `false` past the caller's deadline (so a stuck/finger-gated
/// capture times out instead of hanging). Returns the assembled `width*height` body once complete,
/// or `None` on timeout / short / incomplete stream.
///
/// Mirrors `syna_capture_image@0x180099540`: poll-until-ready, read the header, then read body
/// chunks until `width*height`. For 0x2449 the whole 8064-byte body arrives in the first read; a
/// larger frame is transparently accumulated across continuation reads.
pub fn assemble_polled_frame(
    mut read_chunk: impl FnMut() -> Option<Vec<u8>>,
    mut keep_going: impl FnMut() -> bool,
) -> Option<PolledFrame> {
    // First read: poll (skipping busy) until a chunk with a header + some body arrives.
    let (mut body, header, total) = loop {
        if !keep_going() {
            return None;
        }
        let r = read_chunk()?;
        let s = polled_status(&r);
        if frame_status::is_poll_busy(s) {
            continue;
        }
        if !frame_status::is_poll_ready(s) {
            return None;
        }
        let sp = r.get(POLLED_SENSOR_PAYLOAD_OFF..)?;
        if sp.len() <= POLLED_FRAME_HEADER_LEN {
            continue; // status-only / no body yet — keep polling
        }
        let header = PolledFrameHeader::parse(sp)?;
        let height = usize::from(header.height);
        let width = usize::from(header.width);
        // Plausibility guard: a cursor-drifted / mid-stream read yields garbage dims — keep polling
        // for a frame-aligned header rather than returning a shifted frame.
        if width == 0
            || height == 0
            || width > MAX_POLLED_FRAME_DIM
            || height > MAX_POLLED_FRAME_DIM
        {
            continue;
        }
        let total = header.body_len()?;
        break (sp[POLLED_FRAME_HEADER_LEN..].to_vec(), header, total);
    };

    // Continuation reads (cursor advances, pure body) until the full frame is assembled.
    while body.len() < total {
        if !keep_going() {
            return None;
        }
        let r = read_chunk()?;
        let s = polled_status(&r);
        if frame_status::is_poll_busy(s) {
            continue;
        }
        if !frame_status::is_poll_ready(s) {
            break;
        }
        let cont = r.get(POLLED_SENSOR_PAYLOAD_OFF..)?;
        if cont.is_empty() {
            break;
        }
        body.extend_from_slice(cont);
    }

    if body.len() < total {
        return None; // incomplete — surface as no-frame rather than a torn image
    }
    body.truncate(total);
    Some(PolledFrame { header, body })
}

/// Polled-frame assembly strategy. [`PolledAssemblerStrategy::FastSingleRead`] matches the
/// historical viewer path (always `0x2000` reads). [`PolledAssemblerStrategy::DllFaithful`] mirrors
/// `syna_capture_image@0x180099540`: size-0 poll → `0x10` header read with 4-byte body overlap →
/// sized body chunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolledAssemblerStrategy {
    /// Always issue `READ_FRAME_CHUNK` (`0x2000`) — works on 0x2449 where the whole frame fits.
    #[default]
    FastSingleRead,
    /// Step-for-step DLL poll/header/body sequence for byte-level parity checks.
    DllFaithful,
}

/// **Still-imaging** assembly — the `syna_capture_image@0x180099540` sequence (Path 1, recon=8).
///
/// 1. Poll with `size=0` until wire status ready (`0x0000` / `0x0412`; retry only `0x0001`/`0x0002`).
/// 2. Read `size=0x10` into a 16-byte buffer; parse the 12-byte fw header; copy bytes 12–15 into
///    `body[0..4]` (the DLL `memcpy(body, local_80+6, 4)` overlap).
/// 3. Read body continuation chunks with `size=min(remaining, 0x2000)` until `width*height`.
///
/// **This is NOT the identify/enroll reader.** It is scoped to `syna_capture_image`, whose loop
/// aborts on every code outside `0x192`/`0x193` and which learns the frame size from the header
/// read in step 2. The live identify/enroll pump (`vfmCapture@0x180053bb0`, read_mode 2) has no
/// header read at all and treats `0x195..0x198` as events — use
/// [`assemble_polled_frame_vfm`] for that path.
pub fn assemble_polled_frame_dll_faithful(
    mut read_sized: impl FnMut(u32) -> Option<Vec<u8>>,
    mut keep_going: impl FnMut() -> bool,
) -> Option<PolledFrame> {
    // Phase 1: poll until ready (size-0 reads).
    loop {
        if !keep_going() {
            return None;
        }
        let r = read_sized(0)?;
        let s = polled_status(&r);
        if frame_status::is_poll_busy(s) {
            continue;
        }
        if frame_status::is_poll_ready(s) {
            break;
        }
        return None;
    }

    // Phase 2: 0x10-byte header read (12-byte fw header + first 4 body bytes overlap).
    let r = loop {
        if !keep_going() {
            return None;
        }
        let r = read_sized(DLL_HEADER_READ_BYTES)?;
        let s = polled_status(&r);
        if frame_status::is_poll_busy(s) {
            continue;
        }
        if frame_status::is_poll_ready(s) {
            break r;
        }
        return None;
    };

    let sp = r.get(POLLED_SENSOR_PAYLOAD_OFF..)?;
    if sp.len() < POLLED_FRAME_HEADER_LEN {
        return None;
    }
    let header = PolledFrameHeader::parse(sp)?;
    let width = usize::from(header.width);
    let height = usize::from(header.height);
    if width == 0
        || height == 0
        || width > MAX_POLLED_FRAME_DIM
        || height > MAX_POLLED_FRAME_DIM
    {
        return None;
    }
    let total = header.body_len()?;
    let mut body = vec![0u8; total];

    // Overlap: first up-to-4 body bytes delivered in the header read.
    let overlap = sp
        .len()
        .saturating_sub(POLLED_FRAME_HEADER_LEN)
        .min(4)
        .min(total);
    body[..overlap].copy_from_slice(&sp[POLLED_FRAME_HEADER_LEN..POLLED_FRAME_HEADER_LEN + overlap]);
    let mut filled = overlap;

    // Phase 3: body continuation chunks.
    while filled < total {
        if !keep_going() {
            return None;
        }
        let remaining = total - filled;
        let req = remaining.min(FRAME_CHUNK_MAX) as u32;
        let r = read_sized(req)?;
        let s = polled_status(&r);
        if frame_status::is_poll_busy(s) {
            continue;
        }
        if !frame_status::is_poll_ready(s) {
            break;
        }
        let cont = r.get(POLLED_SENSOR_PAYLOAD_OFF..)?;
        if cont.is_empty() {
            break;
        }
        let copy = cont.len().min(total - filled);
        body[filled..filled + copy].copy_from_slice(&cont[..copy]);
        filled += copy;
    }

    if filled < total {
        return None;
    }
    Some(PolledFrame { header, body })
}

/// Max bytes `vfmCapture` requests per read — `recv_buf_desc[+0x10]`, set to `0x2000` in
/// `syna_capture_identify_enroll@0x180053400`. Shared by the read_mode-2 and read_mode-3 branches.
pub const VFM_ALT_FRAME_BUF: u32 = 0x2000;

/// Assemble one frame the way the **live identify/enroll pump** does: `vfmCapture@0x180053bb0`
/// read_mode 2 (`0x51` over EP-0x81), driven by `syna_wbdi_read_fp_data@0x18001a818`.
///
/// This differs from [`assemble_polled_frame_dll_faithful`] in three ways that matter:
///
/// * **No `0x10` header read.** The expected frame size is supplied by the caller — the DLL takes
///   it from `session+0x20`, which the pump set from its own buffer allocation — so `total` is an
///   input here, not something parsed off the wire. The 12-byte fw header still arrives at the
///   front of the body stream and is split off at the end, as on the alt path.
/// * **Size-0 poll only while unlatched.** With `partial_read_flag` clear the request size is 0;
///   once a read succeeds the flag latches and every later request is
///   `min(0x2000, total - copied)`. `start_latched` lets the caller enter already-latched, which is
///   what the DLL does when the previous `*out_status` was `0x80` (a touch event) — in that case
///   the *first* read of the frame is a body read, not a poll.
/// * **Finger states are events, not aborts** — see [`frame_status::vfm_poll_event`]. And **every**
///   non-zero code truncates the frame to the bytes already copied (`desc->total = desc->copied`
///   at `0x180053f34`, before the status dispatch), which is why a finger-removed mid-frame yields
///   a short frame rather than an error.
///
/// Returns `None` on transport error, timeout, or a frame too short to contain its header.
pub fn assemble_polled_frame_vfm(
    total: usize,
    start_latched: bool,
    mut read_sized: impl FnMut(u32) -> Option<Vec<u8>>,
    mut keep_going: impl FnMut() -> bool,
) -> Option<PolledFrame> {
    let mut body: Vec<u8> = Vec::with_capacity(total);
    let mut latched = start_latched;
    // The DLL shortens desc->total on any non-zero code; `expected` tracks that live value.
    let expected = total;

    loop {
        if !keep_going() {
            return None;
        }
        let req = if latched {
            (expected.saturating_sub(body.len())).min(VFM_ALT_FRAME_BUF as usize) as u32
        } else {
            0
        };
        let r = read_sized(req)?;
        let event = frame_status::vfm_poll_event(polled_status(&r));

        if event.truncates_frame() {
            // The DLL writes `desc->total = desc->copied` on every non-zero code, but vfmCapture is
            // one read per call and re-seeds `desc->total` from `session+0x20` on entry — so the
            // truncation only SURVIVES when this is the code that stops the pump. Applying it on a
            // mid-frame busy poll would zero the target and stall the read.
            //
            // When it does stop us, the truncation needs no explicit step: `body` already holds
            // exactly the bytes that arrived, and the `truncate(declared)` below only ever shortens.
            if !event.keeps_pumping() {
                break; // FingerRemoved stops cleanly; Error yields whatever short frame we have.
            }
            continue;
        }

        // Code 0: a successful read. The first one only latches (the DLL reports FINGER_SETTLED
        // and does not consume a payload); afterwards the payload is body bytes.
        if !latched {
            latched = true;
            continue;
        }
        let chunk = r.get(POLLED_SENSOR_PAYLOAD_OFF..)?;
        if chunk.is_empty() {
            break;
        }
        body.extend_from_slice(chunk);
        // Complete on exact fill, or on a short chunk (the DLL's `local_78[0] < max_chunk` test).
        if body.len() >= expected || chunk.len() < req as usize {
            break;
        }
    }

    let header = PolledFrameHeader::parse(&body)?;
    let declared = header.body_len()?;
    if declared == 0 || declared > MAX_POLLED_FRAME_DIM * MAX_POLLED_FRAME_DIM {
        return None;
    }
    body.drain(0..POLLED_FRAME_HEADER_LEN);
    // A truncated frame keeps whatever arrived; a complete one is cut to the declared body length.
    body.truncate(declared);
    Some(PolledFrame { header, body })
}

/// The two sensor operations the read_mode-3 alt loop interleaves.
///
/// A trait rather than two closures because both operations need `&mut` on the same session, which
/// two `FnMut` parameters cannot express — this is what previously forced a duplicate copy of the
/// loop into `Session`. Same shape as [`CaptureIo`] next door.
pub trait AltFrameIo {
    /// One sized `0x78` alt frame-chunk read (`syna_scs_read_frame_chunk_alt@0x18005d090`).
    fn read_alt(&mut self, size: u32) -> Option<Vec<u8>>;
    /// One `syna_scs_query_capture_result@0x18005d970` state byte.
    fn query_result(&mut self) -> Option<u8>;
}

/// Assemble one frame via `read_mode==3` / `syna_scs_read_frame_chunk_alt@0x18005d090` (`0x78`).
///
/// Mirrors the `vfmCapture@0x180053bb0` alt branch: sized `0x78` reads copy into a flat buffer;
/// a zero-length copy triggers a capture-result query until [`CAPTURE_RESULT_DONE`].
///
/// NOTE this branch is unreachable on the baseline build — `syna_eiv_set_matcher_submode@
/// 0x18001cde4` cannot select read_mode 3 (its `caps[10] < 7` gate implies the `< 10` arm, so the
/// `3` case is dead). Ported for family-completeness.
pub fn assemble_polled_frame_alt(
    io: &mut impl AltFrameIo,
    mut keep_going: impl FnMut() -> bool,
) -> Option<PolledFrame> {
    let mut body = Vec::new();

    loop {
        if !keep_going() {
            return None;
        }
        // `min(max_chunk, total - copied)`, saturating: the previous form
        // `VFM_ALT_FRAME_BUF - body.len()` underflowed for every real frame, since an 8064-byte
        // body exceeds the 0x2000 buffer after the second chunk.
        let req = VFM_ALT_FRAME_BUF.saturating_sub(body.len() as u32).max(1);
        let r = io.read_alt(req)?;
        let (copied, chunk) = parse_alt_chunk_payload(&r)?;
        if copied == 0 {
            let state = io.query_result()?;
            if state == CAPTURE_RESULT_DONE {
                break;
            }
            continue;
        }
        body.extend_from_slice(chunk);
        if body.len() >= POLLED_FRAME_HEADER_LEN
            && let Some(header) = PolledFrameHeader::parse(&body)
            && let Some(total) = header.body_len()
            && body.len() >= POLLED_FRAME_HEADER_LEN + total
        {
            body.drain(0..POLLED_FRAME_HEADER_LEN);
            body.truncate(total);
            return Some(PolledFrame { header, body });
        }
    }

    if body.len() < POLLED_FRAME_HEADER_LEN {
        return None;
    }
    let header = PolledFrameHeader::parse(&body)?;
    let total = header.body_len()?;
    if body.len() < POLLED_FRAME_HEADER_LEN + total {
        return None;
    }
    body.drain(0..POLLED_FRAME_HEADER_LEN);
    body.truncate(total);
    Some(PolledFrame { header, body })
}

// NOTE: the read_mode dispatch lives in `Session::capture_vfm_polled` (`session/read.rs`), not in a
// free function here. read_mode 2 needs the expected frame size, which only the session knows (the
// DLL takes it from `session+0x20`); a free dispatcher would have to be handed it anyway, and the
// two readers need disjoint `&mut self` borrows the session can only satisfy one at a time.

/// Measured recurring 8-byte signature in 0x2449 polled bodies (`reconstruct.rs`, live 2026-07).
/// The DLL copies these as ordinary data — no strip/parse path exists.
pub const REFERENCE_CELL_SIGNATURE: [u8; 8] = [0x43, 0xC1, 0x44, 0x48, 0xBA, 0xBE, 0x43, 0x42];

/// One detected instance of [`REFERENCE_CELL_SIGNATURE`] in a row-major raster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferenceCellHit {
    pub row: usize,
    pub col: usize,
}

/// Scan a flat body re-strided at `width` for [`REFERENCE_CELL_SIGNATURE`] occurrences.
pub fn scan_reference_cells(body: &[u8], width: usize) -> Vec<ReferenceCellHit> {
    if width == 0 || body.len() < REFERENCE_CELL_SIGNATURE.len() {
        return Vec::new();
    }
    let height = body.len() / width;
    let sig = REFERENCE_CELL_SIGNATURE;
    let mut hits = Vec::new();
    for row in 0..height {
        let base = row * width;
        let row_slice = &body[base..base + width];
        for col in 0..row_slice.len().saturating_sub(sig.len() - 1) {
            if row_slice[col..col + sig.len()] == sig {
                hits.push(ReferenceCellHit { row, col });
            }
        }
    }
    hits
}

#[cfg(test)]
mod poll_result_tests {
    use super::frame_status::*;
    use crate::proto::VcsResult;

    #[test]
    fn wire_words_decode_to_vcs_result() {
        // All four wire words that syna_wire_status_to_code@0x180087610 maps to internal 0.
        for w in [WIRE_OK, WIRE_OK_ALT, WIRE_OK_NOTHING_TO_COMMIT, WIRE_OK_TYPE1] {
            assert_eq!(poll_result(w), Some(VcsResult::Ok));
            assert_eq!(poll_disposition_still(w), PollDisposition::Ready);
            assert!(is_poll_ready(w) && !is_poll_busy(w));
        }
        // Internal 0x192/0x193 confirm the VcsResult values match what we observed on 009b.
        assert_eq!(VcsResult::ImgprocInProgress.code(), 0x192);
        assert_eq!(VcsResult::ImgprocFingerSettled.code(), 0x193);
        // 0x0537 decodes rather than falling through to None by accident.
        assert_eq!(
            poll_result(WIRE_NO_IMAGE_CAPTURED),
            Some(VcsResult::ImgprocNoImageCaptured)
        );
        assert_eq!(VcsResult::ImgprocNoImageCaptured.code(), 0x194);
        // There is no `case 3` in the DLL switch — wire 0x0003 hits `default:` -> internal 0xca.
        assert_eq!(poll_result(0x0003), None);
    }

    #[test]
    fn still_path_retries_only_in_progress_and_finger_settled() {
        // syna_capture_image@0x180099540: ONLY 0x192/0x193 retry; everything else aborts.
        assert_eq!(poll_disposition_still(0x0001), PollDisposition::Retry);
        assert_eq!(poll_disposition_still(0x0002), PollDisposition::Retry);
        assert!(is_poll_busy(0x0001) && is_poll_busy(0x0002));
        for (w, r) in [
            (0x0004u16, VcsResult::ImgprocFingerRemoved),
            (0x0005, VcsResult::ImgprocFingerOnSensor),
            (0x0006, VcsResult::ImgprocFingerDetected),
            (0x0007, VcsResult::ImgprocAcquisitionNoImage),
        ] {
            assert_eq!(poll_result(w), Some(r)); // still observable...
            assert_eq!(poll_disposition_still(w), PollDisposition::Abort); // ...but aborts
            assert!(!is_poll_busy(w) && !is_poll_ready(w));
        }
        assert_eq!(poll_disposition_still(0x0003), PollDisposition::Abort);
        assert_eq!(
            poll_disposition_still(WIRE_NO_IMAGE_CAPTURED),
            PollDisposition::Abort
        );
    }

    /// The identify path is deliberately WIDER than the still path — this is the whole point of
    /// keeping the two dispositions apart (`vfmCapture@0x180053bb0`, read_mode 2).
    #[test]
    fn vfm_path_treats_finger_states_as_events_not_aborts() {
        use vfm_status::*;
        for (wire, ev, status) in [
            (0x0001u16, VfmPollEvent::InProgress, IN_PROGRESS),
            (0x0002, VfmPollEvent::FingerSettled, FINGER_SETTLED),
            (0x0004, VfmPollEvent::FingerRemoved, FINGER_REMOVED),
            (0x0005, VfmPollEvent::FingerOnSensor, FINGER_ON_SENSOR),
            (0x0006, VfmPollEvent::FingerDetected, FINGER_DETECTED),
            (0x0007, VfmPollEvent::AcquisitionNoImage, ACQUISITION_NO_IMAGE),
        ] {
            assert_eq!(vfm_poll_event(wire), ev, "wire {wire:#06x}");
            assert_eq!(ev.out_status(), Some(status), "wire {wire:#06x}");
            // Every non-zero code shortens the frame (desc->total = desc->copied @0x180053f34).
            assert!(ev.truncates_frame(), "wire {wire:#06x}");
        }
        // Keep pumping on everything except finger-removed.
        for w in [0x0001u16, 0x0002, 0x0005, 0x0006, 0x0007] {
            assert!(vfm_poll_event(w).keeps_pumping(), "wire {w:#06x}");
        }
        assert!(!vfm_poll_event(0x0004).keeps_pumping()); // FingerRemoved stops, but is NOT an error
        // The two side effects the pump takes on specific codes.
        assert!(vfm_poll_event(0x0005).cancels_timeout());
        assert!(vfm_poll_event(0x0007).latches_touch());
        // Data does not truncate; errors (incl. 0x0537 -> 0x194) propagate.
        assert!(!vfm_poll_event(WIRE_OK).truncates_frame());
        assert_eq!(
            vfm_poll_event(WIRE_NO_IMAGE_CAPTURED),
            VfmPollEvent::Error(WIRE_NO_IMAGE_CAPTURED)
        );
        assert!(!vfm_poll_event(WIRE_NO_IMAGE_CAPTURED).keeps_pumping());
    }

    /// The exact divergence that made the polled-parity KATs fail: wire `0x0006` is terminal for the
    /// still reader and a keep-going event for the identify reader.
    #[test]
    fn finger_detected_diverges_between_the_two_paths() {
        assert_eq!(poll_disposition_still(0x0006), PollDisposition::Abort);
        assert!(vfm_poll_event(0x0006).keeps_pumping());
    }

    #[test]
    fn alt_path_is_narrower_than_both() {
        // read_mode 3: only 0x192 is non-fatal.
        assert_eq!(alt_poll_disposition(WIRE_OK, false), PollDisposition::Ready);
        assert_eq!(alt_poll_disposition(0x0001, false), PollDisposition::Retry);
        for w in [0x0002u16, 0x0004, 0x0005, 0x0006, 0x0007] {
            assert_eq!(alt_poll_disposition(w, false), PollDisposition::Abort);
        }
        assert_eq!(alt_in_progress_status(true), 0x0001);
        assert_eq!(alt_in_progress_status(false), vfm_status::IN_PROGRESS);
    }
}
