//! Sensor calibration — the step we were missing. Before a sensor can image a finger usably, the
//! driver must capture **calibration frames** (blank, `CaptureMode::CALIBRATE`) and compute a
//! per-line dark-frame/gain correction (`calib_data`), which is then patched into every subsequent
//! capture's line-update. The vendor driver does this at `CBiometricDevice` ProcessPairing state 4;
//! python-validity does it in `sensor.open()` → `calibrate()`. Without it, captures are raw and
//! dominated by fixed-pattern noise, so finger-detect misbehaves and no clean image is produced.
//!
//! This module is the faithful port of python-validity `sensor.py` `clip`/`scale`/`add`/`average`/
//! `process_calibration_results`/`calibrate`. The pure math is here + unit-tested; the transport
//! (arming `CALIBRATE` `0x02` and reading the frames off EP-0x82) is injected via [`CalibrateIo`],
//! driven by [`Calibrator::run`].
//!
//! ⚠️ VENDOR DIVERGENCE (verified in Ghidra 2026-07-14): this is python-validity's **0x199-family**
//! calibration — a simple 3-iteration averaging loop. The Windows driver's *actual* 0x2449
//! calibration is a **10-step, capability-gated state machine** `syna_lib_calibration_step`
//! @0x180073270 (loop `syna_lib_run_calibration`@0x1800731d0; entry `CBiometricDevice_calibrateImpl`
//! → `syna_lib_calibrate`@0x18004d5f0 → `syna_lib_generate_calibration`@0x180066370). Steps are gated
//! on per-subtype bits `flex[0x1c]` and include a **subtype-0x2449-specific** WOE/finger-detect step
//! (case 6 uses value 200 for 0x2449 vs 100 default) and a **product-0x33-specific** step 9
//! (`FUN_180078c00`). So this port is a REASONABLE FIRST ATTEMPT to try live (like the community's
//! "alias unsupported type → 0x199" trick that got HP 0xd51 working), but it does NOT reproduce the
//! true 86C flow. If it under-calibrates, port the state machine (sub-routines FUN_180075100 /
//! 77ec0 / 77b90 / 76de0 / 78610 / 78c00 hold the real per-line scale/average — not yet decompiled).
//!
//! ## RAW EP-0x82 buffer stride: 152, NOT bytes_per_line=160 (resolved 2026-07 from live capture)
//! The CALIBRATE frame is streamed off EP-0x82 as `req_lines` lines, each **`line_width + 8` = 152
//! bytes** (8-byte line header + 144 data), NOT `SensorTypeInfo::bytes_per_line` = 160. Evidence,
//! cross-checked against `syna_frame_line_average@0x180099c70` (Ghidra, authoritative):
//!   * The observed read is **51224 B = 337 × 152** exactly (160 does not divide it). 337 =
//!     `req_lines = calibration_frames*lines_per_frame + 1 = 3*112 + 1`.
//!   * The DLL walks the raw buffer at `field8 = syna_prog_get_field(prog,8) = 152` (`param_4`), and
//!     skips one frame via `uVar1 = lines_per_frame(112) * field8(152) = 17024`. If the stride were
//!     160 that 17024 skip would be misaligned in a 152-strided buffer — the DLL only works at 152.
//!   * `bytes_per_line`(160)/`chunk 0x35` is the 0x02-command line width (sensor DMA/alloc), **not**
//!     the wire stride. Walking the 152-packed buffer at 160 drifts every dest row by
//!     `(160-152)*repeat_multiplier = 16` bytes — the observed −16 column/row diagonal drift.
//!   * The DLL dest stride is likewise `flex[0x32]+8 = line_width+8 = 152` (literal `+8`), so raw
//!     and cooked strides are equal; there is **no per-line trailer and no frame header**.
//!
//! So the raw stride is derived family-generically as `line_width + LINE_HEADER`, never 160.
//!
//! Geometry for our 0x2449 ("86C"): line_width=144 → raw/cooked stride=152, lines_2d=56,
//! repeat_multiplier=2 → lines_per_frame=112, lines_per_calibration_data=56 → interleave=2.
//! (SensorTypeInfo bytes_per_line=160 is the 0x02-cmd width, unused for the EP-0x82 walk.)
//! `calibration_frames`/
//! `iterations` are NOT known for 0x2449 (python-validity only defines 0x199=3/3, 0xdb=6/0, and has
//! no 0x2449 record at all); we default to the 0x199-derived 3/3 as a starting hypothesis — see
//! [`CalibrationParams::for_subtype`]. The `scale` divisor `0x22` is likewise per-device (0x199).
//!
//! NOTE: python-validity persists a "clean slate" to flash partition 6 and can reload `calib_data`
//! from it; our sensor's SPI flash is dark, so we compute `calib_data` fresh in RAM each session and
//! skip the flash persist/check entirely.

use crate::error::Result;

/// Per-line header size, both in the raw EP-0x82 stream and in the cooked calibration frame. This is
/// the literal `+8` the DLL adds in `syna_capture_and_reconstruct@0x1800984f0`
/// (`dest_stride = flex[0x32] + 8`) and the `0x42` recon chunk's `offset = 8` (the de-scramble skips
/// these 8 header bytes). The raw line stride the sensor streams is `line_width + LINE_HEADER`.
pub const LINE_HEADER: usize = 8;

/// Raw/cooked line stride for the calibration walk = `line_width + LINE_HEADER`. This is the DLL's
/// `field8` (`syna_prog_get_field(prog,8)`, = 152 for 0x2449), NOT `SensorTypeInfo::bytes_per_line`
/// (160). See the module docs for why 160 is wrong (it drifts each dest row by `8*repeat`).
pub fn line_stride(line_width: usize) -> usize {
    line_width + LINE_HEADER
}

// ---- Typed CALIBRATE line layout -------------------------------------------------------------
// The sensor prepends an 8-byte framing header to every EP-0x82 calibrate line. The Windows DLL
// ignores it (frame completion by byte-count, frame split by arithmetic — see
// `docs/capture/calibrate-buffer.md`), but it is structured firmware metadata (fixed markers + frame/line
// counters + a valid flag) that WE parse for integrity and frame selection. Layout confirmed from
// Ghidra (`syna_frame_line_average@0x180099c70`, struct `syna_calib_line_header`) + live hardware.

/// Fixed marker bytes the sensor emits in the line header (bytes 0,4,5,6,7). The DLL never checks
/// them; we use them only to sanity-check that we are parsing at the correct stride.
pub const CALIB_HDR_MARKERS: [(usize, u8); 5] =
    [(0, 0x01), (4, 0xF0), (5, 0xF7), (6, 0x01), (7, 0x00)];
/// `valid_flag` (header byte 1) on a real imaged line.
pub const CALIB_LINE_VALID: u8 = 0xFE; // 254
/// `valid_flag` on the trailing USB-alignment pad line (`req_lines++` when `stride*req_lines % 64 == 0`).
pub const CALIB_LINE_PAD: u8 = 0x01;

/// The 8-byte per-line framing header of a raw CALIBRATE (EP-0x82) line.
///
/// `[marker0, valid_flag, line_no, frame_no, marker4, marker5, marker6, marker7]`
/// = `[0x01, 254/1, 1..=lines_per_frame, 1.. /0, 0xF0, 0xF7, 0x01, 0x00]`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalibLineHeader {
    pub marker0: u8,
    /// `0xFE` on a real line, `0x01` on the alignment-pad line.
    pub valid_flag: u8,
    /// Line number within the frame: `1..=lines_per_frame`, resets each frame (`0` on the pad line).
    pub line_no: u8,
    /// Frame number: `1..` per frame (`0` on the pad line).
    pub frame_no: u8,
    pub marker4: u8,
    pub marker5: u8,
    pub marker6: u8,
    pub marker7: u8,
}

impl CalibLineHeader {
    /// Hydrate the header from the first [`LINE_HEADER`] bytes of a line. `None` if too short.
    pub fn from_bytes(line: &[u8]) -> Option<Self> {
        let h: [u8; LINE_HEADER] = line.get(..LINE_HEADER)?.try_into().ok()?;
        Some(Self {
            marker0: h[0],
            valid_flag: h[1],
            line_no: h[2],
            frame_no: h[3],
            marker4: h[4],
            marker5: h[5],
            marker6: h[6],
            marker7: h[7],
        })
    }

    /// The trailing USB-alignment pad line (`valid_flag == 0x01`, `frame_no == 0`).
    pub fn is_pad(&self) -> bool {
        self.valid_flag == CALIB_LINE_PAD && self.frame_no == 0
    }

    /// All fixed marker bytes match the expected constants (an independent stride sanity check).
    pub fn markers_ok(&self) -> bool {
        let b = [
            self.marker0,
            self.valid_flag,
            self.line_no,
            self.frame_no,
            self.marker4,
            self.marker5,
            self.marker6,
            self.marker7,
        ];
        CALIB_HDR_MARKERS.iter().all(|&(i, v)| b[i] == v)
    }
}

/// One hydrated CALIBRATE line: its framing header plus a borrow of its `line_width` data bytes.
#[derive(Debug, Clone, Copy)]
pub struct CalibLine<'a> {
    pub header: CalibLineHeader,
    pub data: &'a [u8],
}

/// Hydrate a raw EP-0x82 CALIBRATE buffer into typed lines, walking at [`line_stride`]`(line_width)`.
/// Trailing partial bytes are ignored. The pad line is included (filter with `!line.header.is_pad()`).
pub fn parse_calib_lines(raw: &[u8], line_width: usize) -> Vec<CalibLine<'_>> {
    let stride = line_stride(line_width);
    raw.chunks_exact(stride)
        .filter_map(|chunk| {
            CalibLineHeader::from_bytes(chunk).map(|header| CalibLine {
                header,
                data: &chunk[LINE_HEADER..LINE_HEADER + line_width],
            })
        })
        .collect()
}

/// Integrity report from validating a hydrated buffer against its own framing counters. Because the
/// counters only increment cleanly at the correct 152 stride (they garble at 160), a `well_formed`
/// result is an independent confirmation that the stride/geometry is right.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalibIntegrity {
    /// Distinct `frame_no` values seen on real (non-pad) lines.
    pub frames: u32,
    /// Maximum `line_no` seen (= lines_per_frame).
    pub lines_per_frame: u32,
    /// All real lines carried the expected fixed markers.
    pub markers_ok: bool,
    /// `line_no` ran `1,2,3,…` and reset to 1 exactly when `frame_no` incremented.
    pub sequential: bool,
    /// The trailing alignment-pad line was present.
    pub has_pad: bool,
}

impl CalibIntegrity {
    /// The counters and markers are fully consistent — strong evidence the stride is correct.
    pub fn well_formed(&self) -> bool {
        self.markers_ok && self.sequential && self.frames > 0
    }
}

/// Validate a hydrated CALIBRATE buffer against the sensor's own frame/line counters and markers.
pub fn verify_calib_integrity(lines: &[CalibLine]) -> CalibIntegrity {
    let mut frames = std::collections::BTreeSet::new();
    let mut lines_per_frame = 0u32;
    let mut markers_ok = true;
    let mut sequential = true;
    let mut has_pad = false;
    let (mut prev_line, mut prev_frame): (Option<u8>, Option<u8>) = (None, None);

    for line in lines {
        let h = &line.header;
        if h.is_pad() {
            has_pad = true;
            continue;
        }
        markers_ok &= h.markers_ok();
        frames.insert(h.frame_no);
        lines_per_frame = lines_per_frame.max(h.line_no as u32);
        // line_no must be prev+1 within a frame, or 1 on a new frame.
        match (prev_frame, prev_line) {
            (Some(pf), Some(pl)) if pf == h.frame_no => sequential &= h.line_no == pl + 1,
            (Some(_), _) => sequential &= h.line_no == 1, // frame changed → restart at 1
            _ => sequential &= h.line_no == 1,            // first line
        }
        prev_line = Some(h.line_no);
        prev_frame = Some(h.frame_no);
    }

    CalibIntegrity {
        frames: frames.len() as u32,
        lines_per_frame,
        markers_ok,
        sequential,
        has_pad,
    }
}

/// python-validity `clip`: clamp to signed-byte range, return as a raw `u8` (two's complement).
fn clip(x: i32) -> u8 {
    (x.clamp(-128, 127) & 0xff) as u8
}

/// python-validity `scale`: `clip(int((x - 0x80) * 10 / 0x22))`. The `0x22` divisor is per-device
/// (this value is the 0x199 one; 0x2449's may differ — a live-validation unknown).
fn scale(x: u8) -> u8 {
    clip((x as i32 - 0x80) * 10 / 0x22)
}

/// python-validity `add`: signed-byte add of two raw bytes, clipped.
fn add(l: u8, r: u8) -> u8 {
    clip(l as i8 as i32 + r as i8 as i32)
}

/// Average raw calibration frames into one cooked calibration frame (python-validity `average`;
/// mirrors `syna_frame_line_average@0x180099c70`).
///
/// `line_stride` is the RAW EP-0x82 line stride = [`line_stride`]`(line_width)` = `line_width + 8`
/// (152 for 0x2449) — the DLL's `field8`, **not** `bytes_per_line`=160 (see module docs / the −16
/// drift). `interleave = lines_per_frame / lines_per_calibration_data`. For 0x2449 interleave=2, so
/// we take the second frame (skip the first) and average each interleaved line-pair — exactly the
/// DLL's `>=2` branch (skip `uVar1 = lines_per_frame*line_stride`, average `repeat` lines per dest
/// row). The `interleave==1` branch (other sensors) averages across frames instead.
pub fn average(
    raw: &[u8],
    line_stride: usize,
    lines_per_frame: usize,
    lines_per_calibration_data: usize,
    calibration_frames: usize,
) -> Vec<u8> {
    let bytes_per_line = line_stride;
    let frame_size = lines_per_frame * bytes_per_line;
    if frame_size == 0 || bytes_per_line == 0 {
        return Vec::new();
    }
    let interleave = lines_per_frame / lines_per_calibration_data.max(1);

    if interleave > 1 {
        // Skip the first frame if we captured more than one.
        let base = if calibration_frames > 1 {
            frame_size
        } else {
            0
        };
        let frame = &raw[base.min(raw.len())..(base + frame_size).min(raw.len())];
        let group = interleave * bytes_per_line;
        let mut out = Vec::with_capacity(frame.len() / interleave);
        for g in frame.chunks(group) {
            let lines: Vec<&[u8]> = g.chunks(bytes_per_line).collect();
            let n = lines.len().max(1);
            for i in 0..bytes_per_line {
                let s: u32 = lines
                    .iter()
                    .filter_map(|l| l.get(i))
                    .map(|&b| b as u32)
                    .sum();
                out.push((s / n as u32) as u8);
            }
        }
        out
    } else {
        // interleave == 1: average across `input_frames` frames (skip first two).
        let mut input_frames = calibration_frames;
        let base = if input_frames > 1 {
            input_frames = input_frames.saturating_sub(2);
            frame_size * 2
        } else {
            0
        };
        let input_frames = input_frames.max(1);
        let region = &raw[base.min(raw.len())..(base + frame_size * input_frames).min(raw.len())];
        let frames: Vec<&[u8]> = region.chunks(frame_size).collect();
        let n = frames.len().max(1);
        let mut out = Vec::with_capacity(frame_size);
        for i in 0..frame_size {
            let s: u32 = frames
                .iter()
                .filter_map(|f| f.get(i))
                .map(|&b| b as u32)
                .sum();
            out.push((s / n as u32) as u8);
        }
        out
    }
}

/// Fold a cooked calibration frame into the running `calib_data` (python-validity
/// `process_calibration_results`): scale everything past the first 8 bytes of each line, then either
/// seed `calib_data` (first run) or signed-add line-by-line (subsequent iterations), leaving the
/// first 8 bytes of each line untouched.
pub fn process_calibration_results(calib_data: &mut Vec<u8>, cooked: &[u8], bytes_per_line: usize) {
    if bytes_per_line == 0 {
        return;
    }
    let mut frame = Vec::with_capacity(cooked.len());
    for line in cooked.chunks(bytes_per_line) {
        let keep = line.len().min(8);
        frame.extend_from_slice(&line[..keep]);
        frame.extend(line[keep..].iter().map(|&b| scale(b)));
    }

    if calib_data.is_empty() {
        *calib_data = frame;
        return;
    }
    let mut combined = Vec::with_capacity(calib_data.len());
    for (ll, rr) in calib_data
        .chunks(bytes_per_line)
        .zip(frame.chunks(bytes_per_line))
    {
        let keep = ll.len().min(8);
        combined.extend_from_slice(&ll[..keep]);
        for (l, r) in ll[keep..].iter().zip(&rr[keep..]) {
            combined.push(add(*l, *r));
        }
    }
    *calib_data = combined;
}

/// Per-device calibration parameters. python-validity hardcodes these in `open()` by sensor type;
/// 0x2449 has no entry there, so [`Self::for_subtype`] returns the 0x199-derived hypothesis.
#[derive(Debug, Clone, Copy)]
pub struct CalibrationParams {
    /// Number of frames the `CALIBRATE` `0x02` requests (`req_lines = frames*lines_per_frame + 1`).
    pub frames: usize,
    /// How many accumulate-and-fold iterations `calibrate()` runs.
    pub iterations: usize,
}

impl CalibrationParams {
    /// `iterations=4` = **1 prime + 3 folded** arms, matching the stock 009a DLL calibrate oracle
    /// (`captures/lenovo-009a-pairing/calib-cmd-sequence.txt`: `0x02` arm ×4 — one 944 B prime then
    /// three 13712 B folded, decrypted from `deviceInitAndCalibrate`→`windsor_cal` step 6). This
    /// DIVERGES from python-validity, which uses `0x199 = {frames:3, iterations:3}` (1 prime + 2
    /// folded) — the DLL accumulates one extra dark frame. `frames` (per-arm `req_lines=frames*lpf+1`)
    /// stays 3, which the oracle's `req_lines=0x2a1=673` confirms. 0x2449 ("86C") has no upstream
    /// record and reuses these; revalidate live if a 0x2449 unit is available.
    pub fn for_subtype(_subtype: u16) -> Self {
        CalibrationParams {
            frames: 3,
            iterations: 4,
        }
    }
}

/// Transport hook for the calibration loop — implemented by the caller (an open TLS session): arm a
/// `CALIBRATE`-mode `0x02` carrying the current `calib_data`, then read the raw frame bytes.
pub trait CalibrateIo {
    /// Send `0x02` in `CALIBRATE` mode with `calib_data` patched into the line-update; return the
    /// wire status word.
    fn arm_calibrate(&mut self, calib_data: &[u8]) -> Result<u16>;
    /// Read the raw calibration frame bytes (python-validity `read_82` = EP-0x82 bulk).
    fn read_calibration(&mut self) -> Result<Vec<u8>>;
}

/// Drives python-validity's `calibrate()` loop (minus the flash clean-slate persist, which our dark
/// SPI flash can't do): iterate `params.iterations` times, each time arming a `CALIBRATE` capture
/// with the accumulated `calib_data`, reading the frame, averaging, and folding it in.
pub struct Calibrator {
    /// RAW EP-0x82 line stride = `line_width + LINE_HEADER` (152 for 0x2449). The DLL's `field8`.
    pub line_stride: usize,
    pub lines_per_frame: usize,
    pub lines_per_calibration_data: usize,
    pub params: CalibrationParams,
}

impl Calibrator {
    /// For subtype 0x2449 geometry (line_width=144 → stride=152, lines_2d=56, repeat_multiplier=2).
    /// `line_width` is `SensorTypeInfo::line_width` (`flex[0x32]`, the imaged width); the raw stride is
    /// derived as `line_width + LINE_HEADER` (family-generic) — **do not** pass `bytes_per_line`.
    pub fn new(
        line_width: usize,
        lines_2d: usize,
        repeat_multiplier: usize,
        lines_per_calibration_data: usize,
        subtype: u16,
    ) -> Self {
        Calibrator {
            line_stride: line_stride(line_width),
            lines_per_frame: lines_2d * repeat_multiplier,
            lines_per_calibration_data,
            params: CalibrationParams::for_subtype(subtype),
        }
    }

    /// Run the calibration loop and return the computed `calib_data` (to feed into capture
    /// line-updates). Errors propagate from the transport hook.
    pub fn run<IO: CalibrateIo>(&self, io: &mut IO) -> Result<Vec<u8>> {
        let mut calib = Vec::new();
        for _ in 0..self.params.iterations.max(1) {
            let _status = io.arm_calibrate(&calib)?;
            let raw = io.read_calibration()?;
            let cooked = average(
                &raw,
                self.line_stride,
                self.lines_per_frame,
                self.lines_per_calibration_data,
                self.params.frames,
            );
            process_calibration_results(&mut calib, &cooked, self.line_stride);
        }
        Ok(calib)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one synthetic 152-ish line: `[0x01, valid, line_no, frame_no, 0xF0, 0xF7, 0x01, 0x00]`
    /// + `line_width` bytes of `fill`.
    fn synth_line(valid: u8, line_no: u8, frame_no: u8, fill: u8, line_width: usize) -> Vec<u8> {
        let mut v = vec![0x01, valid, line_no, frame_no, 0xF0, 0xF7, 0x01, 0x00];
        v.extend(std::iter::repeat_n(fill, line_width));
        v
    }

    fn synth_buffer(frames: u8, lines_per_frame: u8, line_width: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        for f in 1..=frames {
            for l in 1..=lines_per_frame {
                buf.extend(synth_line(CALIB_LINE_VALID, l, f, f * 10 + l, line_width));
            }
        }
        // trailing USB-alignment pad line: valid=1, line=0, frame=0
        buf.extend(synth_line(CALIB_LINE_PAD, 0, 0, 0, line_width));
        buf
    }

    #[test]
    fn hydrate_and_verify_calib_buffer() {
        let lw = 144;
        let buf = synth_buffer(3, 112, lw);
        assert_eq!(buf.len(), (3 * 112 + 1) * line_stride(lw)); // 337 * 152 for 0x2449 geometry

        let lines = parse_calib_lines(&buf, lw);
        assert_eq!(lines.len(), 3 * 112 + 1);
        // first real line
        assert_eq!(lines[0].header.frame_no, 1);
        assert_eq!(lines[0].header.line_no, 1);
        assert_eq!(lines[0].header.valid_flag, CALIB_LINE_VALID);
        assert!(lines[0].header.markers_ok());
        assert_eq!(lines[0].data.len(), lw);
        assert_eq!(lines[0].data[0], 11); // fill = frame*10+line
        // last line is the pad
        assert!(lines.last().unwrap().header.is_pad());

        let integ = verify_calib_integrity(&lines);
        assert_eq!(integ.frames, 3);
        assert_eq!(integ.lines_per_frame, 112);
        assert!(integ.markers_ok);
        assert!(integ.sequential);
        assert!(integ.has_pad);
        assert!(integ.well_formed());
    }

    #[test]
    fn wrong_stride_breaks_integrity() {
        // A buffer laid out for line_width=144 (stride 152), parsed as if line_width=152 (stride 160),
        // must fail the counter/marker checks — this is how the framing metadata catches a bad stride.
        let buf = synth_buffer(3, 112, 144);
        let misread = parse_calib_lines(&buf, 152); // stride 160, wrong
        let integ = verify_calib_integrity(&misread);
        assert!(
            !integ.well_formed(),
            "wrong stride should not look well-formed"
        );
    }

    #[test]
    fn clip_scale_add_match_python_validity() {
        // clip: clamp then two's-complement byte.
        assert_eq!(clip(200), 127);
        assert_eq!(clip(-200), 128); // -128 & 0xff
        assert_eq!(clip(-1), 255);
        assert_eq!(clip(5), 5);
        // scale(x) = clip((x-0x80)*10/0x22)
        assert_eq!(scale(0x80), 0); // (0)*10/34 = 0
        assert_eq!(scale(0xff), clip((127 * 10) / 0x22)); // 127*10/34 = 37
        assert_eq!(scale(0x00), clip((-128 * 10) / 0x22)); // -128*10/34 = -37 -> 219
        // add: signed add of two raw bytes, clipped.
        assert_eq!(add(1, 2), 3);
        assert_eq!(add(0xff, 0xff), clip(-2)); // -1 + -1
        assert_eq!(add(0x7f, 0x7f), 127); // 127+127 clamps
    }

    #[test]
    fn average_interleave2_averages_line_pairs_of_second_frame() {
        // Tiny geometry: bytes_per_line=2, lines_per_calibration_data=2, lines_per_frame=4 (interleave=2),
        // 2 frames. average() skips frame 0, then averages each 2-line group of frame 1.
        let bpl = 2;
        let lpf = 4;
        let lpc = 2;
        let frames = 2;
        let frame_size = lpf * bpl; // 8
        // frame0 = all 0xff (skipped); frame1 = lines [10,20],[30,40],[50,60],[70,80]
        let mut raw = vec![0xffu8; frame_size];
        raw.extend_from_slice(&[10, 20, 30, 40, 50, 60, 70, 80]);
        let out = average(&raw, bpl, lpf, lpc, frames);
        // group0 = lines [10,20],[30,40] -> avg [20,30]; group1 = [50,60],[70,80] -> [60,70]
        assert_eq!(out, vec![20, 30, 60, 70]);
    }

    #[test]
    fn process_seeds_then_folds() {
        // bytes_per_line=10 so [..8] is the untouched header, [8..] scaled/added.
        let bpl = 10;
        let cooked: Vec<u8> = (0..bpl as u8).collect(); // one line 0..9
        let mut calib = Vec::new();
        process_calibration_results(&mut calib, &cooked, bpl);
        // header preserved, bytes 8,9 scaled.
        assert_eq!(&calib[..8], &cooked[..8]);
        assert_eq!(calib[8], scale(8));
        assert_eq!(calib[9], scale(9));
        // second fold: signed-add the new scaled bytes onto the running ones.
        let prev = calib.clone();
        process_calibration_results(&mut calib, &cooked, bpl);
        assert_eq!(&calib[..8], &cooked[..8]); // header still preserved
        assert_eq!(calib[8], add(prev[8], scale(8)));
        assert_eq!(calib[9], add(prev[9], scale(9)));
    }
}
