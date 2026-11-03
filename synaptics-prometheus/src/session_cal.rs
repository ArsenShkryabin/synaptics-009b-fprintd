//! TLS session adapter for the vendor calibration state machine (`calibration::CalIo`).
//!
//! Mirrors `syna_lib_generate_calibration` → `syna_lib_run_calibration` device touches. Uses
//! calibration-only arm builders ([`CaptureConfig::upload_cmd_cal_step6_dark`],
//! [`CaptureConfig::upload_cmd_cal_step7_settle`]) — stream capture keeps separate `sync_frames`.
//!
//! Each cal capture arm follows the DLL frames-sync cadence (`syna_capture_arm_and_wait` →
//! `syna_capture_frames_sync`): pre-arm → stop → `0x02` arm → blocking EP-0x82 read → host
//! session reset (implicit once the read completes). Step 7 settle uses one frames-sync batch
//! (`syna_capture_arm_and_wait(ctx,0,1,0)`) — same req_lines as step 6, not `req_lines=0`.

use crate::calibration::{CalIo, CalResults};
use crate::capture::FrameCapturer;
use crate::capture_prog::{CaptureConfig, CAL_STEP7_SETTLE_SYNC_FRAMES};
use crate::error::{Error, Result, Status};
use crate::factory_cal::{
    factory_bits_request, factory_block_table_from_subtag_response, FactoryBlock,
    FACTORY_TAG_BLOCK_TABLE,
};
use crate::session::Session;
use crate::transport::Transport;

pub use crate::capture_prog::CAL_STEP6_SYNC_FRAMES as DARK_FRAME_SYNC_FRAMES;
pub use crate::capture_prog::CAL_STEP6_SYNC_FRAMES as STEP6_SYNC_FRAMES;

fn arm_status_ok(status: u16) -> bool {
    matches!(status, 0x0000 | 0x0412 | 0x0450)
}

/// One frames-sync cal arm: [`FrameCapturer::capture_one`] (stop → arm → EP-0x82 read).
fn run_cal_frames_sync_arm<T: Transport>(
    session: &mut Session<T>,
    cfg: &CaptureConfig,
    arm: &[u8],
    sync_frames: u32,
) -> Result<Vec<u8>> {
    let layout = cfg.sync_layout(sync_frames);
    let req_lines = layout
        .req_lines()
        .ok_or_else(|| Error::Malformed("cal arm req_lines overflow".into()))?;
    // Debug: dump the plaintext calibration arm (SYNA_DUMP_ARM=1) — for offline byte-diff vs oracles.
    if std::env::var_os("SYNA_DUMP_ARM").is_some() {
        eprintln!(
            "SYNA_ARM sync_frames={sync_frames} len={} {}",
            arm.len(),
            arm.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
    }
    let capturer = FrameCapturer::new(layout.wire_stride(), req_lines);
    // Calibration frames send NO pre-arm: the DLL only pre-arms identify/enroll/read-dispatch, never
    // `syna_lib_calibration_step`. With `fw_upload_context=0` (cold 009b) a per-frame pre-arm actually
    // fires and the sensor rejects the second `0x06` with `0x04aa` (wrong capture state). `None` keeps
    // calibration as stop → arm → read — the known-good path (pre-arm was formerly deduped here).
    let frame = capturer.capture_one(session, arm, None)?;
    if !arm_status_ok(frame.arm_status) {
        return Err(Error::Malformed(format!(
            "calibration arm rejected status=0x{:04x}",
            frame.arm_status
        )));
    }
    Ok(frame.bytes)
}

/// Like [`run_cal_frames_sync_arm`] but with NO `0x04` stop before the arm — the pv/DLL calibrate-loop
/// cadence (arms sent back-to-back, no teardown between). A stop before a folded frames-sync CALIBRATE
/// arm faults the 009a die; no stop is accepted.
fn run_cal_frames_sync_arm_nostop<T: Transport>(
    session: &mut Session<T>,
    cfg: &CaptureConfig,
    arm: &[u8],
    sync_frames: u32,
) -> Result<Vec<u8>> {
    let layout = cfg.sync_layout(sync_frames);
    let req_lines = layout
        .req_lines()
        .ok_or_else(|| Error::Malformed("cal arm req_lines overflow".into()))?;
    let capturer = FrameCapturer::new(layout.wire_stride(), req_lines);
    let frame = capturer.capture_one_no_stop(session, arm)?;
    if !arm_status_ok(frame.arm_status) {
        return Err(Error::Malformed(format!(
            "calibration arm rejected status=0x{:04x}",
            frame.arm_status
        )));
    }
    Ok(frame.bytes)
}

/// DLL-faithful CALIBRATE read for the **type-1 die** (0x0199 / device_id_one): arm the calibrate
/// `0x02` then read the frame over the **polled `0x51`** command channel
/// (`syna_capture_image@0x180093750`), NOT EP-0x82. `syna_capture_read_dispatch@0x180068dc0` routes
/// `syna_ctx_is_device_id_one==1` to the polled `syna_capture_image`; EP-0x82 frames-sync is a type-2
/// mechanism (`syna_capture_frames_sync_type2` skips product `'0'`). Reading a bulk pipe the type-1
/// sensor never feeds is what reset the die on the folded arm — see
/// `docs/capture/0x82-read-transport-by-die.md`. The calibrate arm keeps its `req_lines`=sync geometry
/// (captured into sensor RAM); only the READ transport differs.
///
/// Returns the frame reshaped to the `line_width + LINE_HEADER` (8-byte zero header + body row) stride
/// that the callers' averaging expects — matching `syna_capture_image`'s own `width+8` dest reshape.
fn run_cal_polled_arm<T: Transport>(
    session: &mut Session<T>,
    cfg: &CaptureConfig,
    arm: &[u8],
) -> Result<(Vec<u8>, usize, usize)> {
    const H: usize = crate::capture_prog::SYNC_LINE_HEADER;
    // The per-arm dark frame rides the 0x02 arm REPLY body (not a separate poll/EP-0x82): the DLL
    // calibrate pcap shows arms back-to-back with only their ~2000 B replies, then a 0x40 partition-6
    // read for the clean_slate. Order stop → Standard pre-arm → arm (matches arm_polled_capture /
    // read_dispatch's syna_capture_send_pre_arm_rom_config; the arm is rejected 0x057f without it), but
    // sent via `tunnel` so we keep the FULL reply (`arm()` discards the body). The pre-arm upload dedups
    // (no-op once loaded), so repeated calls are safe. Reply header (Lenovo 009a) is 8 bytes
    // [status:u16][0x0288][0x3000][0x005e] then the captured frame body.
    use crate::pre_arm::PreArmMode;
    if std::env::var_os("SYNA_DUMP_ARM").is_some() {
        let _ = std::fs::write(format!("captures/our_cal_arm_{}.bin", arm.len()), arm);
    }
    // NO 0x04 stop between calibrate arms — the DLL sends them back-to-back (pcap arms #41/45/49/53
    // consecutive) and a stop before a calibrate arm faults this die (the old _nostop cadence). But the
    // previous arm's capture-complete interrupt must be DRAINED, else the next arm is rejected 0x0450
    // (stale-state); drain clears EP-0x83 without the die-faulting abort. The Standard pre-arm is
    // deduped (sent once, no-op after), matching read_dispatch's one pre-arm.
    session.drain_interrupts();
    let _ = session.send_pre_arm_rom_config(PreArmMode::Standard)?;
    let reply = session.tunnel(arm)?;
    let status = Session::<T>::status_of(&reply);
    let hdr = 8usize; // 8-byte reply header before the frame body
    let body = reply.get(hdr..).unwrap_or(&[]);
    if std::env::var_os("SYNA_CAL_DEBUG").is_some() {
        let nz = body.iter().filter(|&&b| b != 0).count();
        eprintln!(
            "CAL_POLLED arm_reply len={} status=0x{status:04x} head={} body_len={} body_nonzero={} body_head={}",
            reply.len(),
            reply.get(..8).map(|h| h.iter().map(|b| format!("{b:02x}")).collect::<String>()).unwrap_or_default(),
            body.len(),
            nz,
            body.get(..32).map(|h| h.iter().map(|b| format!("{b:02x}")).collect::<String>()).unwrap_or_default(),
        );
    }
    if !arm_status_ok(status) {
        return Err(Error::Malformed(format!(
            "calibrate polled arm rejected status=0x{status:04x}"
        )));
    }
    // Reshape the flat reply body to the line_width+H stride the callers' averaging expects (8-byte
    // zero per-line header + up to line_width data), for as many whole lines as the reply carries.
    let w = cfg.type_info.line_width as usize;
    let full_h = cfg.lines_2d as usize;
    let avail_lines = if w > 0 { (body.len() / w).min(full_h) } else { 0 };
    let stride = w + H;
    let mut out = vec![0u8; stride * full_h];
    for row in 0..avail_lines {
        let src = &body[row * w..row * w + w];
        out[row * stride + H..row * stride + H + w].copy_from_slice(src);
    }
    Ok((out, stride, full_h))
}

/// Adapter implementing the pv/DLL accumulate-and-fold calibrate loop ([`crate::calibrate::CalibrateIo`])
/// over a live session. Each iteration arms a frames-sync CALIBRATE `0x02` folding the accumulated
/// `calib_data` (empty on the first/prime pass → unfolded) and reads the EP-0x82 frame. Mirrors
/// python-validity's `calibrate()` and the DLL step-6 accumulate
/// (`syna_lib_cal_step6_woe_cleanslate@0x180071cc0` → `syna_cal_accumulate_darkfield_scaled@0x1800748b0`).
pub struct SessionCalibrateIo<'a, T: Transport> {
    session: &'a mut Session<T>,
    cfg: &'a CaptureConfig,
    factory_values: &'a [u8],
    last_raw: Vec<u8>,
}

impl<'a, T: Transport> SessionCalibrateIo<'a, T> {
    pub fn new(session: &'a mut Session<T>, cfg: &'a CaptureConfig, factory_values: &'a [u8]) -> Self {
        Self { session, cfg, factory_values, last_raw: Vec::new() }
    }
}

impl<T: Transport> crate::calibrate::CalibrateIo for SessionCalibrateIo<'_, T> {
    fn arm_calibrate(&mut self, calib_data: &[u8]) -> Result<u16> {
        let frames = self.cfg.calibration_frames() as usize;
        // pv/DLL parity: the CALIBRATE arms are UNFOLDED and IDENTICAL every iteration — calib_data is
        // COMPUTED from the captures (host-side accumulate in process_calibration_results), NOT folded
        // INTO the arm. Our previous folding was the whole bug: (1) folding a frames-sync (req_lines!=0)
        // calibrate arm resets the die (plan §7), and (2) the polled arm reply just echoes the fold and
        // doesn't consume the capture, so the next arm bounced 0x0450. pv sends the constant unfolded arm
        // and read_82 (EP-0x82) CONSUMES the capture, so the identical re-arm is accepted. We mirror that:
        // unfolded arm + frames-sync EP-0x82 read; `calib_data` accumulates in the Calibrator, unused here.
        let _ = calib_data;
        let arm = self
            .cfg
            .upload_cmd_calibrate(self.factory_values, &[], frames, None)
            .ok_or_else(|| Error::Malformed("calibrate loop: arm build failed".into()))?;
        self.last_raw = run_cal_frames_sync_arm_nostop(self.session, self.cfg, &arm, frames as u32)?;
        log::info!("calibrate iter: unfolded arm={} B, read {} B", arm.len(), self.last_raw.len());
        Ok(0)
    }

    fn read_calibration(&mut self) -> Result<Vec<u8>> {
        Ok(std::mem::take(&mut self.last_raw))
    }
}

/// Run the pv/DLL calibrate accumulate-and-fold loop and return the computed `calib_data` (to fold into
/// the polled/frames-sync capture arm). No finger: every arm is a dark-field capture.
pub fn run_calibrate_loop<T: Transport>(
    session: &mut Session<T>,
    cfg: &CaptureConfig,
    factory_values: &[u8],
) -> Result<Vec<u8>> {
    let cal = crate::calibrate::Calibrator::new(
        cfg.type_info.line_width as usize,
        cfg.lines_2d as usize,
        cfg.type_info.repeat_multiplier as usize,
        cfg.type_info.lines_per_calibration_data as usize,
        cfg.subtype,
    );
    // pv/DLL: each unfolded calibrate arm returns a frames-sync BATCH of `frames`; average_second_frame
    // (in average()) skips the leading sync frame. Keep the multi-frame count (no frames=1 override).
    let mut io = SessionCalibrateIo::new(session, cfg, factory_values);
    cal.run(&mut io)
}

/// Capture ONE frames-sync CALIBRATE frame folding `calib_data` (empty = unfolded) and return the
/// line-averaged buffer plus `(wire_stride, lines_2d)` — for measuring the middle-clip before/after the
/// calibrate loop.
pub fn capture_calibrate_frame<T: Transport>(
    session: &mut Session<T>,
    cfg: &CaptureConfig,
    factory_values: &[u8],
    calib_data: &[u8],
) -> Result<(Vec<u8>, usize, usize)> {
    let frames = cfg.calibration_frames();
    let arm = cfg
        .upload_cmd_calibrate(factory_values, calib_data, frames as usize, None)
        .ok_or_else(|| Error::Malformed("calibrate frame: arm build failed".into()))?;
    // DLL parity (default): the type-1 die (0x0199) reads the calibrate frame POLLED
    // (syna_capture_image), one frame per arm — NOT the EP-0x82 frames-sync batch, which reset the die.
    // Opt back into the old (resetting) EP-0x82 batch read with SYNA_CAL_FRAMES_SYNC=1 for A/B.
    if std::env::var_os("SYNA_CAL_FRAMES_SYNC").is_none() {
        return run_cal_polled_arm(session, cfg, &arm);
    }
    let raw = run_cal_frames_sync_arm_nostop(session, cfg, &arm, frames)?;
    let layout = cfg.sync_layout(frames);
    let averaged = if frames >= 2 {
        layout.average_second_frame(&raw)
    } else {
        layout.average_single_frame(&raw)
    }
    .ok_or_else(|| Error::Malformed("calibrate frame: line average failed".into()))?;
    Ok((averaged, layout.wire_stride(), cfg.lines_2d as usize))
}

/// [`CalIo`] over an open [`Session`], using the frames-sync arm for step-6's dark capture.
pub struct SessionCalIo<'a, T: Transport> {
    pub session: &'a mut Session<T>,
    pub cfg: &'a CaptureConfig,
    /// The per-line factory calib blob (`0x80000003` payload) for `prod33_body`'s calib-blob line.
    pub factory_values: Vec<u8>,
    /// Block-table from bootstrap — avoids a second `0x6f` tag `0x0e` read inside `run_calibration`.
    pub cached_factory_blocks: Option<Vec<FactoryBlock>>,
    /// Step-3 measured diff for calibrate-class arms (`upload_cmd_calibrate` DAT lines A/B).
    step3_diff: Option<Vec<u8>>,
    /// Raw step-6 dark frame (wire form). Superseded as the `0x48` source by [`Self::raw_settle_frame`]
    /// (the DLL's `0x48` is the LAST captured frame = the step-7 settle, not the step-6 dark) — kept
    /// only for the Phase-0 A/B comparison.
    raw_dark_frame: Option<Vec<u8>>,
    /// Raw step-7 **settle** frame (wire form, stream/EP-0x82, line-averaged), retained as an
    /// approximation of the `0x48` baseline source.
    ///
    /// CORRECTION 2026-07-24 (RE cross-check, verified in Ghidra): this stream settle is **NOT** the
    /// DLL's `pLast_frame_buf`. The DLL fills `pLast_frame_buf` from a **recon=8** capture
    /// (`syna_capture_image@0x180099540`, capture_flags `0xa0030`, on-chip Image Reconstruction), which
    /// `syna_capture_store_last_frame@0x1800ad800` stores **verbatim** (memmove, no host conditioning).
    /// That firmware-reconstructed frame is **flat ~0x80, std ≈ 1.8** (a baseline-subtracted no-finger
    /// residual). Our stream settle is the raw, still-scrambled frame at **std ≈ 24.7** — the wrong
    /// pipeline stage. Emitting it as the `0x48` made the firmware's finger-detect delta see noise vs
    /// noise (device 2026-07-24: no `0x51` frame, no touch). The correct source is a recon=8 imaging
    /// capture — but our `upload_cmd_image_with_cal` recon=8 arm currently returns **no** `0x51` body
    /// (suspected missing `capture_flags 0xa0030` plumbing); see `docs/capture/last-frame-baseline.md`.
    raw_settle_frame: Option<Vec<u8>>,
}

impl<'a, T: Transport> SessionCalIo<'a, T> {
    pub fn new(
        session: &'a mut Session<T>,
        cfg: &'a CaptureConfig,
        factory_values: Vec<u8>,
    ) -> Self {
        Self {
            session,
            cfg,
            factory_values,
            cached_factory_blocks: None,
            step3_diff: None,
            raw_dark_frame: None,
            raw_settle_frame: None,
        }
    }
}

impl<T: Transport> CalIo for SessionCalIo<'_, T> {
    fn set_step3_diff_for_capture(&mut self, diff: Option<&[u8]>) {
        self.step3_diff = diff.map(<[u8]>::to_vec);
    }

    fn take_raw_dark_frame(&mut self) -> Option<Vec<u8>> {
        self.raw_dark_frame.take()
    }

    fn take_raw_settle_frame(&mut self) -> Option<Vec<u8>> {
        self.raw_settle_frame.take()
    }

    fn read_factory_blocks(&mut self) -> Result<Vec<FactoryBlock>> {
        if let Some(blocks) = self.cached_factory_blocks.take() {
            return Ok(blocks);
        }
        let pt = self.session.tunnel(&factory_bits_request(FACTORY_TAG_BLOCK_TABLE))?;
        let status = if pt.len() >= 2 {
            u16::from_le_bytes([pt[0], pt[1]])
        } else {
            0xffff
        };
        if status != 0 {
            return Err(Error::Status {
                opcode: crate::factory_cal::WIRE_OP_FACTORY_BITS,
                status: Status::from_wire(status),
            });
        }
        Ok(factory_block_table_from_subtag_response(&pt[2..]))
    }

    fn capture_dark_frame(&mut self) -> Result<(Vec<u8>, usize, usize)> {
        let arm = self
            .cfg
            .upload_cmd_cal_step6_dark(&self.factory_values, self.step3_diff.as_deref())
            .ok_or_else(|| Error::Malformed("no step-6 dark-frame arm".into()))?;
        // Frame count is per-subtype: the 0x0199 type-1 family requests 3 frames (python-validity
        // `calibration_frames = 3`, req_lines = 673), 0x2449 a single frame. `average_second_frame`
        // (skip frame 0, average frame 1's line pairs) is pv's `interleave>1 && frames>1` branch;
        // the single-frame path is the 0x2449 DLL early-return.
        let sync_frames = self.cfg.calibration_frames();
        let raw = run_cal_frames_sync_arm(self.session, self.cfg, &arm, sync_frames)?;
        // Keep the raw wire frame (152-stride) for the arm's `0x48` finger-detect baseline chunk.
        self.raw_dark_frame = Some(raw.clone());
        let layout = self.cfg.sync_layout(sync_frames);
        let stride = layout.wire_stride();
        let averaged = if sync_frames >= 2 {
            layout.average_second_frame(&raw)
        } else {
            layout.average_single_frame(&raw)
        }
        .ok_or_else(|| {
            Error::Malformed("step-6 dark-frame line average failed (short EP-0x82 read?)".into())
        })?;
        // Do NOT timeslot-descramble the calibration dark. The DLL folds the RAW (scrambled) dark
        // verbatim into the `0x34` TimeslotTable2d + `0x30` LineUpdate correction
        // (`syna_fold_timeslot_2d_measured@0x180092c70` reads `pStep5or6_buf` in stored order): the
        // per-column dark levels must stay in *timeslot* order to line up with the on-chip multiplex.
        // Our old `reconstruct_frame` (mode-2 cf640) descramble here put them in the wrong columns —
        // `fold(descrambled)` correlated 0.998 with our wrong `0x34` but only 0.21 with the DLL's real
        // `0x34`, so the sensor never dark-corrected the settle frame (std 24 vs the DLL's 1.9).
        // Verified 2026-08-05 (`fold_check`): `fold(raw dark)` reproduces the DLL `0x34` value-for-value.
        // See docs/capture/last-frame-baseline.md §7.
        Ok((averaged, stride, self.cfg.lines_2d as usize))
    }

    fn capture_settle_arm(&mut self, cal: &CalResults) -> Result<()> {
        // The older type-1 family (0x0199 etc.) has NO step-7 settle in its native flow
        // (python-validity: calibrate() ends after the CALIBRATE frames + clean-slate; capture() sends
        // only the req_lines=0 IDENTIFY arm — no settle, no 0x48 baseline chunk). Sending the 009b
        // DLL's settle arm resets these dies even when its fold is byte-exact to python-validity's, so
        // skip it; the persisted-calib path needs no settle-captured baseline.
        if crate::line_update::key_calibration_line(self.cfg.subtype).is_some() {
            return Ok(());
        }
        let arm = self
            .cfg
            .upload_cmd_cal_step7_settle(&self.factory_values, cal)
            .ok_or_else(|| Error::Malformed("no step-7 settle arm".into()))?;
        let raw = run_cal_frames_sync_arm(
            self.session,
            self.cfg,
            &arm,
            CAL_STEP7_SETTLE_SYNC_FRAMES,
        )?;
        // Retain the RAW multi-field settle stream (113 lines, 152-stride) as the `0x48` baseline
        // source. `chunk_baseline` (flex.rs) decimates it to the DLL's 56-line odd-field format
        // (every-other line → headers `01 fe {1,3,5…} 02`), so do NOT line-average or descramble here —
        // that would halve the line count and corrupt the field structure. Since the step-6 dark-fold
        // fix (`capture_dark_frame` now folds the RAW dark, `session_cal.rs`) the sensor dark-corrects
        // this frame on-chip, so the raw settle is now FLAT (std ~2.4, decimating to ~1.85 — matching the
        // DLL's `0x48` std ~1.9). Before the fold fix it was scrambled (std ~24.7). See
        // docs/capture/last-frame-baseline.md §7.
        if !raw.is_empty() {
            self.raw_settle_frame = Some(raw);
        }
        // Disarm is done inside [`CaptureIo::read_frame`] when `req_lines=0` (step-7 settle).
        Ok(())
    }
}
