//! The capture read-mode trait implementations for [`Session`] — the concrete [`CaptureIo`],
//! [`CaptureControl`], [`CaptureFingerDetectIo`], and [`WofIo`] blocks that let a live session drive
//! [`crate::capture::CaptureContext`] / [`crate::capture::run_wof`]. Split out of the session impl;
//! wire opcodes are documented in the mod.rs header.

use super::Session;
use super::{INTR_MAX, WOF_STATUS_CMD, WOF_WAIT_MS, ZERO_FRAME_INTR_POLL_MS, ZERO_FRAME_INTR_WAIT_MS};
use crate::capture::{
    stop_cmd, wof, CaptureControl, CaptureFingerDetectIo, CaptureIo, FrameCapturer, RawFrame,
    ReadMode, SyncFrameLayout, WofIo, READ_FRAME_CHUNK,
};
use crate::error::{Error, Result, Status};
use crate::pre_arm::PreArmMode;
use crate::proto::Opcode;
use crate::transport::Transport;

/// Settle delay after a `0x05` soft reboot before the sensor re-enumerates and accepts a re-arm.
const REBOOT_SETTLE: std::time::Duration =
    std::time::Duration::from_millis(super::REBOOT_SETTLE_MS);

impl<T: Transport> Session<T> {
    /// One capture with DLL-faithful **in-loop capture-fault recovery**.
    ///
    /// Mirrors the vendor capture/match/enroll loops — `CCaptureImage_RunStart@0x18001a51c`,
    /// `CMatchImageToTemplates_Match_capture@0x180026a70`, `CEocMocEIV_EnrollmentUpdate@0x18001f390`
    /// — each of which, on a capture-fault, calls `syna_vfm_reboot_sensor_mode0` (the `0x05` reboot)
    /// and re-arms. A capture-fault here is any of:
    /// - arm status `0xc9`/`0xca`/`0x0450` ([`Status::requests_sensor_reboot_retry`]);
    /// - a frames-sync `received != expected` frame read — the DLL's internal `0xca`, surfaced as
    ///   [`Error::ShortResponse`] (only [`CaptureIo::read_frame`] raises it inside `capture_one`).
    ///
    /// On such a fault it soft-reboots ([`Session::reboot_sensor`]) and re-arms **once** — a single
    /// bounded retry, as the DLL reboots then lets its outer loop re-evaluate. Non-capture errors
    /// (transport failures, short non-frame replies) are returned unchanged: a sensor reboot cannot
    /// fix them. Unlike the plain [`FrameCapturer::capture_one`], which surfaces the fault status to
    /// the caller without acting, this is the path an imaging/identify/enroll driver should use.
    pub fn capture_one_recovering(
        &mut self,
        capturer: &FrameCapturer,
        arm_cmd: &[u8],
        pre_arm: Option<PreArmMode>,
    ) -> Result<RawFrame> {
        let first = capturer.capture_one(self, arm_cmd, pre_arm);
        let needs_recovery = match &first {
            Ok(frame) => Status::from_wire(frame.arm_status).requests_sensor_reboot_retry(),
            Err(Error::Status { status, .. }) => status.requests_sensor_reboot_retry(),
            Err(Error::ShortResponse { .. }) => true,
            Err(_) => false,
        };
        if !needs_recovery {
            return first;
        }
        log::warn!(
            "capture fault ({}) — DLL-faithful soft reboot (0x05) + single re-arm \
             (syna_vfm_reboot_sensor_mode0)",
            match &first {
                Ok(f) => format!("arm status {}", Status::from_wire(f.arm_status)),
                Err(e) => e.to_string(),
            }
        );
        // The reboot re-enumerates on this sensor; settle, then clear any stale arm it left (0x04 +
        // drain) so the re-arm is accepted instead of bouncing on 0x0450.
        let _ = self.reboot_sensor();
        std::thread::sleep(REBOOT_SETTLE);
        CaptureIo::stop(self)?;
        capturer.capture_one(self, arm_cmd, pre_arm)
    }
}

impl<T: Transport> CaptureIo for Session<T> {
    fn stop(&mut self) -> Result<()> {
        // Soft pre-arm abort (0x04) + drain stale interrupts so the next arm is accepted (else 0x0450).
        let _ = self.tunnel(&[stop_cmd::ABORT]);
        self.drain_interrupts();
        Ok(())
    }

    fn arm(&mut self, cmd: &[u8]) -> Result<u16> {
        let reply = self.tunnel(cmd)?;
        // Capture the recon-config (tag 0x30000288) the sensor returns in the arm reply — the host
        // analogue of the DLL recv-cb → syna_capture_recon_setup storing it at ctx+0x88. recon=8
        // imaging arms carry it; identify arms do not (→ None, clearing any stale config). Retrieve
        // via Session::take_recon_config; it feeds matcher reconstruction, NOT the re-stride read.
        self.last_recon_config =
            crate::capture_prog::windsor::WindsorReconConfig::find_in_arm_reply(&reply);
        Ok(Self::status_of(&reply))
    }

    fn arm_with_pre(&mut self, cmd: &[u8], pre_arm: Option<PreArmMode>) -> Result<u16> {
        Session::arm_polled_capture(self, cmd, pre_arm)
    }

    fn read_frame(&mut self, frame_size: usize) -> Result<Vec<u8>> {
        // Frames-sync ([`ReadMode::Stream`]): one blocking bulk read on EP-0x82, no 0x51 poll. The DLL
        // stream reader `syna_read_frame_blocking` (under `syna_capture_frames_sync@0x18006ae20`) does a
        // single blocking EP-0x82 transfer with NO GetPrgStatus (0x51) — verified by decompile and the
        // Frida call-graph (frames_sync never reaches `syna_cmd_send`). 0x51 polling is exclusive to the
        // *polled* path (`syna_capture_image`, see [`Self::read_frame_chunk`]). The old pre-poke loop was
        // a host-clocking habit, not vendor behaviour; removed for stream parity.
        if frame_size == 0 {
            // Step-7 settle / req_lines=0 frames_sync completion (`syna_capture_frames_sync@0x18006ae20`
            // with a zero-length recv buffer, then `syna_capture_session_reset`). The DLL blocks on
            // `syna_read_frame_blocking` until the EP-0x82 URB completes with 0 bytes transferred.
            // nusb `RequestBuffer::new(0)` never completes on this sensor — one max-packet read
            // (discarding any short tail) then wait for EP-0x83 capture-complete.
            let _ = self.transport.read_bulk_timed(
                SyncFrameLayout::USB_PACKET_SIZE,
                ZERO_FRAME_INTR_WAIT_MS,
            )?;
            let polls = ZERO_FRAME_INTR_WAIT_MS / ZERO_FRAME_INTR_POLL_MS;
            for _ in 0..polls {
                match self.transport.read_interrupt(INTR_MAX, ZERO_FRAME_INTR_POLL_MS) {
                    Ok(b) if !b.is_empty() => break,
                    Ok(_) => {}
                    Err(e) => return Err(e),
                }
            }
            // Full stream-class disarm (`syna_vfm_capture_teardown` on 0x2449: 0x04 + 0x52).
            // A bare 0x04 leaves the sensor armed → next arm returns 0x0450 (live-tested post step 7).
            let (st8, st9) = self.status_bytes_for_teardown();
            CaptureControl::teardown(self, ReadMode::Stream, st8, st9, false)?;
            return Ok(Vec::new());
        }
        // Pre-size the read to the DLL's exact recv-buffer size (`req_lines × stride`, see
        // `CaptureConfig::stream_buffer_size`) and length-validate — mirroring
        // `syna_capture_frames_sync@0x18006ae20`, which errors `0xca` on `received != expected`. The
        // `+1` alignment guard in `req_lines` guarantees a short terminating packet, so the exact
        // count arrives; nusb caps the transfer at `frame_size`, hence `got ≤ frame_size`.
        let buf = self.transport.read_bulk(frame_size)?;
        if buf.len() != frame_size {
            return Err(Error::ShortResponse {
                opcode: READ_FRAME_CHUNK[0],
                got: buf.len(),
                need: frame_size,
            });
        }
        Ok(buf)
    }
}

// --- Teardown primitives (drive CaptureContext / teardown) -------------------------------------

impl<T: Transport> CaptureControl for Session<T> {
    fn send_stop_command(&mut self, cmd: u8) -> Result<()> {
        // Tunnel the stop/finalize opcode. A non-zero device status here (e.g. "already stopped") is
        // non-fatal for teardown — only a transport error propagates.
        self.tunnel(&[cmd])?;
        Ok(())
    }

    fn cancel_transfer(&mut self) -> Result<()> {
        // We use synchronous reads, so there is no posted URB to abort as in the DLL's
        // vfmDeviceCtl_180054d10; draining the interrupt endpoint is the practical equivalent (clears
        // any stale wake packet before the stop command).
        self.drain_interrupts();
        Ok(())
    }

    fn disarm_wof(&mut self) -> Result<()> {
        let (class, wake) = self.wof_params()?;
        self.wof_setup(class)?;
        self.tunnel(&wof::arm_command(0, wof::DEFAULT_LED_COLOR, 0, wake))?;
        self.tunnel(&[Opcode::DbInfo.byte()])?;
        Ok(())
    }
}

// --- Capture finger-detect (EP-0x83 IRQ, no SCM WOF arm) --------------------------------------

impl<T: Transport> CaptureFingerDetectIo for Session<T> {
    fn read_capture_interrupt(&mut self, timeout_ms: u64) -> Result<Vec<u8>> {
        self.transport.read_interrupt(INTR_MAX, timeout_ms)
    }
}

// --- Wake-on-finger (SCM path) -----------------------------------------------------------------

impl<T: Transport> WofIo for Session<T> {
    fn arm_wof(&mut self, mask: u8) -> Result<()> {
        let (class, wake) = self.wof_params()?;
        self.wof_setup(class)?;
        self.tunnel(&wof::arm_command(
            wof::arm_tag(mask),
            wof::DEFAULT_LED_COLOR,
            0,
            wake,
        ))?;
        Ok(())
    }

    fn wait_event(&mut self) -> Result<bool> {
        // Block on EP-0x83 for a wake packet; empty (timeout) → no event.
        Ok(!self
            .transport
            .read_interrupt(INTR_MAX, WOF_WAIT_MS)?
            .is_empty())
    }

    fn wof_status(&mut self) -> Result<u8> {
        // Status command = wire opcode 0x77 (no-arg; `syna_cmd_77_reset_noargs`); the raw byte follows
        // the 2-byte tunnel status. Apply the vendor remap (syna_vfm_wof_status_read): 0→0, 1→2, 2→1.
        let reply = self.tunnel(&[WOF_STATUS_CMD])?;
        let raw = reply.get(2).copied().unwrap_or(0);
        Ok(match raw {
            1 => 2,
            2 => 1,
            other => other,
        })
    }
}
