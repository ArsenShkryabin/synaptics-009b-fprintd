//! `Session` read/capture methods: `0x51` frame-chunk reads, capture-complete ack / result query,
//! and the polled-frame assembly (DLL-faithful + alt strategies). Split out of the session impl;
//! a separate inherent-impl block on the same `Session<T>` (methods unchanged, no re-export needed).

use super::Session;
use crate::capture::{
    assemble_polled_frame, assemble_polled_frame_dll_faithful, frame_chunk_alt_cmd, frame_chunk_cmd,
    CaptureFingerDetectIo, PolledAssemblerStrategy, PolledFrame, TouchPluginCache,
    CAPTURE_TOUCH_BUSY_BIT, CAPTURE_TOUCH_LATCH_BIT, READ_FRAME_CHUNK,
};
use crate::error::{Error, Result, Status};
use crate::proto::Opcode;
use crate::transport::Transport;

impl<T: Transport> Session<T> {
    /// Read one `0x51` frame chunk (for [`assemble_polled_frame`]). `None` on transport error.
    pub fn read_frame_chunk(&mut self) -> Option<Vec<u8>> {
        self.tunnel(&READ_FRAME_CHUNK).ok()
    }

    /// Read one `0x51` chunk with an explicit DLL size argument (`0` poll, `0x10` header, etc.).
    pub fn read_frame_chunk_sized(&mut self, size: u32) -> Option<Vec<u8>> {
        self.tunnel(&frame_chunk_cmd(size)).ok()
    }

    /// Read one alt frame chunk (`read_mode==3`) — wire `0x78` + u32 size
    /// (`syna_scs_read_frame_chunk_alt@0x18005d090`).
    pub fn read_frame_chunk_alt_sized(&mut self, size: u32) -> Option<Vec<u8>> {
        self.tunnel(&frame_chunk_alt_cmd(size)).ok()
    }

    /// Post-frame capture-complete ack — SCS idx `0x0a` → wire `CaptureStop` (`0x04`).
    pub fn capture_complete_ack(&mut self) -> Result<()> {
        let status = Self::status_of(&self.tunnel(&[Opcode::CaptureStop.byte()])?);
        if status != 0 {
            return Err(Error::Status {
                opcode: Opcode::CaptureStop.byte(),
                status: Status::from_wire(status),
            });
        }
        Ok(())
    }

    /// Query capture result byte — SCS idx `0x0b` → wire `GetSensorState` (`0x17`).
    pub fn query_capture_result(&mut self) -> Result<u8> {
        let reply = self.tunnel(&[Opcode::GetSensorState.byte()])?;
        let status = Self::status_of(&reply);
        if status != 0 {
            return Err(Error::Status {
                opcode: Opcode::GetSensorState.byte(),
                status: Status::from_wire(status),
            });
        }
        Ok(*reply.get(2).unwrap_or(&0))
    }

    /// `vfmCapture`-shaped polled frame read for [`MatcherSubmode`] 2 or 3.
    ///
    /// When `finger_gate` is true (`read_mode==2` + `bScs_sensor`, Hello identify/enroll), runs the
    /// inner `syna_wbdi_read_fp_data` touch poll until latch bit `0x4` before the first `0x51`.
    ///
    /// The `0x51` read itself only re-strides the flat body (mirroring `syna_capture_image`, which
    /// applies NO coefficients host-side). For recon=8 imaging arms the sensor's recon-config
    /// (`tag 0x30000288`) was stashed by [`Self::arm`] and is available via
    /// [`Self::take_recon_config`]; it feeds the (research-only) matcher reconstruction downstream,
    /// not this capture read.
    ///
    /// `body_len` is the expected flat body size (`width * height`) for the armed capture. On
    /// read_mode 2 the DLL does **not** learn this from the wire — `vfmCapture` takes it from
    /// `session+0x20`, which its pump sized from the capture geometry — so the caller supplies it
    /// here for the same reason. Get it from the resolved [`crate::capture_prog::CaptureConfig`].
    pub fn capture_vfm_polled(
        &mut self,
        submode: crate::capture::MatcherSubmode,
        finger_gate: bool,
        body_len: usize,
        mut keep_going: impl FnMut() -> bool,
    ) -> Option<crate::capture::PolledFrame> {
        use crate::capture::{assemble_polled_frame_vfm, MatcherSubmode, POLLED_FRAME_HEADER_LEN};
        match submode {
            MatcherSubmode::PolledIdentify => {
                let dbg = std::env::var_os("SYNA_FINGER_DEBUG").is_some();
                // pv-faithful finger wait (SYNA_PV_FINGER): python-validity's `capture()` arms, then
                // reads ONLY EP-0x83 (`usb.wait_int`) — NO command-channel traffic (no `0x75`/identity
                // probe, no `0x51` polls) — interpreting interrupt byte0: 0=start, 2=finger-down,
                // 3=complete. Our normal paths send `0x75` (presence_caps) or poll `0x51` while armed,
                // which reset the 0x0199 die (300 ms with `0x75`, ~1.7 s with `0x51`). This isolates
                // whether command-channel activity is the killer and EP-0x83-only is safe.
                if std::env::var_os("SYNA_PV_FINGER").is_some() {
                    if dbg {
                        eprintln!("# pv-wait: EP-0x83 only, no command channel (pv wait_int model)");
                    }
                    let mut n = 0u32;
                    let mut finger = false;
                    while keep_going() {
                        n += 1;
                        let pkt = match self.read_capture_interrupt(200) {
                            Ok(p) => p,
                            Err(e) => {
                                if dbg {
                                    eprintln!("# pv-wait: EP-0x83 ERR after {n} reads: {e}");
                                }
                                return None;
                            }
                        };
                        if pkt.is_empty() {
                            continue;
                        }
                        if dbg {
                            eprintln!(
                                "# pv-wait: read {n} EP-0x83 event byte0={:#04x} len={}",
                                pkt[0],
                                pkt.len()
                            );
                        }
                        match pkt.first() {
                            Some(2) => {
                                if dbg {
                                    eprintln!("# pv-wait: FINGER DOWN (byte0=2) → reading frame");
                                }
                                finger = true;
                                break;
                            }
                            Some(3) => {
                                if dbg {
                                    eprintln!("# pv-wait: capture complete (byte0=3)");
                                }
                                finger = true;
                                break;
                            }
                            _ => {}
                        }
                    }
                    if dbg && !finger {
                        eprintln!("# pv-wait: {n} reads, no finger event, die {}",
                            "survived (timeout)");
                    }
                    if !finger {
                        return None;
                    }
                    return assemble_polled_frame_vfm(
                        body_len + POLLED_FRAME_HEADER_LEN,
                        true,
                        |size| self.read_frame_chunk_sized(size),
                        keep_going,
                    );
                }
                // The touch latch is the DLL's *pre-`0x51`* gate: with read_mode 2 + `bScs_sensor`,
                // `syna_wbdi_read_fp_data` issues no `0x51` at all until it trips. When it does trip
                // via a touch event the DLL enters the frame read already latched (its previous
                // `*out_status` was `0x80`), so the first request is a body read, not a size-0 poll.
                //
                // BUT: the EP-0x83 touch latch is the 0x2449 (`bScs_sensor`) model. The older type-1
                // die (0x0199) routes ALL reads to the polled `0x51` channel
                // (`syna_capture_dispatch_by_die`: type-1 → polled), and empirically reading EP-0x83
                // while armed DISCONNECTS this die ~300 ms in. SYNA_NO_EP83_LATCH skips the latch and
                // drives the finger wait via the `0x51` pump itself (retries on 0x192/0x193
                // IN_PROGRESS/FINGER_SETTLED until a frame), which is the correct transport for this die.
                let skip_latch = std::env::var_os("SYNA_NO_EP83_LATCH").is_some();
                // EP-0x83 poll timeout. Default 50 ms (rapid poll). SYNA_FINGER_POLL_MS overrides it —
                // a large value makes each iteration ONE long blocking interrupt read (closer to the
                // DLL's blocking finger wait) instead of a poll storm, to test whether rapid EP-0x83
                // reads are what disconnect the 0x0199 die.
                let poll_ms: u64 = std::env::var("SYNA_FINGER_POLL_MS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(50);
                let latched = if finger_gate && !skip_latch {
                    if !self.wait_read_fp_data_touch_latch(poll_ms, &mut keep_going)? {
                        return None;
                    }
                    true
                } else {
                    false
                };
                if dbg && skip_latch {
                    eprintln!("# finger-wait: EP-0x83 latch SKIPPED — driving the 0x51 pump directly");
                }
                let mut polls = 0u32;
                let mut disconnected = false;
                let frame = assemble_polled_frame_vfm(
                    body_len + POLLED_FRAME_HEADER_LEN,
                    latched,
                    |size| {
                        polls += 1;
                        match self.read_frame_chunk_sized(size) {
                            Some(r) => {
                                if dbg {
                                    let st = if r.len() >= 2 {
                                        u16::from_le_bytes([r[0], r[1]])
                                    } else {
                                        0xffff
                                    };
                                    eprintln!(
                                        "# 0x51 poll {polls}: req={size} status={st:#06x} len={}",
                                        r.len()
                                    );
                                }
                                Some(r)
                            }
                            None => {
                                disconnected = true;
                                None
                            }
                        }
                    },
                    keep_going,
                );
                if dbg {
                    eprintln!(
                        "# 0x51-pump: {polls} polls, {}",
                        if disconnected {
                            "TRANSPORT ERR (die disconnect)"
                        } else {
                            "survived (frame or clean timeout)"
                        }
                    );
                }
                frame
            }
            MatcherSubmode::PolledEnrollAlt => {
                if finger_gate && !self.wait_read_fp_data_touch_latch(50, &mut keep_going)? {
                    return None;
                }
                self.capture_polled_alt_frame(keep_going)
            }
            MatcherSubmode::StreamEnroll => None,
        }
    }

    /// Inner `read_fp_data` gate — poll EP-0x83 + plugin touch status until finger latched (`0x4`).
    pub fn wait_read_fp_data_touch_latch(
        &mut self,
        poll_ms: u64,
        mut keep_going: impl FnMut() -> bool,
    ) -> Option<bool> {
        let dbg = std::env::var_os("SYNA_FINGER_DEBUG").is_some();
        let caps = match self.presence_caps() {
            Ok(c) => c,
            Err(e) => {
                if dbg {
                    eprintln!("# finger-wait: presence_caps FAILED: {e} — bailing (this is the immediate-return bug)");
                }
                return None;
            }
        };
        let mut cache = TouchPluginCache::for_presence_caps(&caps);
        cache.snapshot_baselines();
        if dbg {
            eprintln!("# finger-wait: policy={:?}, polling EP-0x83 for a touch latch…", cache.policy);
        }
        let mut iters = 0u64;
        let mut last_status = 0u8;
        while keep_going() {
            iters += 1;
            let pkt = match self.read_capture_interrupt(poll_ms) {
                Ok(p) => p,
                Err(e) => {
                    if dbg {
                        eprintln!("# finger-wait: read_capture_interrupt ERR after {iters} polls: {e} — bailing");
                    }
                    return None;
                }
            };
            if !pkt.is_empty() {
                cache.feed_interrupt(&pkt);
            }
            let status = cache.query_capture_touch_status_query1();
            if dbg && status != last_status {
                eprintln!("# finger-wait: iter {iters} touch status = {status:#04x}");
                last_status = status;
            }
            match cache.policy {
                crate::capture::TouchStatusPolicy::CaptureIrqIgnoreType2 => {
                    if (status & CAPTURE_TOUCH_LATCH_BIT) != 0 {
                        if dbg {
                            eprintln!("# finger-wait: LATCHED after {iters} polls (status {status:#04x})");
                        }
                        return Some(true);
                    }
                }
                crate::capture::TouchStatusPolicy::PluginClassByte0 => {
                    if (status & CAPTURE_TOUCH_BUSY_BIT) != 0 {
                        continue;
                    }
                    if (status & CAPTURE_TOUCH_LATCH_BIT) != 0 {
                        if dbg {
                            eprintln!("# finger-wait: LATCHED after {iters} polls (status {status:#04x})");
                        }
                        return Some(true);
                    }
                }
            }
        }
        if dbg {
            eprintln!("# finger-wait: timed out after {iters} polls, no latch (last status {last_status:#04x})");
        }
        Some(false)
    }

    /// Mode-3 alt reader — the loop itself lives in
    /// [`crate::capture::assemble_polled_frame_alt`]; this only supplies the two sensor operations
    /// via [`crate::capture::AltFrameIo`]. (It used to be a verbatim copy of that loop, because two
    /// `FnMut` closures cannot both borrow `self`; the trait removes the duplicate.)
    pub(crate) fn capture_polled_alt_frame(
        &mut self,
        keep_going: impl FnMut() -> bool,
    ) -> Option<crate::capture::PolledFrame> {
        crate::capture::assemble_polled_frame_alt(self, keep_going)
    }

    /// After a mode-3 frame, run DLL post-read ack + optional power query (best-effort).
    pub fn finalize_vfm_alt_capture(&mut self) -> Result<()> {
        self.capture_complete_ack()
    }

    /// Assemble one full polled frame using the DLL-faithful `0x51` sequence
    /// (`syna_capture_image@0x180099540`: size-0 poll → `0x10` header → body chunks).
    pub fn capture_polled_dll(&mut self, keep_going: impl FnMut() -> bool) -> Option<PolledFrame> {
        self.capture_polled_with(PolledAssemblerStrategy::DllFaithful, keep_going)
    }

    /// Assemble one full polled ([`crate::capture::ReadMode::Polled`]) frame from the multi-read
    /// `0x51` stream, bounded by `keep_going` (poll until it returns false). Convenience over
    /// [`assemble_polled_frame`] bound to this session's tunnel.
    pub fn capture_polled(&mut self, keep_going: impl FnMut() -> bool) -> Option<PolledFrame> {
        self.capture_polled_with(PolledAssemblerStrategy::FastSingleRead, keep_going)
    }

    /// [`Self::capture_polled`] with an explicit [`PolledAssemblerStrategy`] for DLL parity experiments.
    pub fn capture_polled_with(
        &mut self,
        strategy: PolledAssemblerStrategy,
        keep_going: impl FnMut() -> bool,
    ) -> Option<PolledFrame> {
        match strategy {
            PolledAssemblerStrategy::FastSingleRead => {
                assemble_polled_frame(|| self.read_frame_chunk(), keep_going)
            }
            PolledAssemblerStrategy::DllFaithful => assemble_polled_frame_dll_faithful(
                |size| self.read_frame_chunk_sized(size),
                keep_going,
            ),
        }
    }
}

/// The two sensor ops the read_mode-3 alt loop needs, so the loop can live once in
/// `capture::assemble_polled_frame_alt` instead of being copied into `Session`.
impl<T: Transport> crate::capture::AltFrameIo for Session<T> {
    fn read_alt(&mut self, size: u32) -> Option<Vec<u8>> {
        self.read_frame_chunk_alt_sized(size)
    }

    fn query_result(&mut self) -> Option<u8> {
        self.query_capture_result().ok()
    }
}
