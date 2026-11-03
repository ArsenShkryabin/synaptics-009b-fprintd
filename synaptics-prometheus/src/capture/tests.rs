//! Unit tests for the capture module (moved out of mod.rs; crate-internal access via super).

use super::*;

/// Mock IO: returns a deterministic frame per arm, records the call order.
struct MockIo {
    arm_status: u16,
    frame_byte: u8,
    calls: Vec<&'static str>,
    arms: usize,
}
impl CaptureIo for MockIo {
    fn stop(&mut self) -> Result<()> {
        self.calls.push("stop");
        Ok(())
    }
    fn arm(&mut self, _cmd: &[u8]) -> Result<u16> {
        self.calls.push("arm");
        self.arms += 1;
        Ok(self.arm_status)
    }
    fn read_frame(&mut self, frame_size: usize) -> Result<Vec<u8>> {
        self.calls.push("read");
        Ok(vec![self.frame_byte; frame_size])
    }
}

#[test]
fn frame_size_is_line_times_lines() {
    let c = FrameCapturer::new(160, 112);
    assert_eq!(c.frame_size(), 160 * 112);
}

#[test]
fn capture_one_stops_then_arms_then_reads() {
    let mut io = MockIo {
        arm_status: 0,
        frame_byte: 0xab,
        calls: vec![],
        arms: 0,
    };
    let c = FrameCapturer::new(160, 112);
    let f = c.capture_one_standard(&mut io, &[0x02]).unwrap();
    // ground-truth order: register/stop → arm → read
    assert_eq!(io.calls, ["stop", "arm", "read"]);
    assert_eq!(f.bytes.len(), 160 * 112);
    assert!(f.is_ok());
}

#[test]
fn capture_n_rearms_each_frame() {
    let mut io = MockIo {
        arm_status: 0,
        frame_byte: 1,
        calls: vec![],
        arms: 0,
    };
    let c = FrameCapturer::new(16, 2);
    let frames = c.capture_n(&mut io, &[0x02], 3, Some(PreArmMode::Standard)).unwrap();
    assert_eq!(frames.len(), 3);
    assert_eq!(io.arms, 3, "one arm per frame (frames_sync re-arms)");
}

#[test]
fn capture_one_skips_read_on_bad_arm() {
    let mut io = MockIo {
        arm_status: 0x0450,
        frame_byte: 1,
        calls: vec![],
        arms: 0,
    };
    let c = FrameCapturer::new(16, 2);
    let f = c.capture_one_standard(&mut io, &[0x02]).unwrap();
    assert_eq!(io.calls, ["stop", "arm"], "no read when arm rejected");
    assert!(f.bytes.is_empty());
    assert!(!f.is_ok());
}

#[test]
fn capture_n_stops_after_bad_arm() {
    let mut io = MockIo {
        arm_status: 0x0450,
        frame_byte: 1,
        calls: vec![],
        arms: 0,
    };
    let c = FrameCapturer::new(16, 2);
    let frames = c.capture_n(&mut io, &[0x02], 5, Some(PreArmMode::Standard)).unwrap();
    assert_eq!(frames.len(), 1, "bail on first rejected arm");
}

// ---- polled-frame assembly (assemble_polled_frame) ----

/// Build a `0x51` host-tunnel response: `[status][payload_len][rsvd][payload]`.
fn resp(status: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = status.to_le_bytes().to_vec();
    v.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    v.extend_from_slice(&[0, 0]); // rsvd
    v.extend_from_slice(payload);
    v
}

/// The 12-byte frame header that prefixes the first response's payload.
fn frame_header(h: u16, w: u16) -> Vec<u8> {
    let mut v = Vec::new();
    for x in [h, w, 333u16, 8, 0, 8] {
        v.extend_from_slice(&x.to_le_bytes());
    }
    v
}

#[test]
fn polled_single_read_full_frame() {
    // 2x3 frame (6 body bytes) delivered in ONE read (the 0x2449 case).
    let mut first = frame_header(2, 3);
    first.extend_from_slice(&[10, 11, 12, 13, 14, 15]);
    let mut it = std::iter::once(resp(frame_status::READY, &first));
    let f = assemble_polled_frame(|| it.next(), || true).expect("frame");
    assert_eq!((f.header.width, f.header.height), (3, 2));
    assert_eq!(
        (
            f.header.raw_line_count,
            f.header.field_6,
            f.header.field_8,
            f.header.field_a
        ),
        (333, 8, 0, 8)
    );
    assert_eq!(f.body, vec![10, 11, 12, 13, 14, 15]);
}

#[test]
fn polled_multi_read_assembles_across_chunks() {
    // 2x4 frame (8 body bytes): 5 in the first read (header + body), 3 in a continuation read
    // (pure body, no repeated header — the sensor's cursor has advanced past the header).
    let mut first = frame_header(2, 4);
    first.extend_from_slice(&[1, 2, 3, 4, 5]);
    let responses = vec![
        resp(frame_status::READY, &first),
        resp(frame_status::READY, &[6, 7, 8]),
    ];
    let mut it = responses.into_iter();
    let f = assemble_polled_frame(|| it.next(), || true).expect("frame");
    assert_eq!((f.header.width, f.header.height), (4, 2));
    assert_eq!(f.body, vec![1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn polled_skips_busy_then_reads() {
    // First poll is busy (still acquiring); the assembler retries and reads the ready frame.
    let mut ok = frame_header(1, 2);
    ok.extend_from_slice(&[9, 9]);
    let responses = vec![
        resp(frame_status::BUSY_A, &[]),
        resp(frame_status::READY, &ok),
    ];
    let mut it = responses.into_iter();
    let f = assemble_polled_frame(|| it.next(), || true).expect("frame");
    assert_eq!(f.body, vec![9, 9]);
}

#[test]
fn polled_incomplete_stream_is_none() {
    // Header promises 4 body bytes but only 2 arrive and the stream ends → no torn frame.
    let mut first = frame_header(1, 4);
    first.extend_from_slice(&[1, 2]);
    let mut it = std::iter::once(resp(frame_status::READY, &first));
    assert!(assemble_polled_frame(|| it.next(), || true).is_none());
}

/// Simulate DLL poll → 0x10 header → body-chunk sequence against the test harness.
fn dll_faithful_responses(full_payload: &[u8], chunk_body: usize) -> impl Iterator<Item = Vec<u8>> {
    let header_part = &full_payload[..full_payload.len().min(POLLED_FRAME_HEADER_LEN + 4)];
    let body_rest = &full_payload[POLLED_FRAME_HEADER_LEN + 4..];
    let mut reads: Vec<Vec<u8>> = vec![
        resp(frame_status::READY, &[]), // size-0 poll ready
        resp(frame_status::READY, header_part),
    ];
    for chunk in body_rest.chunks(chunk_body) {
        reads.push(resp(frame_status::READY, chunk));
    }
    reads.into_iter()
}

#[test]
fn dll_faithful_poll_waits_through_wire_busy() {
    let mut payload = frame_header(1, 4);
    payload.extend_from_slice(&[1, 2, 3, 4]);
    let mut reads = vec![
        resp(frame_status::BUSY_A, &[]),
        resp(frame_status::BUSY_B, &[]),
        resp(frame_status::READY, &[]),
    ];
    reads.extend(dll_faithful_responses(&payload, 4096).skip(1));
    let mut it = reads.into_iter();
    let f = assemble_polled_frame_dll_faithful(|_| it.next(), || true).expect("frame");
    assert_eq!(f.body, vec![1, 2, 3, 4]);
}

#[test]
fn dll_faithful_matches_fast_on_single_read_frame() {
    let mut payload = frame_header(2, 3);
    payload.extend_from_slice(&[10, 11, 12, 13, 14, 15]);
    let fast = {
        let mut it = std::iter::once(resp(frame_status::READY, &payload));
        assemble_polled_frame(|| it.next(), || true).expect("fast")
    };
    let mut it = dll_faithful_responses(&payload, 4096);
    // Record what the assembler *asks* for as well as what it builds: the DLL sequence is a
    // size-0 poll, then the 0x10-byte header read, then body reads — the request sizes are part
    // of the wire behaviour under test, not just the assembled frame.
    let mut requested = Vec::new();
    let faithful = assemble_polled_frame_dll_faithful(
        |size| {
            requested.push(size);
            it.next()
        },
        || true,
    )
    .expect("faithful");
    assert_eq!(requested[0], 0, "first read is the size-0 poll");
    assert_eq!(requested[1], DLL_HEADER_READ_BYTES, "second read is the 0x10 header read");
    assert_eq!(fast.header, faithful.header);
    assert_eq!(fast.body, faithful.body);
}

#[test]
fn dll_faithful_overlap_header_read() {
    // Body starts with signature bytes only in continuation after 4-byte overlap.
    let mut payload = frame_header(1, 8);
    payload.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let mut it = dll_faithful_responses(&payload, 2);
    let f = assemble_polled_frame_dll_faithful(
        |size| {
            let _ = size;
            it.next()
        },
        || true,
    )
    .expect("frame");
    assert_eq!(f.body, vec![1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn scan_reference_cells_finds_signature() {
    let width = 16;
    let mut body = vec![0u8; width * 3];
    body[width + 8..width + 8 + 8].copy_from_slice(&REFERENCE_CELL_SIGNATURE);
    let hits = scan_reference_cells(&body, width);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0], ReferenceCellHit { row: 1, col: 8 });
}

#[test]
fn sync_layout_uses_152_stride_and_conditional_usb_pad() {
    let layout = SyncFrameLayout {
        line_width: 144,
        lines_2d: 56,
        repeat_multiplier: 2,
        frames: 3,
    };
    assert_eq!(layout.wire_stride(), 152);
    assert_eq!(layout.base_req_lines(), Some(336));
    assert_eq!(layout.req_lines(), Some(337));
    assert_eq!(layout.buffer_size(), Some(51_224));

    let unaligned = SyncFrameLayout {
        line_width: 144,
        lines_2d: 3,
        repeat_multiplier: 2,
        frames: 1,
    };
    assert_eq!(unaligned.base_req_lines(), Some(6));
    assert_eq!(unaligned.req_lines(), Some(6));
}

#[test]
fn sync_average_skips_first_frame_and_averages_repeat_pairs() {
    let layout = SyncFrameLayout {
        line_width: 2,
        lines_2d: 2,
        repeat_multiplier: 2,
        frames: 2,
    };
    let stride = layout.wire_stride();
    let mut raw = vec![0u8; layout.base_req_lines().unwrap() * stride];
    let second = layout.lines_per_frame().unwrap() * stride;
    for (line, value) in [10u8, 14, 20, 26].into_iter().enumerate() {
        let off = second + line * stride;
        raw[off..off + stride].fill(value);
    }
    let averaged = layout.average_second_frame(&raw).expect("averaged frame");
    assert_eq!(&averaged[..stride], vec![12; stride]);
    assert_eq!(&averaged[stride..], vec![23; stride]);
}

#[test]
fn sync_average_single_frame_averages_in_first_frame_only() {
    // Step-6 path (sync_frames=1): one 112-line frame on 0x2449 geometry, no frame-zero skip.
    let layout = SyncFrameLayout {
        line_width: 2,
        lines_2d: 2,
        repeat_multiplier: 2,
        frames: 1,
    };
    let stride = layout.wire_stride();
    let mut raw = vec![0u8; layout.lines_per_frame().unwrap() * stride];
    for (line, value) in [10u8, 14, 20, 26].into_iter().enumerate() {
        let off = line * stride;
        raw[off..off + stride].fill(value);
    }
    let averaged = layout.average_single_frame(&raw).expect("single-frame average");
    assert_eq!(&averaged[..stride], vec![12; stride]);
    assert_eq!(&averaged[stride..], vec![23; stride]);
    assert!(layout.average_second_frame(&raw).is_none());
}

#[test]
fn sync_layout_rejects_a_flat_polled_body() {
    let layout = SyncFrameLayout {
        line_width: 144,
        lines_2d: 56,
        repeat_multiplier: 2,
        frames: 2,
    };
    let polled_body = vec![0u8; 144 * 56];
    assert!(layout.average_second_frame(&polled_body).is_none());
}

#[test]
fn polled_deadline_stops_polling() {
    // keep_going=false (past deadline) returns None without ever reading.
    let mut reads = 0;
    let f = assemble_polled_frame(
        || {
            reads += 1;
            Some(resp(frame_status::BUSY_A, &[]))
        },
        || false,
    );
    assert!(f.is_none());
    assert_eq!(reads, 0, "no read attempted once past the deadline");
}

// ---- read-mode teardown + WOF, exercised THROUGH the shared CaptureControl/run_wof impls ----

/// One recording test-double for both traits: it records each PRIMITIVE call in order and scripts
/// the WOF wait/status returns. Tests assert on the recorded sequence, so they drive the canonical
/// [`CaptureControl::teardown`] executor and [`run_wof`] rather than re-deriving the dispatch.
#[derive(Default)]
struct RecordingSession {
    log: Vec<String>,
    events: std::collections::VecDeque<(bool, u8)>, // scripted (irq_fired, status) for WOF
    last_status: u8,
}
impl CaptureControl for RecordingSession {
    fn send_stop_command(&mut self, cmd: u8) -> Result<()> {
        self.log.push(format!("stop:{cmd:#04x}"));
        Ok(())
    }
    fn cancel_transfer(&mut self) -> Result<()> {
        self.log.push("cancel".into());
        Ok(())
    }
    fn disarm_wof(&mut self) -> Result<()> {
        self.log.push("wof_disarm".into());
        Ok(())
    }
}
impl WofIo for RecordingSession {
    fn arm_wof(&mut self, mask: u8) -> Result<()> {
        self.log.push(format!("arm:{mask:#04x}"));
        Ok(())
    }
    fn wait_event(&mut self) -> Result<bool> {
        self.log.push("wait".into());
        let (ev, st) = self.events.pop_front().unwrap_or((false, 0));
        self.last_status = st;
        Ok(ev)
    }
    fn wof_status(&mut self) -> Result<u8> {
        self.log.push("status".into());
        Ok(self.last_status)
    }
}

#[test]
fn finalize_gate_matches_dll() {
    // 0x2449 silicon = st8 6 / st9 0x14 → needs the 0x36 finalize.
    assert!(needs_finalize(6, 0x14, false));
    // Same family, st9 exactly 0x13 → NOT > 0x13 → no finalize (unless the flex bit forces it).
    assert!(!needs_finalize(6, 0x13, false));
    assert!(
        needs_finalize(6, 0x13, true),
        "flex bit forces finalize regardless of silicon"
    );
    // A different silicon class → no finalize.
    assert!(!needs_finalize(4, 0x20, false));
}

#[test]
fn teardown_executor_stop_then_finalize_on_2449() {
    // Polled + Calibrate tear down identically: STOP then FINALIZE for 0x2449 silicon.
    for mode in [ReadMode::Polled, ReadMode::Calibrate] {
        let mut s = RecordingSession::default();
        s.teardown(mode, 6, 0x14, false).unwrap();
        assert_eq!(s.log, ["stop:0x04", "stop:0x52"], "{mode:?}");
    }
    // A silicon that doesn't need finalize → STOP only.
    let mut s = RecordingSession::default();
    s.teardown(ReadMode::Polled, 4, 0x20, false).unwrap();
    assert_eq!(s.log, ["stop:0x04"]);
}

#[test]
fn teardown_executor_stream_cancels_transfer_before_stop() {
    let mut s = RecordingSession::default();
    s.teardown(ReadMode::Stream, 6, 0x14, false).unwrap();
    assert_eq!(
        s.log,
        ["cancel", "stop:0x04", "stop:0x52"],
        "device-pushed mode kills the posted URB first, then the capture stop",
    );
}

#[test]
fn teardown_executor_wof_cancels_then_disarms_no_stop() {
    let mut s = RecordingSession::default();
    s.teardown(ReadMode::WakeOnFinger, 6, 0x14, false).unwrap();
    // WOF is presence detection, not a capture: cancel IRQ + disarm, NEVER STOP/FINALIZE.
    assert_eq!(s.log, ["cancel", "wof_disarm"]);
}

// ---- RAII teardown (CaptureContext) ----

#[test]
fn context_tears_down_on_drop() {
    let mut s = RecordingSession::default();
    {
        let _ctx = s.context(ReadMode::Polled, 6, 0x14, false); // no explicit teardown
    } // drop here → canonical teardown
    assert_eq!(s.log, ["stop:0x04", "stop:0x52"]);
}

#[test]
fn context_finish_tears_down_once_and_surfaces_result() {
    let mut s = RecordingSession::default();
    s.context(ReadMode::Stream, 6, 0x14, false)
        .finish()
        .unwrap();
    // finish tears down exactly once (Drop no-ops afterward — no doubled commands).
    assert_eq!(s.log, ["cancel", "stop:0x04", "stop:0x52"]);
}

#[test]
fn context_into_session_skips_teardown() {
    let mut s = RecordingSession::default();
    s.context(ReadMode::Polled, 6, 0x14, false).into_session();
    assert!(s.log.is_empty(), "a handed-off context must not tear down");
}

#[test]
fn context_owns_session_by_value_and_reclaims_it() {
    // The context can own the session outright (not just borrow), and finish() hands it back.
    let s = RecordingSession::default();
    let ctx = CaptureContext::open(s, ReadMode::Calibrate, 6, 0x14, false);
    let s = ctx.finish().unwrap(); // reclaim the owned session after teardown
    assert_eq!(s.log, ["stop:0x04", "stop:0x52"]);
}

#[test]
fn context_tears_down_on_early_return() {
    // A capture flow that bails mid-way WITHOUT an explicit teardown call: the context's Drop
    // must still dearm (the whole point of RAII).
    fn flow(s: &mut RecordingSession) -> Result<()> {
        let mut ctx = s.context(ReadMode::WakeOnFinger, 6, 0x14, false);
        ctx.arm_wof(0x01)?; // derefs to the session
        Err(crate::Error::Malformed("boom".into())) // return early; `ctx` drops → teardown
    }
    let mut s = RecordingSession::default();
    assert!(flow(&mut s).is_err());
    // arm ran, then the context's Drop ran the WOF teardown (cancel + disarm) despite the err.
    assert_eq!(s.log, ["arm:0x01", "cancel", "wof_disarm"]);
}

#[test]
fn run_wof_detects_and_tears_down_via_canonical_path() {
    // First IRQ status misses the mask (pending), second matches. On exit run_wof MUST invoke the
    // canonical WOF teardown (cancel + disarm) via CaptureControl::teardown — not a bespoke disarm.
    let mut s = RecordingSession {
        events: [(true, 0x00), (true, 0x01)].into_iter().collect(),
        ..Default::default()
    };
    let got = run_wof(&mut s, 0x01, || true).unwrap();
    assert!(got, "finger event matching mask should be detected");
    assert_eq!(
        s.log,
        [
            "arm:0x01",
            "wait",
            "status",
            "wait",
            "status",
            "cancel",
            "wof_disarm"
        ],
    );
}

#[test]
fn run_wof_tears_down_on_timeout() {
    let mut s = RecordingSession {
        events: [(false, 0)].into_iter().collect(),
        ..Default::default()
    };
    let got = run_wof(&mut s, 0x01, || true).unwrap();
    assert!(!got);
    assert_eq!(s.log, ["arm:0x01", "wait", "cancel", "wof_disarm"]);
}

#[test]
fn run_wof_tears_down_when_guard_false() {
    // keep_going false from the start: arm → straight to the canonical teardown, no wait.
    let mut s = RecordingSession::default();
    let got = run_wof(&mut s, 0x01, || false).unwrap();
    assert!(!got);
    assert_eq!(s.log, ["arm:0x01", "cancel", "wof_disarm"]);
}

#[test]
fn query_capture_touch_status_bare_type2_event_sets_no_finger_latch() {
    // GROUNDED (Ghidra + Frida + device, 2026-07-23): EP-0x83 byte0 (0/2/3) is an IRQ
    // *notification*, NOT the touch class — a spurious type-2 `FingerDown` fires ~immediately with
    // no finger. The finger signal is the AFE baseline-delta = bit 0x4 (query_type-1
    // `local_24/local_23 != [+0x4c/+0x4d]`). A bare type-2 (no baseline delta) must set NO latch.
    let fields = [0x02, 0x00, 0x40, 0x10, 0x00, 0, 0];
    let status =
        query_capture_touch_status_query1(&fields, 0, 0, TouchStatusPolicy::CaptureIrqIgnoreType2);
    assert_eq!(status & CAPTURE_TOUCH_LATCH_BIT, 0, "no baseline delta -> no finger latch bit 0x4");
}

#[test]
fn query_capture_touch_status_plugin_class2_is_busy() {
    let fields = [0x02, 0x00, 0x40, 0x10, 0x00, 0, 0];
    let status = query_capture_touch_status_query1(
        &fields,
        0,
        0,
        TouchStatusPolicy::PluginClassByte0,
    );
    assert_eq!(status & CAPTURE_TOUCH_BUSY_BIT, CAPTURE_TOUCH_BUSY_BIT);
}

#[test]
fn query_capture_touch_status_type3_complete_latches_on_2449_policy() {
    let fields = [0x03, 0x00, 0x04, 0x00, 0x00, 0, 0];
    let status = query_capture_touch_status_query1(
        &fields,
        0,
        0,
        TouchStatusPolicy::CaptureIrqIgnoreType2,
    );
    assert_eq!(status & CAPTURE_TOUCH_LATCH_BIT, CAPTURE_TOUCH_LATCH_BIT);
}

#[test]
fn query_capture_touch_status_trailing_byte_delta_latches() {
    let fields = [0x02, 0x00, 0x40, 0x10, 0x00, 0x01, 0];
    let status = query_capture_touch_status_query1(
        &fields,
        0,
        0,
        TouchStatusPolicy::CaptureIrqIgnoreType2,
    );
    assert_eq!(status & CAPTURE_TOUCH_LATCH_BIT, CAPTURE_TOUCH_LATCH_BIT);
}

#[test]
fn wait_capture_finger_detect_ignores_bare_type2_event() {
    // GROUNDED (device + Frida): a bare type-2 `FingerDown` fires spuriously ~post-arm with no
    // finger and carries no AFE baseline delta, so the wait must NOT report a finger. (The DLL's
    // wake loop uses mask 0x06, but its `status` is the plugin's *computed* touch class, not this
    // event byte — for the spurious event that class is 0. The real signal reaching us is the 0x4
    // baseline-delta, so we gate on 0x4.)
    struct MockFingerDetect {
        packets: std::collections::VecDeque<Vec<u8>>,
    }
    impl CaptureFingerDetectIo for MockFingerDetect {
        fn read_capture_interrupt(&mut self, _timeout_ms: u64) -> Result<Vec<u8>> {
            Ok(self.packets.pop_front().unwrap_or_default())
        }
    }
    let mut cache = TouchPluginCache {
        policy: TouchStatusPolicy::CaptureIrqIgnoreType2,
        ..Default::default()
    };
    cache.snapshot_baselines();
    let mut io = MockFingerDetect {
        packets: [vec![], vec![0x02, 0x00, 0x40, 0x10, 0x00]].into(),
    };
    let mut steps = 0usize;
    let got = wait_capture_finger_detect(&mut io, &mut cache, WAIT_FINGER_MASK_HELLO, 10, || {
        steps += 1;
        steps <= 4
    })
    .unwrap();
    assert!(!got, "spurious type-2 event must not latch — real finger = 0x4 baseline-delta");
}

#[test]
fn wait_capture_finger_detect_accepts_type3_complete_on_2449_policy() {
    struct MockFingerDetect {
        packets: std::collections::VecDeque<Vec<u8>>,
    }
    impl CaptureFingerDetectIo for MockFingerDetect {
        fn read_capture_interrupt(&mut self, _timeout_ms: u64) -> Result<Vec<u8>> {
            Ok(self.packets.pop_front().unwrap_or_default())
        }
    }
    let mut cache = TouchPluginCache {
        policy: TouchStatusPolicy::CaptureIrqIgnoreType2,
        ..Default::default()
    };
    cache.snapshot_baselines();
    let mut io = MockFingerDetect {
        packets: [
            vec![],
            vec![0x03, 0x00, 0x04, 0x00, 0x00],
        ]
        .into(),
    };
    let got =
        wait_capture_finger_detect(&mut io, &mut cache, WAIT_FINGER_MASK_HELLO, 10, || true)
            .unwrap();
    assert!(got);
}

#[test]
fn wait_capture_finger_detect_returns_false_when_guard_stops() {
    struct MockFingerDetect;
    impl CaptureFingerDetectIo for MockFingerDetect {
        fn read_capture_interrupt(&mut self, _timeout_ms: u64) -> Result<Vec<u8>> {
            Ok(vec![0x03, 0, 0, 0, 0, 0, 0])
        }
    }
    let mut cache = TouchPluginCache {
        policy: TouchStatusPolicy::CaptureIrqIgnoreType2,
        ..Default::default()
    };
    cache.snapshot_baselines();
    let mut io = MockFingerDetect;
    let got = wait_capture_finger_detect(
        &mut io,
        &mut cache,
        WAIT_FINGER_MASK_HELLO,
        10,
        || false,
    )
    .unwrap();
    assert!(!got);
}

// ---- WOF arm-record wire bytes (wof::arm_command) — validated on 0x2449 hardware ----

#[test]
fn wof_arm_command_2449_wire_bytes() {
    // Arm mask 0x01 → tag (0x01&1)|ARM_ENABLE = 0x03. Fields are LITTLE-ENDIAN (syna_cmd_76 copies
    // them verbatim — `syna_util_u32_identity` is NOT a byteswap), plus 0x2449's 8-byte flex block.
    let cmd = wof::arm_command(wof::arm_tag(0x01), wof::DEFAULT_LED_COLOR, 0, wof::WAKE_FLEX_2449);
    assert_eq!(
        cmd,
        vec![
            0x76, // SendRecordHeader
            0x03, // tag = (mask & 1) | ARM_ENABLE
            0, 0, 0, // pad to the 4-byte tag slot
            0x04, 0x10, 0x40, 0x00, // u32le(0x00401004) wake marker
            0xcc, 0x00, 0xff, 0x00, // u32le(0x00ff00cc) LED colour
            0, 0, 0, 0, // u32le(0) LED colour 2
            0xd0, 0x07, // u16le(2000) wake timeout
            0x08, 0x00, // u16le(8) wake_size = WAKE_FLEX_2449.len()
            3, 0, 0, 0, // record[0x14..0x18], verbatim
            0x00, 0x00, 0x00, 0x00, 0xf2, 0x02, 0x01, 0x00, // flex(+0x70) block
        ],
    );
    // syna_cmd_76 alloc_buf(0x76, wake_size + 0x19) = 8 + 0x19 = 0x21.
    assert_eq!(cmd.len(), 0x21);
    // Disarm = tag 0.
    assert_eq!(wof::arm_command(0, wof::DEFAULT_LED_COLOR, 0, wof::WAKE_FLEX_2449)[1], 0);
}

// =================================================================================================
// read_mode 2 — `vfmCapture@0x180053bb0` / `assemble_polled_frame_vfm`.
//
// The contract these pin is deliberately NOT `syna_capture_image`'s: no `0x10` header read, the
// total supplied by the caller, finger states as events, and truncate-on-any-nonzero.
// =================================================================================================

/// Wire status words, named so the sequences below read as the DLL's own state names.
mod vfm_wire {
    pub const READY: u16 = 0x0000;
    pub const IN_PROGRESS: u16 = 0x0001; // -> 0x192
    pub const FINGER_SETTLED: u16 = 0x0002; // -> 0x193
    pub const FINGER_REMOVED: u16 = 0x0004; // -> 0x195
    pub const FINGER_ON_SENSOR: u16 = 0x0005; // -> 0x196
    pub const FINGER_DETECTED: u16 = 0x0006; // -> 0x197
}

/// Drive `assemble_polled_frame_vfm` over a canned reply list, recording the requested sizes.
fn run_vfm(
    body_len: usize,
    start_latched: bool,
    replies: Vec<Vec<u8>>,
) -> (Option<PolledFrame>, Vec<u32>) {
    let mut it = replies.into_iter();
    let mut sizes = Vec::new();
    let frame = assemble_polled_frame_vfm(
        body_len + POLLED_FRAME_HEADER_LEN,
        start_latched,
        |size| {
            sizes.push(size);
            it.next()
        },
        || true,
    );
    (frame, sizes)
}

#[test]
fn vfm_polls_with_size_zero_then_reads_the_body_without_a_header_read() {
    let mut payload = frame_header(2, 3);
    payload.extend_from_slice(&[10, 11, 12, 13, 14, 15]);
    let (frame, sizes) = run_vfm(
        6,
        false,
        vec![
            resp(vfm_wire::IN_PROGRESS, &[]), // busy poll
            resp(vfm_wire::READY, &[]),       // first success: latches only
            resp(vfm_wire::READY, &payload),  // body (header + 6 bytes)
        ],
    );
    let f = frame.expect("frame");
    assert_eq!(f.body, vec![10, 11, 12, 13, 14, 15]);
    assert_eq!((f.header.height, f.header.width), (2, 3));
    // Requests: 0 while unlatched, then min(0x2000, total) — and NEVER 0x10.
    assert_eq!(sizes[0], 0);
    assert_eq!(sizes[1], 0);
    assert_eq!(sizes[2], (6 + POLLED_FRAME_HEADER_LEN) as u32);
    assert!(
        !sizes.contains(&DLL_HEADER_READ_BYTES),
        "read_mode 2 must not issue the 0x10 header read: {sizes:?}"
    );
}

#[test]
fn vfm_started_latched_reads_body_immediately() {
    // When the pump enters with a touch event (*out_status == 0x80) it is already latched, so the
    // very first request is a body read rather than a size-0 poll.
    let mut payload = frame_header(2, 3);
    payload.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
    let (frame, sizes) = run_vfm(6, true, vec![resp(vfm_wire::READY, &payload)]);
    assert_eq!(frame.expect("frame").body, vec![1, 2, 3, 4, 5, 6]);
    assert_eq!(sizes, vec![(6 + POLLED_FRAME_HEADER_LEN) as u32]);
}

#[test]
fn vfm_keeps_pumping_through_finger_detected_and_on_sensor() {
    // 0x0006 / 0x0005 abort the STILL reader; here they must not.
    let mut payload = frame_header(2, 3);
    payload.extend_from_slice(&[7; 6]);
    let (frame, _) = run_vfm(
        6,
        true,
        vec![
            resp(vfm_wire::FINGER_DETECTED, &[]),
            resp(vfm_wire::FINGER_ON_SENSOR, &[]),
            resp(vfm_wire::FINGER_SETTLED, &[]),
            resp(vfm_wire::READY, &payload),
        ],
    );
    assert_eq!(frame.expect("frame").body, vec![7; 6]);
}

#[test]
fn vfm_finger_removed_stops_cleanly_and_truncates_to_bytes_copied() {
    // desc->total = desc->copied at 0x180053f34: a mid-frame stop yields a SHORT frame, not an
    // error and not a full-length one.
    let mut first = frame_header(2, 3);
    first.extend_from_slice(&[1, 2, 3]); // only 3 of 6 body bytes arrive
    let (frame, _) = run_vfm(
        6,
        true,
        vec![
            resp(vfm_wire::READY, &first),
            resp(vfm_wire::FINGER_REMOVED, &[]),
        ],
    );
    let f = frame.expect("truncated frame is still a frame");
    assert_eq!(f.body, vec![1, 2, 3]);
    assert_eq!((f.header.height, f.header.width), (2, 3));
}

#[test]
fn vfm_short_chunk_completes_the_frame() {
    // The DLL's `local_78[0] < max_chunk` test: a chunk shorter than requested ends the frame.
    let mut payload = frame_header(2, 3);
    payload.extend_from_slice(&[9; 6]);
    let (frame, _) = run_vfm(600, true, vec![resp(vfm_wire::READY, &payload)]);
    assert_eq!(frame.expect("frame").body, vec![9; 6]);
}
