//! Unit tests for the capture_prog module (moved out of mod.rs; access via super).

use super::*;


#[test]
fn capture_status_names_in_progress() {
    // The value our live runs saw — must read as "in progress", not an error.
    assert_eq!(
        CaptureStatus::from_error(0x0008_0000),
        CaptureStatus::InProgress
    );
    assert!(CaptureStatus::from_error(0x0008_0000).is_in_progress());
    assert_eq!(CaptureStatus::from_error(0), CaptureStatus::Ok);
    assert_eq!(CaptureStatus::from_error(0x66), CaptureStatus::Other(0x66));
    // The exact result bytes from the live sensor: len=8076 x=56 y=144 w1=333 w2=8 err=0x80000.
    let d = [
        0x8c, 0x1f, 0x00, 0x00, 0x38, 0x00, 0x90, 0x00, 0x4d, 0x01, 0x08, 0x00, 0x00, 0x00,
        0x08, 0x00,
    ];
    let r = CaptureResult::parse(&d).unwrap();
    assert_eq!((r.len, r.x, r.y, r.w1, r.w2), (8076, 56, 144, 333, 8));
    assert_eq!(r.status, CaptureStatus::InProgress);
}

#[test]
fn capture_event_decodes_interrupt_types() {
    use crate::line_update::Mode;
    assert_eq!(CaptureEvent::parse(&[0]), Some(CaptureEvent::Started));
    assert_eq!(
        CaptureEvent::parse(&[2, 0, 0x40]),
        Some(CaptureEvent::FingerDown)
    );
    // The exact type-2 bytes our live sensor sent.
    assert_eq!(
        CaptureEvent::parse(&[0x02, 0x00, 0x40, 0x10, 0x00]),
        Some(CaptureEvent::FingerDown)
    );
    assert_eq!(
        CaptureEvent::parse(&[3, 0, 4]),
        Some(CaptureEvent::Complete)
    );
    assert_eq!(
        CaptureEvent::parse(&[3, 0, 0]),
        Some(CaptureEvent::Progress)
    );
    assert_eq!(CaptureEvent::parse(&[7]), Some(CaptureEvent::Other(7)));
    assert_eq!(CaptureEvent::parse(&[]), None);
    // Capture-mode values match the vendor CaptureMode enum + the DLL mode mapping.
    assert_eq!(
        (
            Mode::Calibrate.value(),
            Mode::Identify.value(),
            Mode::Enroll.value()
        ),
        (1, 2, 3)
    );
    assert_eq!(Mode::Identify.dll_mode(), Some(4));
    assert_eq!(Mode::Enroll.dll_mode(), Some(6));
    assert_eq!(Mode::Calibrate.dll_mode(), None);
}

#[test]
fn this_box_resolves_to_2449() {
    // 06cb:009b, silicon major 0x190 / minor 0x4b -> subtype 0x2449 ("86C TM-3368-001").
    assert_eq!(subtype_for_silicon(0x190, 0x4b), Some(0x2449));
}

#[test]
fn unknown_major_is_none() {
    assert_eq!(subtype_for_silicon(0xdead, 0x01), None);
}

#[test]
fn select_2449_program_is_200x152_1688b() {
    let p = select_prog(0x2449, 6, 0x14).expect("0x2449 has a program");
    assert_eq!((p.width, p.height), (200, 152));
    assert_eq!(p.program.len(), 1688);
}

#[test]
fn program_chunks_round_trip_and_expose_geometry() {
    let p = select_prog(0x2449, 6, 0x14).unwrap();
    let chunks = split_chunks(p.program).expect("valid timeslot program");
    assert_eq!(chunks.len(), 12);
    assert_eq!(merge_chunks(&chunks), p.program);
    // The 0x2f "2D" chunk carries lines_2d = 56 (0x38) for this sensor.
    assert_eq!(lines_2d(p.program), Some(56));
}

#[test]
fn capture_config_2449_emits_interleave_one() {
    let cfg = CaptureConfig::for_silicon(0x190, 0x4b, 6, 0x14).expect("resolves");
    assert_eq!(cfg.line_update_interleave, 1);
    let arm = cfg
        .upload_cmd_prod33_sync(&[], &[], 3)
        .expect("stream arm");
    // Line-update blob starts after 0x02 header (5) + program chunks; 0x44 chunk = interleave 1.
    assert!(
        arm.windows(8).any(|w| w[0..2] == [0x44, 0x00] && w[4..8] == [1, 0, 0, 0]),
        "stream arm must include Interleave(1) per flex[0x14]=2"
    );
}

#[test]
fn build_cmd_02_frames_correctly() {
    let prog = [0x23u8, 0x00, 0x00, 0x00];
    let cmd = build_cmd_02(&prog, 200, CaptureMode::Identify);
    // 02 | bpl=200 (0xC8) LE | req_lines=0 LE | program
    assert_eq!(&cmd[..5], &[0x02, 0xc8, 0x00, 0x00, 0x00]);
    assert_eq!(&cmd[5..], &prog);
}

#[test]
fn capture_config_end_to_end() {
    let cfg = CaptureConfig::for_silicon(0x190, 0x4b, 6, 0x14).expect("resolves");
    assert_eq!(cfg.subtype, 0x2449);
    assert_eq!(cfg.bytes_per_line, 160); // from the flex-params SensorTypeInfo (not the 200 descriptor width)
    assert_eq!(cfg.type_info.line_width, 144);
    assert_eq!(cfg.descramble_blocks_per_line(), 9);
    assert_eq!(cfg.lines_2d, 56);
    let cmd = cfg.upload_cmd();
    assert_eq!(cmd[0], 0x02);
    assert_eq!(cmd.len(), 5 + 1688);
}

#[test]
fn stream_buffer_size_matches_dll_and_arm() {
    // 0x2449: lines_per_frame = lines_2d(56) × repeat_multiplier(2) = 112; stride = 144+8 = 152.
    let cfg = CaptureConfig::for_silicon(0x190, 0x4b, 6, 0x14).expect("resolves");
    assert_eq!(cfg.lines_per_frame(), 112);
    assert_eq!(cfg.sync_line_stride(), 152);
    // req_lines = frames*112 + 1 (the +1 USB alignment guard); buffer = req_lines × 152.
    assert_eq!(cfg.stream_req_lines(1), 113);
    assert_eq!(cfg.stream_buffer_size(1), 113 * 152); // 17176
    assert_eq!(cfg.stream_req_lines(3), 337);
    assert_eq!(cfg.stream_buffer_size(3), 51224);
    assert_eq!(cfg.stream_req_lines(CAL_STEP7_SETTLE_SYNC_FRAMES), cfg.stream_req_lines(CAL_STEP6_SYNC_FRAMES));
    assert_eq!(
        cfg.stream_buffer_size(CAL_STEP7_SETTLE_SYNC_FRAMES),
        cfg.stream_buffer_size(CAL_STEP6_SYNC_FRAMES)
    );

    // Stream arms: frames ≥ 1 (default 3). Step-7 settle uses dedicated builder, not this loop.
    let fcv = vec![0u8; 64];
    for frames in [1u32, STREAM_DEFAULT_SYNC_FRAMES, 7] {
        let cmd = cfg
            .upload_cmd_prod33_sync(&fcv, &[], frames)
            .expect("builds");
        assert_eq!(
            u16::from_le_bytes([cmd[3], cmd[4]]),
            cfg.stream_req_lines(frames),
            "sync arm req_lines == stream_req_lines for {frames} frames",
        );
    }
}

#[test]
fn upload_cmd_prod33_frames_a_02_command_with_line_update_chunks() {
    let cfg = CaptureConfig::for_silicon(0x190, 0x4b, 6, 0x14).expect("resolves");
    let fcv = vec![0u8; 64]; // stand-in factory bits
    let cmd = cfg.upload_cmd_prod33(&fcv).expect("builds");
    assert_eq!(cmd[0], 0x02);
    assert_eq!(u16::from_le_bytes([cmd[1], cmd[2]]), cfg.bytes_per_line);
    assert_eq!(u16::from_le_bytes([cmd[3], cmd[4]]), 0); // req_lines = 0 (identify)

    let body = &cmd[5..];
    let chunks = split_chunks(body).expect("valid chunk stream");
    let types: Vec<u16> = chunks.iter().map(|c| c.typ).collect();
    assert!(types.contains(&0x34)); // patched timeslot table
    assert!(types.contains(&0x17)); // reply config
    // 0x15 BwReduction is DISABLED — the live DLL identify arm has no 0x15 (see prod33_body caveat).
    assert!(!types.contains(&0x15)); // no bw reduction on the identify arm
    assert!(types.contains(&0x2e)); // image reconstruction
    assert!(types.contains(&0x47)); // empty companion marker (always follows 0x2e in the DLL)
    assert!(types.contains(&0x30)); // line update
    assert!(types.contains(&0x43)); // line update transform (bitpacked lines)

    let lu30 = &chunks
        .iter()
        .find(|c| c.typ == ChunkType::LineUpdate.id())
        .unwrap()
        .payload;
    assert_eq!(u32::from_le_bytes([lu30[0], lu30[1], lu30[2], lu30[3]]), 6);
    // 6 lines, see line_update.rs test
}

#[test]
fn sync_with_cal_arm_differs_from_static_fallback() {
    use crate::calibration::CalResults;
    let cfg = CaptureConfig::for_silicon(0x190, 0x4b, 6, 0x14).expect("resolves");
    let fcv: Vec<u8> = (0..56).map(|i| (120 + (i % 10)) as u8).collect();
    let static_arm = cfg
        .upload_cmd_prod33_sync(&fcv, &[], 3)
        .expect("static sync arm");
    let cal = CalResults {
        step3_diff: Some((0..56).map(|i| (i * 3) as u8).collect()),
        step56_buf: Some(vec![0x80; 144 * 56]),
        ..CalResults::default()
    };
    let folded = cfg
        .upload_cmd_prod33_sync_with_cal(&fcv, &cal, 3)
        .expect("folded sync arm");
    assert_eq!(
        u16::from_le_bytes([static_arm[3], static_arm[4]]),
        u16::from_le_bytes([folded[3], folded[4]]),
        "req_lines unchanged",
    );
    assert_ne!(
        static_arm, folded,
        "measured cal fold must change the 0x02 body",
    );
}

#[test]
fn calibrate_arm_line_update_transform_136_static_152_measured() {
    let cfg = CaptureConfig::for_silicon(0x190, 0x4b, 6, 0x14).expect("resolves");
    let fcv: Vec<u8> = (0..56).map(|i| (120 + (i % 10)) as u8).collect();
    let static_body = &cfg
        .upload_cmd_calibrate(&fcv, &[], 3, None)
        .expect("static cal arm")[5..];
    let step3: Vec<u8> = (0..56).map(|i| (100 + (i % 20)) as u8).collect();
    let measured_body = &cfg
        .upload_cmd_calibrate(&fcv, &[], 3, Some(&step3))
        .expect("measured cal arm")[5..];
    let len43 = |body: &[u8]| {
        split_chunks(body)
            .unwrap()
            .into_iter()
            .find(|c| c.typ == ChunkType::LineUpdateTransform.id())
            .map(|c| c.payload.len())
    };
    assert_eq!(
        len43(static_body),
        Some(136),
        "DAT_CAL_2449 fallback → 28+28 B packed (136 B 0x43)"
    );
    assert_eq!(
        len43(measured_body),
        Some(152),
        "factory step-3 diff → ~35+35 B packed (152 B 0x43, dll.pcap parity)"
    );
}

/// Byte-exact regression vs the stock 009a DLL calibrate oracle. `dll_arm_42_944.bin` is the
/// decrypted TLS-plaintext record of the DLL's PRIME (unfolded) `0x02` frames-sync arm from
/// `deviceInitAndCalibrate` → `windsor_cal` (captured live on the T480,
/// `captures/lenovo-009a-pairing/`); the real arm is its first **897** bytes, then a 47-byte TLS
/// record trailer (SHA256 HMAC + AES-CBC pad). Fed the sensor's REAL factory block — the `0x6f`
/// tag-0x0e response's subtag 3 (`factory_6f_0e_response.bin`) — our `upload_cmd_calibrate` for
/// 0x0199 reproduces the DLL prime arm exactly. This guards the
/// `older_family = key_calibration_line(subtype).is_some()` fix: the prime MUST emit the factory
/// `0x8000203c` DAT-A line (and its `0x43` group entry) even with empty calib_data.
#[test]
fn prime_calibrate_arm_byte_exact_vs_dll_oracle_0199() {
    // The large live captures are not part of the repository, so a clean
    // checkout must still compile. Run the oracle when the fixtures are
    // present and skip cleanly when they are not.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../captures/lenovo-009a-pairing");
    let factory_resp = match std::fs::read(dir.join("factory_6f_0e_response.bin")) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("skipping DLL-oracle test: missing {}: {e}", dir.display());
            return;
        }
    };
    let dll = match std::fs::read(dir.join("dll_arm_42_944.bin")) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("skipping DLL-oracle test: missing {}: {e}", dir.display());
            return;
        }
    };
    let dll_prime = &dll[..897];

    let cfg = CaptureConfig::for_silicon(0x0190, 0x004a, 0, 0).expect("0x0199 cfg");
    // factory calib values = `0x6f` subtag-3 blob, from the response payload after the 2-byte status.
    let fcv = crate::factory_cal::factory_cal_values_subtag3(&factory_resp[2..]);
    assert_eq!(
        fcv.len(),
        cfg.type_info.line_width as usize,
        "real factory block width (line_width)"
    );
    let frames = cfg.calibration_frames() as usize;
    let prime = cfg
        .upload_cmd_calibrate(&fcv, &[], frames, None)
        .expect("prime arm");
    assert_eq!(prime.len(), 897, "prime arm length");
    assert_eq!(
        prime.as_slice(),
        dll_prime,
        "prime calibrate arm not byte-exact to the stock-DLL oracle"
    );
}

#[test]
fn settle_sync_arm_req_lines_match_step6_with_full_cal_fold() {
    use crate::calibration::CalResults;
    let cfg = CaptureConfig::for_silicon(0x190, 0x4b, 6, 0x14).expect("resolves");
    let fcv: Vec<u8> = (0..56).map(|i| (120 + (i % 10)) as u8).collect();
    let cal = CalResults {
        step3_diff: Some((0..56).map(|i| (100 + (i % 20)) as u8).collect()),
        step56_buf: Some(vec![0x80; 152 * 56]),
        ..CalResults::default()
    };
    let settle = cfg
        .upload_cmd_cal_step7_settle(&fcv, &cal)
        .expect("step-7 settle arm");
    let step6 = cfg
        .upload_cmd_cal_step6_dark(&fcv, cal.step3_diff.as_deref())
        .expect("step-6 arm");
    assert_eq!(
        u16::from_le_bytes([settle[3], settle[4]]),
        cfg.stream_req_lines(CAL_STEP6_SYNC_FRAMES),
        "step-7 settle req_lines matches step-6 (syna_capture_arm_and_wait ctx,0,1,0)"
    );
    assert_eq!(
        u16::from_le_bytes([settle[3], settle[4]]),
        u16::from_le_bytes([step6[3], step6[4]]),
    );
}

#[test]
fn cal_step6_uses_sync_frames_one_stream_uses_three() {
    let cfg = CaptureConfig::for_silicon(0x190, 0x4b, 6, 0x14).expect("resolves");
    let fcv: Vec<u8> = vec![120; 56];
    let step3: Vec<u8> = (0..56).map(|i| (100 + i) as u8).collect();
    let step6 = cfg
        .upload_cmd_cal_step6_dark(&fcv, Some(&step3))
        .expect("step-6");
    let stream = cfg
        .upload_cmd_prod33_sync(&fcv, &[], STREAM_DEFAULT_SYNC_FRAMES)
        .expect("stream");
    assert_eq!(
        u16::from_le_bytes([step6[3], step6[4]]),
        cfg.stream_req_lines(CAL_STEP6_SYNC_FRAMES),
        "step-6 req_lines=113",
    );
    assert_eq!(
        u16::from_le_bytes([stream[3], stream[4]]),
        337,
        "stream req_lines=337 unchanged",
    );
}

#[test]
fn sensor_type_info_cf640_groups_match_dll() {
    use crate::capture_progs_9b::SENSOR_TYPE_INFO;
    for ti in SENSOR_TYPE_INFO.iter() {
        let lw = ti.line_width as usize;
        assert_eq!(
            crate::reconstruct::blocks_per_line_from_width(ti.line_width),
            lw / 16,
            "subtype 0x{:04x} line_width {}",
            ti.subtype,
            ti.line_width
        );
        // cf640@0x1800cf640: floor(lw/16) Walsh groups; tail (lw % 16) bytes pass through unchanged.
    }
}

#[test]
fn polled_layout_2449_matches_dll_header() {
    let cfg = CaptureConfig::for_silicon(0x190, 0x4b, 0x06, 0x14).expect("0x2449 cfg");
    let pl = cfg.polled_layout();
    assert_eq!(pl.line_width, 144);
    assert_eq!(pl.lines_2d, 56);
    assert_eq!(pl.body_len(), Some(8064));
    assert_eq!(pl.dest_stride(), 152);
    assert_eq!(pl.descramble_blocks_per_line(), 9);
    assert_eq!(cfg.stream_recon_params().length, 144);
    assert_eq!(cfg.stream_recon_params().offset, 8);
}
