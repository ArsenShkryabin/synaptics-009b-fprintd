//! Unit tests for the line_update module (moved out of mod.rs; crate-internal access via super).

use super::*;
use crate::chunk_codec::split_chunks;
use crate::capture_progs_9b::{CAPTURE_PROGS, SENSOR_TYPE_INFO};

fn prog_2449() -> &'static [u8] {
    CAPTURE_PROGS
        .iter()
        .find(|p| p.subtype == 0x2449)
        .unwrap()
        .program
}

#[test]
fn decodes_the_2449_program_cleanly() {
    // Every timeslot chunk in the real program disassembles without hitting an unknown opcode.
    for c in split_chunks(prog_2449()).unwrap() {
        if c.typ == ChunkType::TimeslotTable2d.id() {
            let mut pc = 0;
            while pc < c.payload.len() {
                let insn = decode_insn(&c.payload[pc..]).expect("known opcode");
                assert!(insn.size >= 1);
                pc += insn.size;
            }
        }
    }
}

#[test]
fn line_update_produces_0x30_and_finger_detect_chunks() {
    let ti = SENSOR_TYPE_INFO
        .iter()
        .find(|t| t.subtype == 0x2449)
        .unwrap();
    let chunks: Vec<(u16, Vec<u8>)> = split_chunks(prog_2449())
        .unwrap()
        .into_iter()
        .map(|c| (c.typ, c.payload.to_vec()))
        .collect();
    let fcv = vec![0u8; 64]; // stand-in factory bits
    let fcd = vec![0u8; 64];
    let ci = CalibrationInputs {
        repeat_multiplier: ti.repeat_multiplier,
        subtype: 0x2449,
        calibration_blob: ti.calibration_blob,
        factory_calib_data: &fcd,
        factory_calibration_values: &fcv,
    };
    let out = line_update_type_2(Mode::Identify, chunks, &ci);
    let types: Vec<u16> = out.iter().map(|c| c.0).collect();
    assert!(types.contains(&ChunkType::ReplyConfig.id()));
    assert!(types.contains(&ChunkType::Wtf.id())); // identify finger-detect
    assert!(types.contains(&ChunkType::ImageReconstruction.id()));
    assert!(types.contains(&ChunkType::LineUpdate.id()));
    // The 0x30 chunk begins with the line count = 3.
    let lu = &out
        .iter()
        .find(|c| c.0 == ChunkType::LineUpdate.id())
        .unwrap()
        .1;
    assert_eq!(u32::from_le_bytes([lu[0], lu[1], lu[2], lu[3]]), 3);
}

#[test]
fn patch_timeslot_table_scales_op11_counts() {
    // op-11 (0x10|..) with count>1 gets ×mult; a leading 0 is skipped; a non-{0,7,11} stops it.
    // op-11 begins at index 1: [opcode 0x10][addr 0x05][count 0x03]. count=out[3], addr=out[2].
    let input = [0x00u8, 0x10, 0x05, 0x03, 0xff, 0xff];
    let out = patch_timeslot_table(&input, true, 2);
    assert_eq!(out[0], 0x00); // leading 0 skipped
    assert_eq!(out[3], 0x06); // count 0x03 * 2
    assert_eq!(out[2], 0x06); // address 0x05 + 1
}

// ---- product-0x33 line update ----

#[test]
fn bitpack_hand_computed() {
    // m=4, x=7 -> delta=3 -> u=2 bits. Values (byte-min): 1,3,2,0 = 0b01,0b11,0b10,0b00.
    // LSB-first packing at bit offsets 0,2,4,6 into one byte: bit0=1,bit2=1,bit3=1,bit5=1
    // -> byte = 0b0010_1101 = 0x2d.
    let (u, m, packed) = bitpack(&[5, 7, 6, 4]);
    assert_eq!(u, 2);
    assert_eq!(m, 4);
    assert_eq!(packed, vec![0x2d]);
}

#[test]
fn bitpack_constant_data_is_zero_width() {
    let (u, m, packed) = bitpack(&[9, 9, 9, 9]);
    assert_eq!(u, 0);
    assert_eq!(m, 9);
    assert_eq!(packed, Vec::<u8>::new());
}

#[test]
fn bitpack_empty_is_empty() {
    assert_eq!(bitpack(&[]), (0, 0, Vec::new()));
}

#[test]
fn bitpack_matches_python_validity_on_dat_2449() {
    // Reference computed with python-validity's `sensor.bitpack` on DAT_CAL_2449.
    let (u, m, packed) = bitpack(&DAT_CAL_2449);
    assert_eq!((u, m), (4, 123));
    let expect = [
        0x50, 0x87, 0x97, 0x78, 0x86, 0x77, 0x95, 0x77, 0x86, 0x68, 0x76, 0x57, 0x65, 0x58,
        0x65, 0x56, 0x75, 0x77, 0x86, 0x87, 0x86, 0x76, 0x75, 0x77, 0x87, 0x98, 0x98, 0x15,
    ];
    assert_eq!(packed, expect);
}

#[test]
fn chunk_finger_detect_2449_identify_bytes() {
    // Transcribed from FUN_180094420/FUN_180096a90 for 0x2449, IDENTIFY: type=0x4e, and with the
    // vendor-default ctx+0x238=100 -> ivar1=g230=160 -> [0xc]=160+0x20000=0x200a0,
    // [0x10]=160+0x9ffe0=0xa0080; identify (short) timeouts 10000/6000.
    let c = chunk_finger_detect_2449(Mode::Identify);
    let expect: [u8; 44] = [
        0x4e, 0x00, 0x28, 0x00, // type=0x4e (identify) len=40
        0xfb, 0xb2, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x30, 0x00, 0x00, 0x00, 0xa0, 0x00,
        0x02, 0x00, 0x80, 0x00, 0x0a, 0x00, 0x01, 0x80, 0x00, 0x00, 0x0a, 0x02, 0x00, 0x00,
        0x0b, 0x19, 0x00, 0x00, 0x10, 0x27, 0x70, 0x17, 0x01, 0x09, 0x10, 0x00,
    ];
    assert_eq!(c, expect);
    // Enroll variant: type 0x26, long timeouts 50000/60000.
    let e = chunk_finger_detect_2449(Mode::Enroll);
    assert_eq!(&e[0..2], &[0x26, 0x00]);
    assert_eq!(&e[0x24..0x28], &[0x50, 0xc3, 0x60, 0xea]);
}

#[test]
fn chunk_15_is_fixed_bytes() {
    assert_eq!(
        chunk_15(),
        [
            0x15, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x28, 0x00, 0x00
        ]
    );
}

#[test]
fn chunk_2e_2449_frames_correctly() {
    let c = chunk_2e(&FLEX_2E_2449, 2, 2);
    assert_eq!(c.len(), 32); // 4-byte header + 28-byte payload
    assert_eq!(&c[0..4], &[0x2e, 0x00, 0x1c, 0x00]);
    // mode=2, local_7a=0x18
    assert_eq!(&c[4..8], &[0x02, 0x00, 0x18, 0x00]);
    // flags=2
    assert_eq!(&c[8..12], &[0x02, 0x00, 0x00, 0x00]);
    // line_width=144, calib_size=56
    assert_eq!(&c[12..16], &[0x90, 0x00, 0x38, 0x00]);
    // field0=recon_cfg[0]=400 (flag clear), recon_cfg[1]=380
    assert_eq!(&c[20..24], &[0x90, 0x01, 0x7c, 0x01]);
}

#[test]
fn flex2e_for_subtype_2449_matches_constant() {
    let f = Flex2eParams::for_subtype(0x2449).expect("0x2449 in flex table");
    assert_eq!(f.line_width, FLEX_2E_2449.line_width);
    assert_eq!(f.calib_size, FLEX_2E_2449.calib_size);
    assert_eq!(f.flex_e, FLEX_2E_2449.flex_e);
    assert_eq!(f.flex_14, FLEX_2E_2449.flex_14);
    assert_eq!(f.flex_16, FLEX_2E_2449.flex_16);
    assert_eq!(f.recon_cfg, FLEX_2E_2449.recon_cfg);
    // family coverage: a sibling 144-wide subtype resolves too.
    assert!(Flex2eParams::for_subtype(0x0121).is_some());
    assert_eq!(crate::flex_params::FLEX_PARAMS.len(), 56);
}

#[test]
fn chunk_2e_image_flags_use_flex16_field0() {
    // The provisioned polled-imaging arm: flags=8 (RECON_FLAGS_IMAGE). Field 0 switches
    // from recon_cfg[0]=400 to flex_16=150 (syna_recon_substruct_build@0x1800ae110's
    // `flex != 0 && alt_field0 != 0` branch). Verified matches the DLL.
    let c = chunk_2e(&FLEX_2E_2449, 2, RECON_FLAGS_IMAGE);
    assert_eq!(&c[8..12], &[0x08, 0x00, 0x00, 0x00], "flags=8");
    assert_eq!(&c[20..22], &150u16.to_le_bytes(), "field0=flex_16=150");
    assert_eq!(&c[22..24], &380u16.to_le_bytes(), "recon_cfg[1] unchanged");
    // Sanity: RECON_FLAGS_IMAGE is exactly the alt-field-0 bit, and it equals recon mode 8.
    assert_eq!(RECON_FLAGS_IMAGE, RECON_FLAG_ALT_FIELD0);
    assert_eq!(RECON_FLAGS_IMAGE, recon_flag::MODE_ALT_FIELD0);
    // The identify/enroll arms keep field-0 = recon_cfg[0] = 400.
    let id = chunk_2e(&FLEX_2E_2449, 2, RECON_FLAGS_DEFAULT);
    assert_eq!(
        &id[20..22],
        &400u16.to_le_bytes(),
        "identify field0=recon_cfg[0]=400"
    );
    let en = chunk_2e(&FLEX_2E_2449, 2, RECON_FLAGS_ENROLL);
    assert_eq!(
        &en[20..22],
        &400u16.to_le_bytes(),
        "enroll field0=recon_cfg[0]=400"
    );
}

#[test]
fn line_update_prod33_matches_live_2449_program() {
    // Ground truth computed with python-validity's own `timeslot.decode_insn` as the oracle
    // (see the repo's line-update spec) against the real, unpatched PROG_10 0x34 payload:
    // p164=172, p160=180, p15c=183, p1a8=303, p1a4=412, p19c=None (no 0x800020fc regwrite in
    // this program, so "DAT line C" is never emitted for our sensor). There are NO opcode-5
    // instructions, so the DLL's accumulated-offset find equals the simple pc here.
    // Flag rule (from the decompile): calib/DAT lines embed `pc+1` (calib via explicit `+1`,
    // DAT via find_nth_regwrite returning pc+1); the 1a8/1a4 lines embed the RAW pc.
    let ti = SENSOR_TYPE_INFO
        .iter()
        .find(|t| t.subtype == 0x2449)
        .unwrap();
    let tst = split_chunks(prog_2449())
        .unwrap()
        .into_iter()
        .find(|c| c.typ == ChunkType::TimeslotTable2d.id())
        .unwrap()
        .payload;

    assert_eq!(find_nth_insn(tst, TimeslotOp::EnableRx.op(), 2), Some(172));
    assert_eq!(find_nth_regwrite(tst, reg::LINE_UPDATE_A, 1), Some(180));
    assert_eq!(find_nth_regwrite(tst, reg::LINE_UPDATE_B, 1), Some(183));
    assert_eq!(find_nth_insn(tst, TimeslotOp::EnableRx.op(), 3), Some(303));
    assert_eq!(find_nth_insn(tst, TimeslotOp::EnableRx.op(), 4), Some(412));
    assert_eq!(find_nth_regwrite(tst, reg::LINE_UPDATE_C, 1), None);

    let lines = line_update_prod33(tst, ti.calibration_blob, 0x2449, None, None, 56, 10, 4, None, &[]);
    // calib_blob, DAT-A, DAT-B, [DAT-C skipped], 1a8, 1a4, model-marker = 6 lines.
    assert_eq!(lines.len(), 6);

    assert_eq!(lines[0].flags, 173 | line_flag::CALIB_BLOB); // calib_blob: pc+1 | const
    assert_eq!(lines[0].data, ti.calibration_blob);
    assert_eq!(lines[1].flags, (3 << 0x14) | line_flag::DAT | 181); // DAT-A: seq=3, pc+1
    assert_eq!(lines[2].flags, (4 << 0x14) | line_flag::DAT | 184); // DAT-B: seq=4, pc+1
    assert_eq!(lines[3].flags, (5 << 0x14) | line_flag::EMPTY_1A | 303); // 1a8: seq=5, RAW pc
    assert_eq!(lines[4].flags, (6 << 0x14) | line_flag::EMPTY_1A | 412); // 1a4: seq=6, RAW pc
    assert_eq!(lines[5].flags, (7 << 0x14) | line_flag::MODEL_MARKER); // model marker: seq=7
    assert_eq!(lines[5].v1, 0x0c);

    // Every non-calib line lands in the 0x43 group (group = seq >= 2 for all of them).
    for l in &lines[1..] {
        assert!((l.flags >> 0x14) & 0xf >= 2);
    }
}

#[test]
fn calib_delta_lines_prod33_2449_geometry() {
    // 0x2449: scanlines=56 (the 0x2f "2D" value), step-6 dark frame incl. header = 152×56 = 8512,
    // flex scale 10/4. count = (stride-8)/4 = (152-8)/4 = 36 delta lines, 56*4 = 224 B.
    let frame = vec![0x80u8; 152 * 56];
    let deltas = calib_delta_lines_prod33(&frame, 56, 10, 4);
    assert_eq!(deltas.len(), 36, "36 delta lines = (stride-8)/4 (matches dll.pcap 8404/42)");
    assert!(deltas.iter().all(|l| l.data.len() == 224 && l.mask == 0xffff_ffff));
    assert_eq!(deltas[0].flags, 0x8500_0000);
    assert_eq!(deltas[2].flags, 0x8500_0008); // (4*2) | 0x85000000, group nibble 0 → 0x30 chunk
    // Flat 0x80 frame → every delta byte = clip_i8(0*10/4) = 0.
    assert!(deltas.iter().all(|l| l.data.iter().all(|&b| b == 0)));
    // The full 42-line 0x30 chunk length: Σ pad4(payload) + 4 + count*8 = 36*224 + 4 + 42*8 = 8404
    // (the 6 base lines are 0-padded, contributing 0 to the payload sum).
    let delta_payload: usize = deltas.iter().map(|l| pad4(l.data.len())).sum();
    assert_eq!(delta_payload + 4 + 42 * 8, 8404, "matches the DLL's 8404-byte LineUpdate");
    // Scaling: a +40 pixel (0xA8) → 40*10/4 = 100; frame[8] is data col 0 of row 0 (d=0,r=0,k=0).
    let mut f2 = vec![0x80u8; 152 * 56];
    f2[8] = 0xA8;
    assert_eq!(calib_delta_lines_prod33(&f2, 56, 10, 4)[0].data[0], 100);
    // No frame / zero scanlines → no delta lines (weak-signal fallback).
    assert!(calib_delta_lines_prod33(&[], 56, 10, 4).is_empty());
    assert!(calib_delta_lines_prod33(&frame, 0, 10, 4).is_empty());
}

#[test]
fn fold_timeslot_2d_2449_patches_leading_144() {
    // 152×56 dark frame (with 8-byte header); rows (18,28,38); scale 10/4. The fold patches the
    // leading line_width=144 bytes as 3 thirds of 48. The source column follows the CONTIGUOUS dst
    // index — dst byte `d` reads data col `8+d` of its third's row (NOT `8 + d%third`); only the row
    // changes per third. (Corrected via the DLL arm oracle — see fold_timeslot_2d doc.)
    let mut frame = vec![0x80u8; 152 * 56];
    // Set a distinctive value at row 18, data col 0 (= frame[18*152 + 8]) → (200-128)*10/4 = 180 → clip 127.
    frame[18 * 152 + 8] = 200;
    // third 1 (row 28) dst 49 reads data col 8+49 (= frame[28*152 + 8 + 49]) → (100-128)*10/4 = -70.
    frame[28 * 152 + 8 + 49] = 100;
    let mut payload = vec![0u8; 536];
    fold_timeslot_2d(&mut payload, &frame, 56, 10, 4, (18, 28, 38));
    assert_eq!(payload[0], 127); // third 0 (row 18) dst 0 = col 8, clamped
    assert_eq!(payload[49] as i8, -70); // third 1 (row 28) dst 49 = col 57
    // bytes beyond the 144-wide table are untouched.
    assert!(payload[144..].iter().all(|&b| b == 0));
    // "avoid-5": a pixel yielding 5 becomes 4.
    let mut f2 = vec![0x80u8; 152 * 56];
    f2[18 * 152 + 8] = 130; // (130-128)*10/4 = 5 → 4
    let mut p2 = vec![0u8; 536];
    fold_timeslot_2d(&mut p2, &f2, 56, 10, 4, (18, 28, 38));
    assert_eq!(p2[0], 4);
}

#[test]
fn serialize_line_update_frames_0x30_and_0x43() {
    let ti = SENSOR_TYPE_INFO
        .iter()
        .find(|t| t.subtype == 0x2449)
        .unwrap();
    let tst = split_chunks(prog_2449())
        .unwrap()
        .into_iter()
        .find(|c| c.typ == ChunkType::TimeslotTable2d.id())
        .unwrap()
        .payload;
    let lines = line_update_prod33(tst, ti.calibration_blob, 0x2449, None, None, 56, 10, 4, None, &[]);
    let out = serialize_line_update(&lines, 0);

    // No interleave chunk requested -> starts directly with 0x30.
    assert_eq!(&out[0..2], &ChunkType::LineUpdate.id().to_le_bytes());
    let len30 = u16::from_le_bytes([out[2], out[3]]) as usize;
    let count = u32::from_le_bytes([out[4], out[5], out[6], out[7]]);
    assert_eq!(count as usize, lines.len());
    // All lines have group >= 2, so the 0x30 payload is just count + headers, no data.
    assert_eq!(len30, 4 + lines.len() * 8);

    // 0x43 chunk follows immediately after the 0x30 payload.
    let off43 = 4 + len30;
    assert_eq!(
        &out[off43..off43 + 2],
        &ChunkType::LineUpdateTransform.id().to_le_bytes()
    );
    let len43 = u16::from_le_bytes([out[off43 + 2], out[off43 + 3]]) as usize;
    assert_eq!(out.len(), off43 + 4 + len43);
}

#[test]
fn serialize_line_update_emits_interleave_when_nonzero() {
    let lines = vec![Line {
        mask: 0xff,
        flags: 0x0700_0002,
        v0: 0,
        v1: 0,
        v2: 0,
        data: vec![],
    }];
    let out = serialize_line_update(&lines, 1);
    assert_eq!(
        &out[0..8],
        &[0x44, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00]
    );
}

#[test]
fn chunk_2e_fields_round_trip() {
    let framed = chunk_2e(&FLEX_2E_2449, 2, RECON_FLAGS_DEFAULT);
    let payload = &framed[4..];
    let fields = Chunk2eFields::parse(payload).expect("parse");
    assert_eq!(fields.mode, 2);
    assert_eq!(fields.flags, RECON_FLAGS_DEFAULT);
    assert_eq!(fields.field0, 400);
    assert_eq!(fields.encode().as_slice(), payload);
}

#[test]
fn chunk_finger_detect_fields_round_trip() {
    let framed = chunk_finger_detect_2449(Mode::Identify);
    let payload = &framed[4..];
    let fields = ChunkFingerDetectFields::parse(payload).expect("parse");
    assert_eq!(fields.timeout_a, 10000);
    assert_eq!(fields.timeout_b, 6000);
    assert_eq!(fields.encode().as_slice(), payload);
    let enroll = chunk_finger_detect_2449(Mode::Enroll);
    let efields = ChunkFingerDetectFields::parse(&enroll[4..]).expect("parse enroll");
    assert_eq!(efields.timeout_a, 50000);
    assert_eq!(efields.timeout_b, 60000);
}

#[test]
fn chunk_baseline_framing_matches_dll_0x48() {
    // The DLL 0x48 (syna_append_chunk_48_last_frame@0x180095ae0) is a verbatim
    // [0x48][len=w*h+4][w][h][w*h frame] wrapping pLast_frame_buf, which
    // syna_capture_store_last_frame@0x1800ad800 fills by a plain memmove (0x2449 path — no
    // conditioning). The live DLL 0x48 frame is 56 lines, ODD line numbers (byte[2]=1,3,…,111),
    // byte[3]=0x02. chunk_baseline reproduces that framing from a 113-line raw settle (even-index
    // source lines → odd line numbers; field byte→0x02). This locks the FORMAT (the content is a
    // separate, device-gated question — see the fn doc + docs/capture/last-frame-baseline.md).
    const STRIDE: usize = 152;
    const RAW_LINES: usize = 113;
    let mut raw = vec![0u8; RAW_LINES * STRIDE];
    for i in 0..RAW_LINES {
        let base = i * STRIDE;
        raw[base] = 0x01;
        raw[base + 1] = 0xfe;
        raw[base + 2] = (i as u8).wrapping_add(1); // line number = index+1
        raw[base + 3] = 0x00; // must be forced to 0x02 by chunk_baseline
        raw[base + 4] = 0xf0;
        // distinctive pixel: first data byte = the source line index
        raw[base + 8] = i as u8;
    }
    let c = chunk_baseline(&raw, STRIDE as u16);

    // Header: [0x48][len][w=152][h=56].
    assert_eq!(u16::from_le_bytes([c[0], c[1]]), 0x0048);
    let len = u16::from_le_bytes([c[2], c[3]]) as usize;
    assert_eq!(u16::from_le_bytes([c[4], c[5]]), STRIDE as u16, "width = wire stride");
    assert_eq!(u16::from_le_bytes([c[6], c[7]]), 56, "height = 56 (113/2)");
    assert_eq!(len, 4 + 56 * STRIDE, "len = w,h + 56 lines = 8516");
    assert_eq!(c.len(), 4 + len);

    // 56 emitted lines: odd numbering 1,3,…,111; byte[3]=0x02; pixels from even-index source lines.
    let frame = &c[8..];
    for k in 0..56 {
        let base = k * STRIDE;
        assert_eq!(frame[base], 0x01, "line {k} hdr[0]");
        assert_eq!(frame[base + 1], 0xfe, "line {k} hdr[1]");
        assert_eq!(frame[base + 2], (2 * k as u8) + 1, "line {k} number is odd {}", 2 * k + 1);
        assert_eq!(frame[base + 3], 0x02, "line {k} field byte stamped 0x02");
        assert_eq!(frame[base + 8], (2 * k) as u8, "line {k} pixel from source index {}", 2 * k);
    }
}
