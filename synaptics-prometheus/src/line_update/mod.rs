//! Timeslot-program disassembly + the `line_update` patch that turns a raw SensorCaptureProg into a
//! runnable capture command.
//!
//! Every `0x02` capture upload patches the program's timeslot chunks with calibration data before
//! sending — the vendor does this in `syna_build_capture_cmd02`@0x180086110, and python-validity in
//! `sensor.line_update_type_1/2`. Without it the sensor arms a capture but never detects a finger
//! (observed live on `06cb:009b`). Subtype `0x2449` is a **type-2** sensor (it is not in
//! python-validity's `line_update_type1_devices`), which is the simpler variant: it needs only the
//! per-subtype [`crate::capture_progs_9b::SensorTypeInfo`] geometry plus two factory-calibration
//! blobs read live from the sensor (`0x6f` factory bits), and no full `calib_data`.
//!
//! This is a faithful port of python-validity `timeslot.py` + `sensor.line_update_type_2`.


mod disasm;
pub use disasm::*;

/// Capture intent (python-validity `CaptureMode`). The discriminants are the vendor's own values
/// (used e.g. in `sensor.py`); the DLL further maps them to an internal capture "mode" number in
/// `syna_capture_identify_enroll`@0x180053400 — see [`Mode::dll_mode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    /// `1` — finger-less reference/dark-field capture used to compute calibration; the destructive
    /// path (persists a clean-slate to flash). Not wired for live use here.
    Calibrate = 1,
    /// `2` — image + match against the enrolled DB (non-destructive). Uses the `0x4e` finger-detect.
    Identify = 2,
    /// `3` — image for adding/refining a template (destructive: writes the DB). Uses `0x26`.
    Enroll = 3,
}

impl Mode {
    /// The vendor `CaptureMode` value (`1`/`2`/`3`).
    pub fn value(self) -> u8 {
        self as u8
    }

    /// The DLL's internal capture-mode number (`syna_capture_identify_enroll` `local_74`): the
    /// identify/enroll request modes `1`/`2`/`3` map to `3`/`4`/`6`, which select the `param_3`
    /// capture configuration. `Calibrate` has no identify/enroll mode (returns `None`).
    pub fn dll_mode(self) -> Option<u8> {
        match self {
            Mode::Calibrate => None,
            Mode::Identify => Some(4),
            Mode::Enroll => Some(6),
        }
    }
}

// Hardcoded type-2 fragments (python-validity sensor.py line_update_type_2). The 0x4e/0x26 are the
// finger-detect config and 0x2e is image reconstruction; the vendor builds these in
// construct_wtf_4e@0x180090BF0 / add_image_reconstruction_cmd_02@0x18008EA70 and they are "mostly
// hardcoded per sensor". These are the type-2-family values (geometry 0x90=144 matches 0x2449's
// line_width); if a live capture rejects them, RE those two builders for the exact 0x2449 bytes.
const BLOB_4E_TYPE2: &[u8] = &[
    0xfb, 0xb2, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x30, 0x00, 0x00, 0x00, 0x60, 0x01, 0x02, 0x00,
    0x40, 0x01, 0x0a, 0x00, 0x01, 0x80, 0x00, 0x00, 0x0a, 0x02, 0x00, 0x00, 0x0b, 0x19, 0x00, 0x00,
    0x88, 0x13, 0xb8, 0x0b, 0x01, 0x09, 0x10, 0x00,
];
const BLOB_26_TYPE2: &[u8] = &[
    0xfb, 0xb2, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x30, 0x00, 0x00, 0x00, 0x60, 0x01, 0x02, 0x00,
    0x40, 0x01, 0x0a, 0x00, 0x01, 0x80, 0x00, 0x00, 0x0a, 0x02, 0x00, 0x00, 0x0b, 0x19, 0x00, 0x00,
    0x50, 0xc3, 0x60, 0xea, 0x01, 0x09, 0x10, 0x00,
];
const BLOB_2E_IDENTIFY_TYPE2: &[u8] = &[
    0x02, 0x00, 0x18, 0x00, 0x02, 0x00, 0x00, 0x00, 0x90, 0x00, 0x90, 0x00, 0x4d, 0x01, 0x00, 0x00,
    0x90, 0x01, 0x7c, 0x01, 0x3c, 0x32, 0x32, 0x32, 0x64, 0x0a, 0x02, 0x01,
];
const BLOB_2E_ENROLL_TYPE2: &[u8] = &[
    0x02, 0x00, 0x18, 0x00, 0x23, 0x00, 0x00, 0x00, 0x90, 0x00, 0x90, 0x00, 0x4d, 0x01, 0x00, 0x00,
    0x90, 0x01, 0x7c, 0x01, 0x3c, 0x32, 0x32, 0x32, 0x64, 0x0a, 0x02, 0x01,
];

fn align4(v: &mut Vec<u8>) {
    v.resize(pad4(v.len()), 0);
}

/// Inputs for [`line_update_type_2`] that come from the live sensor / its flex-params row.
pub struct CalibrationInputs<'a> {
    pub repeat_multiplier: u16,
    /// Sensor subtype — selects the finger-detect patch offset ([`fingerdet_cal_offset`]).
    pub subtype: u16,
    /// `SensorTypeInfo.calibration_blob`.
    pub calibration_blob: &'a [u8],
    /// `0x6f` factory bits subtag 7 (`[4:]`).
    pub factory_calib_data: &'a [u8],
    /// `0x6f` factory bits subtag 3 (`[4:]`).
    pub factory_calibration_values: &'a [u8],
}

/// Apply the type-2 `line_update` to a chunk list (owned `(type, payload)` pairs), returning the
/// patched chunk list ready to `merge_chunks` into a `0x02` command body.
///
/// Port of python-validity `sensor.line_update_type_2`. `chunks` is consumed and returned patched.
pub fn line_update_type_2(
    mode: Mode,
    mut chunks: Vec<(u16, Vec<u8>)>,
    ci: &CalibrationInputs,
) -> Vec<(u16, Vec<u8>)> {
    // Patch the Timeslot-Table-2D chunk (0x34) and keep the patched table for the line lookups.
    let mut tst: Vec<u8> = Vec::new();
    for c in chunks.iter_mut() {
        if c.0 == ChunkType::TimeslotTable2d.id() {
            let mut t = patch_timeslot_table(&c.1, true, ci.repeat_multiplier);
            if mode != Mode::Calibrate {
                // `None`: the DLL only patches reg 0x8000203c when a MEASURED fingerdet cal
                // (ctx+0x288+0x68/+0x70, step5/6) is present; 0x2449 runs step3 only ⇒ no-op.
                t = patch_fingerdet_reg(&t, None, ci.subtype);
            }
            c.1 = t.clone();
            tst = t;
        }
    }

    // Reply Configuration + per-mode finger-detect/image-reconstruction fragments.
    chunks.push((ChunkType::ReplyConfig.id(), Vec::new()));
    match mode {
        Mode::Identify => {
            chunks.push((ChunkType::Wtf.id(), BLOB_4E_TYPE2.to_vec()));
            chunks.push((
                ChunkType::ImageReconstruction.id(),
                BLOB_2E_IDENTIFY_TYPE2.to_vec(),
            ));
        }
        Mode::Enroll => {
            chunks.push((ChunkType::FingerDetect.id(), BLOB_26_TYPE2.to_vec()));
            chunks.push((
                ChunkType::ImageReconstruction.id(),
                BLOB_2E_ENROLL_TYPE2.to_vec(),
            ));
        }
        Mode::Calibrate => {}
    }

    // Three calibration "lines": each is (mask, flags, data). flags encode a program-counter anchor.
    let mut lines: Vec<(u32, u32, Vec<u8>)> = Vec::new();
    let flag = |pc: Option<usize>| pc_flag(pc) | line_flag::TYPE2;
    lines.push((
        0xff,
        flag(find_nth_insn(&tst, TimeslotOp::EnableRx.op(), 2)),
        ci.calibration_blob.to_vec(),
    ));
    lines.push((
        0xff,
        flag(find_nth_regwrite(&tst, reg::LINE_UPDATE_C, 1)),
        ci.factory_calib_data.to_vec(),
    ));
    lines.push((
        0xff,
        flag(find_nth_regwrite(&tst, reg::LINE_UPDATE_A, 1)),
        ci.factory_calibration_values.to_vec(),
    ));
    for l in lines.iter_mut() {
        align4(&mut l.2);
    }

    // 0x30 Line Update: count, then (mask,flags) headers, then all data.
    let mut lu = (lines.len() as u32).to_le_bytes().to_vec();
    for (mask, flags, _) in &lines {
        lu.extend_from_slice(&mask.to_le_bytes());
        lu.extend_from_slice(&flags.to_le_bytes());
    }
    for (_, _, data) in &lines {
        lu.extend_from_slice(data);
    }
    chunks.push((ChunkType::LineUpdate.id(), lu));
    chunks
}


mod calib;
pub use calib::*;


mod flex;
pub use flex::*;

#[cfg(test)]
mod tests;
