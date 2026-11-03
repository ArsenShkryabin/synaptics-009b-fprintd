//! Timeslot-program format + disassembler/patcher — the chunk-type + instruction encoding of the
//! sensor's capture microcode, the register/line-flag constants it anchors to, the instruction
//! decoder (`decode_insn` / `find_nth_*`), and the `patch_timeslot_*` mutations. Extracted from the
//! `line_update` module; re-exported by its `mod.rs` so `line_update::{ChunkType, decode_insn, …}`
//! paths are unchanged.

/// Timeslot-program chunk types — the sections of the sensor's capture microcode. A chunk's wire
/// header is `[type:u16][len:u16]`. Names/ids match python-validity `timeslot.codes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ChunkType {
    ReplyConfigTable = 0x23,
    SetRegister32 = 0x20,
    RegisterList16 = 0x32,
    RegisterList32 = 0x33,
    TimeslotTable2d = 0x34,
    DataEncoder = 0x42,
    TwoD = 0x2f,
    TimeslotOffset = 0x29,
    FingerDetectOffset = 0x35,
    ReplyConfig = 0x17,
    BwReduction = 0x15,
    FingerDetect = 0x26,
    ImageReconstruction = 0x2e,
    Wtf = 0x4e,
    AcmControl = 0x2b,
    CemControl = 0x2d,
    Interleave = 0x44,
    LineUpdate = 0x30,
    LineUpdateTransform = 0x43,
    /// Empty companion marker (`[0x47][len=0]`) the DLL emits **immediately after every `0x2e`
    /// ImageRecon chunk** — `syna_append_chunk_47_recon_marker@0x180095660`, called from the tail of
    /// `syna_append_chunk_2e_image_recon@0x180094990`. Zero payload; purpose opaque (a separator/marker
    /// for the recon block). Emitted for arm parity with the DLL.
    Empty47 = 0x47,
    /// Finger-detect **baseline reference frame** = the DLL's LAST captured frame (`pLast_frame_buf`),
    /// emitted by `syna_append_chunk_48_last_frame@0x180095ae0` for the read_mode-2 / capture-type-4
    /// Hello identify path (provisioned). Payload: `[width:u16][height:u16]` then `height` rows of
    /// `wire_stride` bytes — the **step-7 settle** frame (its odd-line field), NOT the step-6 dark frame
    /// and NOT the enrolled template (`pEnrolled_template` ctx+0x108 is a separate dead-on-our-SKU
    /// matcher struct). Gives the sensor a baseline to subtract; omitting it → spurious finger at arm.
    /// Verified vs the live DLL arm (chunk `0x48`, 152×56 = 8516 B). See [`super::chunk_baseline`].
    Baseline = 0x48,
}

impl ChunkType {
    /// The `u16` type id used in the wire `[type][len]` header.
    pub const fn id(self) -> u16 {
        self as u16
    }

    /// Short label for arm-lab / status readouts (`fdet`, `recon`, …). Empty for unknown ids.
    pub const fn label(self) -> &'static str {
        match self {
            ChunkType::ReplyConfigTable => "replytbl",
            ChunkType::SetRegister32 => "setreg32",
            ChunkType::RegisterList16 => "reglist16",
            ChunkType::RegisterList32 => "reglist32",
            ChunkType::TimeslotTable2d => "timeslot",
            ChunkType::DataEncoder => "enc",
            ChunkType::TwoD => "2d",
            ChunkType::TimeslotOffset => "tsoff",
            ChunkType::FingerDetectOffset => "fdetoff",
            ChunkType::ReplyConfig => "reply",
            ChunkType::BwReduction => "bwred",
            ChunkType::FingerDetect => "fdet",
            ChunkType::ImageReconstruction => "recon",
            ChunkType::Wtf => "wtf",
            ChunkType::AcmControl => "acm",
            ChunkType::CemControl => "cem",
            ChunkType::Interleave => "interleave",
            ChunkType::LineUpdate => "lineupd",
            ChunkType::LineUpdateTransform => "luxform",
            ChunkType::Empty47 => "empty47",
            ChunkType::Baseline => "baseline",
        }
    }

    /// Map a raw wire type id to a [`ChunkType`], if known.
    pub const fn from_id(id: u16) -> Option<Self> {
        match id {
            x if x == ChunkType::ReplyConfigTable.id() => Some(ChunkType::ReplyConfigTable),
            x if x == ChunkType::SetRegister32.id() => Some(ChunkType::SetRegister32),
            x if x == ChunkType::RegisterList16.id() => Some(ChunkType::RegisterList16),
            x if x == ChunkType::RegisterList32.id() => Some(ChunkType::RegisterList32),
            x if x == ChunkType::TimeslotTable2d.id() => Some(ChunkType::TimeslotTable2d),
            x if x == ChunkType::DataEncoder.id() => Some(ChunkType::DataEncoder),
            x if x == ChunkType::TwoD.id() => Some(ChunkType::TwoD),
            x if x == ChunkType::TimeslotOffset.id() => Some(ChunkType::TimeslotOffset),
            x if x == ChunkType::FingerDetectOffset.id() => Some(ChunkType::FingerDetectOffset),
            x if x == ChunkType::ReplyConfig.id() => Some(ChunkType::ReplyConfig),
            x if x == ChunkType::BwReduction.id() => Some(ChunkType::BwReduction),
            x if x == ChunkType::FingerDetect.id() => Some(ChunkType::FingerDetect),
            x if x == ChunkType::ImageReconstruction.id() => Some(ChunkType::ImageReconstruction),
            x if x == ChunkType::Wtf.id() => Some(ChunkType::Wtf),
            x if x == ChunkType::AcmControl.id() => Some(ChunkType::AcmControl),
            x if x == ChunkType::CemControl.id() => Some(ChunkType::CemControl),
            x if x == ChunkType::Interleave.id() => Some(ChunkType::Interleave),
            x if x == ChunkType::LineUpdate.id() => Some(ChunkType::LineUpdate),
            x if x == ChunkType::LineUpdateTransform.id() => Some(ChunkType::LineUpdateTransform),
            x if x == ChunkType::Empty47.id() => Some(ChunkType::Empty47),
            x if x == ChunkType::Baseline.id() => Some(ChunkType::Baseline),
            _ => None,
        }
    }
}

/// Short label for a raw chunk type id (arm-lab / status). Empty string when unknown.
pub fn arm_chunk_label(kind: u16) -> &'static str {
    ChunkType::from_id(kind).map_or("", ChunkType::label)
}

/// Timeslot instruction opcodes (as decoded by [`decode_insn`]). Only the ones the line-update
/// logic keys on are named; numbering matches python-validity `timeslot.codes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TimeslotOp {
    /// "Security" / Enable-Rx (op 6) — the calib / 1a8 / 1a4 line anchors.
    EnableRx = 6,
    /// "Motion 2" / Call (op 11) — `patch_fingerdet_reg` follows its destination address.
    Call = 11,
    /// "Sweep" / Write-Register (op 13).
    WriteRegister = 13,
}

impl TimeslotOp {
    pub const fn op(self) -> u8 {
        self as u8
    }
}

/// Hardware registers the line-update anchors its calibration lines to (write-register targets found
/// in the patched timeslot table). Semantics confirmed from the DLL (`syna_build_line_update_prod23`
/// + `SynaCalResults` layout, 2026-07-27 — see docs/re/capture-fw-decomp.c §8):
///   - `LINE_UPDATE_A` = **the finger-detect register** (`0x8000203c`). DAT line A is bit-packed
///     from the step-3 measured diff (`SynaCalResults.pStep3_diff_ptr@+0x68`, on 0x2449 the raw
///     factory `0x80000003` block) — i.e. the finger-detect threshold IS measured-cal-driven. It is
///     ALSO patched as a single default into the `0x34` timeslot program (see
///     [`patch_fingerdet_reg`] = the DLL's `syna_patch_fingerdet_reg_from_calresults`).
///     NB (verified live): whether finger-detect actually *fires* on 0x2449 is gated by the separate
///     pre-arm encrypted fwext (on-chip), NOT by this register value alone.
///   - `LINE_UPDATE_B` (`0x80002040`) = DAT line B, same step-3 source as A.
///   - `LINE_UPDATE_C` (`0x800020fc`) = DAT line C, source = step-6 WOE dark frame
///     (`pStep5or6_buf_ptr@+0x80`) then step-4 (`pStep4_factory7_ptr@+0x98`); raw memcpy, never packed.
pub mod reg {
    /// `0x8000203c` — the FINGER-DETECT register (DAT line A / step-3 measured cal).
    pub const LINE_UPDATE_A: u32 = 0x8000_203c;
    /// Alias for [`LINE_UPDATE_A`] emphasizing its role.
    pub const FINGER_DETECT: u32 = LINE_UPDATE_A;
    pub const LINE_UPDATE_B: u32 = 0x8000_2040;
    pub const LINE_UPDATE_C: u32 = 0x8000_20fc;
}

/// Index into the step-3 measured diff (`SynaCalResults.pStep3_diff_ptr`, on 0x2449 the raw factory
/// `0x80000003` block == our `factory_calibration_values`) whose byte patches the finger-detect
/// register's default value in the `0x34` timeslot program. This is the DLL's `cal_off` in
/// `syna_patch_fingerdet_reg_from_calresults` (docs/re/capture-fw-decomp.c §3): 0 for most subtypes
/// (incl. 0x2449), only nonzero for a handful. Replaces the earlier `key_calibration_line = lines/2`
/// (=28 on 0x2449), which was inherited from python-validity and does NOT match this DLL.
pub fn fingerdet_cal_offset(subtype: u16) -> usize {
    match subtype {
        0xb3 | 0x143b => 0x25,
        0xea => 0x2c,
        0xed | 0x1ff5 | 0xb5 | 0x1055 | 0x196 | 0x199 | 0x581 => 0x38,
        _ => 0,
    }
}

/// [`Line::flags`] bit patterns. A line's flags pack: bits `[24:28)` = line type, `[20:24)` =
/// sequence number, `[0:20)` = the timeslot program-counter / data offset it targets.
pub(crate) mod line_flag {
    /// python-validity type-2 lines (`line_update_type_2` path).
    pub const TYPE2: u32 = 0x0300_0000;
    /// product-0x33 calib-blob line (its `group` field, bits [20:24), is a hardcoded 2).
    pub const CALIB_BLOB: u32 = 0x0720_0000;
    /// product-0x33 bitpacked DAT-table lines.
    pub const DAT: u32 = 0x0700_0000;
    /// product-0x33 empty "1a8/1a4" lines.
    pub const EMPTY_1A: u32 = 0x4700_0000;
    /// product-0x33 model-marker line (the `0x2449` subtype group).
    pub const MODEL_MARKER: u32 = 0x1700_0374;
    /// bitpack `v0` marker bit: a line's `v0 = (bit_width - 1) | V0_PACKED`.
    pub const V0_PACKED: u8 = 8;
}

/// A decoded timeslot instruction: `(opcode, size, operand0, operand1)`.
/// Opcode numbering matches python-validity `timeslot.decode_insn` (0..15).
#[derive(Debug, Clone, Copy)]
pub struct Insn {
    pub op: u8,
    pub size: usize,
    /// op 13 (Write Register): register address. op 11: `b[0] & 7`.
    pub op0: u32,
    /// op 13: value. op 11: destination address (`b[1] << 2`).
    pub op1: u32,
}

/// Decode one instruction at the start of `b`. `None` if `b` is empty or the encoding is unknown.
/// Ported verbatim (order-sensitive) from python-validity `timeslot.decode_insn`.
pub fn decode_insn(b: &[u8]) -> Option<Insn> {
    if b.is_empty() {
        return None;
    }
    let b0 = b[0];
    let mk = |op, size, op0, op1| Some(Insn { op, size, op0, op1 });
    let b1 = |i: usize| b.get(i).copied().unwrap_or(0) as u32;
    match b0 {
        0 => mk(0, 1, 0, 0),
        1 => mk(1, 1, 0, 0),
        2 => mk(2, 1, 0, 0),
        3 => mk(3, 1, 0, 0),
        4 => mk(4, 1, 0, 0),
        5 => mk(5, 2, b1(1), 0),
        6 => mk(6, 2, b1(1), 0),
        7 => mk(7, 2, if b1(1) == 0 { 0x100 } else { b1(1) }, 0),
        _ if b0 & 0xfe == 0x08 => mk(8, 2, ((b0 as u32 & 1) << 8) | b1(1), 0),
        _ if b0 & 0xfe == 0x0a => mk(9, 2, ((b0 as u32 & 1) << 8) | b1(1), 0),
        _ if b0 & 0xfc == 0x0c => mk(10, 1, b0 as u32 & 3, 0),
        _ if b0 & 0xf8 == 0x10 => mk(11, 3, b0 as u32 & 7, b1(1) << 2),
        _ if b0 & 0xe0 == 0x20 => mk(12, 1, b0 as u32 & 0x1f, 0),
        _ if b0 & 0xc0 == 0x40 => mk(
            13,
            3,
            (b0 as u32 & 0x3f) * 4 + 0x8000_2000,
            b1(1) | (b1(2) << 8),
        ),
        _ if b0 & 0xc0 == 0x80 => mk(14, 1, (b0 as u32 & 0x38) >> 3, b0 as u32 & 7),
        _ if b0 & 0xc0 == 0xc0 => mk(15, 2, (b0 as u32 & 0x38) >> 3, b0 as u32 & 7),
        _ => None,
    }
}

/// Program counter of the `n`-th (1-based) instruction with the given opcode. `None` if not found.
pub fn find_nth_insn(b: &[u8], opcode: u8, mut n: u32) -> Option<usize> {
    let mut pc = 0usize;
    while pc < b.len() {
        let insn = decode_insn(&b[pc..])?;
        if insn.op == opcode {
            n -= 1;
            if n == 0 {
                return Some(pc);
            }
        }
        pc += insn.size;
    }
    None
}

/// Program counter of the `n`-th (1-based) Write-Register (op 13) to `reg_addr`. `None` if not found.
pub fn find_nth_regwrite(b: &[u8], reg_addr: u32, mut n: u32) -> Option<usize> {
    let mut pc = 0usize;
    while pc < b.len() {
        let insn = decode_insn(&b[pc..])?;
        if insn.op == TimeslotOp::WriteRegister.op() && insn.op0 == reg_addr {
            n -= 1;
            if n == 0 {
                return Some(pc);
            }
        }
        pc += insn.size;
    }
    None
}

/// Patch a Timeslot-Table-2D payload: for each op-11 (`b[i]&0xf8==0x10`) with `b[i+2] > 1`, multiply
/// `b[i+2]` by `mult` and (if `inc_address`) bump `b[i+1]`. Stops at the first non-{0,7,11} byte.
/// "This is the exact logic from the DLL. If it looks broken that was probably intended."
pub fn patch_timeslot_table(input: &[u8], inc_address: bool, mult: u16) -> Vec<u8> {
    let mut b = input.to_vec();
    let mut i = 0usize;
    while i + 3 < b.len() {
        if b[i] & 0xf8 == 0x10 {
            if b[i + 2] > 1 {
                b[i + 2] = (b[i + 2] as u16).wrapping_mul(mult) as u8;
                if inc_address {
                    b[i + 1] = b[i + 1].wrapping_add(1);
                }
            }
            i += 3;
        } else if b[i] == 0 {
            i += 1;
        } else if b[i] == 7 {
            i += 2;
        } else {
            break;
        }
    }
    b
}

/// The finger-detect-register default patch — the DLL's `syna_patch_fingerdet_reg_from_calresults`
/// (@0x18008c360; fresh decompile 2026-08-06 supersedes the docs/re §3 transcription). It locates
/// the reg-write to [`reg::FINGER_DETECT`] (`0x8000203c`) in the `0x34` timeslot program and
/// overwrites its low value byte with `fingerdet_cal[fingerdet_cal_offset(subtype)]`.
///
/// **The write is GUARDED**, and the guard is why `0x2449` is a no-op: the DLL only patches when the
/// *measured* fingerdet cal at `ctx+0x288+0x68` (ptr) **and** `+0x70` (length) are both non-zero —
/// `+0x70` is a step5/6 output. On `0x2449` only step3 runs (`flex[0x1c]=0x81`), so `+0x70 == 0`, the
/// guard fails, and reg `0x8000203c` keeps its base `0x80`. **Proven byte-exact** vs the DLL identify
/// (`20260806T093247Z`) and image (`20260806T205237Z`) arms — both leave `0x34[181] = 0x80`. Our old
/// port had no guard and sourced the always-present factory block, so it wrongly wrote `factory[0]`
/// (`0x7e`) — a real bug the DLL image oracle caught.
///
/// So `fingerdet_cal` models the `+0x68`/`+0x70` measured source: `Some(non-empty)` ⇒ the guard holds
/// (a subtype whose step5/6 ran) ⇒ patch; `None` ⇒ guard fails ⇒ no-op. On `0x2449` callers pass
/// `None`. (The DLL's search is a two-pass walk from the `0x35` chunk's start offset — op `0xb`
/// repeat → `sub_off`, then op `0xd` reg-write from there; validated to land on the same `0x34[181]`
/// as the scan below, so the scan is kept for the value position.)
pub fn patch_fingerdet_reg(input: &[u8], fingerdet_cal: Option<&[u8]>, subtype: u16) -> Vec<u8> {
    let cal_off = fingerdet_cal_offset(subtype);
    // DLL guard (ctx+0x288+0x68 && +0x70): no measured fingerdet cal ⇒ no patch (the 0x2449 path).
    let Some(fingerdet_cal) = fingerdet_cal else {
        return input.to_vec();
    };
    let mut b = input.to_vec();
    // Find the last Call (op 11); its destination address is operand1.
    let mut pc = 0usize;
    let mut call_dest: Option<usize> = None;
    while pc < b.len() {
        let Some(insn) = decode_insn(&b[pc..]) else {
            break;
        };
        if insn.op == 1 || insn.op == 2 || insn.op == 4 {
            break;
        }
        if insn.op == TimeslotOp::Call.op() {
            call_dest = Some(insn.op1 as usize);
        }
        pc += insn.size;
    }
    let Some(mut pc) = call_dest else { return b };
    // From there, find the last Write-Register to reg::FINGER_DETECT (0x8000203c).
    let mut regw: Option<usize> = None;
    while pc < b.len() {
        let Some(insn) = decode_insn(&b[pc..]) else {
            break;
        };
        if insn.op == 1 || insn.op == 2 || insn.op == 4 {
            break;
        }
        if insn.op == TimeslotOp::WriteRegister.op() && insn.op0 == reg::FINGER_DETECT {
            regw = Some(pc);
        }
        pc += insn.size;
    }
    if let (Some(pos), Some(&v)) = (regw, fingerdet_cal.get(cal_off))
        && pos + 1 < b.len()
    {
        b[pos + 1] = v;
    }
    b
}
