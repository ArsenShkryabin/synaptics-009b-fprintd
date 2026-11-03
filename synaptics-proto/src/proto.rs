//! Vendor command protocol: opcodes, request/response framing, and typed parsers.
//!
//! Opcodes and their semantics are the full map reverse-engineered in
//! docs/protocol/opcode-map.md (handler table `DAT_18013dc30`, each `syna_cmd_<op>_*`).
//! A request is `opcode_byte ‖ little-endian args`. A response is
//! `u16 status ‖ payload` (status 0 = ok).

use synaptics_core::error::{Error, Result, Status};
use synaptics_core::wire::{self, Cursor};

/// USB vendor command opcodes — the **unified USDK5 / VCSFW command set**, merged from two
/// independent reverse engineerings of `synaWudfBioUsb.dll`:
///  - **009b / Prometheus** (MSI 5.5.11.1086) — `// 9b:` = `syna_cmd_<op>_*` handler address,
///    from `docs/protocol/opcode-map.md`.
///  - **Metallica / MIS** (Lenovo 5.3.3545.26, product `0x0030`) — `// met:` = `scs_cmd_*`,
///    the sibling driver on the same USDK5 core; the two protocols are byte-for-byte the same
///    dispatch/command surface, differing only by version-level additions and sensor silicon.
///
/// `W!` = destructive, `W` = write, `C` = control, `R` = read. Destructive/write opcodes are
/// listed for completeness; the read-only build never emits them (see [`Opcode::is_read_only`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    GetRomInfo = 0x01, // R  9b:syna_cmd_01_get_rom_info@180087b10  met:scs_cmd_get_version
    DbObjectRead = 0x02, // R  9b:syna_cmd_1002_db_object_read@180087be0  met:scs_cmd_capture_image (wire byte overloaded; TBC by capture)
    CaptureStop = 0x04,  // C  9b:syna_cmd_04_capture_stop@180087f50  met:scs_cmd_capture_stop
    Reboot = 0x05,       // C  9b:syna_cmd_05_reboot@180088010  met:scs_cmd_reboot
    SendDataBlob = 0x06, // W  9b:syna_cmd_06_send_data_blob@180088140  met:scs_cmd_send_data_block
    ReadHwReg32 = 0x07, // R  9b:syna_cmd_07_read_hw_reg32@180088270  met:scs_cmd_peek (arbitrary 32-bit addr)
    WriteHwReg32 = 0x08, // W  9b:syna_cmd_08_write_hw_reg32@180088380  met:scs_cmd_poke
    SetConfigParams18 = 0x0d, // W  9b:syna_cmd_0d_set_config_params18@1800884d0  met:scs_cmd_write_config_block (18×u32)
    WipeReset = 0x10,         // W! 9b:syna_cmd_10_wipe_reset@1800886e0  met:scs_cmd_reset_ownership
    GetSensorState = 0x17, // R  9b:syna_cmd_17_unknown_noarg@1800887b0  met:scs_cmd_get_sensor_state (state enum 0..3)
    InitStep = 0x19,       // C  9b:syna_cmd_19_init_step@180088880  met:scs_cmd_get_start_info
    Commit = 0x1a, // C  9b:syna_cmd_1a_commit_or_skip@180088960  met:scs_cmd_session_finalize
    SetLeds = 0x39, // W  met:scs_cmd_set_leds (6-slot on/off/RGB) — Metallica-only, absent on 009b
    GetFlashInfo = 0x3e, // R  9b:syna_cmd_3e_get_flash_info@1800890e0  met:scs_cmd_db2_get_db_info
    EraseFlash = 0x3f, // W! 9b:syna_cmd_3f_erase_flash@1800891d0  met:scs_cmd_db2_format
    ReadFlash = 0x40, // R  9b:syna_cmd_40_read_flash@1800892e0  met:scs_cmd_db2_partition_read
    WriteFlash = 0x41, // W! 9b:syna_cmd_41_write_flash@180089430  met:scs_cmd_db2_partition_write
    WriteSignatureBlock = 0x42, // W  9b:syna_cmd_42_write_signature_block@1800895b0  met:scs_cmd_db2_write_tagged
    GetFwInfo = 0x43, // R  9b:syna_cmd_43_get_fw_info@180089720  met:scs_cmd_db2_get_object_list
    DbInfo = 0x45,    // R  9b:syna_cmd_45_db_info@180089840  met:scs_cmd_db2_get_object_id_list
    GetRecordChildren = 0x46, // R  9b:syna_cmd_46_get_record_children@180089930  met:scs_cmd_db2_get_object_info
    NewRecord = 0x47, // W  9b:syna_cmd_47_new_record@180089a50  met:scs_cmd_db2_create_object
    DelRecord = 0x48, // W! 9b:syna_cmd_48_del_record@180089bd0  met:scs_cmd_db2_delete_object
    GetRecordValue = 0x49, // R  9b:syna_cmd_49_get_record_value@180089ce0  met:scs_cmd_db2_get_object_data (bulk template)
    GetUser = 0x4a, // R  9b:syna_cmd_4a_get_user@180089e00  met:scs_cmd_db2_get_object_composite
    GetUserStorage = 0x4b, // R  9b:syna_cmd_4b_get_user_storage@18008a3f0  met:scs_cmd_db2_get_object_records
    RecordWriteTagged = 0x4c, // W  9b:syna_cmd_4c_record_write_tagged@180089f90  met:scs_cmd_db2_write_sealed_object
    RecordOpByBlob = 0x4d, // W? 9b:syna_cmd_4d_record_op_by_blob@18008a0f0  met:scs_cmd_db2_lookup_object_data
    RecordOpTwoBlobs = 0x4e, // W? 9b:syna_cmd_4e_record_op_two_blobs@18008a250  met:scs_cmd_db2_write_key_value
    PartitionFlash = 0x4f, // R/W! 9b:syna_cmd_4f_send_workkey_partition_data@180088ac0  met:scs_cmd_db2_identify (minimal form = WRKP handshake read)
    GetProvisionKey = 0x50, // R  9b:syna_cmd_50_get_provision_key@18008a560  met:scs_cmd_db2_get_db_info_ex
    GetPrgStatus = 0x51, // R  9b:syna_cmd_51_get_prg_status@18008a640  met:scs_cmd_get_program_status
    NoArgRequest52 = 0x52, // ?  9b:syna_cmd_52_noarg_request@18008c270  met:scs_cmd_get_program_status2
    SetU16Param = 0x57, // W  9b:syna_cmd_57_set_u16_param@18008b360  met:scs_cmd_set_idle_timeout
    MatchFinger = 0x5e, // R  9b:syna_cmd_5e_match_finger@18008a720  met:scs_cmd_match
    GetMatchResult = 0x5f, // R  9b:syna_cmd_5f_get_match_result@18008a9e0  met:scs_cmd_get_match_stats
    GetMatchResultEx = 0x60, // R  9b:syna_cmd_60_get_match_result_ex@18008ab00  met:scs_cmd_get_match_results
    MatchWithData = 0x61, // W  9b:syna_cmd_61_match_with_data@18008ac10  met:scs_cmd_get_match_image
    MatchCleanup = 0x62,  // C  9b:syna_cmd_62_match_cleanup@18008a8d0  met:scs_cmd_match_cleanup
    EnrollUpdateStart = 0x68, // W  9b:syna_cmd_68_enrollment_update_start@18008ad90  met:scs_cmd_enroll_start
    EnrollStart = 0x69, // W  9b:syna_cmd_69_enroll_start@18008aeb0  met:scs_cmd_enroll_create_end
    EnrollPoll = 0x6a, // R/C 9b:syna_cmd_6a_enroll_poll@18008afb0  met:scs_cmd_enroll_commit (→ new template id + hash)
    EnrollAppend = 0x6b, // W  9b:syna_cmd_6b_enroll_append@18008b090  met:scs_cmd_enroll_add_image (≤48 KB image)
    QueryRecordById = 0x6c, // R  9b:syna_cmd_6c_query_record_by_id@18008bc80  met:scs_cmd_send_formatted_record
    SetRecordContext = 0x6e, // W  9b:syna_cmd_6e_set_record_context@18008b1c0  met:scs_cmd_tunneled_data_exchange
    GetFactoryBits = 0x6f, // R  9b:syna_cmd_6f_get_factory_bits@18008ba20  met:scs_cmd_get_factory_bits
    ResetOp = 0x72, // C  9b:syna_cmd_72_reset_op@18008b490  met:scs_cmd_stub (Metallica: reserved)
    SendTaggedDataBlob = 0x73, // W  9b:syna_cmd_73_send_data_blob@18008b570  met:scs_cmd_vendor_data_exchange
    GetSensorId = 0x75, // R  9b:syna_cmd_75_get_sensor_id@18008c1a0  met:scs_cmd_identify_sensor (silicon type)
    SendRecordHeader = 0x76, // W  9b:syna_cmd_76_send_record_header@18008b6c0  (009b-observed)
    ResetNoArgs = 0x77, // C  9b:syna_cmd_77_reset_noargs@18008b950  (009b-observed)
    SetU32Param = 0x78, // W  9b:syna_cmd_78_set_u32_param@18008bba0  met:scs_cmd_read_data
    WriteBuffer = 0x79, // W  9b:syna_cmd_79_write_buffer@18008bf70  (009b-observed)
    SimpleAction = 0x7b, // ?  9b:syna_cmd_7b_simple_action@18008c0b0  (009b-observed)
}

impl Opcode {
    pub fn byte(self) -> u8 {
        self as u8
    }
    /// Map a wire opcode byte back to its [`Opcode`] (for decoding captures). Returns `None` for
    /// bytes outside the known command set. Keep in sync with the enum above.
    pub fn from_byte(b: u8) -> Option<Opcode> {
        use Opcode::*;
        Some(match b {
            0x01 => GetRomInfo,
            0x02 => DbObjectRead,
            0x04 => CaptureStop,
            0x05 => Reboot,
            0x06 => SendDataBlob,
            0x07 => ReadHwReg32,
            0x08 => WriteHwReg32,
            0x0d => SetConfigParams18,
            0x10 => WipeReset,
            0x17 => GetSensorState,
            0x19 => InitStep,
            0x1a => Commit,
            0x39 => SetLeds,
            0x3e => GetFlashInfo,
            0x3f => EraseFlash,
            0x40 => ReadFlash,
            0x41 => WriteFlash,
            0x42 => WriteSignatureBlock,
            0x43 => GetFwInfo,
            0x45 => DbInfo,
            0x46 => GetRecordChildren,
            0x47 => NewRecord,
            0x48 => DelRecord,
            0x49 => GetRecordValue,
            0x4a => GetUser,
            0x4b => GetUserStorage,
            0x4c => RecordWriteTagged,
            0x4d => RecordOpByBlob,
            0x4e => RecordOpTwoBlobs,
            0x4f => PartitionFlash,
            0x50 => GetProvisionKey,
            0x51 => GetPrgStatus,
            0x52 => NoArgRequest52,
            0x57 => SetU16Param,
            0x5e => MatchFinger,
            0x5f => GetMatchResult,
            0x60 => GetMatchResultEx,
            0x61 => MatchWithData,
            0x62 => MatchCleanup,
            0x68 => EnrollUpdateStart,
            0x69 => EnrollStart,
            0x6a => EnrollPoll,
            0x6b => EnrollAppend,
            0x6c => QueryRecordById,
            0x6e => SetRecordContext,
            0x6f => GetFactoryBits,
            0x72 => ResetOp,
            0x73 => SendTaggedDataBlob,
            0x75 => GetSensorId,
            0x76 => SendRecordHeader,
            0x77 => ResetNoArgs,
            0x78 => SetU32Param,
            0x79 => WriteBuffer,
            0x7b => SimpleAction,
            _ => return None,
        })
    }
    /// True for commands that never mutate persistent device state (safe reads).
    ///
    /// Note `PartitionFlash` (0x4f) is *mode-dependent* (5-byte form is a handshake read,
    /// sub-block form is a destructive partition write) and is therefore excluded here — it
    /// is gated at the call site, not by opcode.
    pub fn is_read_only(self) -> bool {
        use Opcode::*;
        matches!(
            self,
            GetRomInfo
                | DbObjectRead
                | ReadHwReg32
                | GetSensorState
                | GetFlashInfo
                | ReadFlash
                | GetFwInfo
                | DbInfo
                | GetRecordChildren
                | GetRecordValue
                | GetUser
                | GetUserStorage
                | GetProvisionKey
                | GetPrgStatus
                | MatchFinger
                | GetMatchResult
                | GetMatchResultEx
                | QueryRecordById
                | GetFactoryBits
                | GetSensorId
        )
    }
}

/// SCS **command-table index** — the `desc[0]` value the DLL's `syna_scs_*` wrappers pass to
/// `syna_cmd_table_dispatch@0x180064700`, which calls `table[index]` (handler table at `0x18013dc30`,
/// entry `N` at `+N*8`). This index is a **DLL-internal dispatch id, not sent on the wire**; the
/// handler it selects emits the actual wire [`Opcode`]. [`Self::wire_opcode`] gives that mapping
/// (verified against the dispatch table + the `syna_cmd_<op>_*` build handlers). Kept as a typed
/// cross-reference for reading DLL behaviour/captures. Full table: `docs/protocol/scs-command-set.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ScsCmdIndex {
    RebootSensor = 0x02,      // → Reboot 0x05
    GetResetInfo = 0x03,      // wire op TBD
    ReadHwReg = 0x04,         // → ReadHwReg32 0x07
    SendFwBlob = 0x07,        // → SendDataBlob 0x06
    UploadCaptureProg = 0x09, // wire 0x02 capture-program upload
    CaptureCompleteAck = 0x0a,
    QueryCaptureResult = 0x0b,
    ReadFrameChunk = 0x0c, // → GetPrgStatus 0x51 (read_mode==2)
    Cmd0x0d = 0x0d,        // dispatch slot = 0x71 "not supported" stub
    SetCfg57 = 0x0e,       // → SetU16Param 0x57
    GetProvisionKey = 0x12,   // → GetProvisionKey 0x50
    SetRecordContext = 0x13,  // → SetRecordContext 0x6e
    FlashReadId = 0x14,       // wire op TBD
    ReadFlash = 0x16,         // → ReadFlash 0x40
    WriteFlash = 0x17,        // → WriteFlash 0x41
    WriteSignatureBlock = 0x18, // → WriteSignatureBlock 0x42
    GetFwInfo = 0x19,         // → GetFwInfo 0x43
    GetDbInfo = 0x1a,         // → DbInfo 0x45
    NewRecord = 0x1b,         // → NewRecord 0x47  (table[0x1b]=syna_cmd_47@0x180089a50)
    DelRecord = 0x1c,         // → DelRecord 0x48
    GetRecordChildren = 0x1d, // → GetRecordChildren 0x46
    GetRecordValue = 0x1e,    // → GetRecordValue 0x49  (table[0x1e]=syna_cmd_49@0x180089ce0)
    RecordWriteTagged = 0x1f, // → RecordWriteTagged 0x4c
    GetUser = 0x20,           // → GetUser 0x4a
    RecordOpByBlob = 0x21,    // → RecordOpByBlob 0x4d
    RecordOpTwoBlobs = 0x22,  // → RecordOpTwoBlobs 0x4e
    GetUserStorage = 0x23,    // → GetUserStorage 0x4b
    MatchFinger = 0x24,       // → MatchFinger 0x5e
    CancelMatch = 0x25,       // → MatchCleanup 0x62
    GetMatchResult = 0x26,    // → GetMatchResult 0x5f
    GetMatchResultEx = 0x27,  // → GetMatchResultEx 0x60
    MatchWithData = 0x28,     // → MatchWithData 0x61
    EnrollUpdateStart = 0x29, // → EnrollUpdateStart 0x68
    EnrollStart = 0x2a,       // → EnrollStart 0x69
    EnrollPoll = 0x2b,        // → EnrollPoll 0x6a
    EnrollAppend = 0x2c,      // → EnrollAppend 0x6b
    FetchTagList = 0x2d,      // wire op TBD
    UploadBlob = 0x2e,        // wire op TBD (reconstruction/module upload)
    WofArmSendRecord = 0x2f,  // → SendRecordHeader 0x76
    ReadWofStatus = 0x30,     // wire op TBD
    ReadFrameChunkAlt = 0x31, // read_mode==3 alt frame reader (EP-0x81)
    SetCalConfig = 0x32,      // wire op TBD
    Cmd0x33 = 0x33,           // var-blob request; verb not decoded
    ReadCaptureState = 0x34,  // single-byte capture-state read
    GetSiliconId = 0x35,      // → GetSensorId 0x75
    CaptureFinalizeOp52 = 0x36, // → NoArgRequest52 0x52
    Cmd0x37 = 0x37,           // dispatch slot = 0x71 "not supported" stub
}

impl ScsCmdIndex {
    /// The DLL dispatch-table index byte.
    pub fn index(self) -> u8 {
        self as u8
    }

    /// The wire [`Opcode`] the selected build handler emits, where confidently resolved from the
    /// dispatch table. `None` for indices whose wire opcode is not yet established, the two `0x71`
    /// "not supported" stubs (`Cmd0x0d`/`Cmd0x37`), and the frame-chunk readers whose wire framing is
    /// documented separately (`0x51`/alt).
    pub fn wire_opcode(self) -> Option<Opcode> {
        use ScsCmdIndex::*;
        Some(match self {
            RebootSensor => Opcode::Reboot,
            ReadHwReg => Opcode::ReadHwReg32,
            SendFwBlob => Opcode::SendDataBlob,
            ReadFrameChunk => Opcode::GetPrgStatus,
            SetCfg57 => Opcode::SetU16Param,
            GetProvisionKey => Opcode::GetProvisionKey,
            SetRecordContext => Opcode::SetRecordContext,
            ReadFlash => Opcode::ReadFlash,
            WriteFlash => Opcode::WriteFlash,
            WriteSignatureBlock => Opcode::WriteSignatureBlock,
            GetFwInfo => Opcode::GetFwInfo,
            GetDbInfo => Opcode::DbInfo,
            NewRecord => Opcode::NewRecord,
            DelRecord => Opcode::DelRecord,
            GetRecordChildren => Opcode::GetRecordChildren,
            GetRecordValue => Opcode::GetRecordValue,
            RecordWriteTagged => Opcode::RecordWriteTagged,
            GetUser => Opcode::GetUser,
            RecordOpByBlob => Opcode::RecordOpByBlob,
            RecordOpTwoBlobs => Opcode::RecordOpTwoBlobs,
            GetUserStorage => Opcode::GetUserStorage,
            MatchFinger => Opcode::MatchFinger,
            CancelMatch => Opcode::MatchCleanup,
            GetMatchResult => Opcode::GetMatchResult,
            GetMatchResultEx => Opcode::GetMatchResultEx,
            MatchWithData => Opcode::MatchWithData,
            EnrollUpdateStart => Opcode::EnrollUpdateStart,
            EnrollStart => Opcode::EnrollStart,
            EnrollPoll => Opcode::EnrollPoll,
            EnrollAppend => Opcode::EnrollAppend,
            WofArmSendRecord => Opcode::SendRecordHeader,
            GetSiliconId => Opcode::GetSensorId,
            CaptureFinalizeOp52 => Opcode::NoArgRequest52,
            // syna_cmd_78_set_u32_param@0x18008bba0 — vfmCapture read_mode==3 frame pump.
            ReadFrameChunkAlt => Opcode::SetU32Param,
            // syna_cmd_04_capture_stop@0x180087f80 — post-frame finalize ack (SCS idx 0x0a).
            CaptureCompleteAck => Opcode::CaptureStop,
            // syna_cmd_17_unknown_noarg@0x1800887b0 — capture-result poll (SCS idx 0x0b).
            QueryCaptureResult => Opcode::GetSensorState,
            // Not (yet) wire-opcode-resolved / documented elsewhere:
            GetResetInfo | UploadCaptureProg | Cmd0x0d | FlashReadId | FetchTagList | UploadBlob
            | ReadWofStatus | SetCalConfig | Cmd0x33 | ReadCaptureState | Cmd0x37 => return None,
        })
    }
}

/// A parsed command response: `status` (first 2 bytes LE) + `payload` (the rest).
#[derive(Debug, Clone)]
pub struct Response {
    pub status: Status,
    pub payload: Vec<u8>,
}

impl Response {
    /// Parse raw response bytes into `{status, payload}`.
    pub fn parse(opcode: u8, raw: &[u8]) -> Result<Response> {
        // A leading 'D' (0x44) marks a TLS/handshake record, which is NOT status-prefixed
        // (ghidra: syna_response_dispatch@0x180087970 branches on first byte == 'D'). Return
        // it whole with an OK status rather than mis-stripping two bytes as a status word.
        if raw.first() == Some(&0x44) {
            return Ok(Response {
                status: Status::OK,
                payload: raw.to_vec(),
            });
        }
        if raw.len() < 2 {
            return Err(Error::ShortResponse {
                opcode,
                got: raw.len(),
                need: 2,
            });
        }
        Ok(Response {
            status: Status::from_wire(u16::from_le_bytes([raw[0], raw[1]])),
            payload: raw[2..].to_vec(),
        })
    }

    /// Return an error if the status word is non-zero.
    pub fn ok(self, opcode: u8) -> Result<Response> {
        if self.status.is_ok() {
            Ok(self)
        } else {
            Err(Error::Status {
                opcode,
                status: self.status,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Typed parsers for the pre-TLS read commands used by `probe`.
// ---------------------------------------------------------------------------

/// `0x01` RomInfo — ASIC/ROM identity. ghidra: syna_cmd_01_get_rom_info;
/// layout matches python-validity `sensor.py RomInfo.get` `<LLBBxBxxxB`.
#[derive(Debug, Clone)]
pub struct RomInfo {
    pub timestamp: u32,
    pub build: u32,
    pub major: u8,
    pub minor: u8,
    pub product: u8,
    pub u1: u8,
}

impl RomInfo {
    /// Minimum payload: fixed fields through `u1` at offset 0x0f (16 bytes; 0x12 incl. status).
    const MIN_LEN: usize = 0x10;

    pub fn parse(p: &[u8]) -> Result<RomInfo> {
        let mut c = Cursor::new_for(Opcode::GetRomInfo.byte(), p);
        c.require(Self::MIN_LEN)?;
        let timestamp = c.read_u32_le()?;
        let build = c.read_u32_le()?;
        let major = c.read_u8()?;
        let minor = c.read_u8()?;
        c.skip(1)?; // p[10] reserved
        let product = c.read_u8()?;
        c.skip(3)?; // p[12..15] reserved
        let u1 = c.read_u8()?;
        Ok(RomInfo {
            timestamp,
            build,
            major,
            minor,
            product,
            u1,
        })
    }
}

/// One flash partition descriptor. python-validity `flash.py PartitionInfo` `<BBHLL`.
#[derive(Debug, Clone)]
pub struct PartitionInfo {
    pub id: u8,
    pub type_: u8,
    pub flags: u16,
    pub addr: u32,
    pub size: u32,
}

/// `0x3e` get_flash_info. ghidra: syna_cmd_3e_get_flash_info; layout matches
/// python-validity `flash.py get_flash_info` (`<HHHHHHH` header + `pcnt` partitions).
#[derive(Debug, Clone)]
pub struct FlashInfo {
    pub jedec: (u16, u16),
    pub blocks: u16,
    pub block_size: u16,
    pub partitions: Vec<PartitionInfo>,
}

impl FlashInfo {
    /// Minimum payload: the `<HHHHHHH>` header before the partition table (14 bytes; 0x10 w/ status).
    const HEADER_LEN: usize = 0xe;
    /// One partition descriptor is `<BBHLL>` = 12 bytes.
    const PARTITION_STRIDE: usize = 0xc;

    pub fn parse(p: &[u8]) -> Result<FlashInfo> {
        let mut c = Cursor::new_for(Opcode::GetFlashInfo.byte(), p);
        c.require(Self::HEADER_LEN)?;
        let jid0 = c.read_u16_le()?;
        let jid1 = c.read_u16_le()?;
        let blocks = c.read_u16_le()?;
        c.skip(2)?; // p[6..8] unknown0
        let block_size = c.read_u16_le()?;
        c.skip(2)?; // p[10..12] unknown1
        let pcnt = c.read_u16_le()? as usize;
        let partitions = wire::read_records(c.take_rest(), Self::PARTITION_STRIDE, pcnt, |q| {
            let mut r = Cursor::new(q);
            PartitionInfo {
                id: r.read_u8().unwrap_or_default(),
                type_: r.read_u8().unwrap_or_default(),
                flags: r.read_u16_le().unwrap_or_default(),
                addr: r.read_u32_le().unwrap_or_default(),
                size: r.read_u32_le().unwrap_or_default(),
            }
        });
        Ok(FlashInfo {
            jedec: (jid0, jid1),
            blocks,
            block_size,
            partitions,
        })
    }
}

/// Named bits of `SensorStatus::flags17` (`payload[0x17]`), as understood from the vendor init
/// (ghidra: `syna_open_init_decide_format` / `syna_parse_status_response@0x180060720`).
pub mod status_flags17 {
    /// bit1 (`0x02`): the sensor reports itself **provisioned**. The driver stores the *inverse* at
    /// `ctx+0x274` (`(flags17 & PROVISIONED) == 0`).
    pub const PROVISIONED: u8 = 0x02;
    /// bit6 (`0x40`): the sensor has **SPI flash** present / partitions formatted. The driver stores
    /// the inverse at `ctx+0x27c` as the format/wipe gate (`(flags17 & HAS_FLASH) == 0` → the
    /// destructive partition-flash path is armed). This bit — not the storage-mode discriminant — is
    /// the per-device "has persistent flash" flag: set ⇒ provision partitions; clear ⇒ transient
    /// tag-7 path. On our 009b (no external SPI, JEDEC `ff:ff`) it reads clear.
    pub const HAS_FLASH: u8 = 0x40;
    /// bit5 (`0x20`): subkey discriminator for id8==6 (`FUN_18009a350` → subkey 2 vs 3).
    pub const SUBKEY2: u8 = 0x20;
}

/// Parsed sensor status — the identity + provisioning view the vendor driver builds from the
/// `0x01` response (ghidra: `syna_read_sensor_status`/`syna_parse_status_response@0x180060720`).
/// The parser copies the response *payload* byte-for-byte at these offsets into a 0x1b-byte
/// struct, so the fields below are `response.payload[..]` (i.e. after the 2-byte status word).
/// These bytes are also the identity keys `syna_select_fw_blob_by_identity` matches modules on.
#[derive(Debug, Clone)]
pub struct SensorStatus {
    /// `payload[0x0a] == 1` — status struct valid.
    pub valid: bool,
    /// `payload[0x0b]` — device id (drives `ctx+0x23c`, the fw-blob outer match key).
    pub device_id: u8,
    /// `payload[0x17]` — provisioning/format flag byte (raw).
    pub flags17: u8,
    /// `ctx+0x274`: `(flags17 & 0x02) == 0`.
    pub flag_274: bool,
    /// `ctx+0x27c` format/wipe gate: `(flags17 & 0x40) == 0` — true means the driver's format
    /// path is armed (would erase the DB on mismatch), i.e. NOT a clean provisioned boot. On a
    /// cold ROM-mode read this bit is unrepresentative until the full init has run.
    pub format_mode: bool,
    /// `payload[0x08]`, `payload[0x09]`, `payload[0x0f]` — the remaining u8 fw-blob match keys.
    pub key_08: u8,
    pub key_09: u8,
    pub key_0f: u8,
    /// The full response payload, kept so later code can read the other identity keys
    /// (`u32@0x04` build, `u16@0x20` → the `id[0x19]` match key) without re-issuing `0x01`.
    pub payload: Vec<u8>,
}

impl SensorStatus {
    /// Parse from a `0x01` (GetRomInfo) response payload. Needs >= 0x24 bytes (reply is 0x26 = 2
    /// status + 0x24 payload).
    pub fn parse(p: &[u8]) -> Result<SensorStatus> {
        if p.len() < 0x24 {
            return Err(Error::ShortResponse {
                opcode: 0x01,
                got: p.len() + 2,
                need: 0x26,
            });
        }
        let flags17 = p[0x17];
        Ok(SensorStatus {
            valid: p[0x0a] == 1,
            device_id: p[0x0b],
            flags17,
            flag_274: (flags17 & status_flags17::PROVISIONED) == 0,
            format_mode: (flags17 & status_flags17::HAS_FLASH) == 0,
            key_08: p[0x08],
            key_09: p[0x09],
            key_0f: p[0x0f],
            payload: p.to_vec(),
        })
    }

    /// True when bit1 of `flags17` is set (sensor reports provisioned).
    pub fn is_provisioned(&self) -> bool {
        self.flags17 & status_flags17::PROVISIONED != 0
    }

    /// Provision/enrollment-state nibble — `payload[0x18] & 0xf`, faithful to
    /// `syna_get_provision_state@0x18006da50`. This is the low nibble of `status[0x18]` (NOT
    /// `flags17`/`status[0x17]`), collapsing `6 → 7`. The DLL treats `3/5/7/8` as provisioned/paired,
    /// `0x0f` as a hard fail, and `2` as "other/needs-format". A cold `GetRomInfo` on 009b reports
    /// `status[0x18]==0` (unpaired) even when host-certstore TLS works — so this returns 0 pre-TLS and
    /// gates the fw-info-partition-2 read (and hence `ctx+0x2d0`) off. Does NOT apply the DLL's
    /// host-override downgrade (`5/7 → 2` when `ctx+0x278==1`, i.e. host has no binding DB): that needs
    /// session state we lack at the pre-TLS seed. The omission is conservative — it can only report a
    /// *higher* state, and any downgrade would only keep the fw-info read (and pre-arm dedup) off.
    pub fn provision_state(&self) -> u8 {
        // Reply is >= 0x24 payload bytes (enforced by `parse`), so `[0x18]` is always present.
        let raw = self.payload.get(0x18).copied().unwrap_or(0) & 0x0f;
        if raw == 6 { 7 } else { raw }
    }
}

/// One firmware module descriptor from a `0x43` (GetFwInfo) response.
/// python-validity `flash.py ModuleInfo` `<HHHHL` — `type, subtype, major, minor, size`.
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub type_: u16,
    pub subtype: u16,
    pub major: u16,
    pub minor: u16,
    pub size: u32,
}

/// `0x43` GetFwInfo — firmware/partition header + module list (the table the `0x06` uploads draw
/// from). ghidra: `syna_cmd_43_get_fw_info` / `syna_read_fw_info_partition`; layout matches
/// python-validity `flash.py get_fw_info` (`<HHHL` header + `modcnt` × `<HHHHL`).
#[derive(Debug, Clone)]
pub struct FwInfo {
    pub major: u16,
    pub minor: u16,
    pub buildtime: u32,
    pub modules: Vec<ModuleInfo>,
}

impl FwInfo {
    /// Minimum payload: the `<HHHL>` header before the module list (10 bytes; 0xc w/ status).
    const HEADER_LEN: usize = 0xa;
    /// One module descriptor is `<HHHHL>` = 12 bytes.
    const MODULE_STRIDE: usize = 0xc;

    pub fn parse(p: &[u8]) -> Result<FwInfo> {
        let mut c = Cursor::new_for(Opcode::GetFwInfo.byte(), p);
        c.require(Self::HEADER_LEN)?;
        let major = c.read_u16_le()?;
        let minor = c.read_u16_le()?;
        let modcnt = c.read_u16_le()? as usize;
        let buildtime = c.read_u32_le()?;
        let modules = wire::read_records(c.take_rest(), Self::MODULE_STRIDE, modcnt, |q| {
            let mut r = Cursor::new(q);
            ModuleInfo {
                type_: r.read_u16_le().unwrap_or_default(),
                subtype: r.read_u16_le().unwrap_or_default(),
                major: r.read_u16_le().unwrap_or_default(),
                minor: r.read_u16_le().unwrap_or_default(),
                size: r.read_u32_le().unwrap_or_default(),
            }
        });
        Ok(FwInfo {
            major,
            minor,
            buildtime,
            modules,
        })
    }
}

/// `0x19` reset/boot info — the "init step" is a *get reset info* read (wValue 0x44 → 68-byte
/// reply). ghidra: `syna_get_reset_info@0x18005e700` parses start_type/reset_type/start_status
/// then reads an nvinfo word; the DLL only writes these to a debug log (resetLog), never acts on
/// them. So this reply is diagnostic, not a handshake/challenge.
#[derive(Debug, Clone)]
pub struct ResetInfo {
    /// `[0]` — start type (live 009b: `2`).
    pub start_type: u8,
    /// `[1]` — reset type (live: `0`).
    pub reset_type: u8,
    /// `[2..4]` — start status word (live: `0x0021`).
    pub start_status: u16,
    /// `[4..6]` — info word (live: `0x0110`).
    pub info: u16,
    /// `[0x12..0x16]` — the "reset nvinfo" word: a **free-running timer/counter**. It advances over
    /// time within a single boot (live: `0xa58fe5d5` on two back-to-back reads, then `0xa58fa5d5`
    /// seconds later) and differs across boots (`0xa58fa5d1` on a prior boot) — the high half
    /// (`0xa58f`) is stable, the low half advances. NOT a cryptographic nonce (predictable, not
    /// session-bound), and the DLL only writes it to a debug log — not consumed in any handshake.
    pub nvinfo: u32,
    /// The full reply, for fields not yet named.
    pub payload: Vec<u8>,
}

impl ResetInfo {
    /// Minimum payload: through the `nvinfo` word at 0x12 (22 bytes; 0x18 incl. status).
    const MIN_LEN: usize = 0x16;
    /// Offset of the "reset nvinfo" word within the payload.
    const NVINFO_OFFSET: usize = 0x12;

    pub fn parse(p: &[u8]) -> Result<ResetInfo> {
        let mut c = Cursor::new_for(Opcode::InitStep.byte(), p);
        c.require(Self::MIN_LEN)?;
        let start_type = c.read_u8()?;
        let reset_type = c.read_u8()?;
        let start_status = c.read_u16_le()?;
        let info = c.read_u16_le()?;
        c.skip(Self::NVINFO_OFFSET - c.offset())?; // gap between `info` and the nvinfo word
        let nvinfo = c.read_u32_le()?;
        Ok(ResetInfo {
            start_type,
            reset_type,
            start_status,
            info,
            nvinfo,
            payload: p.to_vec(),
        })
    }
}

/// `0x75` sensor identify — the runtime silicon/ASIC type (one of the two identity axes; drives the
/// generic geometry/calibration table). ghidra: `syna_cmd_75_get_sensor_id@0x18008c1a0`, a bare
/// 1-byte command. Answers even in ROM mode. Live 009b reply `00 00 00 00 4b 00 90 01`.
#[derive(Debug, Clone)]
pub struct SensorId {
    /// `[0..4]` — reserved / zero on 009b.
    pub reserved: u32,
    /// `[4..6]` — silicon type minor (live: `0x004b`).
    pub minor: u16,
    /// `[6..8]` — silicon type major (live: `0x0190`).
    pub major: u16,
}

impl SensorId {
    /// Minimum payload: reserved word + minor + major (8 bytes; 10 incl. status).
    const MIN_LEN: usize = 8;

    pub fn parse(p: &[u8]) -> Result<SensorId> {
        let mut c = Cursor::new_for(Opcode::GetSensorId.byte(), p);
        c.require(Self::MIN_LEN)?;
        Ok(SensorId {
            reserved: c.read_u32_le()?,
            minor: c.read_u16_le()?,
            major: c.read_u16_le()?,
        })
    }
}

/// Firmware result / status codes (`VCS_RESULT_*`).
///
/// **Provenance / accuracy caveat:** the names *and numeric values* here were recovered from a
/// **later firmware revision** — the `VCSFW_CMD`/`VCS_RESULT` value→name tables in the 6.0.x
/// "niseWrappers/LenovoMis" driver build (`synaWudfBioUsb136.dll` 6.0.41.1136, zoo specimen
/// `rev136`; `docs/protocol/vcsfw-enums.md`). Our baseline `009b` DLL (5.5.11.1086) strips these
/// tables, so the mapping is imported, not observed on-device. Unlike the `VCSFW_CMD` *opcodes*
/// (which are renumbered across firmware generations), the result-code space appears **shared**:
/// the two codes we *have* observed on `009b` — `0x192`/`0x193` from the polled `0x51` loop — match
/// `IMGPROC_IN_PROGRESS`/`IMGPROC_FINGER_SETTLED` exactly. **Still: if a `009b` (or other) device
/// returns a status these names don't explain, treat this table as possibly-inaccurate for that
/// generation and re-verify against a capture before trusting it.**
///
/// Layout: base-100 groups — `Ok=0`, GEN=100, SENSOR=200, MATCHER=300, IMGPROC=400, DB=500, SYS=600,
/// VRC=700 — codes increment by 1 within a group. Decoded from the `[code:u64][name_ptr:u64]` table
/// at `0x1801e6a80` (rev136).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum VcsResult {
    Ok = 0,
    // --- GEN (100) ---
    GenBase = 100,
    GenCoreNotInitialized = 101,
    GenBusy = 102,
    GenOperationCanceled = 103,
    GenOperationDenied = 104,
    GenAlreadyEnrolled = 105,
    GenAuthenticationRequired = 106,
    GenNoMatch = 107,
    GenFingerNotEnrolled = 108,
    GenSignatureVerificationFailed = 109,
    GenInvalid = 110,
    GenBadParam = 111,
    GenNullPointer = 112,
    GenNotImplemented = 113,
    GenUnexpectedFormat = 114,
    GenNoMoreEntries = 115,
    GenBufferTooSmall = 116,
    GenTimeout = 117,
    GenObjectDoesntExist = 118,
    GenError = 119,
    // --- SENSOR (200) ---
    SensorBase = 200,
    SensorReset = 201,
    SensorMalfunctioned = 202,
    SensorUnavailable = 203,
    SensorNeedToResetOwner = 204,
    SensorInAutonomousMode = 205,
    SensorNotReadyForUse = 206,
    SensorOutOfOtpOwnership = 207,
    SensorFwExtProgramFailed = 208,
    SensorBadCmd = 209,
    SensorDrvOpenFailed = 210,
    SensorTlsInternalFailure = 211,
    SensorPartitionNotOpened = 212,
    SensorPartitionIsFull = 213,
    SensorCalibrationFail = 214,
    SensorCalibrationRetry = 215,
    SensorInvalidBaseline = 216,
    SensorCaptureReset = 217,
    SensorFrameNotReady = 218,
    // --- MATCHER (300) ---
    MatcherBase = 300,
    MatcherOpenFailed = 301,
    MatcherMatchFailed = 302,
    MatcherExtractFailed = 303,
    MatcherEnrollFailed = 304,
    MatcherAddImageFailed = 305,
    MatcherFpAreaImageDiscarded = 306,
    MatcherSetParameterFailed = 307,
    MatcherCloseFailed = 308,
    // --- IMGPROC (400) ---
    ImgprocBase = 400,
    ImgprocComplete = 401,
    ImgprocInProgress = 402,       // observed on 009b as 0x192 (polled 0x51 loop)
    ImgprocFingerSettled = 403,    // observed on 009b as 0x193 (polled 0x51 loop)
    ImgprocNoImageCaptured = 404,
    ImgprocFingerRemoved = 405,
    ImgprocFingerOnSensor = 406,
    ImgprocFingerDetected = 407,
    ImgprocAcquisitionNoImage = 408,
    // --- DB (500) ---
    DbBase = 500,
    DbFull = 501,
    DbEmpty = 502,
    // --- SYS (600) ---
    SysBase = 600,
    SysCallFailed = 601,
    SysOutOfMemory = 602,
    SysFileOpenFailed = 603,
    SysFileWriteFailed = 604,
    SysFileReadFailed = 605,
    // --- VRC (700) ---
    VrcBase = 700,
    VrcInvalidOpId = 701,
    VrcBuferToBig = 702, // (sic — vendor spelling)
    VrcInvalidParam = 703,
}

impl VcsResult {
    /// The raw u16 status code.
    pub fn code(self) -> u16 {
        self as u16
    }

    /// Map a raw status code back to a [`VcsResult`]. `None` for codes outside the imported table
    /// (which — per the caveat above — may simply mean this firmware revision uses a code we haven't
    /// seen; do not treat `None` as "invalid on the wire").
    pub fn from_code(c: u16) -> Option<VcsResult> {
        use VcsResult::*;
        Some(match c {
            0 => Ok,
            100 => GenBase, 101 => GenCoreNotInitialized, 102 => GenBusy, 103 => GenOperationCanceled,
            104 => GenOperationDenied, 105 => GenAlreadyEnrolled, 106 => GenAuthenticationRequired,
            107 => GenNoMatch, 108 => GenFingerNotEnrolled, 109 => GenSignatureVerificationFailed,
            110 => GenInvalid, 111 => GenBadParam, 112 => GenNullPointer, 113 => GenNotImplemented,
            114 => GenUnexpectedFormat, 115 => GenNoMoreEntries, 116 => GenBufferTooSmall,
            117 => GenTimeout, 118 => GenObjectDoesntExist, 119 => GenError,
            200 => SensorBase, 201 => SensorReset, 202 => SensorMalfunctioned, 203 => SensorUnavailable,
            204 => SensorNeedToResetOwner, 205 => SensorInAutonomousMode, 206 => SensorNotReadyForUse,
            207 => SensorOutOfOtpOwnership, 208 => SensorFwExtProgramFailed, 209 => SensorBadCmd,
            210 => SensorDrvOpenFailed, 211 => SensorTlsInternalFailure, 212 => SensorPartitionNotOpened,
            213 => SensorPartitionIsFull, 214 => SensorCalibrationFail, 215 => SensorCalibrationRetry,
            216 => SensorInvalidBaseline, 217 => SensorCaptureReset, 218 => SensorFrameNotReady,
            300 => MatcherBase, 301 => MatcherOpenFailed, 302 => MatcherMatchFailed,
            303 => MatcherExtractFailed, 304 => MatcherEnrollFailed, 305 => MatcherAddImageFailed,
            306 => MatcherFpAreaImageDiscarded, 307 => MatcherSetParameterFailed, 308 => MatcherCloseFailed,
            400 => ImgprocBase, 401 => ImgprocComplete, 402 => ImgprocInProgress, 403 => ImgprocFingerSettled,
            404 => ImgprocNoImageCaptured, 405 => ImgprocFingerRemoved, 406 => ImgprocFingerOnSensor,
            407 => ImgprocFingerDetected, 408 => ImgprocAcquisitionNoImage,
            500 => DbBase, 501 => DbFull, 502 => DbEmpty,
            600 => SysBase, 601 => SysCallFailed, 602 => SysOutOfMemory, 603 => SysFileOpenFailed,
            604 => SysFileWriteFailed, 605 => SysFileReadFailed,
            700 => VrcBase, 701 => VrcInvalidOpId, 702 => VrcBuferToBig, 703 => VrcInvalidParam,
            _ => return None,
        })
    }

    /// Success — the operation completed with no error (`Ok`).
    pub fn is_ok(self) -> bool {
        self == VcsResult::Ok
    }

    /// Benign / retry-or-continue: not a hard failure. The caller should keep polling, retry, or
    /// treat the result as an expected outcome rather than an error. Includes the in-progress /
    /// finger-status codes returned by the polled capture loop.
    pub fn is_benign(self) -> bool {
        use VcsResult::*;
        matches!(
            self,
            Ok | GenBusy
                | GenTimeout
                | GenNoMoreEntries
                | GenNoMatch
                | SensorCalibrationRetry
                | SensorFrameNotReady
                | ImgprocComplete
                | ImgprocInProgress
                | ImgprocFingerSettled
                | ImgprocFingerOnSensor
                | ImgprocFingerDetected
                | ImgprocFingerRemoved
                | ImgprocNoImageCaptured
                | ImgprocAcquisitionNoImage
        )
    }

    /// A hard error — the operation failed and will not succeed by retrying as-is. Defined as
    /// "known code, and neither `Ok` nor benign". (Base markers like `GenBase` are group anchors,
    /// not real statuses, and are treated as non-errors.)
    pub fn is_error(self) -> bool {
        use VcsResult::*;
        let is_base = matches!(
            self,
            GenBase | SensorBase | MatcherBase | ImgprocBase | DbBase | SysBase | VrcBase
        );
        !self.is_ok() && !self.is_benign() && !is_base
    }
}

#[cfg(test)]
mod bringup_parse_tests {
    use super::*;

    #[test]
    fn scs_cmd_index_maps_to_wire_opcode() {
        // Dispatch index != wire opcode. Spot-check the pairs verified against the handler table.
        assert_eq!(ScsCmdIndex::ReadFlash.index(), 0x16);
        assert_eq!(ScsCmdIndex::ReadFlash.wire_opcode(), Some(Opcode::ReadFlash)); // 0x40
        assert_eq!(ScsCmdIndex::MatchFinger.wire_opcode(), Some(Opcode::MatchFinger)); // 0x24→0x5e
        assert_eq!(ScsCmdIndex::GetSiliconId.wire_opcode(), Some(Opcode::GetSensorId)); // 0x35→0x75
        // The 0x1b/0x1e swap the parallel labeling passes got wrong — locked to the table read.
        assert_eq!(ScsCmdIndex::NewRecord.index(), 0x1b);
        assert_eq!(ScsCmdIndex::NewRecord.wire_opcode(), Some(Opcode::NewRecord)); // 0x47
        assert_eq!(ScsCmdIndex::GetRecordValue.index(), 0x1e);
        assert_eq!(
            ScsCmdIndex::GetRecordValue.wire_opcode(),
            Some(Opcode::GetRecordValue) // 0x49
        );
        // Stubs / not-yet-resolved indices report no wire opcode.
        assert_eq!(ScsCmdIndex::Cmd0x0d.wire_opcode(), None);
        assert_eq!(ScsCmdIndex::ReadCaptureState.wire_opcode(), None);
        // Every resolved opcode must itself round-trip through Opcode::from_byte.
        for idx in [
            ScsCmdIndex::RebootSensor,
            ScsCmdIndex::EnrollAppend,
            ScsCmdIndex::CaptureFinalizeOp52,
        ] {
            let op = idx.wire_opcode().unwrap();
            assert_eq!(Opcode::from_byte(op.byte()), Some(op));
        }
    }

    #[test]
    fn sensor_status_offsets() {
        // 0x24-byte payload with markers at the RE'd offsets.
        let mut p = vec![0u8; 0x24];
        p[0x0a] = 1; // valid
        p[0x0b] = 0x33; // device id (009b product)
        p[0x08] = 0xaa;
        p[0x09] = 0xbb;
        p[0x0f] = 0xcc;
        p[0x17] = 0x40; // bit6 set -> format_mode false; bit1 clear -> flag_274 true
        let s = SensorStatus::parse(&p).unwrap();
        assert!(s.valid);
        assert_eq!(s.device_id, 0x33);
        assert_eq!((s.key_08, s.key_09, s.key_0f), (0xaa, 0xbb, 0xcc));
        assert!(!s.format_mode);
        assert!(s.flag_274);
    }

    #[test]
    fn fw_info_modules() {
        // header major=1 minor=2 modcnt=2 buildtime=0x5a748cc2, then 2 modules.
        let mut p = vec![0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0xc2, 0x8c, 0x74, 0x5a];
        // module 0: type=1 subtype=0x3446 major=2 minor=7 size=0x3ed0
        p.extend_from_slice(&[0x01, 0, 0x46, 0x34, 0x02, 0, 0x07, 0, 0xd0, 0x3e, 0, 0]);
        // module 1: type=2 subtype=0x8428 major=3 minor=0x12 size=0x10e0
        p.extend_from_slice(&[0x02, 0, 0x28, 0x84, 0x03, 0, 0x12, 0, 0xe0, 0x10, 0, 0]);
        let fw = FwInfo::parse(&p).unwrap();
        assert_eq!((fw.major, fw.minor, fw.buildtime), (1, 2, 0x5a748cc2));
        assert_eq!(fw.modules.len(), 2);
        assert_eq!(fw.modules[0].subtype, 0x3446);
        assert_eq!(fw.modules[1].size, 0x10e0);
    }

    #[test]
    fn reset_info_live_009b() {
        // Live 0x19 reply from 06cb:009b (post-reboot).
        let p = [
            0x02u8, 0x00, 0x21, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xd5, 0xe5, 0x8f, 0xa5, 0x01, 0x00,
        ];
        let r = ResetInfo::parse(&p).unwrap();
        assert_eq!((r.start_type, r.reset_type), (2, 0));
        assert_eq!((r.start_status, r.info), (0x0021, 0x0110));
        assert_eq!(r.nvinfo, 0xa58f_e5d5); // per-boot value
    }

    #[test]
    fn capture_kat_probe_009b() {
        // Byte-exact replies transcribed from captures/probe-009b.txt (live 06cb:009b), fed through
        // the same decode path decode_capture uses — guards the capture-decoder against drift.

        // 0x01 RomInfo reply (38B incl. 2B status). Strip status like Response::parse does.
        let rom01 = [
            0x00u8, 0x00, 0x10, 0xb6, 0x04, 0x54, 0x9a, 0x00, 0x00, 0x00, 0x06, 0x14, 0x01, 0x33,
            0x00, 0x01, 0x00, 0x00, 0x3a, 0x75, 0xc8, 0xc8, 0x41, 0xf6, 0x00, 0x21, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
        ];
        let r = Response::parse(0x01, &rom01).unwrap();
        assert!(r.status.is_ok());
        let ri = RomInfo::parse(&r.payload).unwrap();
        assert_eq!(
            (ri.build, ri.major, ri.minor, ri.product),
            (154, 6, 20, 0x33)
        );
        assert_eq!(ri.timestamp, 0x5404_b610);
        let ss = SensorStatus::parse(&r.payload).unwrap();
        assert_eq!(ss.device_id, 0x33);
        assert_eq!(ss.flags17, 0x21);
        assert!(ss.valid);

        // 0x4302 get_fw_info reply: status 0x04af (no such partition).
        let fw = Response::parse(0x43, &[0xaf, 0x04]).unwrap();
        assert_eq!(fw.status.wire(), 0x04af);
        assert_eq!(fw.status.name(), "NoSuchPartition");

        // 0x3e get_flash_info reply (16B): ff:ff JEDEC, 0 partitions (ROM state).
        let fl = [
            0x00u8, 0x00, 0xff, 0x00, 0xff, 0x00, 0x00, 0x10, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00,
        ];
        let f = Response::parse(0x3e, &fl).unwrap();
        let fi = FlashInfo::parse(&f.payload).unwrap();
        assert_eq!(fi.jedec, (0x00ff, 0x00ff));
        assert_eq!(fi.blocks, 0x1000);
        assert!(fi.partitions.is_empty());
    }

    #[test]
    fn opcode_from_byte_roundtrips() {
        for op in [
            Opcode::GetRomInfo,
            Opcode::SendDataBlob,
            Opcode::InitStep,
            Opcode::GetFwInfo,
            Opcode::GetFlashInfo,
            Opcode::PartitionFlash,
            Opcode::GetSensorId,
            Opcode::MatchFinger,
            Opcode::SimpleAction,
        ] {
            assert_eq!(Opcode::from_byte(op.byte()), Some(op));
        }
        assert_eq!(Opcode::from_byte(0x00), None);
        assert_eq!(Opcode::from_byte(0xff), None);
    }

    #[test]
    fn sensor_id_live_009b() {
        // Live 0x75 reply: silicon major 0x190, minor 0x4b.
        let p = [0x00u8, 0x00, 0x00, 0x00, 0x4b, 0x00, 0x90, 0x01];
        let s = SensorId::parse(&p).unwrap();
        assert_eq!((s.reserved, s.minor, s.major), (0, 0x004b, 0x0190));
    }

    #[test]
    fn vcs_result_observed_009b_poll_codes() {
        // The two status codes we've actually seen on 009b in the polled 0x51 loop.
        assert_eq!(VcsResult::from_code(0x192), Some(VcsResult::ImgprocInProgress));
        assert_eq!(VcsResult::from_code(0x193), Some(VcsResult::ImgprocFingerSettled));
        assert!(VcsResult::ImgprocInProgress.is_benign());
        assert!(VcsResult::ImgprocFingerSettled.is_benign());
        assert_eq!(VcsResult::from_code(0xd8), Some(VcsResult::SensorInvalidBaseline));
        assert!(VcsResult::SensorInvalidBaseline.is_error());
    }

    #[test]
    fn vcs_result_classification() {
        assert!(VcsResult::Ok.is_ok());
        assert!(!VcsResult::Ok.is_error());
        assert!(VcsResult::GenBusy.is_benign());
        assert!(VcsResult::SensorFrameNotReady.is_benign());
        assert!(VcsResult::GenError.is_error());
        assert!(VcsResult::SensorCaptureReset.is_error());
        assert!(VcsResult::MatcherMatchFailed.is_error());
        // Group base markers are anchors, not real statuses → not errors.
        assert!(!VcsResult::SensorBase.is_error());
        assert_eq!(VcsResult::from_code(0x1234), None);
        assert_eq!(VcsResult::SensorCaptureReset.code(), 217);
    }
}
