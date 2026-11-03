//! Error types.

use thiserror::Error;

/// A vendor **wire status word** (first 2 bytes of a command response), decoded to a descriptive
/// variant at the parse boundary so consumers `match`/print the meaning rather than a bare `u16`.
///
/// This is the `0x04xx`/`0x00xx`-band **command-response** status (mapped from
/// `syna_wire_status_to_code@0x180087610`), which is a **different space** from the firmware program
/// result [`crate`]-external `VcsResult` enum (base-100; the `0x51`-poll / imgproc status). Don't
/// conflate them. Unrecognised codes are preserved as [`Status::Unknown`] — never dropped — so a
/// device/firmware-revision we haven't fully mapped still round-trips its raw code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,                        // 0x0000
    AlreadyInState,            // 0x0401
    ModuleAlreadyLoaded,       // 0x0411
    Error0x66,                 // 0x0402
    RejectedUninitialized,     // 0x0404
    NoProgram,                 // 0x0405
    OkInternal,                // 0x0412 (reported "Ok"; distinct wire code)
    OkType1,                   // 0x05cc (type-1 sibling of 0x05cb; also maps to internal 0)
    CaptureAlreadyArmed,       // 0x0450
    SignatureValidationFailed, // 0x044f
    NothingToCommit,           // 0x0491
    NoSuchPartition,           // 0x04af
    NoFirmware,                // 0x04b0
    Db2Unavailable,            // 0x04b2
    NotFound,                  // 0x04b3
    Error0x1f5,                // 0x04b5
    InitBlobRejected,          // 0x04be
    UnexpectedStatus,          // 0x04cb
    CaptureFaultRetry,         // 0x00c9
    CaptureFaultRetryB,        // 0x00ca
    /// A wire code not in [`STATUS_TABLE`] — raw value preserved verbatim.
    Unknown(u16),
}

/// `(variant, wire code, symbolic name, human label)` for every status we recognise — the single
/// source of truth for [`Status::from_wire`]/[`Status::wire`]/[`Status::name`]/[`Status::label`]
/// (adding a status = one row). Wire→internal-code map from `syna_wire_status_to_code@0x180087610`.
const STATUS_TABLE: &[(Status, u16, &str, &str)] = &[
    (Status::Ok, 0x0000, "Ok", "ok"),
    (
        Status::AlreadyInState,
        0x0401,
        "AlreadyInState",
        "already in requested state (benign; internal 0xd1 AlreadyInState)",
    ),
    (
        Status::ModuleAlreadyLoaded,
        0x0411,
        "ModuleAlreadyLoaded",
        "fw-module upload redundant — config already active (benign for pre-arm dedup; WIRE-CONFIRM)",
    ),
    (Status::Error0x66, 0x0402, "Error0x66", "error (internal 0x66)"),
    (
        Status::RejectedUninitialized,
        0x0404,
        "RejectedUninitialized",
        "rejected: sensor uninitialized / hw-register op in ROM (internal 0x68)",
    ),
    (
        Status::NoProgram,
        0x0405,
        "NoProgram",
        "no program running (0x51 get_prg_status in ROM; tentative)",
    ),
    (Status::OkInternal, 0x0412, "Ok", "ok (internal 0)"),
    (
        Status::CaptureAlreadyArmed,
        0x0450,
        "CaptureAlreadyArmed",
        "capture already armed / malformed 0x02 (only the session's first 0x02 is accepted; internal 0x66)",
    ),
    (
        Status::SignatureValidationFailed,
        0x044f,
        "SignatureValidationFailed",
        "signature/MAC validation failed (internal 0x6d)",
    ),
    (
        Status::NothingToCommit,
        0x0491,
        "NothingToCommit",
        "nothing to commit (treated as success)",
    ),
    (
        Status::NoSuchPartition,
        0x04af,
        "NoSuchPartition",
        "no such partition (internal 0xcc generic-failure)",
    ),
    (Status::NoFirmware, 0x04b0, "NoFirmware", "no firmware (internal 0x76)"),
    (
        Status::Db2Unavailable,
        0x04b2,
        "Db2Unavailable",
        "DB2 unavailable: template storage unreachable — SPI flash controller dark / DB2 not provisioned this session (unmapped -> internal 0xca). Gates 0x45/0x46/0x4a/0x4b and match 0x5e/0x60",
    ),
    (Status::NotFound, 0x04b3, "NotFound", "not found (internal 0x76)"),
    (Status::Error0x1f5, 0x04b5, "Error0x1f5", "error (internal 0x1f5)"),
    (
        Status::InitBlobRejected,
        0x04be,
        "InitBlobRejected",
        "init blob rejected (wrong device class; unmapped -> internal 0xca)",
    ),
    (
        Status::UnexpectedStatus,
        0x04cb,
        "UnexpectedStatus",
        "unrecognized sensor status (unmapped -> internal 0xca); observed when a type-2 line-update is sent to a type-1 sensor (the type-1 sibling 0x05cb maps to 0x66)",
    ),
    (
        Status::OkType1,
        0x05cc,
        "Ok",
        "ok (internal 0; type-1 sibling of 0x05cb, which maps to 0x66)",
    ),
    (
        Status::CaptureFaultRetry,
        0x00c9,
        "CaptureFaultRetry",
        "capture fault — DLL reboot+retry band (internal 0xc9)",
    ),
    (
        Status::CaptureFaultRetryB,
        0x00ca,
        "CaptureFaultRetryB",
        "capture fault — DLL reboot+retry band (internal 0xca)",
    ),
];

impl Status {
    pub const OK: Status = Status::Ok;
    /// DLL capture-fault band that triggers `syna_vfm_reboot_sensor_mode0` + retry (match/enroll loops).
    pub const CAPTURE_FAULT_RETRY_LO: u16 = 0x00c9;
    pub const CAPTURE_FAULT_RETRY_HI: u16 = 0x00ca;

    /// Decode a raw 2-byte wire status word into a descriptive [`Status`]. Unknown codes are
    /// preserved as [`Status::Unknown`] (never dropped).
    pub fn from_wire(code: u16) -> Status {
        STATUS_TABLE
            .iter()
            .find(|(_, c, _, _)| *c == code)
            .map_or(Status::Unknown(code), |(s, _, _, _)| *s)
    }

    /// The raw 2-byte wire code. This is the explicit escape hatch for the few call sites that must
    /// compare/return the numeric value; prefer matching the variant.
    pub fn wire(self) -> u16 {
        match self {
            Status::Unknown(c) => c,
            other => STATUS_TABLE
                .iter()
                .find(|(s, _, _, _)| *s == other)
                .map_or(0, |(_, c, _, _)| *c),
        }
    }

    /// True for every wire status the DLL maps to **internal code 0** — i.e. success.
    ///
    /// `syna_wire_status_to_code@0x180087610` returns 0 for four distinct wire words:
    /// `0x0000`, `0x0412`, `0x0491` and `0x05cc`. This previously matched only [`Status::Ok`],
    /// which made a sensor that replied with any of the other three look like a hard error at
    /// [`crate`]-external `Response::ok()` — the sensor considers them success and so must we.
    /// Keep this in step with `capture::polled::frame_status::poll_result`, which maps the same
    /// four wire words to `VcsResult::Ok`.
    pub fn is_ok(self) -> bool {
        matches!(
            self,
            Status::Ok | Status::OkInternal | Status::NothingToCommit | Status::OkType1
        )
    }

    /// True when the DLL would soft-reboot and retry (internal 0xc9..=0xca or stale capture arm).
    pub fn requests_sensor_reboot_retry(self) -> bool {
        matches!(
            self,
            Status::CaptureFaultRetry | Status::CaptureFaultRetryB | Status::CaptureAlreadyArmed
        )
    }
    fn entry(self) -> Option<&'static (Status, u16, &'static str, &'static str)> {
        STATUS_TABLE.iter().find(|(s, _, _, _)| *s == self)
    }
    /// Short symbolic name — the `SynaWireStatus` enum name (docs/protocol/status-codes.md Table B′).
    pub fn name(self) -> &'static str {
        self.entry().map_or("Unknown", |(_, _, name, _)| *name)
    }
    /// A human-readable label for the status codes we recognise, with the internal-code mapping.
    pub fn label(self) -> &'static str {
        self.entry().map_or("unknown", |(_, _, _, label)| *label)
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:04x} {} ({})", self.wire(), self.name(), self.label())
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("USB transport error: {0}")]
    Usb(String),

    #[error("device {vid:04x}:{pid:04x} not found")]
    DeviceNotFound { vid: u16, pid: u16 },

    #[error("no supported Synaptics Prometheus sensor found")]
    NoSupportedDevice,

    /// The device replied but with a non-zero vendor status word.
    #[error("command 0x{opcode:02x} failed: status {status}")]
    Status { opcode: u8, status: Status },

    #[error("short response for command 0x{opcode:02x}: got {got} bytes, need at least {need}")]
    ShortResponse { opcode: u8, got: usize, need: usize },

    #[error("malformed response: {0}")]
    Malformed(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    /// Attempted a state-mutating operation while built read-only (without the
    /// `writes` feature). This is a compile-shaped safety net surfaced at runtime
    /// for the few paths that can't be fully feature-gated.
    #[error("operation '{0}' requires the `writes` feature (read-only build)")]
    ReadOnly(&'static str),

    #[error("feature not yet implemented: {0}")]
    Unimplemented(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Whether bootstrap/match paths should reboot the sensor and retry once (DLL recovery).
    pub fn requests_sensor_reboot_retry(&self) -> bool {
        matches!(self, Error::Status { status, .. } if status.requests_sensor_reboot_retry())
    }
}
