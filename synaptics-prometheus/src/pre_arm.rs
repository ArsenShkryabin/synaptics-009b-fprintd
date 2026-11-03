//! Pre-capture `0x06` ROM-config upload — `syna_capture_send_pre_arm_rom_config@0x1800685c0` /
//! `syna_capture_send_pre_arm_rom_config_mode2@0x180068800`.
//!
//! Runs before every `syna_capture_read_dispatch` and at identify/enroll start. Mirrors
//! `syna_upload_selected_fw_blob` → `syna_commit_then_send_unlock` (`0x45` probe + `0x06` send).

use std::path::Path;

use crate::fw_registry::{self, FwModuleRecord};
use crate::proto::Opcode;

/// Which pre-arm helper the DLL calls (capture type 2 vs everything else on the identify path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreArmMode {
    /// `syna_capture_send_pre_arm_rom_config` — `want_flags=0x80`.
    Standard,
    /// `syna_capture_send_pre_arm_rom_config_mode2` — `want_flags=0x400000`.
    Mode2,
}

impl PreArmMode {
    pub const fn want_flags(self) -> fw_registry::FwWantFlags {
        match self {
            Self::Standard => fw_registry::FwWantFlags::PRE_ARM,
            Self::Mode2 => fw_registry::FwWantFlags::PRE_ARM_MODE2,
        }
    }
}

/// Result of a pre-arm attempt (including intentional no-ops).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreArmOutcome {
    /// `0x06` blob sent successfully.
    Sent,
    /// Skipped because `ctx+0x2d0` upload context is set and `want_flags` is not dedup-exempt.
    SkippedDedup,
    /// No registry row matched this sensor + flags — genuinely not required for this query.
    SkippedNoModule,
    // NOTE: a matched row whose module bytes are absent is NOT a skip — it's a hard
    // `Error::Malformed` (the sensor firmware expects that pre-arm; silently skipping leaves it
    // un-primed and the next arm faults). See `Session::upload_fw_module`.
}

/// Whether the DLL would skip this upload due to upload-context dedup.
pub fn would_dedup(want_flags: fw_registry::FwWantFlags, fw_upload_context: bool) -> bool {
    fw_upload_context && !want_flags.is_always_resend()
}

/// Load module bytes: embedded `record.payload`, then `SYNA_PREARM_MODULE`, then the extracted
/// blob under `data/fw_modules/fwmod_{src_addr:016x}.bin` (the whole firmware-module table dumped from
/// the DLL via the Ghidra `run_script_inline` extractor), falling back to the legacy `prearm_` name
/// and the flat `data/` dir. (`fwmod`, not `prearm`: only ~2 of the ~13 want-flag classes are pre-arm.)
///
/// The `data/` blobs are vendor firmware (gitignored). Length is checked against `record.len` so a
/// truncated/wrong file is rejected rather than sent malformed.
pub fn resolve_payload(record: &FwModuleRecord) -> Option<Vec<u8>> {
    if let Some(p) = record.payload {
        return Some(p.to_vec());
    }
    if let Ok(path) = std::env::var("SYNA_PREARM_MODULE")
        && let Ok(b) = std::fs::read(&path)
    {
        return Some(b);
    }
    // `fwmod_<src_addr>.bin` under `data/fw_modules/` — the extracted firmware-module blob, keyed by
    // its DLL source address. (`fwmod`, not `prearm`: pre-arm is only ~2 of the ~13 want-flag classes
    // these blobs span — see `docs/bringup/fw-wants-flags.md`. The old `prearm_` name is still read as a
    // fallback so un-renamed local blob sets keep resolving.)
    for stem in [
        format!("fwmod_{:016x}.bin", record.src_addr),
        format!("prearm_{:016x}.bin", record.src_addr),
    ] {
        for path in [Path::new("data").join("fw_modules").join(&stem), Path::new("data").join(&stem)] {
            if let Ok(b) = std::fs::read(&path)
                && b.len() == record.len as usize
            {
                return Some(b);
            }
        }
    }
    None
}

/// Build the tunneled `0x06 ‖ payload` command (opcode prepended; payload is raw module body).
pub fn build_upload_cmd(payload: &[u8]) -> Vec<u8> {
    let mut cmd = Vec::with_capacity(1 + payload.len());
    cmd.push(Opcode::SendDataBlob.byte());
    cmd.extend_from_slice(payload);
    cmd
}

/// Status word from a tunneled reply.
pub fn reply_status(reply: &[u8]) -> u16 {
    reply
        .get(..2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0xffff)
}

/// Upload outcomes that mean the module is already present — treat as success.
/// ghidra: `syna_upload_selected_fw_blob` / `syna_commit_then_send_unlock` accept `0x0000`,
/// `0x0401` (AlreadyInState), and live `0x0411` on repeat pre-arm after calibration.
pub fn upload_status_is_success(status: u16) -> bool {
    matches!(status, 0x0000 | 0x0401 | 0x0411 | 0x0412 | 0x0491)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fw_registry::{self, REGISTRY, WILDCARD};

    fn ident(id9: u8, subkey: u32) -> fw_registry::SensorIdentity {
        fw_registry::SensorIdentity {
            id4: WILDCARD,
            id8: 6,
            id9,
            id0a: 1,
            id0f: 0,
            id19: 0,
            subkey,
            subtype: None,
        }
    }

    #[test]
    fn upload_success_includes_benign_repeat_statuses() {
        assert!(upload_status_is_success(0));
        assert!(upload_status_is_success(0x0401));
        assert!(upload_status_is_success(0x0411));
        assert!(!upload_status_is_success(0x0410));
    }

    #[test]
    fn pre_arm_dedup_matches_dll_exempt_list() {
        use fw_registry::FwWantFlags;
        assert!(!would_dedup(FwWantFlags::FLAG4, true));
        assert!(would_dedup(FwWantFlags::PRE_ARM, true));
        assert!(would_dedup(FwWantFlags::PRE_ARM_MODE2, true));
        assert!(!would_dedup(FwWantFlags::DB_PREFIX, true));
    }

    #[test]
    fn resolve_payload_loads_009b_standard_pre_arm_when_extracted() {
        let id = ident(0x14, 3);
        let rec = fw_registry::select_pre_arm(REGISTRY, &id, fw_registry::FwWantFlags::PRE_ARM).unwrap();
        // The blob is only present when the extracted-firmware tree is checked out; when it is
        // absent the registry row is still expected to describe it, so only the length is asserted.
        if let Some(payload) = resolve_payload(rec) {
            assert_eq!(payload.len(), rec.len as usize);
        }
    }

    #[test]
    fn nine_b_selects_pre_arm_via_param4_zero_fallback() {
        let id = ident(0x14, 3);
        let rec = fw_registry::select_pre_arm(REGISTRY, &id, fw_registry::FwWantFlags::PRE_ARM);
        assert!(rec.is_some());
        assert!(rec.unwrap().flags.contains(fw_registry::FwWantFlags::PRE_ARM));
    }
}
