//! Pre-capture `0x06` ROM-config upload — `syna_capture_send_pre_arm_rom_config@0x1800685c0` /
//! `syna_capture_send_pre_arm_rom_config_mode2@0x180068800`.
//!
//! Runs before every `syna_capture_read_dispatch` and at identify/enroll start. Mirrors
//! `syna_upload_selected_fw_blob` → `syna_commit_then_send_unlock` (`0x45` probe + `0x06` send).

use std::path::{Path, PathBuf};

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
/// and system directories (`/usr/share/synaptics/fw_modules`, `/usr/lib/firmware/synaptics`).
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

    let stems = [
        format!("fwmod_{:016x}.bin", record.src_addr),
        format!("prearm_{:016x}.bin", record.src_addr),
    ];

    let mut search_dirs = vec![
        Path::new("data").join("fw_modules"),
        Path::new("synaptics-prometheus").join("data").join("fw_modules"),
        Path::new("data").to_path_buf(),
        Path::new("/usr/share/synaptics/fw_modules").to_path_buf(),
        Path::new("/usr/lib/firmware/synaptics").to_path_buf(),
        Path::new("/etc/synaptics/fw_modules").to_path_buf(),
    ];

    if let Ok(env_dir) = std::env::var("SYNA_FW_MODULES_DIR") {
        search_dirs.insert(0, PathBuf::from(env_dir));
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(exe_dir) = exe.parent()
    {
        search_dirs.push(exe_dir.join("../share/synaptics/fw_modules"));
        search_dirs.push(exe_dir.join("data/fw_modules"));
    }

    for dir in &search_dirs {
        for stem in &stems {
            let path = dir.join(stem);
            if let Ok(b) = std::fs::read(&path)
                && b.len() == record.len as usize
            {
                return Some(b);
            }
        }
    }

    // Direct PE .rdata slice fallback if the DLL is accessible on disk.
    for dll_path in [
        Path::new("windows-driver/synaWudfBioUsb.dll"),
        Path::new("/usr/share/synaptics/synaWudfBioUsb.dll"),
        Path::new("/etc/synaptics/synaWudfBioUsb.dll"),
    ] {
        if let Ok(b) = std::fs::read(dll_path)
            && let Ok(slice) = extract_pe_module(&b, record.src_addr, record.len as usize)
        {
            return Some(slice);
        }
    }

    None
}

/// Slice a firmware module from `synaWudfBioUsb.dll` using PE section headers.
fn extract_pe_module(pe_bytes: &[u8], vma: u64, len: usize) -> Result<Vec<u8>, ()> {
    if pe_bytes.len() < 0x200 {
        return Err(());
    }
    let pe_off = u32::from_le_bytes(pe_bytes[0x3c..0x40].try_into().map_err(|_| ())?) as usize;
    if pe_bytes.len() < pe_off + 24 {
        return Err(());
    }
    let num_sections = u16::from_le_bytes(pe_bytes[pe_off + 6..pe_off + 8].try_into().map_err(|_| ())?) as usize;
    let opt_hdr_size = u16::from_le_bytes(pe_bytes[pe_off + 20..pe_off + 22].try_into().map_err(|_| ())?) as usize;
    let image_base = u64::from_le_bytes(pe_bytes[pe_off + 24 + 24..pe_off + 24 + 32].try_into().map_err(|_| ())?);
    if vma < image_base {
        return Err(());
    }
    let rva = (vma - image_base) as u32;
    let sec_start = pe_off + 24 + opt_hdr_size;

    for i in 0..num_sections {
        let off = sec_start + i * 40;
        if pe_bytes.len() < off + 40 {
            break;
        }
        let sec = &pe_bytes[off..off + 40];
        let vsize = u32::from_le_bytes(sec[8..12].try_into().map_err(|_| ())?);
        let vaddr = u32::from_le_bytes(sec[12..16].try_into().map_err(|_| ())?);
        let roff = u32::from_le_bytes(sec[20..24].try_into().map_err(|_| ())?) as usize;
        if rva >= vaddr && rva < vaddr + vsize {
            let file_off = roff + (rva - vaddr) as usize;
            if pe_bytes.len() >= file_off + len {
                return Ok(pe_bytes[file_off..file_off + len].to_vec());
            }
        }
    }
    Err(())
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
