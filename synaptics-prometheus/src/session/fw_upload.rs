//! `Session` firmware-module upload + identity: the dedup-gated `0x06` module upload core, the
//! WANT-flag variants (pre-arm / DB-prefix / WoF), and cached ROM identity. Split out of the session
//! impl as a separate inherent-impl block on `Session<T>`.

use super::Session;
use crate::error::{Error, Result, Status};
use crate::fw_registry::{self, SensorIdentity};
use crate::pre_arm::{self, PreArmMode, PreArmOutcome};
use crate::proto::{Opcode, SensorStatus};
use crate::transport::Transport;

impl<T: Transport> Session<T> {
    pub fn sensor_identity(&mut self) -> Result<SensorIdentity> {
        if let Some(id) = self.cached_identity.clone() {
            return Ok(id);
        }
        let reply = self.tunnel(&[Opcode::GetRomInfo.byte()])?;
        let status = SensorStatus::parse(&reply[2..])?;
        let mut id = SensorIdentity::from_status(&status);
        id.subtype = None;
        self.cached_identity = Some(id.clone());
        Ok(id)
    }

    /// Shared fw-module upload core (`syna_upload_selected_fw_blob` → `syna_commit_then_send_unlock`):
    /// dedup gate, identity-keyed record select, then probe-DB `0x45` + `0x06 ‖ body`. Returns the
    /// outcome. `select` picks the record for `want_flags`. Does NOT mutate `fw_upload_context` — that
    /// dedup flag (`ctx+0x2d0`) is seed-time-immutable; see the note at the send site.
    pub(crate) fn upload_fw_module(
        &mut self,
        want_flags: fw_registry::FwWantFlags,
        select: impl FnOnce(&fw_registry::SensorIdentity) -> Option<&'static fw_registry::FwModuleRecord>,
    ) -> Result<PreArmOutcome> {
        // `syna_upload_selected_fw_blob` skips a repeat upload on a provisioned sensor unless the
        // want-flag is dedup-exempt (`ctx+0x2d0` / `UPLOAD_DEDUP_EXEMPT`).
        if pre_arm::would_dedup(want_flags, self.fw_upload_context) {
            return Ok(PreArmOutcome::SkippedDedup);
        }
        let id = self.sensor_identity()?;
        // No record for this identity/want ⇒ genuinely not required for this query — skip cleanly.
        let record = match select(&id) {
            Some(r) => r,
            None => return Ok(PreArmOutcome::SkippedNoModule),
        };
        // A record EXISTS ⇒ the sensor firmware expects this pre-arm module. If its bytes are missing
        // this is a hard error, NOT "not required": silently skipping it leaves the sensor un-primed
        // and the next arm (e.g. the `0x48` identify arm) hardware-faults. (This masked task #29 for a
        // week — the worktree lacked `data/fw_modules/`, so the pre-arm was a no-op.)
        let payload = pre_arm::resolve_payload(record).ok_or_else(|| Error::Malformed(format!(
            "required pre-arm fw module missing (want={want_flags:?}, src_addr={:#x}, len={}): expected \
             data/fw_modules/fwmod_{:016x}.bin (cwd-relative) or SYNA_PREARM_MODULE=<file>",
            record.src_addr, record.len, record.src_addr
        )))?;
        // Mirror `syna_commit_then_send_unlock`: probe DB, then `0x06 ‖ body`.
        let _ = self.tunnel(&[Opcode::DbInfo.byte()]);
        let cmd = pre_arm::build_upload_cmd(&payload);
        let status = Self::status_of(&self.tunnel(&cmd)?);
        if !pre_arm::upload_status_is_success(status) {
            return Err(Error::Status {
                opcode: Opcode::SendDataBlob.byte(),
                status: Status::from_wire(status),
            });
        }
        // Do NOT set `fw_upload_context` here: `syna_upload_selected_fw_blob@0x180068c00` reads
        // `ctx+0x2d0` (`syna_scs_fw_upload_context`) but never writes it on a send — it only sets the
        // caller's "was-sent" out-param. `ctx+0x2d0` is decided once, pre-TLS, in
        // `syna_open_init_decide_format` and cleared only by reset/close. Setting it true after the
        // first upload wrongly deduped every later pre-arm (the `0x48` identify-arm reset): on our
        // 009b the DLL re-uploads the pre-arm on *every* arm because the flag stays 0 all session.
        Ok(PreArmOutcome::Sent)
    }

    /// Generic fw-module upload for any traced `want_flags` literal.
    /// ghidra: `syna_upload_selected_fw_blob@0x180068c00` → `syna_rom_exit_send_config`.
    pub fn upload_for_want(
        &mut self,
        want_flags: fw_registry::FwWantFlags,
        param4: u32,
        deny_flags: fw_registry::FwWantFlags,
    ) -> Result<PreArmOutcome> {
        self.upload_fw_module(want_flags, |id| {
            fw_registry::select(fw_registry::REGISTRY, id, want_flags, deny_flags, param4)
        })
    }

    /// DB-prefix module upload (`want=8`) — `syna_upload_fw_module_flag8@0x180068430`.
    pub fn upload_db_prefix(&mut self) -> Result<PreArmOutcome> {
        self.upload_for_want(fw_registry::FwWantFlags::DB_PREFIX, 0, fw_registry::FwWantFlags::empty())
    }

    /// Pre-capture ROM-config poke (`syna_capture_send_pre_arm_rom_config*` → `0x06` upload).
    /// May no-op when deduped, unmatched, or payload bytes are unavailable — all return `Ok`.
    pub fn send_pre_arm_rom_config(&mut self, mode: PreArmMode) -> Result<PreArmOutcome> {
        let want = mode.want_flags();
        self.upload_fw_module(want, |id| {
            fw_registry::select_pre_arm(fw_registry::REGISTRY, id, want)
        })
    }

    /// Upload the WOF wake firmware module (`want_flags=0x800000`) — `syna_upload_fw_module_flag800000`,
    /// which the WOF-arm path (`syna_vfm_scm_wof_arm_disarm`) runs before the `0x76` record. Identity-keyed,
    /// so it works across the device family. No-op (`Ok`) when deduped, unmatched, or the module bytes
    /// aren't available locally (`data/fw_modules/`).
    pub fn upload_wof_module(&mut self) -> Result<PreArmOutcome> {
        self.upload_fw_module(fw_registry::FwWantFlags::WOF, |id| {
            fw_registry::select_wof_module(fw_registry::REGISTRY, id)
        })
    }

}
