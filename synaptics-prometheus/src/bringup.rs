//! Profile-aware ROM→TLS bring-up orchestrator.
//!
//! Mirrors `syna_open_init_decide_format@0x18006e830` over the bulk path for both sensor classes:
//! USDK5 (`009b`, [`crate::devices::InitModel::Usdk5Handshake`]) and the older StaticBlob family
//! (`0090/0097/009a/009d`).

use crate::device::{BringupPrefix, RawDevice, RomExitPlan, SendInitReport};
use crate::devices::{InitModel, SensorProfile};
use crate::error::{Error, Result};
use crate::fw_registry::{self, SensorIdentity};
use crate::init;
use crate::pre_arm;
use crate::proto::{FwInfo, SensorStatus};
use crate::transport::Transport;

/// Provision-state nibbles for which `syna_open_init_decide_format` issues the fw-info-partition-2
/// read (`syna_get_provision_state@0x18006da50` returns one of these → the read gate is open). Cold
/// 009b reports state 0 → not in this set → the read never happens → `ctx+0x2d0` stays 0.
const FW_INFO_READ_STATES: [u8; 4] = [3, 5, 7, 8];

/// The single decision "does the DLL issue the pre-TLS fw-info-partition-2 (`0x43 02`) read for this
/// status" — faithful to `syna_open_init_decide_format@0x18006e830`: provisioned
/// (`syna_ctx_get_provisioned == 0`, i.e. `is_provisioned()`) AND the provision-state nibble is one it
/// reads at (`{3,5,7,8}`). Cold 009b reports state 0 → gate closed → the read never happens → the
/// pre-arm is never deduped. Both the pre-TLS seed read ([`crate::session`]'s
/// `seed_upload_context_from_rom_reply`) and [`infer_fw_upload_context`] gate on this one predicate, so
/// "when do we read fw-info-p2" lives in exactly one place.
pub fn fw_info_read_gate_open(status: &SensorStatus) -> bool {
    status.is_provisioned() && FW_INFO_READ_STATES.contains(&status.provision_state())
}

/// Whether `ctx+0x2d0` (`dwFw_info_valid_flag`) upload dedup is active — i.e. the DLL's pre-TLS
/// fw-info-partition-2 read succeeded, so `syna_upload_selected_fw_blob` skips the `0x06` pre-arm
/// uploads (`0x80`/`0x400000`) on every subsequent arm.
///
/// ghidra: `syna_open_init_decide_format@0x18006e830` sets `dwFw_info_valid_flag` **only** inside a
/// three-part gate — the read is issued iff `syna_get_provision_state ∈ {3,5,7,8}` AND
/// `syna_ctx_get_provisioned == 0` (i.e. `is_provisioned()`) AND the partition ptr is null — and even
/// then a benign `0x76`/`0x6d` read status resets it to 0. No post-TLS path ever writes it (read-only
/// via `syna_scs_fw_upload_context@0x180069530`; cleared by reset/close). On our provisioned 009b the
/// **pre-TLS** provision-state nibble is 0 (cold, unpaired — see [`SensorStatus::provision_state`]), so
/// the read is never issued and the flag stays 0 the whole session → the pre-arm re-uploads on every
/// capture arm (matching the pcap). We previously keyed only on `is_provisioned() && fw_p2.is_some()`,
/// which is missing the `provision_state` gate and wrongly deduped the pre-arm — see
/// [`docs/capture/0x51-arm-contract.md`] and the `0x48` reset investigation.
pub fn infer_fw_upload_context(status: &SensorStatus, fw_p2: Option<&FwInfo>) -> bool {
    fw_info_read_gate_open(status) && fw_p2.is_some()
}

/// Everything needed to drive pre-TLS bring-up and seed a [`crate::session::Session`].
#[derive(Debug, Clone)]
pub struct BringUpPlan {
    pub profile: &'static SensorProfile,
    pub identity: SensorIdentity,
    /// Mirrors `ctx+0x2d0` — when true, most `0x06` uploads are deduped (pre-arm/WOF included).
    pub fw_upload_context: bool,
    pub db_info_status: u16,
    pub rom_exit: RomExitPlan,
    pub fw_p2: Option<FwInfo>,
}

impl BringUpPlan {
    /// Build a plan from a bring-up prefix probe (steps 3–6) plus USB profile lookup.
    pub fn from_prefix(
        profile: &'static SensorProfile,
        prefix: &BringupPrefix,
        rom_exit: RomExitPlan,
    ) -> Self {
        let identity = rom_exit.identity.clone();
        Self {
            profile,
            identity,
            fw_upload_context: infer_fw_upload_context(&prefix.status, prefix.fw_p2.as_ref()),
            db_info_status: prefix.db_info_status,
            rom_exit,
            fw_p2: prefix.fw_p2.clone(),
        }
    }
}

/// Probe the sensor and build a bring-up plan. Non-destructive through step 6.
pub fn plan<T: Transport>(dev: &mut RawDevice<T>, vid: u16, pid: u16) -> Result<BringUpPlan> {
    let profile = SensorProfile::for_id(vid, pid).ok_or_else(|| {
        Error::Malformed(format!("USB {vid:04x}:{pid:04x} not in device registry"))
    })?;
    let prefix = dev.bringup_prefix()?;
    let rom_exit = dev.plan_rom_exit()?;
    Ok(BringUpPlan::from_prefix(profile, &prefix, rom_exit))
}

/// ROM-exit module upload outcome for one registry row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RomExitUpload {
    Sent,
    SkippedNoPayload,
}

/// Upload registry ROM-exit modules (steps 8–9): `want=0x4000` then `want=1`.
/// ghidra: `syna_upload_fw_modules_flag4000` + `syna_drive_out_of_rom`.
pub fn upload_rom_exit_modules<T: Transport>(
    dev: &mut RawDevice<T>,
    modules: &[&'static fw_registry::FwModuleRecord],
) -> Result<Vec<RomExitUpload>> {
    let mut outcomes = Vec::new();
    for record in modules {
        let payload = match pre_arm::resolve_payload(record) {
            Some(p) => p,
            None => {
                outcomes.push(RomExitUpload::SkippedNoPayload);
                continue;
            }
        };
        dev.commit()?;
        let resp = dev.send_data_blob(&payload)?;
        if !resp.status.is_ok() {
            return Err(Error::Status {
                opcode: crate::proto::Opcode::SendDataBlob.byte(),
                status: resp.status,
            });
        }
        outcomes.push(RomExitUpload::Sent);
    }
    Ok(outcomes)
}

/// Upload registry ROM-exit modules from a [`BringUpPlan`].
pub fn drive_out_of_rom<T: Transport>(
    dev: &mut RawDevice<T>,
    plan: &BringUpPlan,
) -> Result<Vec<RomExitUpload>> {
    upload_rom_exit_modules(dev, &plan.rom_exit.modules)
}

/// Framed init blob for StaticBlob sensors when registry ROM-exit rows are absent.
pub fn static_init_blob(plan: &BringUpPlan) -> Option<&'static [u8]> {
    if !plan.rom_exit.modules.is_empty() {
        return None;
    }
    match plan.profile.init {
        InitModel::StaticBlob => Some(crate::blobs_9a::INIT_HARDCODED),
        InitModel::Usdk5Handshake => None,
    }
}

pub fn static_clean_slate_blob(plan: &BringUpPlan) -> Option<&'static [u8]> {
    match plan.profile.init {
        InitModel::StaticBlob => Some(crate::blobs_9a::INIT_HARDCODED_CLEAN_SLATE),
        InitModel::Usdk5Handshake => None,
    }
}

/// Pre-TLS bring-up: prefix probe is assumed done; runs ROM-exit uploads + `send_init`.
pub fn run_pre_tls<T: Transport>(
    dev: &mut RawDevice<T>,
    plan: &BringUpPlan,
) -> Result<SendInitReport> {
    if !plan.rom_exit.modules.is_empty() {
        drive_out_of_rom(dev, plan)?;
    }
    let init_blob = static_init_blob(plan);
    let clean_slate = static_clean_slate_blob(plan);
    dev.send_init(init_blob, clean_slate)
}

/// Post-ROM USDK5 work-key handshake (`0x4f` minimal read → WRKP unwrap). No-op for StaticBlob.
pub fn run_post_rom<T: Transport>(dev: &mut RawDevice<T>, plan: &BringUpPlan) -> Result<()> {
    if plan.profile.init != InitModel::Usdk5Handshake {
        return Ok(());
    }
    let _tag7 = init::run_wrkp_handshake(dev)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{SensorStatus, status_flags17};

    /// `provision_state` selects the `status[0x18]` low nibble; `provisioned` sets `status[0x17]` bit1.
    fn status(provisioned: bool, provision_state: u8) -> SensorStatus {
        let mut payload = vec![0u8; 0x24];
        payload[0x18] = provision_state;
        SensorStatus {
            valid: true,
            device_id: 0x33,
            flags17: if provisioned {
                status_flags17::PROVISIONED
            } else {
                0
            },
            flag_274: !provisioned,
            format_mode: false,
            key_08: 6,
            key_09: 0x14,
            key_0f: 0,
            payload,
        }
    }

    #[test]
    fn fw_upload_context_requires_provisioned_state_and_fw_p2() {
        let fw = FwInfo {
            major: 6,
            minor: 20,
            buildtime: 0,
            modules: vec![],
        };
        // Cold 009b: provisioned bit set but provision-state nibble 0 (unpaired) → flag stays 0 even
        // with a fw-info read result, so the pre-arm re-uploads (the `0x48`-reset fix).
        assert!(!infer_fw_upload_context(&status(true, 0), Some(&fw)));
        // Needs all three: provisioned bit, a read-gate provision-state, and a successful read.
        assert!(!infer_fw_upload_context(&status(false, 3), Some(&fw)));
        assert!(!infer_fw_upload_context(&status(true, 3), None));
        assert!(!infer_fw_upload_context(&status(true, 2), Some(&fw))); // state 2 = needs-format
        // A genuinely provisioned sibling (state ∈ {3,5,7,8}, read ok) does dedup.
        for state in [3u8, 5, 7, 8] {
            assert!(infer_fw_upload_context(&status(true, state), Some(&fw)));
        }
        // 6 collapses to 7.
        assert!(infer_fw_upload_context(&status(true, 6), Some(&fw)));
    }
}
