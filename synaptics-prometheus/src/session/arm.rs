//! `Session` wake-on-finger (WoF) + capture-arm methods: the DLL arm sequence, interrupt drain, the
//! WoF setup/params preamble, and the finger-presence capability row. Split out of the session impl (submodule `arm`)
//! as a separate inherent-impl block on `Session<T>`.

use super::Session;
use super::{DRAIN_MS, INTR_MAX};
use crate::capture::{wof, CaptureIo};
use crate::capture_prog::CaptureConfig;
use crate::error::Result;
use crate::pre_arm::PreArmMode;
use crate::presence_caps::SensorPresenceCaps;
use crate::proto::Opcode;
use crate::transport::Transport;
use crate::wake_flex::{self, WofDeviceClass};

impl<T: Transport> Session<T> {
    /// Test helper: force the `ctx+0x2d0` fw-upload-context dedup flag. Mirrors what the DLL seeds
    /// pre-TLS (`syna_scs_fw_upload_context`); provisioned 009b keeps this 0 so the pre-arm re-uploads.
    /// Used by the `prearm_dll_seq` probe to reproduce the DLL's "upload the pre-arm every session".
    pub fn set_fw_upload_context(&mut self, v: bool) {
        self.fw_upload_context = v;
    }

    /// Current `ctx+0x2d0` fw-upload dedup flag. On a cold, provisioned 009b this stays `false` the
    /// whole session (see [`crate::bringup::infer_fw_upload_context`]), so the pre-arm re-uploads on
    /// every arm. Exposed for the pre-arm/arm HW test's dedup-state assertion.
    #[must_use]
    pub fn fw_upload_context(&self) -> bool {
        self.fw_upload_context
    }

    pub fn arm_polled_capture(&mut self, arm_cmd: &[u8], pre_arm: Option<PreArmMode>) -> Result<u16> {
        // Order: **stop → pre-arm → arm**, matching the DLL's cross-capture order — the capture-context
        // teardown (which stops) precedes the next `syna_capture_identify_enroll` (pre-arm → arm). The
        // pre-arm `0x06` is a once-per-TLS-session step (the sensor accepts the module once; re-sending
        // → `0x04aa` idle / reset while armed — verified `examples/prearm_lifetime`), so the *caller*
        // (`CaptureSession`) passes `Some(_)` only on the first arm and `None` on every re-arm. It's
        // sent ONLY on the identify/enroll/read-dispatch path (`@0x180053400`), never
        // `syna_lib_calibration_step`; `None` (calibration/stream frames-sync, and all re-arms) skips it.
        CaptureIo::stop(self)?;
        // E1 probe: pv's older-family `capture()` (sensor.py:695) sends NO `0x06` pre-arm before the
        // identify arm — only the 0x2449 DLL does. SYNA_NO_PREARM suppresses it to test whether the
        // Mode2 pre-arm + folded recon is what faults the 0x0199 die.
        let skip_prearm = std::env::var_os("SYNA_NO_PREARM").is_some();
        if let Some(pre_arm) = pre_arm.filter(|_| !skip_prearm) {
            let outcome = self.send_pre_arm_rom_config(pre_arm)?;
            log::info!(target: "syna::cmd", "pre-arm {pre_arm:?} → {outcome:?}");
        }
        let status = self.arm(arm_cmd)?;
        Ok(status)
    }

    /// Take the recon-config (`tag 0x30000288`) captured from the most recent `0x02` capture arm, if
    /// the sensor returned one. recon=8 imaging arms carry it (`upload_cmd_image_with_cal`); identify
    /// arms do not. Cleared on read — the host analogue of the DLL's `ctx+0x88` windsor view. It feeds
    /// matcher reconstruction; the recon=8 capture read itself only re-strides the flat body.
    pub fn take_recon_config(&mut self) -> Option<crate::capture_prog::windsor::WindsorReconConfig> {
        self.last_recon_config.take()
    }

    /// Borrow the most recent arm's recon-config without consuming it.
    #[must_use]
    pub fn recon_config(&self) -> Option<&crate::capture_prog::windsor::WindsorReconConfig> {
        self.last_recon_config.as_ref()
    }

    /// Drain any pending interrupt packets (best-effort; used by stop / cancel_transfer).
    pub(crate) fn drain_interrupts(&mut self) {
        for _ in 0..4 {
            match self.transport.read_interrupt(INTR_MAX, DRAIN_MS) {
                Ok(b) if !b.is_empty() => {}
                _ => break,
            }
        }
    }

    /// WOF preamble shared by arm/disarm (`syna_vfm_scm_wof_arm_disarm`): `cfg57(0)` → probe-DB `0x45` →
    /// optional `0x800000` fw-module upload → per-class AFE writes (`0x08`).
    pub(crate) fn wof_setup(&mut self, class: WofDeviceClass) -> Result<()> {
        self.tunnel(&wof::cfg57_command(0))?;
        self.tunnel(&[Opcode::DbInfo.byte()])?;
        let _ = self.upload_wof_module()?;
        for &(addr, val) in wake_flex::afe_writes_for_class(class) {
            self.tunnel(&wof::hw_reg_write_command(addr, val))?;
        }
        Ok(())
    }

    /// Resolve WOF device class and flex wake tail from cached ROM identity (no extra wire probes).
    ///
    /// Falls back to `0x2449` class-3 when identity is not cached (unit tests / pre-bootstrap).
    pub(crate) fn wof_params(&mut self) -> Result<(WofDeviceClass, &'static [u8])> {
        let (subtype, st8, st9) = if let Some(id) = &self.cached_identity {
            let subtype = id.subtype.unwrap_or(0x2449) as u16;
            (subtype, id.id8 as u16, id.id9 as u16)
        } else {
            (0x2449, 6, 0x14)
        };
        let class = if subtype == 0x2449 {
            WofDeviceClass::Class3
        } else {
            WofDeviceClass::from_silicon(st8, st9, subtype)
        };
        Ok((class, wake_flex::wake_flex_block(subtype)))
    }

    /// Finger-presence capability row for the connected sensor (cached identity + silicon).
    pub fn presence_caps(&mut self) -> Result<SensorPresenceCaps> {
        let (major, minor, st8, st9) = self.probe_silicon()?;
        let mut id = self.sensor_identity()?;
        let subtype = id
            .subtype
            .map(|s| s as u16)
            .or_else(|| CaptureConfig::for_silicon(major, minor, st8, st9).map(|c| c.subtype))
            .unwrap_or(0x2449);
        id.subtype = Some(subtype as u32);
        Ok(SensorPresenceCaps::for_identity(&id, subtype, st8, st9))
    }
}
