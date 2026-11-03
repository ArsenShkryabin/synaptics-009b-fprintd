//! Per-sensor finger-presence capabilities — data-driven (Rule #6), keyed by ROM identity + subtype.
//!
//! Sources: `syna_pal_query_device_info@0x18004daa0` (`enrollSession+0x33`), Tudor identify pcap,
//! `wof_probe` on `0x2449`, Ghidra `syna_wbdi_wait_for_finger@0x18001c0a8`.

use crate::fw_registry::{self, SensorIdentity};
use crate::wake_flex::WofDeviceClass;

/// How the DLL (or our port) should detect finger presence for runtime capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerPresenceStrategy {
    /// SCM wake-on-finger only — `syna_vfm_scm_wof_arm_disarm` + `GetWOFStatus` (`CCaptureImage+0xa0 == 1`).
    ScmWof,
    /// Capture program with `FingerDetect(0x26)` + EP-0x83 IRQ (`+0xa0 == 0`, Hello identify/enroll).
    CaptureFingerDetect,
    /// No wait loop — only OR the `capture_start` session-blob hint bit (`| 0x4`).
    CaptureStartWofHint,
}

/// Finger-presence / WOF capability row for one sensor instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensorPresenceCaps {
    /// `enrollSessionState+0x33` bit 0 (`scsSensor==1`) — WOF-capable in vendor caps.
    pub scs_sensor: bool,
    /// Registry provides an `0x800000` WOF wake module for this identity (`select_wof_module`).
    pub wof_module_available: bool,
    /// Type-2 EP-0x83 `FingerDown` on capture finger-detect is spurious (~100 ms post-arm, finger or not).
    pub spurious_type2_irq: bool,
    /// Recommended strategy for Hello-style runtime capture on this unit.
    pub preferred: FingerPresenceStrategy,
    /// AFE preamble class for `syna_vfm_scm_wof_arm_disarm`.
    pub wof_device_class: WofDeviceClass,
}

impl SensorPresenceCaps {
    /// Resolve caps from ROM identity and classified subtype (`ctx+0x128`).
    pub fn for_identity(id: &SensorIdentity, subtype: u16, st8: u16, st9: u16) -> Self {
        let wof_device_class = WofDeviceClass::from_silicon(st8, st9, subtype);
        let wof_module_available =
            fw_registry::select_wof_module(fw_registry::REGISTRY, id).is_some();
        // MSI 009b / subtype 0x2449 — Hello uses capture finger-detect; SCM WOF needs the module.
        if id.id8 == 6 && id.id9 == 0x14 && subtype == 0x2449 {
            return Self {
                scs_sensor: true,
                wof_module_available,
                spurious_type2_irq: true,
                preferred: FingerPresenceStrategy::CaptureFingerDetect,
                wof_device_class,
            };
        }
        // Default: advertise WOF when prod-3 Prometheus; prefer capture IRQ until profiled.
        let scs_sensor = id.id8 == 6;
        Self {
            scs_sensor,
            wof_module_available,
            spurious_type2_irq: false,
            preferred: if scs_sensor {
                FingerPresenceStrategy::CaptureFingerDetect
            } else {
                FingerPresenceStrategy::ScmWof
            },
            wof_device_class,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fw_registry::SensorIdentity;

    fn ident_009b_2449(subkey: u32) -> SensorIdentity {
        SensorIdentity {
            id4: 0,
            id8: 6,
            id9: 0x14,
            id0a: 1,
            id0f: 0,
            id19: 0,
            subkey,
            subtype: Some(0x2449),
        }
    }

    #[test]
    fn nine_b_2449_subkey3_has_wof_module_and_spurious_type2() {
        let id = ident_009b_2449(3);
        let caps = SensorPresenceCaps::for_identity(&id, 0x2449, 6, 0x14);
        assert!(caps.scs_sensor);
        assert!(caps.wof_module_available);
        assert!(caps.spurious_type2_irq);
        assert_eq!(caps.preferred, FingerPresenceStrategy::CaptureFingerDetect);
    }

    #[test]
    fn nine_b_2449_subkey2_wof_module_unavailable() {
        let id = ident_009b_2449(2);
        let caps = SensorPresenceCaps::for_identity(&id, 0x2449, 6, 0x14);
        assert!(caps.scs_sensor);
        assert!(!caps.wof_module_available);
        assert!(caps.spurious_type2_irq);
        assert_eq!(caps.preferred, FingerPresenceStrategy::CaptureFingerDetect);
    }
}
