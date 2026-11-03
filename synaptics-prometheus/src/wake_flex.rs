//! Per-subtype WOF wake-record tail bytes and AFE setup for `syna_vfm_scm_wof_arm_disarm@0x18004ed90`.
//!
//! Ground truth: `syna_scs_build_wof_record_class3@0x1800911e0` packs flex `+0x70` into the `0x76`
//! record tail; class-2 vs class-3 AFE writes branch on ROM identity byte at status `+0xb` (`'2'` / `'3'`).

/// Device class for WOF AFE preamble (`syna_vfm_scm_wof_arm_disarm` branches).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WofDeviceClass {
    /// `syna_write_hw_reg_0x08(*, 0x800003a0, 0xf, 4)` only.
    Class2,
    /// Class-3 writes (`0x800003a0` = `0xffffff`, then `0x80000374` = `0x12`).
    Class3,
}

impl WofDeviceClass {
    /// Map prod-3 silicon status byte `st8` and subtype to the DLL's WOF device class.
    ///
    /// `0x2449` (`st8==6`, `st9==0x14`) uses class-3 AFE writes per Ghidra.
    pub fn from_silicon(st8: u16, st9: u16, subtype: u16) -> Self {
        if st8 == 6 && st9 == 0x14 && subtype == 0x2449 {
            Self::Class3
        } else if st8 == 6 && (10 < st9) && (st9 < 0x14) {
            Self::Class2
        } else {
            // Conservative default for unprofiled siblings — extend the table as RE confirms rows.
            Self::Class3
        }
    }
}

/// AFE register writes before the `0x76` wake record (`syna_write_hw_reg_0x08`).
pub fn afe_writes_for_class(class: WofDeviceClass) -> &'static [(u32, u32)] {
    match class {
        WofDeviceClass::Class2 => &[(0x8000_03a0, 0x0000_000f)],
        WofDeviceClass::Class3 => &[
            (0x8000_03a0, 0x00ff_ffff),
            (0x8000_0374, 0x0000_0012),
        ],
    }
}

/// Flex wake tail appended to the class-3 `0x76` record (`wake_size` field).
///
/// `syna_scs_build_wof_record_class3` @0x1800911e0 — only subtype rows extracted so far; others get
/// an empty tail until the flex sub-table is ported.
pub fn wake_flex_block(subtype: u16) -> &'static [u8] {
    match subtype {
        // 0x2449 @ g_flex_params_table row 41 → sub-table @0x180137bd8, var @0x180137316.
        0x2449 => &[0x00, 0x00, 0x00, 0x00, 0xf2, 0x02, 0x01, 0x00],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wake_flex_2449_golden() {
        assert_eq!(
            wake_flex_block(0x2449),
            &[0x00, 0x00, 0x00, 0x00, 0xf2, 0x02, 0x01, 0x00]
        );
    }

    #[test]
    fn class3_afe_writes_match_legacy_constants() {
        assert_eq!(
            afe_writes_for_class(WofDeviceClass::Class3),
            &[(0x8000_03a0, 0x00ff_ffff), (0x8000_0374, 0x0000_0012)]
        );
    }
}
