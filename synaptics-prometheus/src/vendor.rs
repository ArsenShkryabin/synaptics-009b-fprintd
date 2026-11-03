//! Reverse-engineered layout of the **Windows vendor driver** (`synaWudfBioUsb.dll`, MSI SecurePad
//! `5.5.11.1086`). This is *not* wire protocol — it documents how the vendor driver decides where
//! templates live and where matching runs, so our driver can mirror those choices or diverge from
//! them deliberately (e.g. TPM-sealed storage, or routing match to the sensor if the firmware
//! supports it). Every offset/address is a `// ghidra:` reference into that DLL.
//!
//! Key finding: on this SKU (`06cb:009b`) the DLL uses **Enroll-on-Host / Match-on-Host**
//! (`CEohMohEIV`). Other family members may use on-chip storage (`storage_mode == 3`).
//! See `docs/bringup/storage-mode-by-sku.md`.

/// The vendor's enroll/identify/verify **storage + match strategy**, chosen once at device init by
/// `syna_eiv_strategy_factory@0x18001cc20` from the discriminant [`EivConfig::storage_mode`]
/// (`CBiometricDevice+0x1cc`).
///
/// NOTE the two axes are independent: this enum is *where templates live / where match runs*; the
/// separate sensor-reported [`crate::proto::status_flags17::HAS_FLASH`] bit only decides, within an
/// on-chip build, whether provisioning persists to SPI flash or stays transient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EivStorageMode {
    /// `storage_mode == 3` → `CEocMocEIV` (Enroll-on-Chip / Match-on-Chip). Present in the binary
    /// but **vestigial** on this SKU — the discriminant is never set to 3.
    /// ghidra: ctor `syna_eiv_ctor_CEocMocEIV_onchip@0x18001eaa0`, vtable `0x18012b380`,
    /// `CEocMocEIV_EnrollmentCreate@0x18001f150`.
    OnChip,
    /// `storage_mode != 3` (default `1`) → `CEohMohEIV` (Enroll-on-Host / Match-on-Host). The
    /// **always-taken** branch here: templates persist in the host WBF `.DAT`, matching runs on the
    /// host QM matcher (`syna_qm_match_all@0x1800a78f0` — pure host compute, no USB).
    /// ghidra: ctor `syna_eiv_ctor_CEohMohEIV_host@0x180021574`, vtable `0x18012b780`,
    /// `CEohMohEIV_EnrollmentCreate@0x180020a30`; default set by `syna_eiv_config_init@0x18001ca54`.
    Host,
}

impl EivStorageMode {
    /// Decode from the raw `storage_mode` discriminant (`eiv_config+0x04`).
    pub fn from_discriminant(v: i32) -> Self {
        if v == 3 { Self::OnChip } else { Self::Host }
    }

    /// True when the vendor driver runs the biometric match on the host CPU (our 009b/SecurePad
    /// case). If we want on-chip matching we must either flip to an `OnChip` build *and* have a
    /// firmware matcher, or port the host matcher — see `examples/onchip_probe.rs`.
    pub fn matches_on_host(self) -> bool {
        matches!(self, Self::Host)
    }
}

/// Mirror of `syna_eiv_config` — the mode-selector struct embedded at `CBiometricDevice+0x1c8`
/// (which the `CBiometricDevice` layout mislabels as `pSessionObj`; it is *not* a pointer — the
/// factory and `syna_eiv_config_init@0x18001ca54` treat `+0x1c8` as an embedded struct whose first
/// int is `1`). We don't parse this off the wire; it's documented for parity. ghidra: struct
/// `syna_eiv_config`.
#[derive(Debug, Clone, Copy)]
pub struct EivConfig {
    /// `+0x00`: init flag (`= 1`); the factory also passes `init_flag == 1` as an init bool.
    pub init_flag: i32,
    /// `+0x04`: storage/match strategy discriminant — see [`EivStorageMode`].
    pub storage_mode: i32,
    /// `+0x18`: on-chip matcher submode (caps-derived).
    /// ghidra: `syna_eiv_set_matcher_submode@0x18001cde4`.
    pub matcher_submode: i32,
}

impl EivConfig {
    pub fn mode(&self) -> EivStorageMode {
        EivStorageMode::from_discriminant(self.storage_mode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminant_mapping() {
        // The vendor default (syna_eiv_config_init writes 1) is Host, and only 3 is OnChip.
        assert_eq!(EivStorageMode::from_discriminant(1), EivStorageMode::Host);
        assert_eq!(EivStorageMode::from_discriminant(3), EivStorageMode::OnChip);
        assert_eq!(EivStorageMode::from_discriminant(0), EivStorageMode::Host);
        assert!(EivStorageMode::from_discriminant(1).matches_on_host());
        assert!(!EivStorageMode::from_discriminant(3).matches_on_host());
    }
}
