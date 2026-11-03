//! Device registry + the strategy traits that capture what varies across the
//! Synaptics Prometheus / Validity family.
//!
//! Shared core (transport, proto, crypto, DB) lives in the other modules. Only three
//! things differ per sensor generation, and each is a small trait here:
//!
//! | axis            | older `0090/0097/009a/009d` | USDK5 `009b`             |
//! |-----------------|-----------------------------|--------------------------|
//! | machine binding | DMI product_name+serial     | Windows MachineGuid      |
//! | ROM-exit        | replay static `0x06` blob   | replay static `0x06` blob |
//! | session         | TLS session                 | + post-ROM WRKP/ECDH hs   |
//! | firmware source | separate `.xpfwext` file    | embedded / in-flash       |
//!
//! Note: both families leave ROM by *replaying* a small static `0x06` `init_hardcoded` blob — 009b
//! simply needs its own (its bytes are still being RE'd). The USDK5 ECDH/"WRKP" handshake is a
//! *later, session-layer* step (opcode `0x4f`/tag-7), NOT the ROM-exit unlock — an earlier reading
//! that conflated the two has been corrected (docs/bringup/handshake-reconstruction.md §5).
//!
//! Adding a new sensor = add a [`SensorProfile`] entry (and only a new strategy impl
//! if it is a genuinely new class).

/// Host-side machine binding. **This is a driver convention, not a sensor requirement**
/// — the sensor stores the owner blob opaquely and never checks machine identity itself
/// (see `CeivMode::ValidateDatabase`, docs/bringup/provisioning-state-machine.md). So the binding
/// is ours to choose: match the value Windows used to reuse its pairing, or pick a fresh
/// stable value to re-provision.
pub trait MachineBinding {
    /// The `hw_key` bytes fed into the GWK derivation (`crate::crypto::derive_gwk`).
    fn hw_key(&self) -> Vec<u8>;
    fn describe(&self) -> String;
}

/// USDK5 binding: the Windows **MachineGuid** string (lowercase, hyphenated), UTF-8.
/// To reuse an existing Windows pairing, pass the GUID from that install's
/// `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`.
///
/// NOTE: confirmed as the DB-ownership binding; that it is *also* the GWK crypto-seal
/// input (vs. DMI product+serial) is inferred, pending a wire capture — see
/// docs/bringup/provisioning-state-machine.md.
pub struct MachineGuidBinding(pub String);

impl MachineBinding for MachineGuidBinding {
    fn hw_key(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
    fn describe(&self) -> String {
        format!("MachineGuid({})", self.0)
    }
}

/// Older-sensor binding: DMI `product_name\0serial\0` (python-validity `set_hwkey`).
pub struct DmiBinding {
    pub product_name: String,
    pub serial: String,
}

impl MachineBinding for DmiBinding {
    fn hw_key(&self) -> Vec<u8> {
        let mut v = self.product_name.as_bytes().to_vec();
        v.push(0);
        v.extend_from_slice(self.serial.as_bytes());
        v.push(0);
        v
    }
    fn describe(&self) -> String {
        format!("Dmi({}/{})", self.product_name, self.serial)
    }
}

impl DmiBinding {
    /// Build from Linux sysfs DMI ids (python-validity `set_hwkey` inputs).
    ///
    /// Override with `SYNA_DMI_PRODUCT` / `SYNA_DMI_SERIAL` when sysfs is unavailable.
    pub fn from_sysfs() -> std::io::Result<Self> {
        fn read_or_env(path: &str, var: &str) -> std::io::Result<String> {
            if let Ok(v) = std::env::var(var) {
                return Ok(v);
            }
            std::fs::read_to_string(path).map(|s| s.trim_end().to_string())
        }
        Ok(Self {
            product_name: read_or_env("/sys/class/dmi/id/product_name", "SYNA_DMI_PRODUCT")?,
            serial: read_or_env("/sys/class/dmi/id/product_serial", "SYNA_DMI_SERIAL")?,
        })
    }
}

/// How a sensor generation is brought out of ROM into a working session.
///
/// Both variants leave ROM the same way — by replaying a small opaque static `0x06`
/// `init_hardcoded` blob (python-validity style, `crate::device::RawDevice::send_init`). They
/// differ in the *session* layer that follows the unlock, not in the unlock itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitModel {
    /// Older generations (`0090/0097/009a/009d`): `0x06` unlock, then a plain TLS session.
    StaticBlob,
    /// USDK5 (`009b`): the same `0x06` unlock, plus a post-ROM P-256 ECDH / "WRKP" work-key
    /// handshake in the session layer (opcode `0x4f`/tag-7, a pinned root key —
    /// docs/bringup/handshake-reconstruction.md). The handshake is NOT the ROM-exit step.
    Usdk5Handshake,
}

/// Where the signed `.xpfwext` firmware comes from (if it needs uploading at all).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareSource {
    /// Extract from a vendor driver package (older generations).
    File,
    /// Already persisted in the sensor's flash (typical for a used device).
    Flashed,
}

/// Flash partition layout profile (template-DB partition size differs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashProfile {
    /// 1 MB-class template DB (`0x80000`) — 0097/009a/009d.
    Large,
    /// 512 KB-class template DB (`0x30000`) — 0090 and 009b.
    Small,
}

impl FlashProfile {
    /// Template-DB partition size for this generation (partition id 3 in the vendor layout).
    pub const fn template_db_size(self) -> u32 {
        match self {
            Self::Large => 0x0008_0000,
            Self::Small => 0x0003_0000,
        }
    }
}

/// A supported sensor generation.
#[derive(Debug)]
pub struct SensorProfile {
    pub usb_ids: &'static [(u16, u16)],
    pub name: &'static str,
    pub init: InitModel,
    pub firmware: FirmwareSource,
    pub flash: FlashProfile,
}

/// The static registry. New sensors get a row here.
pub static REGISTRY: &[SensorProfile] = &[
    SensorProfile {
        // MSI GS66 (MSISecurePad-086) and other USDK5 units. Reference implementation.
        usb_ids: &[(0x06cb, 0x009b)],
        name: "Synaptics Prometheus USDK5 (009b)",
        init: InitModel::Usdk5Handshake,
        firmware: FirmwareSource::Flashed,
        flash: FlashProfile::Small,
    },
    SensorProfile {
        // ThinkPad-class older Prometheus. Strategies stubbed until hardware-tested.
        usb_ids: &[
            (0x06cb, 0x009a),
            (0x138a, 0x0097),
            (0x138a, 0x009d),
            (0x138a, 0x0090),
        ],
        name: "Synaptics/Validity Prometheus (0090/0097/009a/009d)",
        init: InitModel::StaticBlob,
        firmware: FirmwareSource::File,
        flash: FlashProfile::Large,
    },
];

impl SensorProfile {
    /// Find the profile that claims a given USB id.
    pub fn for_id(vid: u16, pid: u16) -> Option<&'static SensorProfile> {
        REGISTRY.iter().find(|p| p.usb_ids.contains(&(vid, pid)))
    }

    /// All USB ids across the registry (for device discovery).
    pub fn all_ids() -> Vec<(u16, u16)> {
        REGISTRY
            .iter()
            .flat_map(|p| p.usb_ids.iter().copied())
            .collect()
    }
}
