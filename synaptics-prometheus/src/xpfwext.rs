//! Parser for Validity / Synaptics `.xpfwext` firmware-extension images.
//!
//! On-disk layout (confirmed against `6_07f_lenovo_mis_qm.xpfwext`, and matching the vendor
//! generator `genfwext.pl`):
//!
//! ```text
//!   ASCII manifest            "// Validity Sensors V4 Firmware Extension File\r\n"
//!                             "Key = Value\r\n" lines + "// ..." comments
//!   0x00 0x1A                 delimiter (first 0x1A byte in the file)
//!   <encrypted body>          the firmware to write to flash partition 2 (Encryption != 0)
//!   <signature>               trailing `SignatureLength` bytes (RSA-2048 => 0x100)
//! ```
//!
//! The body is encrypted (whole-body entropy ~8.0), so the on-sensor **module table**
//! (`0x43` get_fw_info) is only observable *after* upload+decrypt — it is not readable from the
//! file offline. This parser therefore exposes the manifest metadata and the exact
//! `(body, signature)` split used to flash the image.
//!
//! Upload procedure (matches python-validity `upload_fwext`, ghidra `syna_on_update_firmware`):
//!   1. `write_flash_all(partition=2, addr=0, body)`   (`0x41` in 0x800/0x1000 chunks)
//!   2. `write_fw_signature(partition=2, signature)`   (`0x42`)
//!   3. reboot; the sensor verifies the RSA signature and decrypts the body.

use crate::error::{Error, Result};

/// A parsed `.xpfwext` image (borrows the input buffer).
#[derive(Debug, Clone)]
pub struct Xpfwext<'a> {
    /// `FirmwareVersion` string, e.g. `"6.07.0164"`.
    pub firmware_version: String,
    /// `Encryption` (`0x0002` = normal encrypted body; `0` = plaintext).
    pub encryption: u16,
    /// `Target` selector.
    pub target: u16,
    /// `Product` id — the sensor family this image targets (e.g. `0x0030` = Metallica MIS).
    pub product: u16,
    /// `StartAddress` the body loads at (e.g. `0x51002000`).
    pub start_address: u32,
    /// `Signed` flag.
    pub signed: bool,
    /// `SignatureLength` — size of the trailing signature (`0x100` for RSA-2048).
    pub signature_length: usize,
    /// `Buildnum` (decimal).
    pub buildnum: u32,
    /// `FwextType`.
    pub fwext_type: u16,
    /// `FwextMajorver` / `FwextMinorver` / `FwextBuildnum`.
    pub fwext_major: u8,
    pub fwext_minor: u8,
    pub fwext_buildnum: u16,
    /// `FwextBuildtime` (unix time).
    pub fwext_buildtime: u32,
    /// The encrypted firmware body — write to flash partition 2.
    pub body: &'a [u8],
    /// The trailing signature — write via the `0x42` signature command.
    pub signature: &'a [u8],
}

fn parse_int(v: &str) -> Option<u64> {
    let v = v.trim();
    if let Some(hex) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        v.parse::<u64>().ok()
    }
}

impl<'a> Xpfwext<'a> {
    /// Parse an `.xpfwext` image. Returns an error if the `0x1A` delimiter is missing or the
    /// payload is shorter than the declared signature.
    pub fn parse(data: &'a [u8]) -> Result<Xpfwext<'a>> {
        let delim = data
            .iter()
            .position(|&b| b == 0x1a)
            .ok_or_else(|| Error::Malformed("xpfwext: no 0x1A header delimiter".into()))?;
        let header = &data[..delim];

        // Collect "Key = Value" lines (skip "//" comments and blanks). Header is ASCII/latin1.
        let mut get = |key: &str| -> Option<String> {
            for line in header.split(|&b| b == b'\n') {
                let line = String::from_utf8_lossy(line);
                let line = line.trim();
                if line.starts_with("//") || line.is_empty() {
                    continue;
                }
                if let Some((k, val)) = line.split_once('=')
                    && k.trim() == key
                {
                    return Some(val.trim().to_string());
                }
            }
            None
        };

        let req_int = |g: &mut dyn FnMut(&str) -> Option<String>, key: &str| -> Result<u64> {
            g(key)
                .as_deref()
                .and_then(parse_int)
                .ok_or_else(|| Error::Malformed(format!("xpfwext: missing/!int field {key}")))
        };

        let firmware_version = get("FirmwareVersion")
            .ok_or_else(|| Error::Malformed("xpfwext: missing FirmwareVersion".into()))?;
        let encryption = req_int(&mut get, "Encryption")? as u16;
        let signature_length = get("SignatureLength")
            .as_deref()
            .and_then(parse_int)
            .unwrap_or(0x100) as usize;
        let signed = get("Signed").as_deref().and_then(parse_int).unwrap_or(0) != 0;
        // Optional-ish metadata (default 0 if a given image omits a field).
        let opt = |g: &mut dyn FnMut(&str) -> Option<String>, key: &str| -> u64 {
            g(key).as_deref().and_then(parse_int).unwrap_or(0)
        };
        let target = opt(&mut get, "Target") as u16;
        let product = opt(&mut get, "Product") as u16;
        let start_address = opt(&mut get, "StartAddress") as u32;
        let buildnum = opt(&mut get, "Buildnum") as u32;
        let fwext_type = opt(&mut get, "FwextType") as u16;
        let fwext_major = opt(&mut get, "FwextMajorver") as u8;
        let fwext_minor = opt(&mut get, "FwextMinorver") as u8;
        let fwext_buildnum = opt(&mut get, "FwextBuildnum") as u16;
        let fwext_buildtime = opt(&mut get, "FwextBuildtime") as u32;

        let payload = &data[delim + 1..];
        if payload.len() < signature_length {
            return Err(Error::Malformed(format!(
                "xpfwext: payload {} < signature_length {}",
                payload.len(),
                signature_length
            )));
        }
        let (body, signature) = payload.split_at(payload.len() - signature_length);

        Ok(Xpfwext {
            firmware_version,
            encryption,
            target,
            product,
            start_address,
            signed,
            signature_length,
            buildnum,
            fwext_type,
            fwext_major,
            fwext_minor,
            fwext_buildnum,
            fwext_buildtime,
            body,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal synthetic image and round-trip the split (CI-safe, no real firmware).
    #[test]
    fn parse_synthetic() {
        let mut f = Vec::new();
        f.extend_from_slice(b"// Validity Sensors V4 Firmware Extension File\r\n");
        f.extend_from_slice(b"FirmwareVersion = 6.07.0164\r\n");
        f.extend_from_slice(b"Encryption = 0x0002\r\n");
        f.extend_from_slice(b"Product = 0x0030\r\n");
        f.extend_from_slice(b"StartAddress = 0x51002000\r\n");
        f.extend_from_slice(b"Signed = 0x0001\r\n");
        f.extend_from_slice(b"SignatureLength = 0x0004\r\n");
        f.extend_from_slice(b"FwextType = 0x2000\r\n");
        f.push(0x00);
        f.push(0x1a);
        f.extend_from_slice(&[0xaa; 16]); // body
        f.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]); // 4-byte signature

        let x = Xpfwext::parse(&f).unwrap();
        assert_eq!(x.firmware_version, "6.07.0164");
        assert_eq!(x.encryption, 0x0002);
        assert_eq!(x.product, 0x0030);
        assert_eq!(x.start_address, 0x5100_2000);
        assert!(x.signed);
        assert_eq!(x.signature_length, 4);
        assert_eq!(x.body, &[0xaa; 16]);
        assert_eq!(x.signature, &[0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn no_delimiter_errs() {
        assert!(Xpfwext::parse(b"FirmwareVersion = 1.2.3\r\nno delimiter here").is_err());
    }

    /// Validate against the real Metallica image if present (gitignored; skipped in CI).
    #[test]
    fn parse_real_metallica_if_present() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../firmware/blobs_9a/6_07f_lenovo_mis_qm.xpfwext"
        );
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => return, // not present -> skip
        };
        let x = Xpfwext::parse(&data).unwrap();
        assert_eq!(x.firmware_version, "6.07.0164");
        assert_eq!(x.encryption, 0x0002);
        assert_eq!(x.product, 0x0030); // Metallica MIS (not our 0x33 MetViper)
        assert_eq!(x.start_address, 0x5100_2000);
        assert_eq!(x.signature_length, 0x100);
        assert_eq!(x.body.len(), 198_016);
        assert_eq!(x.signature.len(), 0x100);
        assert_eq!(
            x.body.len() + x.signature.len() + 1,
            data.len() - data.iter().position(|&b| b == 0x1a).unwrap()
        );
    }
}
