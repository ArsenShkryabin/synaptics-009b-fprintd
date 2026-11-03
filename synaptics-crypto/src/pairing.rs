//! Pairing state: read the sensor's on-flash **cert-store** and recover the material a TLS
//! session needs — the host's private key (GWK-unsealed), the sensor's ECDH public key, and
//! the host TLS cert. Because the GWK constants + machine binding match the Windows driver
//! (see `docs/bringup/ghidra-crypto.md`), a pairing sealed by Windows unseals here on the same box —
//! the "enroll on Windows, authenticate on Linux" path.
//!
//! All pure: the cert-store bytes come from the `ReadFlash`/`PartitionFlash` transport path
//! (`crate::device`), but parsing + unseal are independent and fully tested here. Mirrors
//! `vendor/python-validity/tls.py` (`parse_tls_flash`/`handle_priv`/`handle_ecdh`).

use crate::crypto::{
    GwkKeys, aes256_cbc_decrypt, aes256_cbc_encrypt, ct_eq, derive_gwk, hmac_sha256, pkcs7_unpad,
};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use synaptics_core::error::{Error, Result};

const END_BLOCK: u16 = 0xffff;
const PRIV_BLOCK: u16 = 4;
const ECDH_BLOCK: u16 = 6;
const CERT_BLOCK: u16 = 3;
const BLOCK_HASH_LEN: usize = 0x20;
const SEAL_PREFIX: u8 = 0x02;
const COORD_LEN: usize = 0x20;
/// Offsets of the X/Y coordinates inside the 0x90-byte ECDH key blob (little-endian).
const ECDH_X_OFF: usize = 0x08;
const ECDH_Y_OFF: usize = 0x4c;
const ECDH_KEY_LEN: usize = 0x90;

/// Everything a session needs, recovered from the cert-store.
pub struct Pairing {
    pub host_priv: SecretKey,
    pub sensor_pub: PublicKey,
    pub host_cert: Vec<u8>,
}

impl Pairing {
    /// Recover pairing material from a parsed cert-store using the machine's GWK keys.
    pub fn open(store: &CertStore, gwk: &GwkKeys) -> Result<Pairing> {
        let priv_blob = store
            .priv_blob
            .as_deref()
            .ok_or_else(|| Error::Malformed("cert-store has no private-key block".into()))?;
        let ecdh_blob = store
            .ecdh_blob
            .as_deref()
            .ok_or_else(|| Error::Malformed("cert-store has no ECDH block".into()))?;
        Ok(Pairing {
            host_priv: unseal_host_key(priv_blob, gwk)?,
            sensor_pub: parse_sensor_pubkey(ecdh_blob)?,
            host_cert: store.cert.clone().unwrap_or_default(),
        })
    }

    /// Convenience: derive the GWK keys from a machine binding and open in one step.
    pub fn open_with_binding(store: &CertStore, hw_key: &[u8]) -> Result<Pairing> {
        Self::open(store, &derive_gwk(hw_key))
    }
}

/// The raw, still-sealed blocks pulled from the cert-store partition.
#[derive(Default, Debug)]
pub struct CertStore {
    pub priv_blob: Option<Vec<u8>>,
    pub ecdh_blob: Option<Vec<u8>>,
    pub cert: Option<Vec<u8>>,
}

/// Parse a cert-store partition image: a sequence of `[id:u16 le][size:u16 le][sha256:32]
/// [body:size]` blocks, terminated by id `0xffff`. Each block's body hash is verified.
pub fn parse_cert_store(mut r: &[u8]) -> Result<CertStore> {
    let mut store = CertStore::default();
    while r.len() >= 4 {
        let id = u16::from_le_bytes([r[0], r[1]]);
        if id == END_BLOCK {
            break;
        }
        let size = u16::from_le_bytes([r[2], r[3]]) as usize;
        let block_end = 4 + BLOCK_HASH_LEN + size;
        let block = r
            .get(..block_end)
            .ok_or_else(|| Error::Malformed(format!("cert-store block {id} truncated")))?;
        let (hash, body) = (&block[4..4 + BLOCK_HASH_LEN], &block[4 + BLOCK_HASH_LEN..]);
        if Sha256::digest(body).as_slice() != hash {
            return Err(Error::Malformed(format!(
                "cert-store block {id} hash mismatch"
            )));
        }
        match id {
            PRIV_BLOCK => store.priv_blob = Some(body.to_vec()),
            ECDH_BLOCK => store.ecdh_blob = Some(body.to_vec()),
            CERT_BLOCK => store.cert = Some(body.to_vec()),
            _ => {} // 0/1/2 are empty padding blocks
        }
        r = &r[block_end..];
    }
    Ok(store)
}

impl CertStore {
    /// Serialize the present priv/ecdh/cert blocks back into the block-image format
    /// [`parse_cert_store`] reads (`[id:u16 le][len:u16 le][sha256(body):32][body]` per block, an
    /// `0xffff` terminator). The padding blocks (0/1/2/5) the reader ignores are omitted, so this is
    /// a *minimal* cert-store — sufficient for our session path, not a byte-for-byte flash image.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut push = |id: u16, body: &[u8]| {
            out.extend_from_slice(&id.to_le_bytes());
            out.extend_from_slice(&(body.len() as u16).to_le_bytes());
            out.extend_from_slice(&Sha256::digest(body));
            out.extend_from_slice(body);
        };
        if let Some(b) = &self.priv_blob {
            push(PRIV_BLOCK, b);
        }
        if let Some(b) = &self.cert {
            push(CERT_BLOCK, b);
        }
        if let Some(b) = &self.ecdh_blob {
            push(ECDH_BLOCK, b);
        }
        out.extend_from_slice(&END_BLOCK.to_le_bytes());
        out
    }
}

/// Re-seal a cert-store's host key from `from_binding` to `to_binding`, returning a portable
/// cert-store image. Passing `to_binding = b""` drops the machine binding (the unbound seat key),
/// so the result opens with an empty binding on any host — turning a DMI/MachineGuid-bound pairing
/// into a machine-independent one. `iv` seeds the AES-CBC block.
///
/// # Errors
/// Returns [`Error::Malformed`] if the store has no private-key block, or [`Error::Crypto`] if the
/// host key does not unseal under `from_binding` (wrong machine).
pub fn rebind_cert_store(
    store_bytes: &[u8],
    from_binding: &[u8],
    to_binding: &[u8],
    iv: [u8; crate::tls::IV_LEN],
) -> Result<Vec<u8>> {
    let mut store = parse_cert_store(store_bytes)?;
    let priv_blob = store
        .priv_blob
        .as_deref()
        .ok_or_else(|| Error::Malformed("cert-store has no private-key block".into()))?;
    let key = unseal_host_key(priv_blob, &derive_gwk(from_binding))?;
    store.priv_blob = Some(seal_host_key(&key, &derive_gwk(to_binding), iv)?);
    Ok(store.to_bytes())
}

/// Unseal the host private key from block 4: `[0x02] ‖ IV(16) ‖ AES-256-CBC(psk_enc, pad(x‖y‖d))
/// ‖ HMAC-SHA256(psk_val, IV‖ct)`, coordinates little-endian, standard PKCS7 pad. Only the
/// private scalar `d` is needed. ghidra: `handle_priv`.
pub fn unseal_host_key(priv_blob: &[u8], gwk: &GwkKeys) -> Result<SecretKey> {
    let body = match priv_blob.split_first() {
        Some((&SEAL_PREFIX, rest)) => rest,
        Some((p, _)) => return Err(Error::Malformed(format!("unknown seal prefix 0x{p:02x}"))),
        None => return Err(Error::Malformed("empty private-key blob".into())),
    };
    if body.len() < crate::tls::IV_LEN + BLOCK_HASH_LEN {
        return Err(Error::Malformed("private-key blob too short".into()));
    }
    let (c, tag) = body.split_at(body.len() - BLOCK_HASH_LEN);
    if !ct_eq(tag, &hmac_sha256(&gwk.validation_key, c)) {
        return Err(Error::Crypto(
            "private-key blob MAC failed — sensor was paired with a different machine".into(),
        ));
    }
    let iv: [u8; crate::tls::IV_LEN] = c[..crate::tls::IV_LEN].try_into().expect("checked len");
    let plain = aes256_cbc_decrypt(&gwk.encryption_key, &iv, &c[crate::tls::IV_LEN..])?;
    let plain = pkcs7_unpad(&plain)?;

    let d_off = 2 * COORD_LEN;
    let d_le = plain
        .get(d_off..d_off + COORD_LEN)
        .ok_or_else(|| Error::Malformed("private-key plaintext too short".into()))?;
    let d_be = reversed(d_le);
    SecretKey::from_slice(&d_be)
        .map_err(|e| Error::Crypto(format!("invalid host private key: {e}")))
}

/// Extract the sensor's ECDH public key from block 6 (X/Y little-endian at fixed offsets in
/// the first 0x90 bytes; the trailing signature is checked elsewhere). ghidra: `handle_ecdh`.
pub fn parse_sensor_pubkey(ecdh_blob: &[u8]) -> Result<PublicKey> {
    let key = ecdh_blob
        .get(..ECDH_KEY_LEN)
        .ok_or_else(|| Error::Malformed("ECDH blob shorter than key".into()))?;
    let mut sec1 = Vec::with_capacity(1 + 2 * COORD_LEN);
    sec1.push(0x04); // uncompressed point
    sec1.extend(reversed(&key[ECDH_X_OFF..ECDH_X_OFF + COORD_LEN]));
    sec1.extend(reversed(&key[ECDH_Y_OFF..ECDH_Y_OFF + COORD_LEN]));
    PublicKey::from_sec1_bytes(&sec1)
        .map_err(|e| Error::Crypto(format!("sensor ECDH key not on curve: {e}")))
}

/// Seal a host key back into the block-4 format (inverse of [`unseal_host_key`]). Used to
/// re-provision and to round-trip test the seal. `iv` must be random in real use.
pub fn seal_host_key(
    key: &SecretKey,
    gwk: &GwkKeys,
    iv: [u8; crate::tls::IV_LEN],
) -> Result<Vec<u8>> {
    let point = key.public_key().to_sec1_point(false);
    let mut plain = Vec::with_capacity(3 * COORD_LEN);
    plain.extend(reversed(point.x().expect("uncompressed point")));
    plain.extend(reversed(point.y().expect("uncompressed point")));
    plain.extend(reversed(&key.to_bytes()));
    pkcs7_pad(&mut plain);

    let mut c = iv.to_vec();
    c.extend(aes256_cbc_encrypt(&gwk.encryption_key, &iv, &plain)?);
    let tag = hmac_sha256(&gwk.validation_key, &c);

    let mut blob = Vec::with_capacity(1 + c.len() + tag.len());
    blob.push(SEAL_PREFIX);
    blob.extend(c);
    blob.extend(tag);
    Ok(blob)
}

fn reversed(b: &[u8]) -> Vec<u8> {
    b.iter().rev().copied().collect()
}

/// Standard PKCS7: pad value == count, always adds a block if already aligned.
fn pkcs7_pad(b: &mut Vec<u8>) {
    let n = 16 - (b.len() % 16);
    b.extend(std::iter::repeat_n(n as u8, n));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gwk() -> GwkKeys {
        derive_gwk(b"5cd257d2-c93c-4120-96a4-6bfd6f07066a") // a MachineGuid
    }

    #[test]
    fn seal_unseal_roundtrips_the_host_key() {
        let g = gwk();
        let key = SecretKey::from_slice(&[0x37; 32]).unwrap();
        let blob = seal_host_key(&key, &g, [0x99; 16]).unwrap();
        assert_eq!(blob[0], SEAL_PREFIX);
        let back = unseal_host_key(&blob, &g).unwrap();
        assert_eq!(back.to_bytes(), key.to_bytes());
    }

    #[test]
    fn unseal_rejects_wrong_machine() {
        let key = SecretKey::from_slice(&[0x37; 32]).unwrap();
        let blob = seal_host_key(&key, &gwk(), [0x99; 16]).unwrap();
        let other = derive_gwk(b"a-different-machine-guid");
        assert!(unseal_host_key(&blob, &other).is_err()); // MAC fails
    }

    #[test]
    fn rebind_drops_the_machine_binding() {
        // A DMI-bound cert-store (only the priv block is needed for rebinding).
        let key = SecretKey::from_slice(&[0x37; 32]).unwrap();
        let dmi = b"20L5000BGE\0SERIAL123\0".as_slice();
        let sealed = seal_host_key(&key, &derive_gwk(dmi), [1; 16]).unwrap();
        let mut image = 4u16.to_le_bytes().to_vec(); // PRIV_BLOCK
        image.extend_from_slice(&(sealed.len() as u16).to_le_bytes());
        image.extend_from_slice(&Sha256::digest(&sealed));
        image.extend_from_slice(&sealed);
        image.extend_from_slice(&END_BLOCK.to_le_bytes());

        // Rebind DMI → empty (the unbound seat key).
        let portable = rebind_cert_store(&image, dmi, b"", [2; 16]).unwrap();
        let out_priv = parse_cert_store(&portable).unwrap().priv_blob.unwrap();

        // The portable store yields the same host key under an EMPTY binding…
        let reunsealed = unseal_host_key(&out_priv, &derive_gwk(b"")).unwrap();
        assert_eq!(reunsealed.to_bytes(), key.to_bytes());
        // …and no longer under the original DMI binding.
        assert!(unseal_host_key(&out_priv, &derive_gwk(dmi)).is_err());
    }

    #[test]
    fn sensor_pubkey_roundtrips() {
        // Build a block-6 key layout from a known public key, then parse it back.
        let sensor = SecretKey::from_slice(&[0x51; 32]).unwrap();
        let point = sensor.public_key().to_sec1_point(false);
        let mut blob = vec![0u8; ECDH_KEY_LEN + 4]; // key + a little trailing sig space
        blob[ECDH_X_OFF..ECDH_X_OFF + COORD_LEN].copy_from_slice(&reversed(point.x().unwrap()));
        blob[ECDH_Y_OFF..ECDH_Y_OFF + COORD_LEN].copy_from_slice(&reversed(point.y().unwrap()));
        assert_eq!(parse_sensor_pubkey(&blob).unwrap(), sensor.public_key());
    }

    #[test]
    fn cert_store_parses_and_verifies_hashes() {
        let g = gwk();
        let priv_blob =
            seal_host_key(&SecretKey::from_slice(&[9; 32]).unwrap(), &g, [1; 16]).unwrap();
        let cert = b"opaque-tls-cert".to_vec();

        let block = |id: u16, body: &[u8]| {
            let mut v = id.to_le_bytes().to_vec();
            v.extend_from_slice(&(body.len() as u16).to_le_bytes());
            v.extend_from_slice(&Sha256::digest(body));
            v.extend_from_slice(body);
            v
        };
        let mut image = block(PRIV_BLOCK, &priv_blob);
        image.extend(block(CERT_BLOCK, &cert));
        image.extend(END_BLOCK.to_le_bytes()); // terminator

        let store = parse_cert_store(&image).unwrap();
        assert_eq!(store.priv_blob.as_deref(), Some(priv_blob.as_slice()));
        assert_eq!(store.cert.as_deref(), Some(cert.as_slice()));
        assert!(store.ecdh_blob.is_none());
    }

    #[test]
    fn cert_store_rejects_corrupt_block() {
        let mut img = 4u16.to_le_bytes().to_vec();
        img.extend_from_slice(&3u16.to_le_bytes());
        img.extend_from_slice(&[0u8; BLOCK_HASH_LEN]); // wrong hash
        img.extend_from_slice(b"abc");
        assert!(parse_cert_store(&img).is_err());
    }
}
