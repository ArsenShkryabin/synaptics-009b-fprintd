//! The USDK5 secure channel — a hand-rolled **TLS-1.2-like record layer**.
//!
//! Reversed identically from both drivers: Metallica `scsTLS.c`
//! (`FUN_18007bc30` wrap / `FUN_18007bd70` parse / `FUN_18007ac80` finalize) and MSI 009b
//! `docs/bringup/ghidra-crypto.md`; and byte-for-byte the construction in
//! `vendor/python-validity/validitysensor/tls.py` (`make_keys`/`sign`/`encrypt`). Once a
//! session is established, every command rides inside an `ApplicationData` record.
//!
//! Construction (MAC-then-encrypt):
//! ```text
//! plaintext = payload ‖ HMAC-SHA256(sign_key, [type][03][03][len(payload):BE16] ‖ payload)
//! body      = IV(16) ‖ AES-256-CBC(encryption_key, IV, pad(plaintext))
//! record    = [type][03][03][len(body):BE16] ‖ body
//! ```
//! `pad` is the vendor variant: pad byte value = `padlen - 1`, repeated `padlen` times
//! (`1..=16`). Keys come from the TLS key block (see [`SessionKeys::derive`]).

use crate::crypto::{aes256_cbc_decrypt, aes256_cbc_encrypt, ct_eq, hmac_sha256, prf};
use synaptics_core::error::{Error, Result};

pub const IV_LEN: usize = 16;
pub const MAC_LEN: usize = 32;
const BLOCK: usize = 16;
const KEY_BLOCK_LEN: usize = 0x120;

/// TLS-style record content type (record header byte 0). ghidra: scsTLS.c `FUN_18007bd70`
/// (`local_60 = *record`), matching python-validity's record framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    ChangeCipherSpec = 0x14,
    Alert = 0x15,
    Handshake = 0x16,
    ApplicationData = 0x17,
}

impl TryFrom<u8> for RecordType {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self> {
        Ok(match v {
            0x14 => Self::ChangeCipherSpec,
            0x15 => Self::Alert,
            0x16 => Self::Handshake,
            0x17 => Self::ApplicationData,
            _ => {
                return Err(Error::Malformed(format!(
                    "unknown TLS record type 0x{v:02x}"
                )));
            }
        })
    }
}

/// The four directional keys derived from the TLS key block. `sign`/`encryption` protect
/// host→sensor records; `validation`/`decryption` verify sensor→host records.
pub struct SessionKeys {
    pub sign: [u8; 32],
    pub validation: [u8; 32],
    pub encryption: [u8; 32],
    pub decryption: [u8; 32],
}

impl SessionKeys {
    /// Derive the session keys from the ECDH pre-master secret and the two 32-byte randoms.
    /// ghidra: `syna_tls_make_keys` (MSI `FUN_18007de00`) == python-validity `make_keys`.
    pub fn derive(pre_master_secret: &[u8], client_random: &[u8], server_random: &[u8]) -> Self {
        let mut seed = Vec::with_capacity(client_random.len() + server_random.len());
        seed.extend_from_slice(client_random);
        seed.extend_from_slice(server_random);

        let master_secret = prf(pre_master_secret, &prefixed(b"master secret", &seed), 0x30);
        let key_block = prf(
            &master_secret,
            &prefixed(b"key expansion", &seed),
            KEY_BLOCK_LEN,
        );

        let slice32 = |r: std::ops::Range<usize>| -> [u8; 32] {
            let mut a = [0u8; 32];
            a.copy_from_slice(&key_block[r]);
            a
        };
        Self {
            sign: slice32(0x00..0x20),
            validation: slice32(0x20..0x40),
            encryption: slice32(0x40..0x60),
            decryption: slice32(0x60..0x80),
        }
    }
}

/// Encrypt `payload` into a full record of `rtype`. `iv` must be freshly random per record
/// (the real driver uses `os.urandom(16)`); it is a parameter so the transform is testable.
pub fn wrap(
    keys: &SessionKeys,
    rtype: RecordType,
    payload: &[u8],
    iv: [u8; IV_LEN],
) -> Result<Vec<u8>> {
    let t = rtype as u8;
    let mut plain = payload.to_vec();
    plain.extend_from_slice(&mac(&keys.sign, t, payload));
    synaptics_core::pcap_log::log_transfer(
        synaptics_core::pcap_log::SYNA_PCAP_TLS_PLAINTEXT,
        synaptics_transport::transport::EP_CMD_OUT,
        &plain,
    );
    pad_in_place(&mut plain);

    let ct = aes256_cbc_encrypt(&keys.encryption, &iv, &plain)?;

    let body_len = IV_LEN + ct.len();
    let mut rec = Vec::with_capacity(5 + body_len);
    rec.extend_from_slice(&[t, 3, 3]);
    rec.extend_from_slice(&record_len(body_len)?.to_be_bytes());
    rec.extend_from_slice(&iv);
    rec.extend_from_slice(&ct);
    Ok(rec)
}

/// Parse and decrypt one record, verifying its MAC in constant time.
pub fn unwrap(keys: &SessionKeys, record: &[u8]) -> Result<(RecordType, Vec<u8>)> {
    if record.len() < 5 {
        return Err(Error::ShortResponse {
            opcode: 0,
            got: record.len(),
            need: 5,
        });
    }
    let (t, v_major, v_minor) = (record[0], record[1], record[2]);
    if (v_major, v_minor) != (3, 3) {
        return Err(Error::Malformed(format!(
            "bad TLS record version {v_major}.{v_minor}"
        )));
    }
    let body_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    let body = record
        .get(5..5 + body_len)
        .ok_or_else(|| Error::Malformed(format!("record body truncated: need {body_len}")))?;
    if body.len() < IV_LEN + BLOCK || !(body.len() - IV_LEN).is_multiple_of(BLOCK) {
        return Err(Error::Malformed(format!(
            "record body not block-aligned: {} bytes",
            body.len()
        )));
    }
    let iv: [u8; IV_LEN] = body[..IV_LEN].try_into().expect("body has >= IV_LEN bytes");
    let plain = aes256_cbc_decrypt(&keys.decryption, &iv, &body[IV_LEN..])?;

    let unpadded = unpad(&plain)?;
    synaptics_core::pcap_log::log_transfer(
        synaptics_core::pcap_log::SYNA_PCAP_TLS_PLAINTEXT,
        synaptics_transport::transport::EP_CMD_IN,
        unpadded,
    );
    let (payload, tag) = unpadded.split_at(
        unpadded
            .len()
            .checked_sub(MAC_LEN)
            .ok_or_else(|| Error::Malformed("record shorter than its MAC".into()))?,
    );
    if !ct_eq(tag, &mac(&keys.validation, t, payload)) {
        return Err(Error::Crypto("record MAC verification failed".into()));
    }
    Ok((RecordType::try_from(t)?, payload.to_vec()))
}

fn prefixed(label: &[u8], seed: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(label.len() + seed.len());
    v.extend_from_slice(label);
    v.extend_from_slice(seed);
    v
}

/// `HMAC-SHA256(key, [type][03][03][len(payload):BE16] ‖ payload)`. ghidra: scsTLS.c MAC over
/// the record header (with the *plaintext* length) + payload.
fn mac(key: &[u8; 32], rtype: u8, payload: &[u8]) -> [u8; MAC_LEN] {
    let len = u16::try_from(payload.len())
        .unwrap_or(u16::MAX)
        .to_be_bytes();
    let mut data = Vec::with_capacity(5 + payload.len());
    data.extend_from_slice(&[rtype, 3, 3, len[0], len[1]]);
    data.extend_from_slice(payload);
    hmac_sha256(key, &data)
}

/// Vendor pad: append `padlen` bytes of value `padlen - 1`, `padlen` in `1..=16`.
fn pad_in_place(b: &mut Vec<u8>) {
    let padlen = BLOCK - (b.len() % BLOCK);
    b.extend(std::iter::repeat_n((padlen - 1) as u8, padlen));
}

fn unpad(b: &[u8]) -> Result<&[u8]> {
    let last = *b
        .last()
        .ok_or_else(|| Error::Malformed("empty plaintext".into()))?;
    let padlen = last as usize + 1;
    if padlen > BLOCK || padlen > b.len() {
        return Err(Error::Malformed(format!("bad pad length {padlen}")));
    }
    Ok(&b[..b.len() - padlen])
}

fn record_len(n: usize) -> Result<u16> {
    u16::try_from(n).map_err(|_| Error::Malformed(format!("record body too large: {n}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> SessionKeys {
        // Deterministic keys via the real derivation (values themselves are arbitrary here).
        SessionKeys::derive(b"pre-master-secret", &[0x11; 32], &[0x22; 32])
    }

    /// The counterpart's key view: our write keys (`sign`/`encryption`) are its read keys
    /// (`validation`/`decryption`) and vice-versa — so it can unwrap what we wrapped.
    fn peer(k: &SessionKeys) -> SessionKeys {
        SessionKeys {
            sign: k.validation,
            validation: k.sign,
            encryption: k.decryption,
            decryption: k.encryption,
        }
    }

    #[test]
    fn pad_roundtrips_all_lengths() {
        for len in 0..40usize {
            let mut b = vec![0xABu8; len];
            pad_in_place(&mut b);
            assert_eq!(b.len() % BLOCK, 0);
            assert!(b.len() > len && b.len() - len <= BLOCK);
            assert_eq!(unpad(&b).unwrap(), &vec![0xABu8; len][..]);
        }
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let k = keys();
        let rx = peer(&k);
        let payload = b"identify-finger-please";
        let rec = wrap(&k, RecordType::ApplicationData, payload, [0x42; IV_LEN]).unwrap();
        assert_eq!(rec[0], RecordType::ApplicationData as u8);
        assert_eq!((rec[1], rec[2]), (3, 3));
        let (t, got) = unwrap(&rx, &rec).unwrap();
        assert_eq!(t, RecordType::ApplicationData);
        assert_eq!(got, payload);
    }

    #[test]
    fn tampering_fails_the_mac() {
        let k = keys();
        let rx = peer(&k);
        let mut rec = wrap(
            &k,
            RecordType::ApplicationData,
            b"balance=100",
            [0u8; IV_LEN],
        )
        .unwrap();
        assert!(unwrap(&rx, &rec).is_ok()); // untampered verifies
        *rec.last_mut().unwrap() ^= 0x01; // flip a ciphertext bit
        assert!(unwrap(&rx, &rec).is_err());
    }

    #[test]
    fn key_block_split_is_distinct() {
        let k = keys();
        assert_ne!(k.sign, k.validation);
        assert_ne!(k.encryption, k.decryption);
    }
}
