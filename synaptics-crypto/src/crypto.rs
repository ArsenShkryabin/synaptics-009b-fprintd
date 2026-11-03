//! Shared crypto for the Prometheus family.
//!
//! Every constant here was recovered from `synaWudfBioUsb.dll` and verified
//! **byte-for-byte identical to python-validity** — see docs/bringup/ghidra-crypto.md.
//! The primitives (TLS-1.2 `P_hash` PRF over HMAC-SHA256, AES-256-CBC, HMAC-SHA256,
//! P-256 ECDH) are common across the whole sensor family; only the *inputs*
//! (machine binding, init handshake) vary per device — see `crate::devices`.

use synaptics_core::error::{Error, Result};
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::NoPadding};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Constant-time byte comparison. ghidra: `syna_const_time_memcmp` @ 0x1800e0400
/// (XOR-accumulate, no early exit) — used to check record and pairing-seal MACs.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `HMAC-SHA256(key, data)`. The record MAC, the pairing-seal MAC, and the PRF all use it.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = <HmacSha256 as KeyInit>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// AES-256-CBC over already-block-aligned `data` (no padding — the caller owns padding, which
/// differs between the TLS record layer and the pairing seal). ghidra: `syna_aes_cbc_capi`.
pub fn aes256_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    Ok(Aes256CbcEnc::new_from_slices(key, iv)
        .map_err(|e| Error::Crypto(format!("aes key/iv: {e}")))?
        .encrypt_padded_vec::<NoPadding>(data))
}

pub fn aes256_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    Aes256CbcDec::new_from_slices(key, iv)
        .map_err(|e| Error::Crypto(format!("aes key/iv: {e}")))?
        .decrypt_padded_vec::<NoPadding>(data)
        .map_err(|e| Error::Crypto(format!("aes-cbc decrypt: {e}")))
}

/// 32-byte hardcoded PRF key ("password").
/// ghidra: syna_pw_bytes_00_07/08_15/16_23/24_31 @ 0x180083b10/c00/cf0/de0
/// (assembled byte-by-byte on the stack — anti-scan). == python-validity `password_hardcoded`.
pub const PASSWORD_HARDCODED: [u8; 32] = [
    0x71, 0x7c, 0xd7, 0x2d, 0x09, 0x62, 0xbc, 0x4a, 0x28, 0x46, 0x13, 0x8d, 0xbb, 0x2c, 0x24, 0x19,
    0x25, 0x12, 0xa7, 0x64, 0x07, 0x06, 0x5f, 0x38, 0x38, 0x46, 0x13, 0x9d, 0x4b, 0xec, 0x20, 0x33,
];

/// 32-byte hardcoded GWK_SIGN seed.
/// ghidra: syna_derive_psk_val_GWK_SIGN @ 0x180083ed0. == python-validity `gwk_sign_hardcoded`.
pub const GWK_SIGN_HARDCODED: [u8; 32] = [
    0x3a, 0x4c, 0x76, 0xb7, 0x6a, 0x97, 0x98, 0x1d, 0x12, 0x74, 0x24, 0x7e, 0x16, 0x66, 0x10, 0xe7,
    0x7f, 0x4d, 0x9c, 0x9d, 0x07, 0xd3, 0xc7, 0x28, 0xe5, 0x32, 0x91, 0x6b, 0xdd, 0x28, 0xb4, 0x54,
];

/// TLS-1.2 `P_hash` PRF over HMAC-SHA256.
/// ghidra: syna_prf @ 0x1800ed7a0 (== python-validity `tls.py prf`).
///
/// `seed` is the already-concatenated label‖data (e.g. `b"GWK" ‖ hw_key`).
/// Standard PKCS#7 unpad: the last byte is the pad count `n` (1..=16); strip the last `n` bytes.
/// `Error::Malformed` on empty input or an invalid count. NB the TLS record layer uses a *different*
/// vendor scheme (`padlen = last + 1`, see `tls::unpad`) — do NOT use this there.
pub fn pkcs7_unpad(b: &[u8]) -> Result<&[u8]> {
    let n = *b
        .last()
        .ok_or_else(|| Error::Malformed("empty plaintext".into()))? as usize;
    if n == 0 || n > 16 || n > b.len() {
        return Err(Error::Malformed(format!("bad PKCS7 pad {n}")));
    }
    Ok(&b[..b.len() - n])
}

pub fn prf(secret: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let mac = |data: &[u8]| -> Vec<u8> {
        let mut m = <HmacSha256 as KeyInit>::new_from_slice(secret).expect("hmac key");
        m.update(data);
        m.finalize().into_bytes().to_vec()
    };
    let mut out = Vec::with_capacity(out_len + 32);
    let mut a = seed.to_vec(); // A(0) = seed
    while out.len() < out_len {
        a = mac(&a); // A(i) = HMAC(secret, A(i-1))
        let mut ai_seed = a.clone();
        ai_seed.extend_from_slice(seed);
        out.extend_from_slice(&mac(&ai_seed)); // HMAC(secret, A(i) ‖ seed)
    }
    out.truncate(out_len);
    out
}

/// The machine-bound "GWK" key pair that seals the host TLS key into flash.
///
/// `hw_key` is the per-machine binding bytes — DMI `product_name\0serial\0` for the
/// older sensors, or the Windows **MachineGuid** for USDK5 (`009b`). See
/// `crate::devices::MachineBinding`. Constants + derivation are identical across the
/// family; only `hw_key` differs, which is exactly what makes a Windows pairing
/// reusable on Linux on the same machine.
pub struct GwkKeys {
    pub encryption_key: [u8; 32],
    pub validation_key: [u8; 32],
}

pub fn derive_gwk(hw_key: &[u8]) -> GwkKeys {
    // psk_encryption_key (ghidra: syna_derive_psk_enc_GWK@0x1800839d0): the function assembles the
    // raw password into its output buffer, then PRFs it with "GWK" ‖ hw_key **only if hw_key is
    // non-empty** (guard `param_2 && *(param_2+8)`). The Windows 009b driver pairs with an EMPTY
    // hw_key (syna_hw_key_salt is never populated), so the encryption key is the *raw password*.
    // (Verified against the live SYSTEM\...\PairingData block-4 MAC — see examples/unseal_pairing.)
    let encryption_key: [u8; 32] = if hw_key.is_empty() {
        PASSWORD_HARDCODED
    } else {
        let mut seed = b"GWK".to_vec();
        seed.extend_from_slice(hw_key);
        prf(&PASSWORD_HARDCODED, &seed, 32)
            .try_into()
            .expect("prf(_,_,32) is 32 bytes")
    };

    // psk_validation_key = prf(enc, "GWK_SIGN" ‖ gwk_sign_hardcoded, 32)
    let mut seed2 = b"GWK_SIGN".to_vec();
    seed2.extend_from_slice(&GWK_SIGN_HARDCODED);
    let validation_key: [u8; 32] = prf(&encryption_key, &seed2, 32)
        .try_into()
        .expect("prf(_,_,32) is 32 bytes");

    GwkKeys {
        encryption_key,
        validation_key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prf_is_deterministic_and_sized() {
        let a = prf(b"key", b"seed", 64);
        let b = prf(b"key", b"seed", 64);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        // First 32 bytes are a prefix of a longer request (P_hash property).
        assert_eq!(prf(b"key", b"seed", 32), a[..32]);
    }

    #[test]
    fn gwk_derivation_runs() {
        // Smoke test: derivation with a MachineGuid-style binding yields 32-byte keys.
        let k = derive_gwk(b"5cd257d2-c93c-4120-96a4-6bfd6f07066a");
        assert_eq!(k.encryption_key.len(), 32);
        assert_ne!(k.encryption_key, k.validation_key);
    }
}
