//! USDK5 (`009b`) pre-TLS init handshake — the ECDH-with-pinned-root-key exchange
//! reconstructed in docs/bringup/handshake-reconstruction.md.
//!
//! Flow:
//! ```text
//! minimal 0x4f  ──►  ciphertext "work-key package" record
//! devid (tag 0x6e) ─►  pick pinned root pubkey from the embedded table
//! ECDH(host ephemeral P-256, root pubkey)
//!   → SHA-256(shared_x)
//!     → PRF("WRKP", 64)  → enc_key[0:32] ‖ mac_key[32:64]
//!       → AES-256-CBC decrypt + HMAC-SHA256 verify the record → strip 4B header
//!         → tag-7 payload
//! ```
//!
//! Fully specified except three items flagged `WIRE-CONFIRM` below (initial CBC IV,
//! host-key determinism, exact minimal-0x4f request bytes) — these resolve the moment
//! the record's MAC verifies against a live exchange, which is the read-only test.

use crate::crypto::{
    aes256_cbc_decrypt, ct_eq, derive_gwk, hmac_sha256, pkcs7_unpad, prf, PASSWORD_HARDCODED,
};
use crate::device::RawDevice;
use crate::error::{Error, Result};
use crate::fw_registry::{self, FwWantFlags, SensorIdentity};
use crate::pre_arm;
use crate::proto::Opcode;
use crate::transport::Transport;
use synaptics_crypto::pairing::seal_host_key;

use p256::ecdh::diffie_hellman;
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use p256::elliptic_curve::Generate;
use p256::{PublicKey, Sec1Point, SecretKey};
use sha2::{Digest, Sha256};

/// One pinned root-key table entry (Table A, P-256).
/// ghidra: DAT_180143630, 0x103-byte stride; selected in syna_lookup_root_key_by_devid@180098310.
struct RootKey {
    m0: u8,
    m1: u8,
    flag: bool,
    /// X, Y as stored in the DLL (little-endian in a 68-byte slot; low 32 bytes here).
    x_le: [u8; 32],
    y_le: [u8; 32],
}

/// Common `flag=0` root key (shared by every flag=0 entry).
const COMMON_X_LE: [u8; 32] =
    hexlit("5dfe8bc06c0d1244d8d937e94c0cfc7e32675ea21cea464b82daf5a58c20d633");
const COMMON_Y_LE: [u8; 32] =
    hexlit("fda0347c77f0c1571fc4424708e7dc18c71eb6f3cdaf912bc6f64bfc81e155b9");

/// Table A (P-256). `flag=1` entries have per-subclass keys; `flag=0` use the common key.
const ROOT_KEYS: &[RootKey] = &[
    RootKey {
        m0: 0x06,
        m1: 0x07,
        flag: false,
        x_le: COMMON_X_LE,
        y_le: COMMON_Y_LE,
    },
    RootKey {
        m0: 0x06,
        m1: 0x07,
        flag: true,
        x_le: hexlit("d3a8f669df1f6743a792120d31bea0d0d7303a7f4d89a66506ce164e3b6527f7"),
        y_le: hexlit("94caa62147a861f78d9493238bc54362887ad0f4d58bef6e0dc5beb6f83855a8"),
    },
    RootKey {
        m0: 0x06,
        m1: 0x08,
        flag: false,
        x_le: COMMON_X_LE,
        y_le: COMMON_Y_LE,
    },
    RootKey {
        m0: 0x06,
        m1: 0x08,
        flag: true,
        x_le: hexlit("49b2ce0e3b7b3b89a9d2394be7f600943b34c45bacd9776240bfc894c34b7778"),
        y_le: hexlit("bd76e5e9f0bc75b2a48d20bf9bf1f442d4834c49c19e049c72da1f47372c5a11"),
    },
    RootKey {
        m0: 0x06,
        m1: 0x0b,
        flag: false,
        x_le: COMMON_X_LE,
        y_le: COMMON_Y_LE,
    },
    RootKey {
        m0: 0x06,
        m1: 0x0b,
        flag: true,
        x_le: hexlit("6cfd3c9e44496d8722a49a7c71d00ba26c7acb558306f75231f04b4b957e9d68"),
        y_le: hexlit("1850517af5a086064474ad6e1b1caa24ca9b36306afc085c0c125638589fda68"),
    },
    RootKey {
        m0: 0x06,
        m1: 0x14,
        flag: false,
        x_le: COMMON_X_LE,
        y_le: COMMON_Y_LE,
    },
    RootKey {
        m0: 0x06,
        m1: 0x14,
        flag: true,
        x_le: hexlit("c77e3f71e27b84236e70e34ddc6b5b1f2f0e97741c38e677ca3057dbf3c8b078"),
        y_le: hexlit("00567e72ab4dde29552a7e4369eea4d2416299e94ccf8ce5cf1a56cd912f4454"),
    },
    RootKey {
        m0: 0x06,
        m1: 0x15,
        flag: true,
        x_le: hexlit("593af3bc12ade5f5cc36f9b8966018a11c3facc1b8a8e634497c3e06c9c1fcd5"),
        y_le: hexlit("f9990bbf5842fc9c975e884e04626826f1615713cefcce2f8a2c0434a2554aeb"),
    },
    RootKey {
        m0: 0x06,
        m1: 0x15,
        flag: false,
        x_le: COMMON_X_LE,
        y_le: COMMON_Y_LE,
    },
    RootKey {
        m0: 0x08,
        m1: 0x00,
        flag: false,
        x_le: COMMON_X_LE,
        y_le: COMMON_Y_LE,
    },
];

/// Look up the pinned root public key for a device by its `tag 0x6e` id bytes.
/// `m0 = devid[8]`, `m1 = devid[9]`, `flag = (devid[0x17] & 0x20) != 0`.
pub fn lookup_root_key(m0: u8, m1: u8, flag: bool) -> Result<PublicKey> {
    let e = ROOT_KEYS
        .iter()
        .find(|e| e.m0 == m0 && e.m1 == m1 && e.flag == flag)
        .ok_or_else(|| {
            Error::Crypto(format!(
                "no root key for devid {m0:02x}:{m1:02x} flag={flag}"
            ))
        })?;
    // DLL byte-reverses each coordinate before use (LE-stored → BE for the curve math).
    let mut x = e.x_le;
    let mut y = e.y_le;
    x.reverse();
    y.reverse();
    let pt = Sec1Point::from_affine_coordinates(&x.into(), &y.into(), false);
    PublicKey::from_sec1_point(&pt)
        .into_option()
        .ok_or_else(|| Error::Crypto("pinned root key is not a valid P-256 point".into()))
}

/// A freshly generated host ephemeral P-256 key.
///
/// WIRE-CONFIRM: the DLL round-trips a value through cmd `0x139` and re-reads it (§2.2/§2.4);
/// whether the host private key is truly random (BCryptGenerateKeyPair) or derived from GWK
/// is unresolved. We use a random ephemeral key (the standard, most-likely-correct reading);
/// if a live record fails to MAC-verify, try the GWK-deterministic variant.
pub struct HostEphemeral {
    pub secret: SecretKey,
}

impl HostEphemeral {
    pub fn random() -> Self {
        Self {
            secret: SecretKey::generate_from_rng(&mut crate::session::os_rng()),
        }
    }
    pub fn public(&self) -> PublicKey {
        self.secret.public_key()
    }
}

/// `enc_key ‖ mac_key = PRF(SHA-256(ECDH_x), "WRKP" ‖ 0x00000000, 64)`.
/// ghidra: syna_kdf_derive_from_secret(KDF_HASH) then syna_prf(label DAT_180232438="WRKP").
pub fn derive_wrkp_keys(shared_x: &[u8]) -> ([u8; 32], [u8; 32]) {
    let secret_hash = Sha256::digest(shared_x);
    // PRF seed = label ‖ ctx = "WRKP" ‖ 4 zero bytes.
    let out = prf(&secret_hash, b"WRKP\x00\x00\x00\x00", 64);
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    enc.copy_from_slice(&out[0..32]);
    mac.copy_from_slice(&out[32..64]);
    (enc, mac)
}

/// ECDH shared secret (P-256 x-coordinate, 32 bytes big-endian).
pub fn ecdh_shared(host: &HostEphemeral, root: &PublicKey) -> [u8; 32] {
    let ss = diffie_hellman(host.secret.to_nonzero_scalar(), root.as_affine());
    let mut out = [0u8; 32];
    out.copy_from_slice(ss.raw_secret_bytes());
    out
}

/// Unwrap the work-key record: verify HMAC-SHA256, AES-256-CBC decrypt, PKCS7-depad,
/// strip the leading 4-byte header. Returns the tag-7 payload.
/// ghidra: syna_unwrap_decrypt_verify_record@0x1800ef0e0 (MAC=syna_hmac_sha256_capi_init,
/// cipher=syna_aes_cbc_capi CRYPT_MODE_CBC).
pub fn unwrap_record(record: &[u8], enc_key: &[u8; 32], mac_key: &[u8; 32]) -> Result<Vec<u8>> {
    if record.len() < 0x24 {
        return Err(Error::Malformed(format!(
            "work-key record too short: {} < 0x24",
            record.len()
        )));
    }
    let n = record.len();
    let body = &record[..n - 0x24];
    let trailer_len = &record[n - 0x24..n - 0x20]; // 4-byte length field
    let tag = &record[n - 0x20..]; // 32-byte HMAC

    // HMAC-SHA256(mac_key, body ‖ trailer_len) == tag  (constant-time).
    let mut mac_data = Vec::with_capacity(body.len() + trailer_len.len());
    mac_data.extend_from_slice(body);
    mac_data.extend_from_slice(trailer_len);
    if !ct_eq(&hmac_sha256(mac_key, &mac_data), tag) {
        return Err(Error::Crypto("work-key record MAC verify failed".into()));
    }

    // AES-256-CBC decrypt. WIRE-CONFIRM: initial IV source (assuming all-zero for the
    // first block; the DLL chains the IV from the last ciphertext block thereafter).
    if !body.len().is_multiple_of(16) {
        return Err(Error::Malformed("cipher body not block-aligned".into()));
    }
    let pt = aes256_cbc_decrypt(enc_key, &[0u8; 16], body)?;

    // PKCS7 de-pad (DLL: last byte = pad len in 1..=0x10).
    let plain = pkcs7_unpad(&pt)?;
    if plain.len() < 4 {
        return Err(Error::Malformed(
            "plaintext shorter than 4-byte header".into(),
        ));
    }
    Ok(plain[4..].to_vec()) // strip the leading 4-byte header (FUN_1800720c0 tail)
}

/// End-to-end tag-7 payload calculation from a live work-key record + device id.
/// ghidra: FUN_1800720c0.
pub fn compute_tag7(record: &[u8], devid: &[u8], host: &HostEphemeral) -> Result<Vec<u8>> {
    if devid.len() < 0x18 {
        return Err(Error::Malformed(
            "devid (tag 0x6e) shorter than 0x18".into(),
        ));
    }
    let flag = (devid[0x17] & 0x20) != 0;
    let root = lookup_root_key(devid[8], devid[9], flag)?;
    let shared = ecdh_shared(host, &root);
    let (enc, mac) = derive_wrkp_keys(&shared);
    unwrap_record(record, &enc, &mac)
}

/// Minimal `0x4f` work-key read + WRKP unwrap over a pre-TLS [`crate::device::RawDevice`].
/// ghidra: the USDK5 pre-TLS handshake before TLS (`syna_open_init_decide_format` post-ROM path).
pub fn run_wrkp_handshake<T: crate::transport::Transport>(
    dev: &mut crate::device::RawDevice<T>,
) -> Result<Vec<u8>> {
    const MINIMAL_4F: &[u8] = &[0x4f, 0x00, 0x00, 0x00, 0x00];
    let resp = dev.transact(MINIMAL_4F)?;
    if !resp.status.is_ok() {
        return Err(Error::Status {
            opcode: 0x4f,
            status: resp.status,
        });
    }
    let status = dev.read_sensor_status()?;
    let devid = status.payload;
    let host = HostEphemeral::random();
    compute_tag7(&resp.payload, &devid, &host)
}

/// Hardcoded 420-byte (`0x1a4`) P-256 curve parameters (`syna_crt_hardcoded_p256_params` / Block 5).
pub const CRT_HARDCODED: &[u8; 420] = &hexlit_420(concat!(
    "170000000001000001000000fcffffffffffffffffffffff00000000000000000000000001000000ffff",
    "ffff0000000000000000000000000000000000000000000000000000000000000000000000004b60d227",
    "3e3cce3bf6b053ccb0061d65bc86987655bdebb3e7933aaad835c65a0000000000000000000000000000",
    "0000000000000000000000000000000000000000000096c298d84539a1f4a033eb2d817d0377f240a463",
    "e5e6bcf847422ce1f2d1176b000000000000000000000000000000000000000000000000000000000000",
    "000000000000f551bf376840b6cbce5e316b5733ce2b169e0f7c4aebe78e9b7f1afee242e34f00000000",
    "0000000000000000000000000000000000000000000000000000000000000000512563fcc2cab9f3849e",
    "17a7adfae6bcffffffffffffffff00000000ffffffff0000000000000000000000000000000000000000",
    "00000000000000000000000000000000ffffffffffffffffffffffff0000000000000000000000000100",
    "0000ffffffff000000000000000000000000000000000000000000000000000000000000000000000000"
));

/// Derive the deterministic P-256 `hs_key` (`syna_hs_key_gen@0x180071d90`).
pub fn derive_hs_key() -> SecretKey {
    let key = &PASSWORD_HARDCODED[..16];
    let mut seed = Vec::with_capacity(15 + 18);
    seed.extend_from_slice(b"HS_KEY_PAIR_GEN");
    seed.extend_from_slice(&PASSWORD_HARDCODED[16..32]);
    seed.extend_from_slice(&[0xaa, 0xaa]);
    let mut raw = prf(key, &seed, 32);
    raw.reverse();
    SecretKey::from_slice(&raw).expect("deterministic hs_key is a valid P-256 scalar")
}

/// Build the 184-byte (`0xb8`) host public-key certificate header (`FUN_1800715e0`).
pub fn build_host_cert_header_184(host_pub: &PublicKey) -> [u8; 184] {
    let pt = host_pub.to_sec1_point(false);
    let mut x_le = [0u8; 32];
    let mut y_le = [0u8; 32];
    x_le.copy_from_slice(pt.x().expect("uncompressed X"));
    y_le.copy_from_slice(pt.y().expect("uncompressed Y"));
    x_le.reverse();
    y_le.reverse();

    let mut out = [0u8; 184];
    out[0..4].copy_from_slice(&0x17u32.to_le_bytes());
    out[4..8].copy_from_slice(&0x20u32.to_le_bytes());
    out[0x08..0x28].copy_from_slice(&x_le);
    out[0x4c..0x6c].copy_from_slice(&y_le);
    out
}

/// Build the 444-byte (`0x1bc`) `subblock 5` signed host certificate (`FUN_1800727b0`).
pub fn build_subblock_5_signed_host_cert(host_pub: &PublicKey) -> [u8; 444] {
    let hdr = build_host_cert_header_184(host_pub);
    let signing_key = SigningKey::from(&derive_hs_key());
    let sig: Signature = signing_key.sign(&hdr);
    let der = sig.to_der();
    let der_bytes = der.as_bytes();

    let mut out = [0u8; 444];
    out[..184].copy_from_slice(&hdr);
    out[184..188].copy_from_slice(&(der_bytes.len() as u32).to_le_bytes());
    out[188..188 + der_bytes.len()].copy_from_slice(der_bytes);
    out
}

/// Build the 453-byte (`0x1c5`) flashless `06cb:009b` `0x4f` host-cert registration command
/// (`syna_cmdhandler10_workkey_req_0x4f@0x180088ac0` with `ctx+0x274 == 1`).
pub fn build_009b_register_host_cert_cmd_0x4f(host_pub: &PublicKey) -> Vec<u8> {
    let sub5 = build_subblock_5_signed_host_cert(host_pub);
    let mut cmd = Vec::with_capacity(5 + 4 + 444);
    cmd.extend_from_slice(&[0x4f, 0x00, 0x00, 0x00, 0x00]);
    cmd.extend_from_slice(&5u16.to_le_bytes());
    cmd.extend_from_slice(&(sub5.len() as u16).to_le_bytes());
    cmd.extend_from_slice(&sub5);
    cmd
}

/// Verify a 400-byte `ecdh_blob` (Block 6, returned by `0x50`) against the `06:14 (flag=1)`
/// Synaptics root public key and return the sensor's P-256 ECDH public key.
pub fn verify_sensor_ecdh_blob_009b(eb: &[u8]) -> Result<PublicKey> {
    if eb.len() != 400 {
        return Err(Error::Malformed(format!(
            "expected 400-byte ecdh_blob, got {}",
            eb.len()
        )));
    }
    let mut x_be = [0u8; 32];
    let mut y_be = [0u8; 32];
    x_be.copy_from_slice(&eb[0x08..0x28]);
    y_be.copy_from_slice(&eb[0x4c..0x6c]);
    x_be.reverse();
    y_be.reverse();
    let pt = Sec1Point::from_affine_coordinates(&x_be.into(), &y_be.into(), false);
    let pk = PublicKey::from_sec1_point(&pt)
        .into_option()
        .ok_or_else(|| Error::Crypto("sensor ECDH point is not on P-256".into()))?;

    let sig_len = u32::from_le_bytes(eb[0x90..0x94].try_into().unwrap()) as usize;
    if 0x94 + sig_len > eb.len() {
        return Err(Error::Malformed("ecdh_blob sig_len overruns buffer".into()));
    }
    let sig = Signature::from_der(&eb[0x94..0x94 + sig_len])
        .map_err(|e| Error::Crypto(format!("invalid DER in ecdh_blob: {e}")))?;
    let root = lookup_root_key(0x06, 0x14, true)?;
    let vk = VerifyingKey::from(&root);
    vk.verify(&eb[..0x90], &sig).map_err(|e| {
        Error::Crypto(format!(
            "sensor ecdh_blob signature rejected by 06:14(flag=1) root key: {e}"
        ))
    })?;
    Ok(pk)
}

/// Assemble the complete 4096-byte `certstore.bin` image from:
/// - `priv_blob` (Block 4, 161 bytes)
/// - `tls_cert_184` (Block 3, 184 bytes returned by the sensor)
/// - `ecdh_blob_400` (Block 6, 400 bytes returned by `0x50`)
pub fn assemble_certstore_4096(
    priv_blob: &[u8],
    tls_cert_184: &[u8],
    ecdh_blob_400: &[u8],
) -> [u8; 4096] {
    let mut out = [0xffu8; 4096];
    let mut pos = 0usize;
    let mut push_block = |id: u16, body: &[u8]| {
        out[pos..pos + 2].copy_from_slice(&id.to_le_bytes());
        out[pos + 2..pos + 4].copy_from_slice(&(body.len() as u16).to_le_bytes());
        let digest = Sha256::digest(body);
        out[pos + 4..pos + 36].copy_from_slice(&digest);
        out[pos + 36..pos + 36 + body.len()].copy_from_slice(body);
        pos += 36 + body.len();
    };

    let zeros_256 = [0u8; 256];
    push_block(0, &[0x00]);
    push_block(4, priv_blob);
    push_block(3, tls_cert_184);
    push_block(5, CRT_HARDCODED);
    push_block(1, &zeros_256);
    push_block(2, &zeros_256);
    push_block(6, ecdh_blob_400);
    out
}

/// Perform Linux-native fresh pairing for `06cb:009b` without Windows.
///
/// Runs the safe, flashless sequence (`ctx+0x274 == 1`):
/// 1. Upload `want=0x4` RAM module (`0x1801d6fb0`) to transition sensor to state 4.
/// 2. Generate or reuse `host_sk`, sign 453-byte `0x4f` command with `hs_key`.
/// 3. Register host cert over `0x4f` -> receive sensor-signed Block 3 (`tls_cert`).
/// 4. Read Block 6 (`ecdh_blob`) over `0x50` and verify root signature.
/// 5. Assemble and return the complete 4096-byte `certstore.bin`.
pub fn pair_009b_flashless<T: Transport>(
    dev: &mut RawDevice<T>,
    host_sk: Option<SecretKey>,
) -> Result<[u8; 4096]> {
    let status = dev.read_sensor_status()?;
    let id = SensorIdentity::from_status(&status);
    let is_009b = id.id8 == 6 && id.id9 == 0x14;
    if !is_009b {
        return Err(Error::Malformed(format!(
            "pair_009b_flashless: unsupported sensor id8={:#x} id9={:#x}",
            id.id8, id.id9
        )));
    }

    let flag4_rec = fw_registry::select(
        fw_registry::REGISTRY,
        &id,
        FwWantFlags::FLAG4,
        FwWantFlags::empty(),
        0,
    )
    .ok_or_else(|| Error::Malformed("no want=0x4 module in registry for 009b".into()))?;

    let flag4_payload = pre_arm::resolve_payload(flag4_rec)
        .ok_or_else(|| Error::Malformed("missing 009b want=0x4 firmware module blob".into()))?;

    let host_sk = host_sk.unwrap_or_else(|| SecretKey::generate_from_rng(&mut crate::session::os_rng()));
    let host_pub = host_sk.public_key();

    let mut iv = [0u8; 16];
    rand_core::Rng::fill_bytes(&mut crate::session::os_rng(), &mut iv);
    let priv_blob = seal_host_key(&host_sk, &derive_gwk(b""), iv)?;

    let mut cmd_06 = Vec::with_capacity(1 + flag4_payload.len());
    cmd_06.push(Opcode::SendDataBlob.byte());
    cmd_06.extend_from_slice(&flag4_payload);

    let cmd_4f = build_009b_register_host_cert_cmd_0x4f(&host_pub);

    // State 1: commit + 0x06 upload want=0x4
    let _ = dev.cmd_raw(Opcode::Commit, &[])?;
    let resp06 = dev.transact(&cmd_06)?;
    if !pre_arm::upload_status_is_success(resp06.status.wire()) {
        return Err(Error::Status {
            opcode: Opcode::SendDataBlob.byte(),
            status: resp06.status,
        });
    }

    // State 3: send 0x4f subblock 5 -> recv Block 3
    let resp4f = dev.transact(&cmd_4f)?;
    if !resp4f.status.is_ok() || resp4f.payload.len() < 4 + 184 {
        return Err(Error::Status {
            opcode: Opcode::PartitionFlash.byte(),
            status: resp4f.status,
        });
    }
    let cert_len = u32::from_le_bytes(resp4f.payload[0..4].try_into().unwrap()) as usize;
    if 4 + cert_len > resp4f.payload.len() {
        return Err(Error::Malformed("0x4f cert_len overruns response payload".into()));
    }
    let tls_cert_184 = &resp4f.payload[4..4 + cert_len];

    // State 4: commit + 0x06 + 0x50 read Block 6
    let _ = dev.cmd_raw(Opcode::Commit, &[])?;
    let _ = dev.transact(&cmd_06)?;
    let resp50 = dev.cmd_raw(Opcode::GetProvisionKey, &[])?;
    if !resp50.status.is_ok() || resp50.payload.len() < 400 {
        return Err(Error::Status {
            opcode: Opcode::GetProvisionKey.byte(),
            status: resp50.status,
        });
    }
    let ecdh_blob_400 = &resp50.payload[resp50.payload.len() - 400..];
    verify_sensor_ecdh_blob_009b(ecdh_blob_400)?;

    // Commit state
    let _ = dev.cmd_raw(Opcode::Commit, &[])?;

    Ok(assemble_certstore_4096(&priv_blob, tls_cert_184, ecdh_blob_400))
}

const fn hexlit_420(s: &str) -> [u8; 420] {
    let b = s.as_bytes();
    assert!(b.len() == 840, "expected 840 hex chars");
    let mut out = [0u8; 420];
    let mut i = 0;
    while i < 420 {
        out[i] = (hexval(b[i * 2]) << 4) | hexval(b[i * 2 + 1]);
        i += 1;
    }
    out
}

/// Compile-time hex literal → `[u8; 32]`.
const fn hexlit(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    assert!(b.len() == 64, "expected 64 hex chars");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (hexval(b[i * 2]) << 4) | hexval(b[i * 2 + 1]);
        i += 1;
    }
    out
}
const fn hexval(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("bad hex"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToSec1Point;

    #[test]
    fn common_root_key_is_on_curve() {
        // If the LE→BE reversal and slot layout are right, this constructs a valid point.
        let k = lookup_root_key(0x06, 0x07, false).expect("common key lookup");
        let _ = k.to_sec1_point(false);
    }

    #[test]
    fn all_root_keys_on_curve() {
        for e in ROOT_KEYS {
            lookup_root_key(e.m0, e.m1, e.flag).unwrap_or_else(|_| {
                panic!(
                    "root key {:02x}:{:02x} flag={} off-curve",
                    e.m0, e.m1, e.flag
                )
            });
        }
    }

    #[test]
    fn ecdh_and_kdf_run() {
        let host = HostEphemeral::random();
        let root = lookup_root_key(0x06, 0x07, false).unwrap();
        let shared = ecdh_shared(&host, &root);
        let (enc, mac) = derive_wrkp_keys(&shared);
        assert_ne!(enc, mac);
    }

    #[test]
    fn hs_key_and_cmd4f_subblock5_verified() {
        let hs_sk = derive_hs_key();
        let hs_pub = hs_sk.public_key();
        let sub5 = build_subblock_5_signed_host_cert(&hs_pub);
        assert_eq!(sub5.len(), 444);

        let sig_len = u32::from_le_bytes(sub5[184..188].try_into().unwrap()) as usize;
        let sig = Signature::from_der(&sub5[188..188 + sig_len]).unwrap();
        let hs_vk = VerifyingKey::from(&hs_pub);
        assert!(hs_vk.verify(&sub5[..184], &sig).is_ok());

        let cmd4f = build_009b_register_host_cert_cmd_0x4f(&hs_pub);
        assert_eq!(cmd4f.len(), 453);
        assert_eq!(&cmd4f[..5], &[0x4f, 0, 0, 0, 0]);
        assert_eq!(&cmd4f[5..9], &[0x05, 0x00, 0xbc, 0x01]);
    }
}
