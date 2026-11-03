//! The TLS-1.2-like **handshake** that brings up a [`crate::tls::SessionKeys`] session.
//!
//! Reversed identically from both drivers and byte-for-byte matching
//! `vendor/python-validity/validitysensor/tls.py` (`open`/`make_client_hello`/`make_keys`/
//! `handle_server_hello`/`make_client_kex`/`make_finish`). It is a *custom* TLS profile:
//!  - only cipher suite `0xc005` (`TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA`);
//!  - the peer's ECDH public key (`ecdh_q`) is **pinned from pairing**, not sent in a server
//!    Certificate — so bring-up consumes pairing state (host cert + key + sensor pubkey),
//!    passed in here rather than negotiated.
//!
//! This module is the pure message layer + key derivation; `the driver device layer` drives the USB
//! round-trips. The ephemeral key and randoms are parameters so every transform is testable.

use synaptics_core::error::{Error, Result};
use crate::tls::SessionKeys;
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

/// Handshake message type (the first byte of a handshake message header).
/// ghidra: `handle_handshake` switch (`t`), == python-validity `handle_handshake`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    ClientHello = 0x01,
    ServerHello = 0x02,
    Certificate = 0x0b,
    CertificateRequest = 0x0d,
    ServerHelloDone = 0x0e,
    CertificateVerify = 0x0f,
    ClientKeyExchange = 0x10,
    Finished = 0x14,
}

/// The one cipher suite this protocol speaks: `TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA`.
pub const CIPHER_SUITE: u16 = 0xc005;
/// TLS 1.2 version bytes used everywhere in the record/handshake headers.
pub const TLS_VERSION: [u8; 2] = [3, 3];
const RANDOM_LEN: usize = 0x20;
const VERIFY_DATA_LEN: usize = 0x0c;

/// Length-prefix a chunk with a 2-byte big-endian size (`with_2bytes_size`).
fn with_len16(chunk: &[u8]) -> Vec<u8> {
    let mut v = (chunk.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(chunk);
    v
}

/// A handshake message: `[type][len:3 BE] ‖ body` (`with_neg_hdr`).
fn handshake_msg(t: HandshakeType, body: &[u8]) -> Vec<u8> {
    let len = body.len();
    let mut v = Vec::with_capacity(4 + len);
    v.push(t as u8);
    v.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    v.extend_from_slice(body);
    v
}

/// Running SHA-256 over all handshake messages, for the Finished `verify_data`.
/// ghidra: `handshake_hash` (`self.update_neg`).
#[derive(Clone, Default)]
pub struct Transcript(Sha256);

impl Transcript {
    pub fn new() -> Self {
        Self(Sha256::new())
    }
    /// Feed a fully-framed handshake message (`[type][len:3]‖body`) into the transcript.
    pub fn update(&mut self, framed_msg: &[u8]) {
        self.0.update(framed_msg);
    }
    pub fn hash(&self) -> [u8; 32] {
        self.0.clone().finalize().into()
    }
}

/// Build the ClientHello handshake message (already `[0x01][len:3]`-framed; feed to the
/// transcript and wrap in a Handshake record to send). ghidra: `make_client_hello`.
///
/// Replicates the vendor quirk where the extensions-length field is `len(exts) - 2`.
pub fn client_hello(client_random: &[u8; RANDOM_LEN]) -> Vec<u8> {
    let mut h = Vec::with_capacity(64);
    h.extend_from_slice(&TLS_VERSION);
    h.extend_from_slice(client_random);
    h.push(7); // session id: 7 zero bytes
    h.extend_from_slice(&[0; 7]);

    let mut suites = Vec::new();
    for s in [CIPHER_SUITE, 0x003d, 0x008d] {
        suites.extend_from_slice(&s.to_be_bytes());
    }
    h.extend_from_slice(&with_len16(&suites));
    h.push(0); // compression methods: none

    let ext = |id: u16, body: &[u8]| {
        let mut e = id.to_be_bytes().to_vec();
        e.extend_from_slice(&with_len16(body));
        e
    };
    let mut exts = ext(0x0004, &[0x00, 0x17]); // truncated_hmac
    exts.extend(ext(0x000b, &[0x01, 0x00])); // ec_point_formats = uncompressed
                                             // Vendor bug faithfully reproduced: the length field is `len(exts) - 2`, not `len(exts)`.
    h.extend_from_slice(&((exts.len() - 2) as u16).to_be_bytes());
    h.extend_from_slice(&exts);

    handshake_msg(HandshakeType::ClientHello, &h)
}

/// Parse a ServerHello body (the bytes after the `[0x02][len:3]` header), returning the
/// 32-byte server random. ghidra: `handle_server_hello`.
pub fn parse_server_hello(body: &[u8]) -> Result<[u8; RANDOM_LEN]> {
    // Layout: [version:2][random:32][sid_len:1][sid][suite:2][compression:1].
    let bad = |m: &str| Error::Malformed(format!("ServerHello: {m}"));
    if body.len() < 2 + RANDOM_LEN + 1 {
        return Err(bad("truncated"));
    }
    if body[..2] != TLS_VERSION {
        return Err(bad(&format!("version {}.{}", body[0], body[1])));
    }
    let random: [u8; RANDOM_LEN] = body[2..2 + RANDOM_LEN].try_into().expect("checked len");
    let sid_len = body[2 + RANDOM_LEN] as usize;
    let after_sid = 2 + RANDOM_LEN + 1 + sid_len;
    let suite = body
        .get(after_sid..after_sid + 2)
        .ok_or_else(|| bad("suite overruns"))?;
    let suite = u16::from_be_bytes([suite[0], suite[1]]);
    if suite != CIPHER_SUITE {
        return Err(bad(&format!("unsupported suite {suite:04x}")));
    }
    match body.get(after_sid + 2) {
        Some(0) => Ok(random),
        Some(c) => Err(bad(&format!("compression {c} unsupported"))),
        None => Err(bad("no compression byte")),
    }
}

/// Perform the ECDH agreement and derive the session keys. Returns our ephemeral public key
/// (to send in ClientKeyExchange) alongside the keys. ghidra: `make_keys`.
pub fn derive_session(
    ephemeral: &SecretKey,
    sensor_pub: &PublicKey,
    client_random: &[u8; RANDOM_LEN],
    server_random: &[u8; RANDOM_LEN],
) -> (PublicKey, SessionKeys) {
    let shared = p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), sensor_pub.as_affine());
    let keys = SessionKeys::derive(shared.raw_secret_bytes(), client_random, server_random);
    (ephemeral.public_key(), keys)
}

/// ClientKeyExchange: `0x04 ‖ X ‖ Y` with coordinates **big-endian** (the natural SEC1 form).
/// python-validity `make_client_kex` is `0x04 ‖ to_bytes(x)[::-1] ‖ to_bytes(y)[::-1]`, and
/// `to_bytes` is *little-endian*, so the `[::-1]` yields big-endian — i.e. the coordinates are
/// sent as-is, NOT reversed. (The on-flash `ecdh` blob stores them LE; the wire uses BE.)
pub fn client_key_exchange(session_public: &PublicKey) -> Vec<u8> {
    let point = session_public.to_sec1_point(false);
    let mut body = Vec::with_capacity(1 + 64);
    body.push(0x04);
    for coord in [point.x(), point.y()] {
        let c = coord.expect("uncompressed point has both coordinates");
        body.extend_from_slice(c); // big-endian, unreversed
    }
    handshake_msg(HandshakeType::ClientKeyExchange, &body)
}

/// CertificateVerify: DER ECDSA-P256-SHA256 signature over the running transcript hash,
/// signed with the host's paired private key. ghidra: `make_cert_verify`.
pub fn certificate_verify(host_priv: &SigningKey, transcript: &Transcript) -> Result<Vec<u8>> {
    let sig: Signature = host_priv
        .sign_prehash(&transcript.hash())
        .map_err(|e| Error::Crypto(format!("cert_verify sign: {e}")))?;
    Ok(handshake_msg(
        HandshakeType::CertificateVerify,
        sig.to_der().as_bytes(),
    ))
}

/// The Finished `verify_data`: `prf(master_secret, label ‖ transcript_hash, 12)`.
/// `label` is `b"client finished"` for our Finished, `b"server finished"` to check theirs.
/// ghidra: `make_finish` / `handle_finish`.
pub fn verify_data(
    master_secret: &[u8],
    label: &[u8],
    transcript: &Transcript,
) -> [u8; VERIFY_DATA_LEN] {
    let mut seed = label.to_vec();
    seed.extend_from_slice(&transcript.hash());
    let out = crate::crypto::prf(master_secret, &seed, VERIFY_DATA_LEN);
    out.try_into().expect("prf returns requested length")
}

/// Finished handshake message: `[0x14][len:3] ‖ verify_data`.
pub fn finished(verify_data: &[u8; VERIFY_DATA_LEN]) -> Vec<u8> {
    handshake_msg(HandshakeType::Finished, verify_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_layout() {
        let cr = [0x5a; RANDOM_LEN];
        let m = client_hello(&cr);
        assert_eq!(m[0], HandshakeType::ClientHello as u8);
        let body = &m[4..]; // skip [type][len:3]
        assert_eq!(&body[0..2], &TLS_VERSION);
        assert_eq!(&body[2..2 + RANDOM_LEN], &cr); // client random
                                                   // suite list contains 0xc005
        assert!(body.windows(2).any(|w| w == CIPHER_SUITE.to_be_bytes()));
    }

    #[test]
    fn server_hello_parses() {
        let sr = [0x33u8; RANDOM_LEN];
        let mut body = TLS_VERSION.to_vec();
        body.extend_from_slice(&sr);
        body.push(0); // empty session id
        body.extend_from_slice(&CIPHER_SUITE.to_be_bytes());
        body.push(0); // no compression
        assert_eq!(parse_server_hello(&body).unwrap(), sr);
    }

    #[test]
    fn server_hello_rejects_wrong_suite() {
        let mut body = TLS_VERSION.to_vec();
        body.extend_from_slice(&[0u8; RANDOM_LEN]);
        body.push(0);
        body.extend_from_slice(&0x1234u16.to_be_bytes());
        body.push(0);
        assert!(parse_server_hello(&body).is_err());
    }

    #[test]
    fn ecdh_both_sides_derive_equal_keys() {
        // Two fixed test keys; ECDH(a, B) == ECDH(b, A) ⇒ identical session keys.
        let a = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let b = SecretKey::from_slice(&[0x22; 32]).unwrap();
        let (cr, sr) = (&[1u8; 0x20], &[2u8; 0x20]);
        let (a_pub, ka) = derive_session(&a, &b.public_key(), cr, sr);
        let (b_pub, kb) = derive_session(&b, &a.public_key(), cr, sr);
        assert_eq!(ka.encryption, kb.encryption);
        assert_eq!(ka.sign, kb.sign);
        assert_eq!(a_pub, a.public_key());
        assert_eq!(b_pub, b.public_key());
    }

    #[test]
    fn verify_data_is_12_bytes_and_label_sensitive() {
        let t = Transcript::new();
        let c = verify_data(b"ms", b"client finished", &t);
        let s = verify_data(b"ms", b"server finished", &t);
        assert_eq!(c.len(), VERIFY_DATA_LEN);
        assert_ne!(c, s);
    }

    #[test]
    fn cert_verify_produces_der_signature() {
        let key = SigningKey::from_slice(&[0x42; 32]).unwrap();
        let msg = certificate_verify(&key, &Transcript::new()).unwrap();
        assert_eq!(msg[0], HandshakeType::CertificateVerify as u8);
        assert!(msg.len() > 4);
    }
}
