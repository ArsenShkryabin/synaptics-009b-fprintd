//! # synaptics-crypto
//!
//! The secure-session crypto for the Synaptics Prometheus driver — the family-wide primitives and
//! protocol layers that bring up the encrypted app-data tunnel. Modules:
//!
//!   * [`crypto`] — AES-256-CBC, HMAC-SHA256, the TLS PRF, PKCS#7, constant-time compare.
//!   * [`tls`] — the TLS 1.2 record layer (wrap/unwrap) + derived [`tls::SessionKeys`].
//!   * [`handshake`] — the ClientHello…Finished ECDH handshake message layer + key derivation.
//!   * [`pairing`] — cert-store parse + unseal (host-key pairing).
//!
//! Sits above [`synaptics_core`] (error model, pcap log) and [`synaptics_transport`] (USB endpoint
//! constants for wire logging); everything device-specific lives above this in the driver crate.

pub mod crypto;
pub mod handshake;
pub mod pairing;
pub mod tls;
