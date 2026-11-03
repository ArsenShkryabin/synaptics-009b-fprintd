//! # synaptics-core
//!
//! Foundation utilities shared across the Synaptics Prometheus driver crates — the deepest leaf in
//! the workspace, depending on nothing else in it. Modules:
//!
//!   * [`error`] — the [`Error`]/[`Result`] model and the wire [`Status`] code table.
//!   * [`wire`] — the bounds-checked little-endian [`wire::Cursor`] reader shared by the response
//!     parsers (panic-free framing).
//!   * [`pcap_log`] — opt-in pcapng wire-logging of USB/TLS transfers (a diagnostic sink shared by
//!     the transport + crypto layers).

pub mod error;
pub mod pcap_log;
pub mod wire;

pub use error::{Error, Result, Status};
