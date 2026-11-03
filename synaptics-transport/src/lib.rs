//! # synaptics-transport
//!
//! The USB transport seam for the Synaptics Prometheus driver — the swappable [`transport::Transport`]
//! trait plus the pure-Rust `nusb` backend (`NusbTransport`, behind the `nusb-backend` feature). A
//! leaf above [`synaptics_core`] (uses its error model + pcap wire log) and nothing else.

pub mod transport;
