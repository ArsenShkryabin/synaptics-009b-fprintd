//! # synaptics-proto
//!
//! The Synaptics Prometheus command protocol — the wire [`proto::Opcode`] table, the SCS
//! command-index map, and the sensor response parsers. A leaf above [`synaptics_core`] (uses its
//! error model + wire cursor) and nothing else in the workspace.

pub mod proto;
