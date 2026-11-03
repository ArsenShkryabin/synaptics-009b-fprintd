//! The QM biometric backend now lives in the qm crate (`synaptics_prometheus_qm::backend`), which
//! implements the neutral [`synaptics_biometric::HostBiometricBackend`] seam directly. This module is
//! kept as a re-export so `synaptics_prometheus::QmBackend` and `qm_adapter::QmBackend` still resolve.
//!
//! Compiled only with `--features qm`; the default driver build does not link the QM crate.

pub use synaptics_prometheus_qm::backend::QmBackend;
