//! Algorithm-neutral host-side biometric backend interface.
//!
//! The interface now lives in the leaf crate [`synaptics_biometric`] so the driver, the QM matcher
//! crate, and any OSS matcher can share it without a dependency cycle. This module re-exports it so
//! existing `crate::host_biometric::*` paths keep working; the test-only [`mock`] backend stays here.

pub use synaptics_biometric::{
    ConditionedImage, EnrollProgress, EnrollSession, HostBiometricBackend, HostBiometricError,
    MatchLevel, MatchOutcome,
};

#[cfg(test)]
pub(crate) mod mock;
