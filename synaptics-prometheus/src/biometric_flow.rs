//! Host enroll / verify orchestration, **capture-source agnostic**.
//!
//! The `capture` callback yields one conditioned `144×56` frame. The live driver supplies a callback
//! backed by [`crate::session::Session`] capture + reconstruction + conditioning — a **finger-gated**
//! operation (AGENTS.md #1), so the live loop lives only in `examples/enroll.rs`, which announces and
//! waits for the user each touch. Tests supply synthetic frames. This keeps the flow logic pure and
//! hardware-free while the same functions drive real enrollment/verification.

use crate::host_biometric::{
    ConditionedImage, HostBiometricBackend, HostBiometricError, MatchLevel, MatchOutcome,
    EnrollProgress,
};
use crate::template_store::TemplateStore;
use std::io;

/// Conditioned-frame geometry the flow feeds to the backend (subtype `0x2449`).
pub const ENROLL_WIDTH: u16 = 144;
pub const ENROLL_HEIGHT: u16 = 56;
/// Safety cap on enrollment touches (a real enroll completes in `~8`; this guards against a finger
/// that never yields enough distinct coverage).
pub const MAX_ENROLL_TOUCHES: u32 = 32;

/// Result of a completed enrollment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrollSummary {
    pub views: usize,
    pub touches: u32,
}

/// Errors from an enroll/verify flow. `E` is the capture callback's error type.
#[derive(Debug)]
pub enum FlowError<E> {
    /// The capture callback failed.
    Capture(E),
    /// The backend (extract/enroll/verify) failed.
    Backend(HostBiometricError),
    /// The template store failed.
    Store(io::Error),
    /// Enrollment hard-failed (too many rejects, or the touch cap was hit).
    EnrollFailed,
    /// Verify: no template enrolled for `(user, subtype)`.
    NotEnrolled,
}

/// Drive an enrollment to completion, then persist it. `capture` yields a conditioned `144×56` frame;
/// `on_progress` is called after each touch (for UI). Finger-gated when `capture` reads hardware.
pub fn enroll_finger<B, F, P, E>(
    backend: &B,
    store: &TemplateStore,
    user: u32,
    subtype: u8,
    mut capture: F,
    mut on_progress: P,
) -> Result<EnrollSummary, FlowError<E>>
where
    B: HostBiometricBackend,
    F: FnMut() -> Result<Vec<u8>, E>,
    P: FnMut(&EnrollProgress),
{
    let mut session = backend.new_enrollment();
    let mut touches = 0u32;
    let views;
    loop {
        if touches >= MAX_ENROLL_TOUCHES {
            return Err(FlowError::EnrollFailed);
        }
        touches += 1;
        let px = capture().map_err(FlowError::Capture)?;
        let img = ConditionedImage {
            pixels: &px,
            width: ENROLL_WIDTH,
            height: ENROLL_HEIGHT,
            stride: ENROLL_WIDTH,
        };
        let progress = session.add_sample(img).map_err(FlowError::Backend)?;
        on_progress(&progress);
        if progress.failed {
            return Err(FlowError::EnrollFailed);
        }
        if session.is_complete() {
            views = progress.views;
            break;
        }
    }
    let blob = session.finalize().map_err(FlowError::Backend)?;
    store.store(user, subtype, &blob).map_err(FlowError::Store)?;
    Ok(EnrollSummary { views, touches })
}

/// Verify one captured frame against the enrolled template for `(user, subtype)`.
pub fn verify_finger<B, F, E>(
    backend: &B,
    store: &TemplateStore,
    user: u32,
    subtype: u8,
    level: MatchLevel,
    mut capture: F,
) -> Result<MatchOutcome, FlowError<E>>
where
    B: HostBiometricBackend,
    F: FnMut() -> Result<Vec<u8>, E>,
{
    let enrolled = store
        .load_blob(user, subtype)
        .map_err(FlowError::Store)?
        .ok_or(FlowError::NotEnrolled)?;
    let px = capture().map_err(FlowError::Capture)?;
    let img = ConditionedImage {
        pixels: &px,
        width: ENROLL_WIDTH,
        height: ENROLL_HEIGHT,
        stride: ENROLL_WIDTH,
    };
    let probe = backend.extract_template(img).map_err(FlowError::Backend)?;
    backend.verify(&probe, &enrolled, level).map_err(FlowError::Backend)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_biometric::mock::MockBackend;

    fn frame(fill: u8) -> Vec<u8> {
        vec![fill; ENROLL_WIDTH as usize * ENROLL_HEIGHT as usize]
    }

    #[test]
    fn enroll_completes_stores_then_verifies() {
        let backend = MockBackend;
        let root = std::env::temp_dir().join(format!("spts_flow_mock_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = TemplateStore::open(&root).unwrap();

        // distinct frames → distinct mock views → completes at MockBackend's required count
        let mut n = 0u8;
        let summary = enroll_finger(
            &backend,
            &store,
            1,
            0x05,
            || {
                n += 1;
                Ok::<_, ()>(frame(n))
            },
            |_p| {},
        )
        .expect("enroll completes");
        assert!(summary.views >= 3);
        assert!(store.load_blob(1, 0x05).unwrap().is_some());

        // verify with a frame equal to an enrolled view → the mock matches
        let outcome = verify_finger(&backend, &store, 1, 0x05, MatchLevel::Level1, || Ok::<_, ()>(frame(2)))
            .expect("verify runs");
        assert!(outcome.matched, "an enrolled frame should verify against the mock");

        // verify a never-enrolled frame → not matched
        let miss = verify_finger(&backend, &store, 1, 0x05, MatchLevel::Level1, || Ok::<_, ()>(frame(200)))
            .expect("verify runs");
        assert!(!miss.matched);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn verify_without_enrollment_errors() {
        let backend = MockBackend;
        let root = std::env::temp_dir().join(format!("spts_flow_none_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = TemplateStore::open(&root).unwrap();
        let r = verify_finger(&backend, &store, 7, 0x01, MatchLevel::Level1, || Ok::<_, ()>(frame(1)));
        assert!(matches!(r, Err(FlowError::NotEnrolled)));
        let _ = std::fs::remove_dir_all(&root);
    }
}
