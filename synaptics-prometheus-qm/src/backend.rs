//! QM implementation of the neutral [`synaptics_biometric::HostBiometricBackend`] seam.
//!
//! This lets the QM matcher be dropped into the driver (or any consumer) as an opaque biometric
//! backend without a main-crate adapter. Research-only; see the crate docs.

use synaptics_biometric::{
    ConditionedImage, EnrollProgress, EnrollSession, HostBiometricBackend, HostBiometricError,
    MatchLevel, MatchOutcome,
};

use crate::types::MatchLevel as QmMatchLevel;
use crate::{EnrollAccumulator, EnrolledTemplate, SampleOutcome, Template, score_with_dims};

/// QM-backed host biometric backend (research only).
#[derive(Debug, Default, Clone, Copy)]
pub struct QmBackend;

impl QmBackend {
    pub fn new() -> Self {
        Self
    }
}

/// Map the neutral security level to the QM crate's.
fn to_qm_level(level: MatchLevel) -> QmMatchLevel {
    match level {
        MatchLevel::Level1 => QmMatchLevel::Level1,
        MatchLevel::Level2 => QmMatchLevel::Level2,
        MatchLevel::Level3 => QmMatchLevel::Level3,
    }
}

/// Wrap a QM [`crate::MatchResult`] into the neutral [`MatchOutcome`].
fn to_outcome(r: &crate::MatchResult) -> MatchOutcome {
    MatchOutcome {
        score: r.score,
        threshold: r.threshold_used,
        matched: r.decision,
        consensus_ok: r.consensus.found,
        anchor_count: r.anchor_count,
    }
}

/// QM multi-view enrollment session (wraps [`EnrollAccumulator`]).
struct QmEnrollSession {
    acc: EnrollAccumulator,
}

impl EnrollSession for QmEnrollSession {
    fn add_sample(&mut self, image: ConditionedImage<'_>) -> Result<EnrollProgress, HostBiometricError> {
        image.validated_pixels()?;
        use crate::extractor::{extract_template, ExtractError};
        let outcome = match extract_template(image) {
            Ok(t) => self.acc.add_sample(t),
            // extractor found too few minutiae → treat as an out-of-spec capture (bumps reject streak)
            Err(ExtractError::TooFewMinutiae) => self.acc.reject(),
            Err(ExtractError::InvalidGeometry) => {
                return Err(HostBiometricError::InvalidImage("geometry".into()))
            }
            Err(ExtractError::Unsupported) => return Err(HostBiometricError::ExtractionUnsupported),
        };
        let (accepted, redundant, failed) = match outcome {
            SampleOutcome::Accepted { .. } => (true, false, false),
            SampleOutcome::Redundant { .. } => (false, true, false),
            SampleOutcome::Rejected { .. } => (false, false, false),
            SampleOutcome::Failed => (false, false, true),
        };
        Ok(EnrollProgress {
            accepted,
            redundant,
            failed,
            views: self.acc.view_count(),
            samples: self.acc.samples(),
            percent: self.acc.percent(),
            done: self.acc.is_complete(),
        })
    }

    fn is_complete(&self) -> bool {
        self.acc.is_complete()
    }

    fn finalize(self: Box<Self>) -> Result<Vec<u8>, HostBiometricError> {
        self.acc
            .finalize()
            .ok_or_else(|| HostBiometricError::Backend("no views enrolled".into()))?
            .to_blob()
            .map_err(|e| HostBiometricError::InvalidTemplate(format!("{e:?}")))
    }
}

impl HostBiometricBackend for QmBackend {
    fn extract_template(
        &self,
        image: ConditionedImage<'_>,
    ) -> Result<Vec<u8>, HostBiometricError> {
        image.validated_pixels()?;
        let template = crate::extractor::extract_template(image).map_err(|e| match e {
            crate::extractor::ExtractError::InvalidGeometry => {
                HostBiometricError::InvalidImage("geometry".into())
            }
            crate::extractor::ExtractError::TooFewMinutiae => {
                HostBiometricError::Backend("too few minutiae".into())
            }
            crate::extractor::ExtractError::Unsupported => HostBiometricError::ExtractionUnsupported,
        })?;
        template
            .to_blob()
            .map_err(|e| HostBiometricError::InvalidTemplate(format!("{e:?}")))
    }

    fn match_templates(
        &self,
        probe: &[u8],
        gallery: &[u8],
        level: MatchLevel,
    ) -> Result<MatchOutcome, HostBiometricError> {
        let probe = Template::from_blob(probe)
            .map_err(|e| HostBiometricError::InvalidTemplate(format!("{e:?}")))?;
        let gallery = Template::from_blob(gallery)
            .map_err(|e| HostBiometricError::InvalidTemplate(format!("{e:?}")))?;
        let r = score_with_dims(
            &probe,
            &gallery,
            to_qm_level(level),
            crate::matcher::DEFAULT_IMAGE_W,
            crate::matcher::DEFAULT_IMAGE_H,
        );
        Ok(to_outcome(&r))
    }

    fn new_enrollment(&self) -> Box<dyn EnrollSession> {
        Box::new(QmEnrollSession {
            acc: EnrollAccumulator::new(crate::detect::SUBTYPE_2449),
        })
    }

    fn verify(
        &self,
        probe: &[u8],
        enrolled: &[u8],
        level: MatchLevel,
    ) -> Result<MatchOutcome, HostBiometricError> {
        let probe = Template::from_blob(probe)
            .map_err(|e| HostBiometricError::InvalidTemplate(format!("{e:?}")))?;
        let enrolled = EnrolledTemplate::from_blob(enrolled)
            .map_err(|e| HostBiometricError::InvalidTemplate(format!("{e:?}")))?;
        let qm_level = to_qm_level(level);
        match enrolled.identify(&probe, qm_level) {
            Some((_i, r)) => Ok(to_outcome(&r)),
            // no views enrolled — a non-match at this level's threshold
            None => Ok(MatchOutcome {
                score: 0,
                threshold: qm_level.threshold(),
                matched: false,
                consensus_ok: false,
                anchor_count: 0,
            }),
        }
    }
}

#[cfg(test)]
mod conformance_tests {
    //! The QM backend is the driver's only real [`HostBiometricBackend`], so it is the conformance
    //! witness for the seam: if the trait or `QmBackend` drift so the matcher is no longer a drop-in,
    //! these fail. Deterministic by construction — they exercise the object-safe seam and the
    //! blob-validation error paths only, never synthetic-image matcher scoring (AGENTS.md Rule #7).
    use super::*;

    /// Compile-time: `QmBackend` satisfies the neutral trait bound (a future OSS backend swaps in here).
    fn _assert_impls_backend<T: HostBiometricBackend>() {}
    const _: fn() = || _assert_impls_backend::<QmBackend>();

    /// The backend is usable through a trait object — the form the driver actually stores it as.
    fn as_dyn(b: &QmBackend) -> &dyn HostBiometricBackend {
        b
    }

    #[test]
    fn match_and_verify_reject_malformed_blobs_through_the_trait_object() {
        let backend = QmBackend::new();
        let dyn_backend = as_dyn(&backend);
        // A garbage blob must surface as InvalidTemplate at the seam, not panic — this is the
        // contract a consumer relies on when feeding it stored templates.
        let err = dyn_backend
            .match_templates(b"not-a-template", b"also-not", MatchLevel::Level2)
            .unwrap_err();
        assert!(matches!(err, HostBiometricError::InvalidTemplate(_)));
        let verr = dyn_backend
            .verify(b"junk", b"junk", MatchLevel::Level3)
            .unwrap_err();
        assert!(matches!(verr, HostBiometricError::InvalidTemplate(_)));
    }

    #[test]
    fn fresh_enrollment_session_starts_incomplete() {
        let backend = QmBackend::new();
        let session = as_dyn(&backend).new_enrollment();
        assert!(!session.is_complete(), "a session with no samples cannot be complete");
    }
}
