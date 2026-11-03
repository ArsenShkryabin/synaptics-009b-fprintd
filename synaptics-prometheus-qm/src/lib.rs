//! synaptics-prometheus-qm — research-only Synaptics QM matcher port.
//!
//! Vendor-derived algorithms and model data live in this crate, isolated from the main
//! driver so the host biometric interface can swap implementations if QM is patent-
//! encumbered. See `../docs/qm/qm-pipeline.md`.
//!
//! **IP gate:** do not publish or ship until patent review clears this port.

pub mod types;

/// QM implementation of the neutral `synaptics_biometric::HostBiometricBackend` seam.
pub mod backend;
pub mod consensus;
pub mod descriptor;
pub mod detect;
pub mod enroll;
pub mod extractor;
pub mod feature_vector;
pub mod int_math;
pub mod matcher;
pub mod geometry_features;
pub mod metviper;
pub mod metviper_weights;
pub mod neighbor;
pub mod oracle;
pub mod scorer;
pub mod scorer_weights;
pub mod similarity;
pub mod template;
pub mod template_cache;
pub mod work_record;

pub use backend::QmBackend;
pub use enroll::{
    EnrollAccumulator, EnrollParams, EnrollSampleStats, EnrolledTemplate, RedundancyHit, SampleOutcome,
    DEFAULT_QUALITY_DENOM, DEFAULT_REDUNDANCY_THRESHOLD, DEFAULT_REQUIRED_MINUTIAE,
    DEFAULT_REQUIRED_SAMPLES, REJECT_STREAK_MAX, SAMPLE_COUNT_BIAS, SUBCODE_PROBE_FAIL,
    SUBCODE_REDUNDANT, SUBCODE_REJECT_STREAK, SUBCODE_SKIP,
};
pub use matcher::{
    diagnose, diagnose_prepared, AnchorDiagnostic, MatchDiagnostics, MatchResult, score,
    score_with_dims,
};
pub use template::{Minutia, Template, TemplateError, DEFAULT_TEMPLATE_IMAGE_H, DEFAULT_TEMPLATE_IMAGE_W};
pub use template_cache::{
    clear_prepared_cache, prepared_enrolled_cached, PreparedEnrolled, PreparedView,
};
