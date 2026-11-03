//! Algorithm-neutral host-side biometric backend interface.
//!
//! The driver captures and reconstructs conditioned images; a concrete backend turns those
//! pixels into opaque template bytes and scores template pairs. This interface is intentionally
//! free of any matcher-specific types so an alternative matcher (the research-only QM port, or an
//! OSS matcher such as an NBIS/SourceAFIS-style implementation) can replace it without touching the
//! capture/session code. `synaptics-prometheus-qm` and `synaptics-prometheus` both depend on this
//! leaf crate; a new backend is a drop-in `impl HostBiometricBackend`.

use thiserror::Error;

/// A conditioned grayscale frame ready for template extraction.
///
/// `stride` is the byte distance between row starts (may exceed `width`). Pixels are
/// row-major; only the first `width` bytes of each row are valid image data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConditionedImage<'a> {
    pub pixels: &'a [u8],
    pub width: u16,
    pub height: u16,
    pub stride: u16,
}

impl<'a> ConditionedImage<'a> {
    /// Validate geometry and return the contiguous `width × height` pixel slice in row order.
    pub fn validated_pixels(self) -> Result<&'a [u8], HostBiometricError> {
        let w = self.width as usize;
        let h = self.height as usize;
        let stride = self.stride as usize;
        if w == 0 || h == 0 {
            return Err(HostBiometricError::InvalidImage(
                "width and height must be non-zero".into(),
            ));
        }
        if stride < w {
            return Err(HostBiometricError::InvalidImage(format!(
                "stride {stride} < width {w}"
            )));
        }
        let need = stride * (h - 1) + w;
        if self.pixels.len() < need {
            return Err(HostBiometricError::InvalidImage(format!(
                "buffer {} bytes, need {need} for {w}x{h} stride {stride}",
                self.pixels.len()
            )));
        }
        Ok(self.pixels)
    }
}

/// Generic security level for template-pair comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchLevel {
    Level1,
    Level2,
    Level3,
}

/// Outcome of comparing a probe template against one gallery template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchOutcome {
    pub score: u32,
    pub threshold: u32,
    pub matched: bool,
    pub consensus_ok: bool,
    pub anchor_count: usize,
}

/// Errors from host-side biometric operations (algorithm-neutral).
#[derive(Debug, Error)]
pub enum HostBiometricError {
    #[error("invalid image: {0}")]
    InvalidImage(String),
    #[error("invalid template: {0}")]
    InvalidTemplate(String),
    #[error("extraction not supported")]
    ExtractionUnsupported,
    #[error("backend error: {0}")]
    Backend(String),
}

/// Progress after feeding one capture to an [`EnrollSession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrollProgress {
    /// A new distinct view was added.
    pub accepted: bool,
    /// The capture overlapped an accepted view and was skipped.
    pub redundant: bool,
    /// Enrollment has hard-failed (too many out-of-spec captures) — abandon it.
    pub failed: bool,
    /// Accepted views so far.
    pub views: usize,
    /// Total captures fed so far.
    pub samples: u32,
    /// Progress `0..=100`.
    pub percent: u8,
    /// Enrollment is complete — [`EnrollSession::finalize`] may be called.
    pub done: bool,
}

/// A stateful multi-capture enrollment. Feed conditioned frames until [`Self::is_complete`], then
/// [`Self::finalize`] into an opaque enrolled-template blob (backend-defined; consumed by
/// [`HostBiometricBackend::verify`]).
pub trait EnrollSession: Send {
    /// Feed one captured frame; returns progress.
    fn add_sample(&mut self, image: ConditionedImage<'_>) -> Result<EnrollProgress, HostBiometricError>;
    /// Whether enough captures have been accepted.
    fn is_complete(&self) -> bool;
    /// Consume the session into the enrolled-template blob.
    fn finalize(self: Box<Self>) -> Result<Vec<u8>, HostBiometricError>;
}

/// Host-side template extraction, enrollment, and matching — swappable implementation.
///
/// A backend defines its own opaque template byte format; the driver treats templates as bytes and
/// only compares them through this trait. To add a new matcher (e.g. an OSS one), implement this
/// trait plus [`EnrollSession`] — no capture/session changes are needed.
pub trait HostBiometricBackend: Send + Sync {
    /// Encode a conditioned image into an opaque probe template blob.
    fn extract_template(
        &self,
        image: ConditionedImage<'_>,
    ) -> Result<Vec<u8>, HostBiometricError>;

    /// Score a probe template against a gallery template at the given security level.
    fn match_templates(
        &self,
        probe: &[u8],
        gallery: &[u8],
        level: MatchLevel,
    ) -> Result<MatchOutcome, HostBiometricError>;

    /// Start a stateful multi-capture enrollment.
    fn new_enrollment(&self) -> Box<dyn EnrollSession>;

    /// Verify a probe template against an enrolled multi-view template (produced by
    /// [`EnrollSession::finalize`]) — the best match across the enrolled views.
    fn verify(
        &self,
        probe: &[u8],
        enrolled: &[u8],
        level: MatchLevel,
    ) -> Result<MatchOutcome, HostBiometricError>;
}
