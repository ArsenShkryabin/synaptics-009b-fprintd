//! Mock backend for testing the swappable [`super::HostBiometricBackend`] trait.

use super::{
    ConditionedImage, EnrollProgress, EnrollSession, HostBiometricBackend, HostBiometricError,
    MatchLevel, MatchOutcome,
};

/// Deterministic stub backend for unit tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct MockBackend;

/// Mock enrollment: accepts distinct captures until `REQUIRED` are collected; the enrolled blob is a
/// length-prefixed concatenation of the accepted views.
struct MockEnrollSession {
    views: Vec<Vec<u8>>,
    samples: u32,
}
const MOCK_REQUIRED_VIEWS: usize = 3;

impl EnrollSession for MockEnrollSession {
    fn add_sample(&mut self, image: ConditionedImage<'_>) -> Result<EnrollProgress, HostBiometricError> {
        self.samples += 1;
        let blob = image.validated_pixels()?.to_vec();
        let redundant = self.views.contains(&blob);
        if !redundant {
            self.views.push(blob);
        }
        let views = self.views.len();
        Ok(EnrollProgress {
            accepted: !redundant,
            redundant,
            failed: false,
            views,
            samples: self.samples,
            percent: ((views.min(MOCK_REQUIRED_VIEWS) * 100 / MOCK_REQUIRED_VIEWS) as u8),
            done: views >= MOCK_REQUIRED_VIEWS,
        })
    }
    fn is_complete(&self) -> bool {
        self.views.len() >= MOCK_REQUIRED_VIEWS
    }
    fn finalize(self: Box<Self>) -> Result<Vec<u8>, HostBiometricError> {
        let mut out = (self.views.len() as u32).to_le_bytes().to_vec();
        for v in &self.views {
            out.extend_from_slice(&(v.len() as u32).to_le_bytes());
            out.extend_from_slice(v);
        }
        Ok(out)
    }
}

impl MockBackend {
    fn parse_views(enrolled: &[u8]) -> Vec<&[u8]> {
        let mut out = Vec::new();
        let mut c = 4usize; // skip count
        while c + 4 <= enrolled.len() {
            let len = u32::from_le_bytes(enrolled[c..c + 4].try_into().unwrap()) as usize;
            c += 4;
            if let Some(v) = enrolled.get(c..c + len) {
                out.push(v);
                c += len;
            } else {
                break;
            }
        }
        out
    }
}

impl HostBiometricBackend for MockBackend {
    fn extract_template(
        &self,
        image: ConditionedImage<'_>,
    ) -> Result<Vec<u8>, HostBiometricError> {
        let px = image.validated_pixels()?;
        Ok(px.to_vec())
    }

    fn match_templates(
        &self,
        probe: &[u8],
        gallery: &[u8],
        level: MatchLevel,
    ) -> Result<MatchOutcome, HostBiometricError> {
        let threshold = match level {
            MatchLevel::Level1 => 1200,
            MatchLevel::Level2 => 2251,
            MatchLevel::Level3 => 2501,
        };
        let score = if probe == gallery { threshold + 1 } else { 0 };
        Ok(MatchOutcome {
            score,
            threshold,
            matched: score > threshold,
            consensus_ok: probe == gallery,
            anchor_count: if probe == gallery { 1 } else { 0 },
        })
    }

    fn new_enrollment(&self) -> Box<dyn EnrollSession> {
        Box::new(MockEnrollSession { views: Vec::new(), samples: 0 })
    }

    fn verify(
        &self,
        probe: &[u8],
        enrolled: &[u8],
        level: MatchLevel,
    ) -> Result<MatchOutcome, HostBiometricError> {
        // best match across the enrolled views
        let mut best = self.match_templates(probe, &[], level)?;
        for v in Self::parse_views(enrolled) {
            let o = self.match_templates(probe, v, level)?;
            if o.score >= best.score {
                best = o;
            }
        }
        Ok(best)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_backend_self_match() {
        let b = MockBackend;
        let blob = b
            .extract_template(ConditionedImage {
                pixels: &[1, 2, 3, 4],
                width: 2,
                height: 2,
                stride: 2,
            })
            .unwrap();
        let o = b
            .match_templates(&blob, &blob, MatchLevel::Level1)
            .unwrap();
        assert!(o.matched);
    }
}
