//! Versioned golden-vector fixtures for bit-exact validation against `synaWudfBioUsb.dll`.
//!
//! Full format spec: `docs/qm/qmfx-format.md` (header, stage IDs, payload conventions).
//! Fixtures are produced by `tools/qm-dll-oracle/` (Wine + pinned DLL hash) and consumed by
//! integration tests. Each stage can be checked independently before end-to-end matching.

use sha2::{Digest, Sha256};
use std::path::Path;

/// Pinned vendor DLL SHA-256 (`windows-driver/synaWudfBioUsb.dll`, MSI 5.5.11.1086).
pub const PINNED_DLL_SHA256: &str =
    "ab56871c7bf83841719b3ae90e8bfdc646bf0f0fd01e49f1b83bdded17d3bf7b";

/// Magic header for binary fixture files (`QMFX`).
pub const FIXTURE_MAGIC: [u8; 4] = *b"QMFX";

/// Fixture format version.
pub const FIXTURE_VERSION: u32 = 1;

/// One validated pipeline stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FixtureStage {
    ConditionedImage = 1,
    FlippedPixels = 2,
    PrimitiveMinutiae = 3,
    VtmlBody = 4,
    AspBlob = 5,
    NeighborCandidates = 6,
    Q16Transform = 7,
    WorkRecordFeatures = 8,
    NormalizedFeatures = 9,
    MlpOutput = 10,
    MatchScore = 11,
    Consensus = 12,
}

/// Parsed fixture metadata + payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fixture {
    pub stage: FixtureStage,
    pub dll_sha256: [u8; 32],
    pub payload: Vec<u8>,
}

impl Fixture {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 4 + 4 + 32 + self.payload.len());
        out.extend_from_slice(&FIXTURE_MAGIC);
        out.extend_from_slice(&FIXTURE_VERSION.to_le_bytes());
        out.extend_from_slice(&(self.stage as u32).to_le_bytes());
        out.extend_from_slice(&self.dll_sha256);
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, OracleError> {
        if bytes.len() < 4 + 4 + 4 + 32 + 4 {
            return Err(OracleError::Truncated);
        }
        if bytes[0..4] != FIXTURE_MAGIC {
            return Err(OracleError::BadMagic);
        }
        let ver = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        if ver != FIXTURE_VERSION {
            return Err(OracleError::UnsupportedVersion(ver));
        }
        let stage = match u32::from_le_bytes(bytes[8..12].try_into().unwrap()) {
            1 => FixtureStage::ConditionedImage,
            2 => FixtureStage::FlippedPixels,
            3 => FixtureStage::PrimitiveMinutiae,
            4 => FixtureStage::VtmlBody,
            5 => FixtureStage::AspBlob,
            6 => FixtureStage::NeighborCandidates,
            7 => FixtureStage::Q16Transform,
            8 => FixtureStage::WorkRecordFeatures,
            9 => FixtureStage::NormalizedFeatures,
            10 => FixtureStage::MlpOutput,
            11 => FixtureStage::MatchScore,
            12 => FixtureStage::Consensus,
            n => return Err(OracleError::UnknownStage(n)),
        };
        let mut dll_sha256 = [0u8; 32];
        dll_sha256.copy_from_slice(&bytes[12..44]);
        let pay_len = u32::from_le_bytes(bytes[44..48].try_into().unwrap()) as usize;
        let body = bytes
            .get(48..48 + pay_len)
            .ok_or(OracleError::Truncated)?;
        Ok(Fixture {
            stage,
            dll_sha256,
            payload: body.to_vec(),
        })
    }

    pub fn load(path: &Path) -> Result<Self, OracleError> {
        let bytes = std::fs::read(path).map_err(|e| OracleError::Io(e.to_string()))?;
        Self::decode(&bytes)
    }
}

/// Verify a DLL on disk matches the pinned research hash.
pub fn verify_pinned_dll(path: &Path) -> Result<(), OracleError> {
    let data = std::fs::read(path).map_err(|e| OracleError::Io(e.to_string()))?;
    let digest = Sha256::digest(&data);
    let got = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if got != PINNED_DLL_SHA256 {
        return Err(OracleError::DllHashMismatch);
    }
    Ok(())
}

// ---- stage 3 (PrimitiveMinutiae) payload -------------------------------------------------------
// The DLL runtime minutia is a 0x20-byte record (`syna_qm_detect_minutiae@0x18000aa00` output
// container, stride 0x20). The SYNA_DUMP_QM tap in the synaTudor relinker writes the container as
// `[u32 count][u8 split][3 pad][count * 0x20 raw records]` (see
// docs/validation/tudor-touch-registration-handoff.md). This parses that payload so the port's
// detector output can be checked against the DLL — most importantly the class partition (gaps #1-3):
// minutiae are ordered class-0 (ridge endings) first, and `split` = the count of that leading run.

/// One DLL runtime minutia (`0x20` bytes). Offsets from `syna_qm_detect_minutiae`:
/// `+0x08` class (0 = ridge ending, non-zero = bifurcation), `+0x09` tile, `+0x0c` angle,
/// `+0x10` score, `+0x14` x, `+0x18` y. The 64-bit descriptor (`+0x00`) is filled by a later PASS-2,
/// so it is typically zero at detection output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawMinutia {
    pub class: u8,
    pub tile: u8,
    pub angle: i32,
    pub score: i32,
    pub x: i32,
    pub y: i32,
}

/// The parsed stage-3 dump: the header count/split plus the runtime minutiae.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectMinutiaeDump {
    /// The template's stored near/far split byte (`min[+0xc]`) — the count of leading class-0 minutiae
    /// that partitions the neighbour pairing (endings vs bifurcations).
    pub split: u8,
    pub minutiae: Vec<RawMinutia>,
}

/// Byte stride of a DLL runtime minutia record.
pub const MINUTIA_STRIDE: usize = 0x20;

impl DetectMinutiaeDump {
    /// Parse the SYNA_DUMP_QM stage-3 payload (`[u32 count][u8 split][3 pad][count*0x20]`).
    ///
    /// # Errors
    /// [`OracleError::Truncated`] if the buffer is shorter than the 8-byte header or the declared
    /// `count` records.
    pub fn parse(bytes: &[u8]) -> Result<Self, OracleError> {
        let header = bytes.get(0..8).ok_or(OracleError::Truncated)?;
        let count = u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
        let split = header[4];
        let body = bytes.get(8..8 + count * MINUTIA_STRIDE).ok_or(OracleError::Truncated)?;
        let minutiae = body
            .chunks_exact(MINUTIA_STRIDE)
            .map(|r| {
                let i32_at = |o: usize| i32::from_le_bytes(r[o..o + 4].try_into().unwrap());
                RawMinutia {
                    class: r[0x08],
                    tile: r[0x09],
                    angle: i32_at(0x0c),
                    score: i32_at(0x10),
                    x: i32_at(0x14),
                    y: i32_at(0x18),
                }
            })
            .collect();
        Ok(Self { split, minutiae })
    }

    /// Count of leading minutiae whose `class == 0` (ridge endings) — what the DLL stores as `split`.
    #[must_use]
    pub fn leading_class0(&self) -> usize {
        self.minutiae.iter().take_while(|m| m.class == 0).count()
    }

    /// Whether the minutiae are class-partitioned: every class-0 precedes every non-zero-class one,
    /// and `split` equals the count of the leading class-0 run. This is the invariant the faithful
    /// neighbour split (gap #1) and candidate ordering (gap #2) rely on.
    #[must_use]
    pub fn is_class_partitioned(&self) -> bool {
        let lead = self.leading_class0();
        self.split as usize == lead && self.minutiae[lead..].iter().all(|m| m.class != 0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OracleError {
    #[error("truncated fixture")]
    Truncated,
    #[error("bad fixture magic")]
    BadMagic,
    #[error("unsupported fixture version {0}")]
    UnsupportedVersion(u32),
    #[error("unknown fixture stage {0}")]
    UnknownStage(u32),
    #[error("DLL SHA-256 does not match pinned oracle")]
    DllHashMismatch,
    #[error("io: {0}")]
    Io(String),
    #[error("internal: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_roundtrip() {
        let fx = Fixture {
            stage: FixtureStage::MatchScore,
            dll_sha256: [0xab; 32],
            payload: vec![1, 2, 3],
        };
        let back = Fixture::decode(&fx.encode()).unwrap();
        assert_eq!(fx, back);
    }

    /// Build a synthetic stage-3 payload: `n` minutiae, the first `split` with class 0.
    fn synth_dump(classes: &[u8]) -> Vec<u8> {
        let split = classes.iter().take_while(|&&c| c == 0).count() as u8;
        let mut out = Vec::new();
        out.extend_from_slice(&(classes.len() as u32).to_le_bytes());
        out.push(split);
        out.extend_from_slice(&[0, 0, 0]); // pad
        for (i, &class) in classes.iter().enumerate() {
            let mut rec = [0u8; MINUTIA_STRIDE];
            rec[0x08] = class;
            rec[0x09] = 1; // tile
            rec[0x0c..0x10].copy_from_slice(&((i as i32 * 15) % 180).to_le_bytes());
            rec[0x10..0x14].copy_from_slice(&(1000 - i as i32).to_le_bytes());
            rec[0x14..0x18].copy_from_slice(&(10 + i as i32).to_le_bytes());
            rec[0x18..0x1c].copy_from_slice(&(20 + i as i32).to_le_bytes());
            out.extend_from_slice(&rec);
        }
        out
    }

    #[test]
    fn stage3_parse_reads_fields_and_split() {
        let dump = DetectMinutiaeDump::parse(&synth_dump(&[0, 0, 0, 1, 1])).unwrap();
        assert_eq!(dump.minutiae.len(), 5);
        assert_eq!(dump.split, 3);
        assert_eq!(dump.minutiae[0].class, 0);
        assert_eq!(dump.minutiae[0].x, 10);
        assert_eq!(dump.minutiae[0].y, 20);
        assert_eq!(dump.minutiae[4].class, 1);
    }

    #[test]
    fn stage3_class_partition_invariant() {
        // Ordered class-0-first with split = leading run: partitioned.
        assert!(DetectMinutiaeDump::parse(&synth_dump(&[0, 0, 1, 1, 1])).unwrap().is_class_partitioned());
        // split mismatch (a class-0 appears after a bifurcation) breaks the invariant.
        assert!(!DetectMinutiaeDump::parse(&synth_dump(&[0, 1, 0, 1])).unwrap().is_class_partitioned());
    }

    #[test]
    fn stage3_parse_rejects_truncation() {
        assert_eq!(DetectMinutiaeDump::parse(&[0, 0]), Err(OracleError::Truncated));
        // header says 4 records but body is empty
        let mut short = Vec::new();
        short.extend_from_slice(&4u32.to_le_bytes());
        short.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(DetectMinutiaeDump::parse(&short), Err(OracleError::Truncated));
    }
}
