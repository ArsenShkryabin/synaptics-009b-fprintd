//! Windsor recon-config blob (`tag 0x30000288`) — the coefficient table the sensor returns in the
//! `0x02` capture-arm reply, unpacked host-side by `syna_capture_recon_setup@0x1800681e0` →
//! `syna_capture_recon_windsor_store@0x18009b4b0` → `syna_capture_recon_windsor_unpack@0x18009b600`.
//!
//! Layout (little-endian `u32` words), from `windsor_unpack`:
//! ```text
//!   word[0]                 = tag = 0x30000288   (validated)
//!   word[1]                 = coeff_count         (unpacked out.size = coeff_count << 2)
//!   word[2 .. 2+coeff_count] = u32 coefficient table (out.data = &word[2])
//! ```
//!
//! IMPORTANT (Ghidra + on-device, 2026-07-25): this is a *reconstruction-quality* input, NOT the
//! get-a-body fix for the recon=8 `0x0537` (see [`recon8-0537-prearm-rom-config`] memory). Two facts
//! bound how it is used:
//!  - `syna_capture_recon_setup` does ZERO wire I/O — it only stores this blob on the scs ctx
//!    (`ctx+0x80` raw, unpacked view `ctx+0x88`). It cannot clear a sensor-side status.
//!  - `syna_capture_image@0x180099540`'s host read does ONLY re-stride (8 zero bytes + memmove per
//!    row) — it does **not** apply these coefficients to the captured frame. The flat recon=8
//!    baseline is firmware-side. The unpacked table at `ctx+0x88` is consumed LATER by the matcher
//!    reconstruction, not the capture read.
//!
//! So this module *captures + parses* the config so it is available to a session
//! ([`crate::session::Session::take_recon_config`]); *applying* the coefficients belongs to the
//! (research-only) matcher-recon path and awaits a trace of the `ctx+0x88` consumer against a golden
//! recon=8 capture (Phase A). We deliberately do not fabricate the transform here.

/// Windsor recon-config TLV tag (`*param_2 == 0x30000288` in `windsor_store`).
pub const WINDSOR_RECON_CONFIG_TAG: u32 = 0x3000_0288;

/// Largest coefficient table we will accept from an untrusted reply (guards a bogus length word).
const MAX_RECON_COEFFS: usize = 0x4000;

/// Parsed windsor recon-config: the `u32` coefficient table from the `0x02` arm reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindsorReconConfig {
    /// The `coeff_count` little-endian `u32` coefficients (`&word[2..]`).
    pub coeffs: Vec<u32>,
}

impl WindsorReconConfig {
    /// Parse a blob that **starts** with the tag word (as `windsor_store` receives it). Returns
    /// `None` if the tag mismatches, the declared count is implausible, or it overruns `blob`.
    #[must_use]
    pub fn parse(blob: &[u8]) -> Option<Self> {
        if blob.len() < 8 {
            return None;
        }
        let tag = u32::from_le_bytes(blob[0..4].try_into().ok()?);
        if tag != WINDSOR_RECON_CONFIG_TAG {
            return None;
        }
        let count = u32::from_le_bytes(blob[4..8].try_into().ok()?) as usize;
        if count == 0 || count > MAX_RECON_COEFFS {
            return None;
        }
        let need = 8usize.checked_add(count.checked_mul(4)?)?;
        if blob.len() < need {
            return None;
        }
        let coeffs = blob[8..need]
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        Some(Self { coeffs })
    }

    /// Byte size of the unpacked coefficient table (`out.size = coeff_count << 2` in `windsor_unpack`).
    #[must_use]
    pub fn table_bytes(&self) -> usize {
        self.coeffs.len() * 4
    }

    /// Locate + parse the tag-`0x30000288` recon-config anywhere in a `0x02` arm reply
    /// (`[status:u16][..]`). The exact byte offset of the blob within the reply is not yet pinned
    /// (awaiting the golden recon=8 capture), so we scan for the distinctive tag and validate the
    /// declared table fits. Returns the first structurally-valid match.
    #[must_use]
    pub fn find_in_arm_reply(reply: &[u8]) -> Option<Self> {
        let tag = WINDSOR_RECON_CONFIG_TAG.to_le_bytes();
        reply
            .windows(4)
            .enumerate()
            .filter(|(_, w)| *w == tag)
            .find_map(|(i, _)| Self::parse(&reply[i..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(count: u32, coeffs: &[u32]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&WINDSOR_RECON_CONFIG_TAG.to_le_bytes());
        b.extend_from_slice(&count.to_le_bytes());
        for &c in coeffs {
            b.extend_from_slice(&c.to_le_bytes());
        }
        b
    }

    #[test]
    fn parses_valid_blob() {
        let b = blob(3, &[0x1111_1111, 0x2222_2222, 0x3333_3333]);
        let cfg = WindsorReconConfig::parse(&b).expect("valid");
        assert_eq!(cfg.coeffs, vec![0x1111_1111, 0x2222_2222, 0x3333_3333]);
        assert_eq!(cfg.table_bytes(), 12); // out.size = count << 2
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut b = blob(1, &[0xdead_beef]);
        b[0] ^= 0xff;
        assert!(WindsorReconConfig::parse(&b).is_none());
    }

    #[test]
    fn rejects_count_overrun() {
        // Declares 4 coeffs but only carries 1.
        let mut b = blob(1, &[0xaaaa_aaaa]);
        b[4..8].copy_from_slice(&4u32.to_le_bytes());
        assert!(WindsorReconConfig::parse(&b).is_none());
    }

    #[test]
    fn rejects_zero_and_absurd_count() {
        assert!(WindsorReconConfig::parse(&blob(0, &[])).is_none());
        let mut b = blob(1, &[0]);
        b[4..8].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        assert!(WindsorReconConfig::parse(&b).is_none());
    }

    #[test]
    fn finds_blob_after_status_prefix() {
        // reply = [status:u16=0x0000][pad][tag-blob][trailing]
        let mut reply = vec![0x00, 0x00, 0x99, 0x88, 0x77];
        reply.extend_from_slice(&blob(2, &[0x0102_0304, 0x0506_0708]));
        reply.extend_from_slice(&[0xde, 0xad]);
        let cfg = WindsorReconConfig::find_in_arm_reply(&reply).expect("found");
        assert_eq!(cfg.coeffs, vec![0x0102_0304, 0x0506_0708]);
    }

    #[test]
    fn find_returns_none_without_tag() {
        assert!(WindsorReconConfig::find_in_arm_reply(&[0u8; 64]).is_none());
    }
}
