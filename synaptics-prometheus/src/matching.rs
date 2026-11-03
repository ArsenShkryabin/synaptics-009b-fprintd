//! `0x5e` → EP-0x83 type-3 → `0x60` → `0x62` — python-validity's **on-chip** match family.
//!
//! CORRECTION (2026-07-14, Ghidra RE of the MSI SecurePad driver): the vendor driver on this SKU
//! does **NOT** match on the chip. `CeivMode_VerifyUserStorageOnFlash@0x18002cbd0` only *images*
//! on the sensor (arm `0x02`, wait the EP-`0x83` finger interrupt) and then matches on the **host**
//! via the QM matcher `syna_qm_match_all` (`0x1800a78f0` — pure host compute, no USB). No
//! `0x5e`/`0x60` command is emitted anywhere in the active path; the on-chip strategy `CEocMocEIV`
//! is compiled-in but never instantiated. So "the sensor matches on chip" was a wrong assumption:
//! templates live on the host WBF DB (see `vendor::EivStorageMode::Host`), and the earlier `0x04b2`
//! we blamed on "dark flash" is really the wrong-backend answer for a host-storage SKU.
//!
//! Whether the 009b **firmware** still implements the on-chip matcher (even though the driver never
//! calls it) is UNTESTED — that is exactly what `examples/onchip_probe.rs` checks. The builders
//! below are the correct python-validity wire forms for that probe; they are read-only. If the
//! sensor answers `0x5e` with a real/"empty-DB" status it has a matcher (pursue on-chip); if it
//! maps to internal `0xca` "unknown" it does not (host matcher port is the only path).

use crate::error::{Error, Result};
use crate::proto::Opcode;
use crate::wire::Cursor;

/// `0x5e match_finger` — match the just-captured finger against storage `stg_id` / user `usr_id`
/// (`0`/`0` = match against *any* storage and user). python-validity:
/// `pack('<BBBHHHHH', 0x5e, 2, 0xff, stg_id, usr_id, 1, 0, 0)`.
pub fn cmd_match_finger(stg_id: u16, usr_id: u16) -> Vec<u8> {
    let mut c = vec![Opcode::MatchFinger.byte(), 0x02, 0xff];
    c.extend_from_slice(&stg_id.to_le_bytes());
    c.extend_from_slice(&usr_id.to_le_bytes());
    c.extend_from_slice(&1u16.to_le_bytes());
    c.extend_from_slice(&0u16.to_le_bytes());
    c.extend_from_slice(&0u16.to_le_bytes());
    c
}

/// `0x5e` against any user in any storage (the usual identify call).
pub fn cmd_match_any() -> Vec<u8> {
    cmd_match_finger(0, 0)
}

/// `0x60 get_match_result_ex` — fetch the match result after the type-3 interrupt.
/// python-validity: `60 00 00 00 00`.
pub fn cmd_get_match_result() -> Vec<u8> {
    vec![Opcode::GetMatchResultEx.byte(), 0x00, 0x00, 0x00, 0x00]
}

/// `0x62 match_cleanup` — finalize/cleanup after a match attempt (sent in `finally`).
/// python-validity: `62 00 00 00 00`.
pub fn cmd_match_cleanup() -> Vec<u8> {
    vec![Opcode::MatchCleanup.byte(), 0x00, 0x00, 0x00, 0x00]
}

/// A parsed match result from `0x60`: which enrolled finger matched.
///
/// `hash` is the sensor's match-derived digest (an identity token, not a releasable secret — see the
/// capture-detection notes on why there is no hardware seal-on-match). Use `usrid`+`subtype` to look
/// the finger up in the DB2 tree ([`crate::db`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchResult {
    /// DB2 user record id (Windows account) that owns the matched finger.
    pub usrid: u32,
    /// Finger position (Windows biometric subtype; see [`crate::db::finger_name`]).
    pub subtype: u16,
    /// Match hash / template digest (opaque).
    pub hash: Vec<u8>,
}

impl MatchResult {
    /// Parse the `0x60` payload **after** the 2-byte status word. Layout (python-validity
    /// `match_finger`): `len:u16` then a TLV dict of `{tag:u16, len:u16, value}` with
    /// `tag 1 = usrid(u32)`, `tag 3 = subtype(u16)`, `tag 4 = hash`.
    pub fn parse(p: &[u8]) -> Result<MatchResult> {
        if p.len() < 2 {
            return Err(Error::Malformed(format!("match result short: {}", p.len())));
        }
        let mut c = Cursor::new(p);
        let l = c.read_u16_le()? as usize;
        let body = c.take_rest();
        if l != body.len() {
            return Err(Error::Malformed(format!(
                "match result size mismatch: {l} != {}",
                body.len()
            )));
        }
        let dict = parse_tlv_dict(body);
        let usrid = dict
            .iter()
            .find(|(t, _)| *t == 1)
            .and_then(|(_, v)| Cursor::new(v).read_u32_le().ok())
            .ok_or_else(|| Error::Malformed("match result missing usrid (tag 1)".into()))?;
        let subtype = dict
            .iter()
            .find(|(t, _)| *t == 3)
            .map(|(_, v)| Cursor::new(v).read_u16_le().unwrap_or_default())
            .ok_or_else(|| Error::Malformed("match result missing subtype (tag 3)".into()))?;
        let hash = dict
            .iter()
            .find(|(t, _)| *t == 4)
            .map(|(_, v)| v.to_vec())
            .unwrap_or_default();
        Ok(MatchResult {
            usrid,
            subtype,
            hash,
        })
    }
}

/// Parse a `{tag:u16, len:u16, value[len]}` TLV dict (python-validity `parse_dict`). Best-effort:
/// stops on a truncated entry.
pub fn parse_tlv_dict(x: &[u8]) -> Vec<(u16, Vec<u8>)> {
    /// A TLV entry header is `tag:u16 ‖ len:u16`.
    const TLV_HEADER_LEN: usize = 4;
    let mut out = Vec::new();
    let mut c = Cursor::new(x);
    while c.remaining() >= TLV_HEADER_LEN {
        // Safe: the `remaining()` guard covers the tag+len read.
        let tag = c.read_u16_le().unwrap_or_default();
        let len = c.read_u16_le().unwrap_or_default() as usize;
        match c.read_bytes(len) {
            Ok(v) => out.push((tag, v.to_vec())),
            Err(_) => break, // truncated value -> stop (best-effort)
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_finger_wire_matches_python_validity() {
        // pack('<BBBHHHHH', 0x5e, 2, 0xff, 0, 0, 1, 0, 0)
        assert_eq!(
            cmd_match_any(),
            vec![
                0x5e, 0x02, 0xff, 0, 0, 0, 0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
        // storage 0x1234, user 0xabcd
        let c = cmd_match_finger(0x1234, 0xabcd);
        assert_eq!(&c[3..7], &[0x34, 0x12, 0xcd, 0xab]);
        assert_eq!(cmd_get_match_result(), vec![0x60, 0, 0, 0, 0]);
        assert_eq!(cmd_match_cleanup(), vec![0x62, 0, 0, 0, 0]);
    }

    #[test]
    fn match_result_parses_tlv_dict() {
        // len=0x1c, then tags: 1=usrid(4B)=0x0102, 3=subtype(2B)=0x02(right index), 4=hash(8B)
        let mut body = Vec::new();
        body.extend_from_slice(&[0x01, 0x00, 0x04, 0x00, 0x02, 0x01, 0x00, 0x00]); // tag1 usrid
        body.extend_from_slice(&[0x03, 0x00, 0x02, 0x00, 0x02, 0x00]); // tag3 subtype
        body.extend_from_slice(&[0x04, 0x00, 0x08, 0x00, 1, 2, 3, 4, 5, 6, 7, 8]); // tag4 hash
        let mut p = (body.len() as u16).to_le_bytes().to_vec();
        p.extend_from_slice(&body);
        let r = MatchResult::parse(&p).expect("parses");
        assert_eq!(r.usrid, 0x0102);
        assert_eq!(r.subtype, 0x02);
        assert_eq!(r.hash, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
