//! Enrollment flow (`0x68`/`0x69`/`0x6b`/`0x6a`) — **destructive**, behind the `writes` feature.
//!
//! **On-chip enroll (CEocMocEIV, `storage_mode == 3`):** match-on-chip, stitched **on the device**.
//! The host captures each touch (`0x02`), shuttles the accumulating opaque template back via
//! `0x6b enroll_append`, and the *sensor* merges the new image and decides when coverage is
//! sufficient — it withholds the template id (`tid`) until enrollment is complete. The host stores
//! the finished record in the sensor DB2.
//!
//! **Not this SKU (`06cb:009b`, EOH/MOH):** Windows uses `CEohMohEIV_EnrollmentUpdate@0x180020ca0`
//! → host QM (`syna_qm_enroll_extract_vt90@0x1800ff610`) → `syna_asp_serialize_template` → WBF.
//! See [`docs/qm/qm-enrollment.md`](../../docs/qm/qm-enrollment.md). The wire path below is unused on
//! SecurePad; do not conflate `0x6b` tag-0 blobs with `SynaAspTemplateBlob` QM templates.
//!
//! Wire forms and the response layout are from python-validity `sensor.enroll` /
//! `append_new_image`. Compiled only with `--features writes`: `0x6b`/`0x69` mutate the sensor's
//! enrollment state and the final `new_finger` writes flash — never run by the default build.
#![cfg(feature = "writes")]

use crate::error::{Error, Result};
use crate::proto::Opcode;
use crate::wire::Cursor;

/// `0x68 enrollment_update_start` — begin an enrollment update round. python-validity:
/// `pack('<BLL', 0x68, key, 0)`. Returns a new `key` (see [`parse_update_start`]).
pub fn cmd_enroll_update_start(key: u32) -> Vec<u8> {
    let mut c = vec![Opcode::EnrollUpdateStart.byte()];
    c.extend_from_slice(&key.to_le_bytes());
    c.extend_from_slice(&0u32.to_le_bytes());
    c
}

/// `0x69` create-enrollment (`arg = 1`) — start a fresh enrollment. python-validity `create_enrollment`.
pub fn cmd_enroll_create() -> Vec<u8> {
    let mut c = vec![Opcode::EnrollStart.byte()];
    c.extend_from_slice(&1u32.to_le_bytes());
    c
}

/// `0x69` enrollment-update-end (`arg = 0`) — end the current update round.
pub fn cmd_enroll_update_end() -> Vec<u8> {
    let mut c = vec![Opcode::EnrollStart.byte()];
    c.extend_from_slice(&0u32.to_le_bytes());
    c
}

/// `0x6b enroll_append` — feed the previously-accumulated template back so the sensor merges the
/// latest capture into it. python-validity `enrollment_update`: `0x6b ‖ prev`. Returns the updated
/// template + progress header + (when complete) tid — see [`EnrollProgress`].
pub fn cmd_enroll_append(prev: &[u8]) -> Vec<u8> {
    let mut c = vec![Opcode::EnrollAppend.byte()];
    c.extend_from_slice(prev);
    c
}

/// The `key` returned by `0x68`. Payload is the 4-byte new key after the status word.
pub fn parse_update_start(p: &[u8]) -> Result<u32> {
    if p.len() < 4 {
        return Err(Error::Malformed(format!("enroll key short: {}", p.len())));
    }
    Ok(u32::from_le_bytes([p[0], p[1], p[2], p[3]]))
}

/// The `magic_len` prefix each `0x6b` response record carries before its value (hardcoded in the DLL).
const MAGIC_LEN: usize = 0x38;

/// A parsed `0x6b enroll_append` response (python-validity `append_new_image`).
///
/// The response is a `len:u16` then a sequence of `[tag:u16, len:u16, <MAGIC_LEN-byte record header>,
/// value]` entries: `tag 0` = the updated accumulated **template** (kept whole, incl. the record
/// header), `tag 1` = a progress **header** (coverage/quality the UI shows), `tag 3` = **tid**
/// (template id) — present **only when the sensor deems enrollment complete**.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnrollProgress {
    /// The new accumulated template to pass back into the next [`cmd_enroll_append`].
    pub template: Vec<u8>,
    /// Progress/coverage header (opaque; drives the "keep touching" UI).
    pub header: Vec<u8>,
    /// Template id — `Some` only when enrollment is complete (sensor's coverage decision).
    pub tid: Option<Vec<u8>>,
}

impl EnrollProgress {
    /// True once the sensor has signalled sufficient coverage (a `tid` was returned).
    pub fn is_complete(&self) -> bool {
        self.tid.is_some()
    }

    /// Parse the payload **after** the 2-byte status word.
    pub fn parse(p: &[u8]) -> Result<EnrollProgress> {
        if p.len() < 2 {
            return Err(Error::Malformed(format!("enroll resp short: {}", p.len())));
        }
        let mut hdr = Cursor::new(p);
        let l = hdr.read_u16_le()? as usize;
        let res = hdr.take_rest();
        if l != res.len() {
            return Err(Error::Malformed(format!(
                "enroll resp size mismatch: {l} != {}",
                res.len()
            )));
        }
        /// Each record starts with a `tag:u16 ‖ len:u16` header (the first 4 bytes of MAGIC_LEN).
        const RECORD_HEADER_LEN: usize = 4;
        let mut out = EnrollProgress::default();
        let mut c = Cursor::new(res);
        while c.remaining() >= RECORD_HEADER_LEN {
            // Peek tag/vlen: the whole `entry`-byte record (incl. its MAGIC_LEN header) is kept for
            // tag 0, so the record is consumed as one block rather than field-by-field.
            let tag = c.peek_u16_le(0)?;
            let vlen = c.peek_u16_le(2)? as usize;
            let entry = MAGIC_LEN + vlen;
            if c.remaining() < entry {
                break;
            }
            let rec = c.read_bytes(entry)?;
            match tag {
                0 => out.template = rec.to_vec(),
                1 => out.header = rec[MAGIC_LEN..].to_vec(),
                3 => out.tid = Some(rec[MAGIC_LEN..].to_vec()),
                _ => {}
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_command_wire_forms() {
        assert_eq!(
            cmd_enroll_update_start(0x11223344),
            vec![0x68, 0x44, 0x33, 0x22, 0x11, 0, 0, 0, 0]
        );
        assert_eq!(cmd_enroll_create(), vec![0x69, 1, 0, 0, 0]);
        assert_eq!(cmd_enroll_update_end(), vec![0x69, 0, 0, 0, 0]);
        assert_eq!(cmd_enroll_append(&[0xaa, 0xbb]), vec![0x6b, 0xaa, 0xbb]);
        assert_eq!(parse_update_start(&[0x0d, 0xf0, 0, 0]).unwrap(), 0xf00d);
    }

    #[test]
    fn enroll_progress_parses_tags_and_completion() {
        // one tag-1 header (value 4B) then a tag-3 tid (value 8B): complete.
        let mk = |tag: u16, val: &[u8]| {
            let mut e = tag.to_le_bytes().to_vec();
            e.extend_from_slice(&(val.len() as u16).to_le_bytes());
            e.extend(std::iter::repeat_n(0u8, MAGIC_LEN - 4)); // pad record header to MAGIC_LEN
            e.extend_from_slice(val);
            e
        };
        let mut body = mk(1, &[9, 9, 9, 9]);
        body.extend(mk(3, &[1, 2, 3, 4, 5, 6, 7, 8]));
        let mut p = (body.len() as u16).to_le_bytes().to_vec();
        p.extend_from_slice(&body);
        let e = EnrollProgress::parse(&p).expect("parses");
        assert_eq!(e.header, vec![9, 9, 9, 9]);
        assert_eq!(e.tid.as_deref(), Some(&[1u8, 2, 3, 4, 5, 6, 7, 8][..]));
        assert!(e.is_complete());
    }
}
