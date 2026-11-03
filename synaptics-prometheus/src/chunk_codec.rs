//! Timeslot-program chunk codec: split/merge `[type:u16][len:u16][payload]` chunks.
//!
//! Extracted from `capture_prog` so the imaging path (`reconstruct`, `line_update`) can share it
//! without depending on the whole capture-program selection module. Port of python-validity
//! `timeslot.split_chunks` / `merge_chunks`.

/// A parsed timeslot chunk: `[type:u16][len:u16][payload]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk<'a> {
    pub typ: u16,
    pub payload: &'a [u8],
}

/// Split a timeslot program into its `[type:u16][len:u16][payload]` chunks.
/// (python-validity `timeslot.split_chunks`.) Returns `None` on a truncated stream.
pub fn split_chunks(mut b: &[u8]) -> Option<Vec<Chunk<'_>>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        if b.len() < 4 {
            return None;
        }
        let typ = u16::from_le_bytes([b[0], b[1]]);
        let len = u16::from_le_bytes([b[2], b[3]]) as usize;
        if b.len() < 4 + len {
            return None;
        }
        out.push(Chunk {
            typ,
            payload: &b[4..4 + len],
        });
        b = &b[4 + len..];
    }
    Some(out)
}

/// Reassemble chunks into a program (python-validity `timeslot.merge_chunks`).
pub fn merge_chunks(chunks: &[Chunk<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    for c in chunks {
        out.extend_from_slice(&c.typ.to_le_bytes());
        out.extend_from_slice(&(c.payload.len() as u16).to_le_bytes());
        out.extend_from_slice(c.payload);
    }
    out
}
