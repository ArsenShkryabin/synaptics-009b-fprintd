//! Serialized QM template I/O — the flat `33 + 10·N` minutia body and its `SynaAspTemplateBlob`
//! container, ported from `syna_qm_deserialize_minutiae@0x180005a00` (decode) and its inverse
//! (`syna_asp_serialize_template@0x180102600` for the container wrapper).
//!
//! The flat body is a plain little-endian byte stream (NOT bit-packed), read strictly in order:
//!
//! | order | bytes  | field                                              |
//! |-------|--------|----------------------------------------------------|
//! | 1     | 8      | template-level 64-bit descriptor                   |
//! | 2     | 1      | total minutia count `N`                            |
//! | 3     | `N`×10 | per-minutia { 8B descriptor, 1B x, 1B y }          |
//! | 4     | 1      | group-1 split count `S`                            |
//! | 5     | 1      | field (→ runtime ctx+0x0c)                          |
//! | 6     | 11     | group-1 angle-bin cumulative boundaries [0..S)     |
//! | 7     | 11     | group-2 angle-bin cumulative boundaries [S..N)     |
//!
//! Total = `FLAT_BODY_FIXED_LEN + 10·N` (= `33 + 10·N`). Angles are NOT stored per minutia; they
//! are reconstructed from the 11 cumulative boundaries per group (12 bins of 15°, tail = 165°),
//! exactly as the decoder does.

use super::types::{
    ANGLE_BIN_BOUNDARIES, ANGLE_BIN_STEP_DEG, ANGLE_TAIL_DEG, DESCRIPTOR_BYTES,
    FLAT_BODY_FIXED_LEN, ON_DISK_MINUTIA_LEN,
};

/// Default conditioned-image width for minutiae `(x,y)` on subtype `0x2449`.
pub const DEFAULT_TEMPLATE_IMAGE_W: u16 = 144;
/// Default conditioned-image height — see [`DEFAULT_TEMPLATE_IMAGE_W`].
pub const DEFAULT_TEMPLATE_IMAGE_H: u16 = 56;

/// A single minutia in the deserialized template.
///
/// `descriptor` is the opaque 64-bit MetViper local-neighbor feature (matched only by Hamming
/// distance). `angle_deg` is the reconstructed undirected orientation (0..=179, in 15° steps, or
/// 165° for the tail bin) — see [`Template::deserialize_body`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Minutia {
    /// 64-bit binary local-neighbor descriptor (stored verbatim). syna_qm_deserialize_minutiae@0x180005a00.
    pub descriptor: [u8; DESCRIPTOR_BYTES],
    /// Image column (u8; fits the 144×56 sensor). → runtime min+0x14.
    pub x: u8,
    /// Image row (u8). → runtime min+0x18.
    pub y: u8,
    /// Reconstructed orientation in degrees (0..=179), quantized to 15° bins. → runtime min+0x0c.
    pub angle_deg: u16,
}

/// A deserialized QM template (probe or gallery).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    /// Template-level 64-bit descriptor (→ runtime minutiaeCtx+0x20). syna_qm_deserialize_minutiae@0x180005a00.
    pub descriptor: [u8; DESCRIPTOR_BYTES],
    /// Group-1 split count `S`: minutiae `[0..S)` form angle-group 1, `[S..N)` group 2.
    /// (→ runtime minutiaArr+0x0c.)
    pub split: u8,
    /// The extra byte read after the split (→ runtime minutiaeCtx+0x0c). Opaque; preserved for
    /// round-trip fidelity.
    pub field_0c: u8,
    /// The minutiae, in stored order.
    pub minutiae: Vec<Minutia>,
}

/// Errors from template (de)serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TemplateError {
    /// The byte stream ended before a field could be fully read.
    #[error("unexpected end of byte stream")]
    UnexpectedEof,
    /// The container blob's declared body size does not fit the buffer.
    #[error("container blob size does not fit the buffer")]
    BadBlobSize,
    /// More than 255 minutiae — the count is a single byte, so it cannot be serialized.
    #[error("more than 255 minutiae — cannot serialize")]
    TooManyMinutiae,
    /// A real DLL `AspBlob` body's tag container is malformed, or the minutia tag (`0x6b`) is absent.
    #[error("malformed tag container or missing minutia tag")]
    BadTagContainer,
}

/// A minimal little-endian byte-stream reader mirroring `SynaQmStreamReader`
/// (`syna_qm_stream_read_u8@0x180006530`, `_read_bytes@0x180006560`).
struct Reader<'a> {
    data: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, cursor: 0 }
    }
    fn read_u8(&mut self) -> Result<u8, TemplateError> {
        let b = *self
            .data
            .get(self.cursor)
            .ok_or(TemplateError::UnexpectedEof)?;
        self.cursor += 1;
        Ok(b)
    }
    fn read_desc(&mut self) -> Result<[u8; DESCRIPTOR_BYTES], TemplateError> {
        let end = self.cursor + DESCRIPTOR_BYTES;
        let slice = self
            .data
            .get(self.cursor..end)
            .ok_or(TemplateError::UnexpectedEof)?;
        let mut d = [0u8; DESCRIPTOR_BYTES];
        d.copy_from_slice(slice);
        self.cursor = end;
        Ok(d)
    }
    fn read_boundaries(&mut self) -> Result<[u8; ANGLE_BIN_BOUNDARIES], TemplateError> {
        let end = self.cursor + ANGLE_BIN_BOUNDARIES;
        let slice = self
            .data
            .get(self.cursor..end)
            .ok_or(TemplateError::UnexpectedEof)?;
        let mut b = [0u8; ANGLE_BIN_BOUNDARIES];
        b.copy_from_slice(slice);
        self.cursor = end;
        Ok(b)
    }
}

impl Template {
    /// Decode a flat minutia body (the `33 + 10·N` stream, WITHOUT the 8-byte container header).
    /// Bit-exact mirror of `syna_qm_deserialize_minutiae@0x180005a00`, including the angle-bin
    /// reconstruction.
    pub fn deserialize_body(body: &[u8]) -> Result<Template, TemplateError> {
        let mut r = Reader::new(body);
        let descriptor = r.read_desc()?;
        let n = r.read_u8()? as usize;

        let mut minutiae = Vec::with_capacity(n);
        for _ in 0..n {
            let descriptor = r.read_desc()?;
            let x = r.read_u8()?;
            let y = r.read_u8()?;
            minutiae.push(Minutia {
                descriptor,
                x,
                y,
                angle_deg: 0,
            });
        }

        let split = r.read_u8()?;
        let field_0c = r.read_u8()?;

        // Angle reconstruction. The decoder only runs this block when N != 0.
        if n != 0 {
            let g1 = r.read_boundaries()?;
            reconstruct_angles(&mut minutiae, &g1, 0, split as usize);
            let g2 = r.read_boundaries()?;
            reconstruct_angles(&mut minutiae, &g2, split as usize, n);
        }

        Ok(Template {
            descriptor,
            split,
            field_0c,
            minutiae,
        })
    }

    /// Encode this template to a flat minutia body (`33 + 10·N` bytes). Inverse of
    /// [`Template::deserialize_body`]; re-derives the angle-bin boundaries from each minutia's
    /// `angle_deg`. This IS the DLL's serializer `syna_qm_consensus_hash_grid@0x1800058b0` (writes the
    /// template descriptor, per-minutia `{descriptor, x, y}`, split + field_0c, then the 22-byte
    /// angle-bin trailer via `FUN_1800057f0`) — verified structurally against its decompile.
    ///
    /// Precondition for an exact round-trip: within each angle group the minutiae must be sorted
    /// by `angle_deg` ascending (as the vendor extractor emits them). Decoded templates satisfy
    /// this by construction.
    pub fn serialize_body(&self) -> Result<Vec<u8>, TemplateError> {
        let n = self.minutiae.len();
        if n > u8::MAX as usize {
            return Err(TemplateError::TooManyMinutiae);
        }
        let mut out = Vec::with_capacity(FLAT_BODY_FIXED_LEN + ON_DISK_MINUTIA_LEN * n);
        out.extend_from_slice(&self.descriptor);
        out.push(n as u8);
        for m in &self.minutiae {
            out.extend_from_slice(&m.descriptor);
            out.push(m.x);
            out.push(m.y);
        }
        out.push(self.split);
        out.push(self.field_0c);
        if n != 0 {
            let split = self.split as usize;
            out.extend_from_slice(&group_boundaries(&self.minutiae, 0, split));
            out.extend_from_slice(&group_boundaries(&self.minutiae, split, n));
        }
        Ok(out)
    }

    /// Decode a template from a full `SynaAspTemplateBlob` container (`[u32 size][u32 pad][body]`).
    pub fn from_blob(blob: &[u8]) -> Result<Template, TemplateError> {
        Template::deserialize_body(unwrap_blob(blob)?)
    }

    /// Encode this template into a `SynaAspTemplateBlob` container.
    pub fn to_blob(&self) -> Result<Vec<u8>, TemplateError> {
        Ok(wrap_blob(&self.serialize_body()?))
    }

    /// Conditioned-image dimensions the minutiae `(x,y)` were extracted against.
    ///
    /// Defaults to subtype `0x2449` (`144×56`). Override via [`Self::dimensions_or`] when a polled
    /// frame header supplies geometry.
    pub fn dimensions(&self) -> (u16, u16) {
        (DEFAULT_TEMPLATE_IMAGE_W, DEFAULT_TEMPLATE_IMAGE_H)
    }

    /// [`dimensions`] unless `width`/`height` are non-zero (polled header override).
    pub fn dimensions_or(&self, width: u16, height: u16) -> (u16, u16) {
        if width > 0 && height > 0 {
            (width, height)
        } else {
            self.dimensions()
        }
    }
}

/// Reconstruct minutia angles for a group `[start..end)` from its 11 cumulative bin boundaries.
/// Mirrors the group loops in `syna_qm_deserialize_minutiae@0x180005a00`: boundary `b` is the
/// cumulative absolute minutia index through bin `b` (angle `b·15°`); minutiae past the last
/// boundary get the tail angle 165°.
fn reconstruct_angles(
    minutiae: &mut [Minutia],
    boundaries: &[u8; ANGLE_BIN_BOUNDARIES],
    start: usize,
    end: usize,
) {
    let mut prev = start;
    for (b, &bound) in boundaries.iter().enumerate() {
        let bound = bound as usize;
        if prev < bound {
            for m in minutiae.iter_mut().take(bound.min(end)).skip(prev) {
                m.angle_deg = (b as u16) * ANGLE_BIN_STEP_DEG as u16;
            }
        }
        prev = bound;
    }
    // Tail bin: from the last boundary to the group end -> 165°.
    let tail_start = boundaries[ANGLE_BIN_BOUNDARIES - 1] as usize;
    for m in minutiae.iter_mut().take(end).skip(tail_start) {
        m.angle_deg = ANGLE_TAIL_DEG as u16;
    }
}

/// Re-derive a group's 11 cumulative angle-bin boundaries from the minutiae's `angle_deg`.
/// boundary[b] = absolute index = `start` + (# minutiae in `[start..end)` with `angle <= b·15°`).
/// The tail (angle 165°) is > 150° so it is excluded from every boundary, matching the decoder.
fn group_boundaries(minutiae: &[Minutia], start: usize, end: usize) -> [u8; ANGLE_BIN_BOUNDARIES] {
    let mut b = [0u8; ANGLE_BIN_BOUNDARIES];
    for (bin, slot) in b.iter_mut().enumerate() {
        let thresh = (bin as u16) * ANGLE_BIN_STEP_DEG as u16;
        let count = minutiae[start..end]
            .iter()
            .filter(|m| m.angle_deg <= thresh)
            .count();
        *slot = (start + count) as u8;
    }
    b
}

/// Wrap a flat body in a `SynaAspTemplateBlob` container: `[u32 size][u32 pad=0][body]`.
/// syna_asp_serialize_template@0x180102600.
pub fn wrap_blob(body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + body.len());
    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(body);
    v
}

/// Extract the flat body from a `SynaAspTemplateBlob` container. Inverse of [`wrap_blob`].
pub fn unwrap_blob(blob: &[u8]) -> Result<&[u8], TemplateError> {
    let size = blob
        .get(0..4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize)
        .ok_or(TemplateError::UnexpectedEof)?;
    blob.get(8..8 + size).ok_or(TemplateError::BadBlobSize)
}

/// Length of the fixed header before the tag-node tree in a real DLL template body
/// (`syna_qm_template_body_reader_init@0x180006840` sets the cursor to `body + 0xc`).
pub const TEMPLATE_BODY_HEADER_LEN: usize = 0x0c;
/// Tag `0x69` — conditioned-image dimensions (`{u32 width, u32 height}`; `syna_qm_template_get_dims`).
pub const TAG_DIMS: u16 = 0x69;
/// Tag `0x6b` — the flat `33 + 10·N` minutia block (fed to [`Template::deserialize_body`]).
pub const TAG_MINUTIA: u16 = 0x6b;

/// A template parsed from a real DLL/Windows `AspBlob`: the minutiae plus the dims the template
/// carries (from tag [`TAG_DIMS`]). See `docs/qm/template-format-corroboration.md`.
#[derive(Debug, Clone, PartialEq)]
pub struct TaggedTemplate {
    pub template: Template,
    pub width: u16,
    pub height: u16,
}

/// Walk the tag-node tree of a DLL template body (starting at [`TEMPLATE_BODY_HEADER_LEN`]), invoking
/// `f(tag, payload)` for each `[tag:u16][len:u32][payload]` entry. Stops cleanly at the first
/// truncated entry (mirrors the DLL's length-bounded walk rather than erroring on trailing bytes).
fn walk_tag_tree<'a>(body: &'a [u8], mut f: impl FnMut(u16, &'a [u8])) {
    let mut c = TEMPLATE_BODY_HEADER_LEN;
    while c + 6 <= body.len() {
        let tag = u16::from_le_bytes([body[c], body[c + 1]]);
        let len = u32::from_le_bytes([body[c + 2], body[c + 3], body[c + 4], body[c + 5]]) as usize;
        let start = c + 6;
        let Some(payload) = body.get(start..start + len) else { break };
        f(tag, payload);
        c = start + len;
    }
}

impl Template {
    /// Decode a real DLL/Windows `AspBlob` — the tagged-container form (unlike [`Template::from_blob`],
    /// which assumes the body is already the flat minutia stream). Strips `[u32 size][u32 pad]`, then
    /// parses the `0x0c` header + tag tree: tag [`TAG_MINUTIA`] (`0x6b`) is the flat body →
    /// [`Template::deserialize_body`]; tag [`TAG_DIMS`] (`0x69`) supplies `(width, height)`.
    ///
    /// # Errors
    /// [`TemplateError::BadTagContainer`] if the body is shorter than the header or has no minutia tag;
    /// propagates [`TemplateError`] from the inner flat-body decode.
    pub fn from_dll_blob(blob: &[u8]) -> Result<TaggedTemplate, TemplateError> {
        let body = unwrap_blob(blob)?;
        if body.len() < TEMPLATE_BODY_HEADER_LEN {
            return Err(TemplateError::BadTagContainer);
        }
        let mut minutia_block: Option<&[u8]> = None;
        let mut dims: Option<(u16, u16)> = None;
        walk_tag_tree(body, |tag, payload| match tag {
            TAG_MINUTIA => minutia_block = Some(payload),
            TAG_DIMS if payload.len() >= 8 => {
                let w = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let h = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                dims = Some((w as u16, h as u16));
            }
            _ => {}
        });
        let body = minutia_block.ok_or(TemplateError::BadTagContainer)?;
        let template = Template::deserialize_body(body)?;
        let (width, height) = dims.unwrap_or((DEFAULT_TEMPLATE_IMAGE_W, DEFAULT_TEMPLATE_IMAGE_H));
        Ok(TaggedTemplate { template, width, height })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a small template with two angle groups and hand-set angles.
    fn sample() -> Template {
        // Group 1 = indices [0..3): angles 0, 15, 165 (tail). Group 2 = [3..5): 30, 165.
        let mk = |seed: u8, x: u8, y: u8, a: u16| Minutia {
            descriptor: [
                seed,
                seed ^ 0x5a,
                0x11,
                0x22,
                0x33,
                0x44,
                0x55,
                seed.wrapping_add(1),
            ],
            x,
            y,
            angle_deg: a,
        };
        Template {
            descriptor: [1, 2, 3, 4, 5, 6, 7, 8],
            split: 3,
            field_0c: 0x2a,
            minutiae: vec![
                mk(0x10, 10, 20, 0),
                mk(0x20, 30, 40, 15),
                mk(0x30, 50, 60, 165),
                mk(0x40, 70, 80, 30),
                mk(0x50, 90, 100, 165),
            ],
        }
    }

    #[test]
    fn deserialize_matches_oracle_golden() {
        // The exact flat 33+10·3 body syna_qm_deserialize_minutiae@0x180005a00 decoded in the oracle
        // (tools/qm-dll-oracle/golden/template.txt) — angles m0=45° (bin3), m1=30° (bin2), m2=165° (tail).
        #[rustfmt::skip]
        let body: [u8; 63] = [
            0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7, 3,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17, 11, 22,
            0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27, 33, 44,
            0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37, 55, 66,
            1, 0x2a,
            0,0,0,1,1,1,1,1,1,1,1,
            1,1,2,2,2,2,2,2,2,2,2,
        ];
        let t = Template::deserialize_body(&body).unwrap();
        assert_eq!(t.descriptor, [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7]);
        assert_eq!((t.split, t.field_0c, t.minutiae.len()), (1, 0x2a, 3));
        #[rustfmt::skip]
        let want: [(u8, u8, u16, [u8; 8]); 3] = [
            (11, 22, 45,  [0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17]),
            (33, 44, 30,  [0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27]),
            (55, 66, 165, [0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37]),
        ];
        for (m, (x, y, a, d)) in t.minutiae.iter().zip(want) {
            assert_eq!((m.x, m.y, m.angle_deg, m.descriptor), (x, y, a, d), "minutia");
        }
        // The serializer is the exact inverse: re-encoding reproduces the byte-for-byte body.
        assert_eq!(t.serialize_body().unwrap(), body.to_vec(), "serialize round-trip");
    }

    #[test]
    fn body_roundtrip() {
        let t = sample();
        let body = t.serialize_body().unwrap();
        // 33 + 10*N
        assert_eq!(
            body.len(),
            FLAT_BODY_FIXED_LEN + ON_DISK_MINUTIA_LEN * t.minutiae.len()
        );
        let back = Template::deserialize_body(&body).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn blob_roundtrip() {
        let t = sample();
        let blob = t.to_blob().unwrap();
        // container header = 8 bytes
        assert_eq!(
            blob.len(),
            8 + FLAT_BODY_FIXED_LEN + ON_DISK_MINUTIA_LEN * t.minutiae.len()
        );
        let back = Template::from_blob(&blob).unwrap();
        assert_eq!(t, back);
    }

    /// Build a synthetic real-DLL `AspBlob`: `[u32 size][u32 pad][0x0c header][tag 0x69 dims]
    /// [tag 0x6b flat-body]` and confirm `from_dll_blob` recovers the minutiae AND the tagged dims —
    /// the tag-container layer the plain `from_blob` skips. See template-format-corroboration.md.
    #[test]
    fn dll_tagged_blob_parses_minutiae_and_dims() {
        let t = sample();
        let flat = t.serialize_body().unwrap();
        let (w, h): (u32, u32) = (200, 100);

        let mut body = vec![0u8; TEMPLATE_BODY_HEADER_LEN]; // 0x0c header (contents opaque here)
        // tag 0x69 = dims {u32 w, u32 h}
        body.extend_from_slice(&TAG_DIMS.to_le_bytes());
        body.extend_from_slice(&8u32.to_le_bytes());
        body.extend_from_slice(&w.to_le_bytes());
        body.extend_from_slice(&h.to_le_bytes());
        // tag 0x6b = the flat minutia block
        body.extend_from_slice(&TAG_MINUTIA.to_le_bytes());
        body.extend_from_slice(&(flat.len() as u32).to_le_bytes());
        body.extend_from_slice(&flat);

        let blob = wrap_blob(&body);
        let parsed = Template::from_dll_blob(&blob).unwrap();
        assert_eq!(parsed.template, t, "minutiae recovered from tag 0x6b");
        assert_eq!((parsed.width, parsed.height), (200, 100), "dims from tag 0x69");
    }

    /// A body shorter than the `0x0c` header is a malformed tag container.
    #[test]
    fn dll_tagged_blob_rejects_short_body() {
        let blob = wrap_blob(&[0u8; 4]); // body shorter than TEMPLATE_BODY_HEADER_LEN
        assert_eq!(Template::from_dll_blob(&blob), Err(TemplateError::BadTagContainer));
    }

    #[test]
    fn empty_template_roundtrips() {
        let t = Template {
            descriptor: [0; 8],
            split: 0,
            field_0c: 0,
            minutiae: vec![],
        };
        let body = t.serialize_body().unwrap();
        // N == 0 => no angle-bin blocks are written (matches the decoder's `if N != 0` guard).
        assert_eq!(body.len(), 8 + 1 + 1 + 1);
        assert_eq!(Template::deserialize_body(&body).unwrap(), t);
    }

    #[test]
    fn angles_reconstruct_in_15deg_steps() {
        let t = sample();
        let body = t.serialize_body().unwrap();
        let back = Template::deserialize_body(&body).unwrap();
        let angles: Vec<u16> = back.minutiae.iter().map(|m| m.angle_deg).collect();
        assert_eq!(angles, vec![0, 15, 165, 30, 165]);
    }
}
