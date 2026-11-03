//! Grayscale image container + self-contained PGM/PNG encoders.
//!
//! Extracted from `reconstruct` — the encoders (CRC-32, Adler-32, a "stored" zlib wrapper, PNG chunk
//! framing) are generic image I/O with nothing to do with sensor reconstruction. `reconstruct`
//! re-exports [`Image`] so existing `reconstruct::Image` paths keep working.
//!
//! # Annotated PNGs
//!
//! A stage tap is a `f32` (or `i32`) field; a PNG of it is a *display mapping* — clamped, windowed
//! and quantised to 8 bits. That picture is what you want to look at and exactly what you cannot
//! test against, because two different fields can map to the same bytes.
//!
//! [`Image::to_png_annotated`] therefore writes both into one file: the display-mapped preview any
//! viewer can open, plus the untouched samples in a private [`saFX`](EXACT_CHUNK) chunk and the
//! provenance in text chunks. Decoders that do not know `saFX` ignore it — that is what "ancillary"
//! means in the PNG spec — so the file stays an ordinary greyscale PNG everywhere else.
//!
//! [`read_png_sidecar`] walks the chunk list and never touches `IDAT`, so it needs no inflate and
//! does not care how the preview was compressed.

/// A de-scrambled grayscale image: `width * height` bytes, row-major.
#[derive(Debug, Clone)]
pub struct Image {
    pub width: usize,
    pub height: usize,
    pub pixels: Vec<u8>,
}

impl Image {
    /// Serialize as a binary PGM (`P5`) for eyeballing.
    pub fn to_pgm(&self) -> Vec<u8> {
        let mut v = format!("P5\n{} {}\n255\n", self.width, self.height).into_bytes();
        v.extend_from_slice(&self.pixels);
        v
    }

    /// Serialize as an 8-bit grayscale PNG — self-contained (uncompressed/"stored" zlib blocks, no
    /// external crate). Pixels are clamped to `width*height`; missing pixels are zero-filled.
    pub fn to_png(&self) -> Vec<u8> {
        let raw = self.scanlines();
        let mut out = PNG_SIG.to_vec();
        png_chunk(&mut out, b"IHDR", &self.ihdr());
        png_chunk(&mut out, b"IDAT", &zlib_store(&raw));
        png_chunk(&mut out, b"IEND", &[]);
        out
    }

    /// The same PNG as [`to_png`](Self::to_png), plus provenance text and — optionally — the exact
    /// samples the preview was mapped from.
    ///
    /// `text` becomes one text chunk per entry, written *before* `IDAT` so a reader hits the
    /// metadata before the pixels. Pure-ASCII values use `tEXt` (which every tool that shows PNG
    /// metadata understands); anything else uses `iTXt`, whose payload is UTF-8 by definition —
    /// `tEXt` is Latin-1 and would mangle a label like `144×56`. Keywords that PNG would reject
    /// (empty, over 79 bytes, non-printable, or space-padded at either end) are **skipped**, because
    /// a malformed keyword would make the whole file unreadable and losing one annotation should not
    /// cost you the capture.
    pub fn to_png_annotated(&self, text: &[(&str, &str)], exact: Option<&ExactPlane>) -> Vec<u8> {
        let mut out = self.to_png();
        // Splice the ancillary chunks in ahead of IDAT. Rebuilding is cheaper to reason about than
        // duplicating the IHDR/IDAT construction above, and keeps `to_png` the single definition of
        // what our PNGs look like.
        let idat = find_chunk_start(&out, b"IDAT").expect("to_png always writes an IDAT");
        let mut extra = Vec::new();
        for (key, value) in text {
            write_text_chunk(&mut extra, key, value);
        }
        if let Some(e) = exact {
            png_chunk(&mut extra, EXACT_CHUNK, &e.encode());
        }
        out.splice(idat..idat, extra);
        out
    }

    /// Filtered scanlines: each row prefixed with filter byte 0 (None). Pixels are clamped to
    /// `width*height`; missing pixels are zero-filled.
    fn scanlines(&self) -> Vec<u8> {
        let (w, h) = (self.width, self.height);
        let mut raw = Vec::with_capacity(h * (w + 1));
        for y in 0..h {
            raw.push(0);
            let start = y * w;
            for x in 0..w {
                raw.push(self.pixels.get(start + x).copied().unwrap_or(0));
            }
        }
        raw
    }

    /// bit depth 8, grayscale, deflate, filter 0, no interlace.
    fn ihdr(&self) -> Vec<u8> {
        let mut ihdr = Vec::with_capacity(13);
        ihdr.extend_from_slice(&(self.width as u32).to_be_bytes());
        ihdr.extend_from_slice(&(self.height as u32).to_be_bytes());
        ihdr.extend_from_slice(&[8, 0, 0, 0, 0]);
        ihdr
    }
}

/// The 8-byte PNG signature.
const PNG_SIG: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/// One tap across a burst, as an animated PNG — a viewing convenience beside the exact per-frame
/// files, playable in any browser without a container crate or a codec.
///
/// Returns `None` unless every frame matches the first one's dimensions: APNG frames are composited
/// into a single canvas declared by `IHDR`, so a mismatch is a malformed file rather than a
/// resizing animation. `delay_num / delay_den` is the inter-frame delay in seconds (`1/10` for the
/// sensor's ~10 Hz); `den == 0` is read as 100 by decoders, so pass a real denominator.
pub fn to_apng(frames: &[Image], delay_num: u16, delay_den: u16) -> Option<Vec<u8>> {
    let first = frames.first()?;
    if frames.iter().any(|f| f.width != first.width || f.height != first.height) {
        return None;
    }
    let mut out = PNG_SIG.to_vec();
    png_chunk(&mut out, b"IHDR", &first.ihdr());

    // acTL must precede IDAT. num_plays 0 = loop forever.
    let mut actl = Vec::with_capacity(8);
    actl.extend_from_slice(&(frames.len() as u32).to_be_bytes());
    actl.extend_from_slice(&0u32.to_be_bytes());
    png_chunk(&mut out, b"acTL", &actl);

    // One shared sequence counter across every fcTL and fdAT, which is what APNG orders frames by.
    let mut seq: u32 = 0;
    let fctl = |seq: u32, w: usize, h: usize| {
        let mut v = Vec::with_capacity(26);
        v.extend_from_slice(&seq.to_be_bytes());
        v.extend_from_slice(&(w as u32).to_be_bytes());
        v.extend_from_slice(&(h as u32).to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes()); // x_offset
        v.extend_from_slice(&0u32.to_be_bytes()); // y_offset
        v.extend_from_slice(&delay_num.to_be_bytes());
        v.extend_from_slice(&delay_den.to_be_bytes());
        v.push(0); // dispose_op NONE
        v.push(0); // blend_op SOURCE
        v
    };

    // Frame 0 is the IDAT itself, so a decoder with no APNG support still shows something.
    png_chunk(&mut out, b"fcTL", &fctl(seq, first.width, first.height));
    seq += 1;
    png_chunk(&mut out, b"IDAT", &zlib_store(&first.scanlines()));

    for f in &frames[1..] {
        png_chunk(&mut out, b"fcTL", &fctl(seq, f.width, f.height));
        seq += 1;
        let mut fdat = seq.to_be_bytes().to_vec();
        seq += 1;
        fdat.extend_from_slice(&zlib_store(&f.scanlines()));
        png_chunk(&mut out, b"fdAT", &fdat);
    }
    png_chunk(&mut out, b"IEND", &[]);
    Some(out)
}

/// Text annotations and exact samples read back out of an annotated PNG.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PngSidecar {
    /// `(keyword, value)` from every `tEXt`/`iTXt` chunk, in file order.
    pub text: Vec<(String, String)>,
    /// The [`EXACT_CHUNK`] payload, if the file carries one.
    pub exact: Option<ExactPlane>,
}

impl PngSidecar {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.text.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }
}

/// Read the annotations back without decoding the image.
///
/// `None` means the bytes are not a PNG, or the chunk stream is malformed or fails CRC — a
/// corrupt file yields nothing rather than whichever prefix happened to parse, because partial
/// metadata that looks complete is worse than an honest failure.
pub fn read_png_sidecar(bytes: &[u8]) -> Option<PngSidecar> {
    let mut out = PngSidecar::default();
    for (_, typ, payload) in png_chunks(bytes)? {
        match &typ {
            b"tEXt" => {
                let split = payload.iter().position(|&b| b == 0)?;
                let key = latin1(&payload[..split]);
                out.text.push((key, latin1(&payload[split + 1..])));
            }
            b"iTXt" => {
                // keyword \0 comp_flag comp_method lang \0 translated \0 text(UTF-8)
                let k = payload.iter().position(|&b| b == 0)?;
                let key = latin1(&payload[..k]);
                let rest = payload.get(k + 1..)?;
                // Compressed iTXt would need an inflate we deliberately do not have; skip it rather
                // than reporting the compressed bytes as if they were text.
                if *rest.first()? != 0 {
                    continue;
                }
                let after_flags = rest.get(2..)?;
                let lang = after_flags.iter().position(|&b| b == 0)?;
                let after_lang = after_flags.get(lang + 1..)?;
                let tr = after_lang.iter().position(|&b| b == 0)?;
                let text = after_lang.get(tr + 1..)?;
                out.text.push((key, String::from_utf8_lossy(text).into_owned()));
            }
            t if t == EXACT_CHUNK => out.exact = ExactPlane::decode(payload),
            b"IEND" => break,
            _ => {}
        }
    }
    Some(out)
}

/// One chunk as it sits in the file: `(offset of its length field, type, payload)`.
type Chunk<'a> = (usize, [u8; 4], &'a [u8]);

/// Every chunk in order, or `None` if the stream is not a well-formed PNG. CRCs are checked: this is
/// the only integrity signal a bundle file has.
fn png_chunks(bytes: &[u8]) -> Option<Vec<Chunk<'_>>> {
    if !bytes.starts_with(&PNG_SIG) {
        return None;
    }
    let mut at = PNG_SIG.len();
    let mut chunks = Vec::new();
    while at < bytes.len() {
        let len = {
            let b = bytes.get(at..at + 4)?;
            u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize
        };
        let typ: [u8; 4] = bytes.get(at + 4..at + 8)?.try_into().ok()?;
        let payload = bytes.get(at + 8..at + 8 + len)?;
        let stored = {
            let b = bytes.get(at + 8 + len..at + 12 + len)?;
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        };
        let mut crcbuf = Vec::with_capacity(4 + len);
        crcbuf.extend_from_slice(&typ);
        crcbuf.extend_from_slice(payload);
        if crc32(&crcbuf) != stored {
            return None;
        }
        chunks.push((at, typ, payload));
        at += 12 + len;
        if &typ == b"IEND" {
            break;
        }
    }
    Some(chunks)
}

fn find_chunk_start(bytes: &[u8], typ: &[u8; 4]) -> Option<usize> {
    png_chunks(bytes)?.into_iter().find(|(_, t, _)| t == typ).map(|(at, _, _)| at)
}

fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

/// PNG keywords: 1–79 bytes of printable Latin-1, no leading/trailing space and no doubled space.
fn valid_png_keyword(key: &str) -> bool {
    let b = key.as_bytes();
    (1..=79).contains(&b.len())
        && b.iter().all(|&c| (32..=126).contains(&c) || (161..=255).contains(&c))
        && b[0] != b' '
        && b[b.len() - 1] != b' '
        && !key.contains("  ")
}

/// One text chunk, in whichever of the two encodings can carry the value losslessly.
fn write_text_chunk(out: &mut Vec<u8>, key: &str, value: &str) {
    if !valid_png_keyword(key) {
        return;
    }
    let mut d = key.as_bytes().to_vec();
    if value.is_ascii() && !value.contains('\0') {
        d.push(0);
        d.extend_from_slice(value.as_bytes());
        png_chunk(out, b"tEXt", &d);
    } else {
        // keyword \0, comp_flag 0, comp_method 0, empty lang \0, empty translated keyword \0, UTF-8.
        d.extend_from_slice(&[0, 0, 0, 0, 0]);
        d.extend_from_slice(value.as_bytes());
        png_chunk(out, b"iTXt", &d);
    }
}

/// PNG chunk type for the exact samples: `s` ancillary · `a` private · `F` reserved-uppercase ·
/// `X` **unsafe-to-copy**.
///
/// Unsafe-to-copy is the deliberate half. A tool that rewrites the pixels without understanding this
/// chunk is required to drop it, which is exactly right: once the preview has been edited, samples
/// claiming to be "what that picture was mapped from" are a lie. (All four bytes are letters because
/// the PNG spec restricts chunk types to `A-Za-z` — digits are not allowed.)
pub const EXACT_CHUNK: &[u8; 4] = b"saFX";

/// Payload magic — 7 bytes, so the version byte lands at a fixed offset.
const EXACT_MAGIC: &[u8; 7] = b"SYNAF32";
const EXACT_VERSION: u8 = 1;

/// Sample type of an [`ExactPlane`]. One type per chunk: a tap's planes are homogeneous (a gray
/// field is all `f32`, a Hessian field is all `i32`), so a per-plane tag would only be able to
/// express states that cannot occur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneType {
    F32,
    I32,
}

impl PlaneType {
    fn tag(self) -> u8 {
        match self {
            PlaneType::F32 => 0,
            PlaneType::I32 => 1,
        }
    }
    fn from_tag(t: u8) -> Option<Self> {
        match t {
            0 => Some(PlaneType::F32),
            1 => Some(PlaneType::I32),
            _ => None,
        }
    }
}

/// The untouched samples behind a display-mapped preview: one or more equally-sized named planes.
///
/// Stored as little-endian bytes rather than typed vectors so a round-trip is byte-exact by
/// construction — there is no decode step in the middle to get wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactPlane {
    pub width: usize,
    pub height: usize,
    pub dtype: PlaneType,
    /// `(name, little-endian samples)`; every plane holds exactly `width * height` samples.
    pub planes: Vec<(String, Vec<u8>)>,
}

impl ExactPlane {
    /// The common case: one `f32` plane, which is what a gray tap is.
    pub fn gray_f32(width: usize, height: usize, samples: &[f32]) -> Self {
        Self::f32_planes(width, height, &[("gray", samples)])
    }

    pub fn f32_planes(width: usize, height: usize, planes: &[(&str, &[f32])]) -> Self {
        Self {
            width,
            height,
            dtype: PlaneType::F32,
            planes: planes
                .iter()
                .map(|(n, d)| ((*n).to_string(), d.iter().flat_map(|v| v.to_le_bytes()).collect()))
                .collect(),
        }
    }

    pub fn i32_planes(width: usize, height: usize, planes: &[(&str, &[i32])]) -> Self {
        Self {
            width,
            height,
            dtype: PlaneType::I32,
            planes: planes
                .iter()
                .map(|(n, d)| ((*n).to_string(), d.iter().flat_map(|v| v.to_le_bytes()).collect()))
                .collect(),
        }
    }

    /// Samples of one named plane, or `None` if the name is absent or the type does not match.
    pub fn plane_f32(&self, name: &str) -> Option<Vec<f32>> {
        (self.dtype == PlaneType::F32)
            .then(|| self.raw(name))
            .flatten()
            .map(|b| b.chunks_exact(4).map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect())
    }

    pub fn plane_i32(&self, name: &str) -> Option<Vec<i32>> {
        (self.dtype == PlaneType::I32)
            .then(|| self.raw(name))
            .flatten()
            .map(|b| b.chunks_exact(4).map(|c| i32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect())
    }

    fn raw(&self, name: &str) -> Option<&[u8]> {
        self.planes.iter().find(|(n, _)| n == name).map(|(_, d)| d.as_slice())
    }

    /// Samples per plane, as declared by the header.
    fn expected_len(&self) -> Option<usize> {
        self.width.checked_mul(self.height)?.checked_mul(4)
    }

    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(EXACT_MAGIC);
        v.push(EXACT_VERSION);
        v.push(self.dtype.tag());
        v.extend_from_slice(&(self.width as u32).to_be_bytes());
        v.extend_from_slice(&(self.height as u32).to_be_bytes());
        v.push(self.planes.len().min(u8::MAX as usize) as u8);
        for (name, data) in &self.planes {
            let n = name.as_bytes();
            v.push(n.len().min(u8::MAX as usize) as u8);
            v.extend_from_slice(&n[..n.len().min(u8::MAX as usize)]);
            v.extend_from_slice(data);
        }
        v
    }

    fn decode(payload: &[u8]) -> Option<Self> {
        let magic = payload.get(..7)?;
        if magic != EXACT_MAGIC || *payload.get(7)? != EXACT_VERSION {
            return None;
        }
        let dtype = PlaneType::from_tag(*payload.get(8)?)?;
        let be = |o: usize| -> Option<usize> {
            let b = payload.get(o..o + 4)?;
            Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
        };
        let (width, height) = (be(9)?, be(13)?);
        let count = *payload.get(17)? as usize;
        let mut me = Self { width, height, dtype, planes: Vec::with_capacity(count) };
        let stride = me.expected_len()?;
        let mut at = 18;
        for _ in 0..count {
            let name_len = *payload.get(at)? as usize;
            at += 1;
            let name = String::from_utf8(payload.get(at..at + name_len)?.to_vec()).ok()?;
            at += name_len;
            let data = payload.get(at..at + stride)?.to_vec();
            at += stride;
            me.planes.push((name, data));
        }
        Some(me)
    }
}

fn crc32(buf: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in buf {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn adler32(buf: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in buf {
        a = (a + x as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

fn png_chunk(out: &mut Vec<u8>, typ: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(typ);
    out.extend_from_slice(data);
    let mut crcbuf = Vec::with_capacity(4 + data.len());
    crcbuf.extend_from_slice(typ);
    crcbuf.extend_from_slice(data);
    out.extend_from_slice(&crc32(&crcbuf).to_be_bytes());
}

/// zlib wrapper around DEFLATE "stored" (uncompressed) blocks — valid zlib, zero compression.
fn zlib_store(raw: &[u8]) -> Vec<u8> {
    let mut z = vec![0x78, 0x01]; // CMF/FLG
    let mut i = 0;
    if raw.is_empty() {
        z.extend_from_slice(&[0x01, 0x00, 0x00, 0xff, 0xff]);
    }
    while i < raw.len() {
        let n = (raw.len() - i).min(0xffff);
        let is_final = i + n >= raw.len();
        z.push(if is_final { 1 } else { 0 });
        z.extend_from_slice(&(n as u16).to_le_bytes());
        z.extend_from_slice(&(!(n as u16)).to_le_bytes());
        z.extend_from_slice(&raw[i..i + n]);
        i += n;
    }
    z.extend_from_slice(&adler32(raw).to_be_bytes());
    z
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Image {
        Image { width: 4, height: 2, pixels: (0..8).collect() }
    }

    #[test]
    fn to_png_has_valid_signature_and_chunks() {
        let png = sample().to_png();
        assert_eq!(&png[..8], &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        // IHDR type follows the 8-byte sig + 4-byte length
        assert_eq!(&png[12..16], b"IHDR");
        // ends with IEND chunk (type + 4-byte CRC)
        assert_eq!(&png[png.len() - 8..png.len() - 4], b"IEND");
    }

    /// The annotations are additive: existing callers and existing goldens must not shift.
    #[test]
    fn annotating_with_nothing_reproduces_to_png_byte_for_byte() {
        assert_eq!(sample().to_png_annotated(&[], None), sample().to_png());
    }

    #[test]
    fn text_and_exact_survive_a_round_trip() {
        let field: Vec<f32> = vec![0.5, -1.25, 3.0e7, f32::MIN_POSITIVE, 0.0, -0.0, 1.0, 2.0];
        let exact = ExactPlane::gray_f32(4, 2, &field);
        let png = sample().to_png_annotated(
            &[("Software", "synaptics-viewer"), ("syna:stage", "Descramble"), ("syna:label", "144×56")],
            Some(&exact),
        );
        let side = read_png_sidecar(&png).expect("annotated PNG parses");
        assert_eq!(side.get("Software"), Some("synaptics-viewer"));
        assert_eq!(side.get("syna:stage"), Some("Descramble"));
        // Non-ASCII went out as iTXt (UTF-8); tEXt is Latin-1 and would have mangled the '×'.
        assert_eq!(side.get("syna:label"), Some("144×56"));
        assert_eq!(side.exact.as_ref(), Some(&exact));
        assert_eq!(side.exact.unwrap().plane_f32("gray").unwrap(), field);
    }

    /// Bit patterns, not values: the point of carrying the samples is that nothing rounds them.
    #[test]
    fn exact_plane_preserves_nan_and_negative_zero_bit_patterns() {
        let field = vec![f32::NAN, -0.0f32, f32::INFINITY, f32::NEG_INFINITY];
        let png = sample().to_png_annotated(&[], Some(&ExactPlane::gray_f32(4, 1, &field)));
        let back = read_png_sidecar(&png).unwrap().exact.unwrap().plane_f32("gray").unwrap();
        let bits = |v: &[f32]| v.iter().map(|f| f.to_bits()).collect::<Vec<_>>();
        assert_eq!(bits(&back), bits(&field));
    }

    #[test]
    fn multi_plane_i32_round_trips_by_name() {
        let exact = ExactPlane::i32_planes(2, 2, &[("lxx", &[1, 2, 3, 4]), ("lyy", &[-5, 6, -7, 8])]);
        let png = sample().to_png_annotated(&[], Some(&exact));
        let back = read_png_sidecar(&png).unwrap().exact.unwrap();
        assert_eq!(back.plane_i32("lxx").unwrap(), vec![1, 2, 3, 4]);
        assert_eq!(back.plane_i32("lyy").unwrap(), vec![-5, 6, -7, 8]);
        assert_eq!(back.plane_i32("nope"), None);
        // Asking for the wrong sample type is a miss, not a reinterpretation of the bytes.
        assert_eq!(back.plane_f32("lxx"), None);
    }

    /// A flipped byte anywhere must not surface as plausible metadata. This is the only integrity
    /// check a bundle file has.
    #[test]
    fn a_corrupt_chunk_yields_nothing_rather_than_a_partial_read() {
        let mut png = sample().to_png_annotated(&[("syna:stage", "Source")], None);
        let at = find_chunk_start(&png, b"tEXt").unwrap();
        png[at + 9] ^= 0x01; // inside the payload, so the stored CRC no longer matches
        assert!(read_png_sidecar(&png).is_none());
    }

    #[test]
    fn keywords_png_would_reject_are_skipped_not_written_malformed() {
        let long = "k".repeat(80);
        let png = sample().to_png_annotated(
            &[("", "empty"), (&long, "too long"), (" lead", "space"), ("ok", "kept")],
            None,
        );
        let side = read_png_sidecar(&png).unwrap();
        assert_eq!(side.text, vec![("ok".to_string(), "kept".to_string())]);
    }

    /// The whole premise of the private chunk: other decoders still read the file.
    #[test]
    fn a_third_party_decoder_still_reads_an_annotated_png() {
        let img = Image { width: 4, height: 2, pixels: (0..8).collect() };
        let bytes = img.to_png_annotated(
            &[("Software", "synaptics-viewer")],
            Some(&ExactPlane::gray_f32(4, 2, &[1.0; 8])),
        );
        let decoder = png::Decoder::new(std::io::Cursor::new(&bytes));
        let mut reader = decoder.read_info().expect("the png crate accepts our file");
        let info = reader.info();
        assert_eq!((info.width, info.height), (4, 2));
        assert_eq!(info.color_type, png::ColorType::Grayscale);
        assert_eq!(info.bit_depth, png::BitDepth::Eight);
        assert!(
            info.uncompressed_latin1_text.iter().any(|t| t.keyword == "Software"),
            "the tEXt annotation is visible to a standard decoder"
        );
        let mut buf = vec![0; reader.output_buffer_size().unwrap()];
        let frame = reader.next_frame(&mut buf).expect("pixels decode");
        assert_eq!(&buf[..frame.buffer_size()], &img.pixels[..]);
    }

    #[test]
    fn apng_frames_share_one_canvas_and_are_sequenced() {
        let frames: Vec<Image> =
            (0..3).map(|i| Image { width: 4, height: 2, pixels: vec![i * 10; 8] }).collect();
        let bytes = to_apng(&frames, 1, 10).expect("uniform frames encode");
        let chunks = png_chunks(&bytes).expect("well-formed");
        let types: Vec<String> =
            chunks.iter().map(|(_, t, _)| String::from_utf8_lossy(t).into_owned()).collect();
        assert_eq!(types, ["IHDR", "acTL", "fcTL", "IDAT", "fcTL", "fdAT", "fcTL", "fdAT", "IEND"]);
        // acTL announces the real frame count, and sequence numbers run 0..n over fcTL+fdAT.
        let actl = chunks.iter().find(|(_, t, _)| t == b"acTL").unwrap().2;
        assert_eq!(u32::from_be_bytes(actl[..4].try_into().unwrap()), 3);
        let seqs: Vec<u32> = chunks
            .iter()
            .filter(|(_, t, _)| t == b"fcTL" || t == b"fdAT")
            .map(|(_, _, p)| u32::from_be_bytes(p[..4].try_into().unwrap()))
            .collect();
        assert_eq!(seqs, [0, 1, 2, 3, 4]);
    }

    #[test]
    fn apng_refuses_frames_that_do_not_share_the_canvas() {
        let a = Image { width: 4, height: 2, pixels: vec![0; 8] };
        let b = Image { width: 2, height: 2, pixels: vec![0; 4] };
        assert!(to_apng(&[a, b], 1, 10).is_none());
        assert!(to_apng(&[], 1, 10).is_none());
    }
}
