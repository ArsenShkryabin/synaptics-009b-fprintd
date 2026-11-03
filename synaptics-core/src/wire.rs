//! Bounds-checked little-endian byte cursor for response parsing.
//!
//! The vendor protocol replies are `u16 status ‖ payload` and every typed parser in the crate
//! works on the *payload* (the caller strips the 2-byte status word first — see
//! [`crate::proto::Response::parse`]). Historically each parser open-coded its own
//! `let u16le = |i| u16::from_le_bytes([p[i], p[i+1]])` closures plus manual slice indexing, which
//! (a) duplicated the same little-endian logic in a dozen places and (b) would **panic** on a
//! truncated USB response.
//!
//! [`Cursor`](crate::wire::Cursor) centralises that: every read is bounds-checked and, on underflow, returns
//! [`Error::ShortResponse`] instead of panicking. To stay bug-for-bug compatible with the old
//! parsers, the reported `got`/`need` byte counts are **inclusive of the stripped 2-byte status
//! word** (`got = buf.len() + STATUS_WORD_LEN`), matching what the hand-rolled length checks
//! emitted.

use crate::error::{Error, Result};

/// Length of the vendor status word (first 2 bytes of a raw response) that callers strip before
/// handing the payload to a parser.
///
/// The pre-existing parsers reported short-response byte counts *inclusive* of this word (a
/// response of `N` payload bytes is `N + STATUS_WORD_LEN` on the wire), so [`Cursor`] adds it back
/// into every [`Error::ShortResponse`] to reproduce that convention exactly.
pub const STATUS_WORD_LEN: usize = 2;

/// A forward-only, bounds-checked reader over a response payload slice.
///
/// Construct with [`Cursor::new_for`] when the emitted [`Error::ShortResponse`] should carry the
/// originating opcode (the pre-TLS `RomInfo`/`FlashInfo`/… parsers), or [`Cursor::new`] for the
/// DB2/match/enroll parsers whose own up-front `Malformed` checks guard every read (so the
/// cursor's error path is unreachable and the opcode is irrelevant).
#[derive(Debug, Clone)]
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
    opcode: u8,
}

impl<'a> Cursor<'a> {
    /// A cursor whose underflow errors carry opcode `0` (no such command). Use for parsers that
    /// bounds-check up front with their own [`Error::Malformed`] so the cursor never actually
    /// underflows.
    pub fn new(buf: &'a [u8]) -> Cursor<'a> {
        Cursor::new_for(0, buf)
    }

    /// A cursor whose underflow errors report `opcode` (so callers get the same
    /// [`Error::ShortResponse`] the hand-rolled parser produced).
    pub fn new_for(opcode: u8, buf: &'a [u8]) -> Cursor<'a> {
        Cursor {
            buf,
            pos: 0,
            opcode,
        }
    }

    /// Build the [`Error::ShortResponse`] for a read that needs the buffer to reach absolute
    /// offset `end`. Both counts include the stripped status word (see [`STATUS_WORD_LEN`]).
    fn short(&self, end: usize) -> Error {
        Error::ShortResponse {
            opcode: self.opcode,
            got: self.buf.len() + STATUS_WORD_LEN,
            need: end + STATUS_WORD_LEN,
        }
    }

    /// Assert the payload is at least `min_len` bytes, reproducing the historical up-front length
    /// check: on failure the error reports `got = len + 2`, `need = min_len + 2`.
    pub fn require(&self, min_len: usize) -> Result<()> {
        if self.buf.len() < min_len {
            return Err(self.short(min_len));
        }
        Ok(())
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Current read offset into the payload.
    pub fn offset(&self) -> usize {
        self.pos
    }

    /// Read one byte.
    pub fn read_u8(&mut self) -> Result<u8> {
        let end = self.pos + 1;
        if end > self.buf.len() {
            return Err(self.short(end));
        }
        let v = self.buf[self.pos];
        self.pos = end;
        Ok(v)
    }

    /// Read a little-endian `u16`.
    pub fn read_u16_le(&mut self) -> Result<u16> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Read a little-endian `u32`.
    pub fn read_u32_le(&mut self) -> Result<u32> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read `n` raw bytes.
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos + n;
        if end > self.buf.len() {
            return Err(self.short(end));
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    /// Consume and return everything from the current offset to the end (never fails).
    pub fn take_rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }

    /// Advance past `n` bytes (bounds-checked).
    pub fn skip(&mut self, n: usize) -> Result<()> {
        let end = self.pos + n;
        if end > self.buf.len() {
            return Err(self.short(end));
        }
        self.pos = end;
        Ok(())
    }

    /// Read a little-endian `u16` at `rel` bytes *ahead* of the current offset **without**
    /// advancing. Used by walkers whose record length includes its own header (enroll `0x6b`).
    pub fn peek_u16_le(&self, rel: usize) -> Result<u16> {
        let start = self.pos + rel;
        let end = start + 2;
        if end > self.buf.len() {
            return Err(self.short(end));
        }
        Ok(u16::from_le_bytes([self.buf[start], self.buf[start + 1]]))
    }
}

/// Read up to `count` fixed-`stride` records out of `buf`, stopping early (truncating, never
/// panicking) if the buffer runs out mid-record.
///
/// Mirrors the hand-rolled `for i in 0..cnt { if i*stride+stride > len { break } … }` loops the
/// DB2/flash/fw parsers used. `parse` is handed exactly `stride` bytes per record; it can read
/// them with a fresh [`Cursor`] (whose reads cannot fail on a full-`stride` slice).
pub fn read_records<T>(
    buf: &[u8],
    stride: usize,
    count: usize,
    parse: impl Fn(&[u8]) -> T,
) -> Vec<T> {
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let start = i * stride;
        let end = start + stride;
        if end > buf.len() {
            break;
        }
        out.push(parse(&buf[start..end]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn sequential_reads_at_boundaries() {
        let buf = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let mut c = Cursor::new(&buf);
        assert_eq!(c.read_u8().unwrap(), 0x01);
        assert_eq!(c.offset(), 1);
        assert_eq!(c.read_u16_le().unwrap(), 0x0302);
        assert_eq!(c.read_u32_le().unwrap(), 0x0706_0504);
        assert_eq!(c.remaining(), 0);
        // Exhausted: one more byte underflows.
        assert!(c.read_u8().is_err());
    }

    #[test]
    fn take_rest_and_skip() {
        let buf = [0xaau8, 0xbb, 0xcc, 0xdd];
        let mut c = Cursor::new(&buf);
        c.skip(1).unwrap();
        assert_eq!(c.take_rest(), &[0xbb, 0xcc, 0xdd]);
        assert_eq!(c.remaining(), 0);
        assert_eq!(c.take_rest(), &[] as &[u8]);
    }

    #[test]
    fn skip_past_end_errors() {
        let buf = [0x00u8, 0x11];
        let mut c = Cursor::new(&buf);
        assert!(c.skip(3).is_err());
    }

    #[test]
    fn underflow_reports_got_and_need_with_status_word() {
        // 5-byte payload; reading a u32 starting at offset 4 needs the buffer to reach offset 8.
        // got = 5 + 2, need = 8 + 2 — the stripped-status-word convention.
        let buf = [0u8; 5];
        let mut c = Cursor::new_for(0x43, &buf);
        c.skip(4).unwrap();
        match c.read_u32_le() {
            Err(Error::ShortResponse { opcode, got, need }) => {
                assert_eq!(opcode, 0x43);
                assert_eq!(got, 5 + STATUS_WORD_LEN);
                assert_eq!(need, 8 + STATUS_WORD_LEN);
            }
            other => panic!("expected ShortResponse, got {other:?}"),
        }
    }

    #[test]
    fn require_reports_min_len_convention() {
        let buf = [0u8; 6];
        let c = Cursor::new_for(0x01, &buf);
        // Needs 0x10 payload bytes -> reports need 0x12 (incl. status), got 8 (= 6 + 2).
        match c.require(0x10) {
            Err(Error::ShortResponse { opcode, got, need }) => {
                assert_eq!(
                    (opcode, got, need),
                    (0x01, 6 + STATUS_WORD_LEN, 0x10 + STATUS_WORD_LEN)
                );
            }
            other => panic!("expected ShortResponse, got {other:?}"),
        }
        // Exactly-enough passes.
        assert!(Cursor::new(&[0u8; 0x10]).require(0x10).is_ok());
    }

    #[test]
    fn peek_does_not_advance() {
        let buf = [0x10u8, 0x20, 0x30, 0x40];
        let c = Cursor::new(&buf);
        assert_eq!(c.peek_u16_le(0).unwrap(), 0x2010);
        assert_eq!(c.peek_u16_le(2).unwrap(), 0x4030);
        assert_eq!(c.offset(), 0);
        assert!(c.peek_u16_le(3).is_err()); // would read [3..5], out of bounds
    }

    #[test]
    fn read_records_reads_full_records() {
        // three 2-byte LE records
        let buf = [0x01u8, 0x00, 0x02, 0x00, 0x03, 0x00];
        let v = read_records(&buf, 2, 3, |b| {
            Cursor::new(b).read_u16_le().unwrap_or_default()
        });
        assert_eq!(v, vec![1u16, 2, 3]);
    }

    #[test]
    fn read_records_truncates_on_short_buffer() {
        // count says 4 records of stride 3, but only 2.5 records' worth of bytes are present.
        let buf = [1u8, 2, 3, 4, 5, 6, 7];
        let v = read_records(&buf, 3, 4, |b| b[0]);
        assert_eq!(v, vec![1u8, 4]); // third record (bytes 6..9) is incomplete -> stop
    }

    #[test]
    fn read_records_zero_count_is_empty() {
        let buf = [1u8, 2, 3, 4];
        let v: Vec<u8> = read_records(&buf, 2, 0, |b| b[0]);
        assert!(v.is_empty());
    }
}
