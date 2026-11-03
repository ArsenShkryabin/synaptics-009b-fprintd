//! Offline artifact diagnostics for flat `0x51` polled bodies — numeric reports only (Rule #7).
//!
//! Boxy patches that **jump frame-to-frame** usually come from one of:
//!   1. **In-body reference cells** — [`crate::capture::REFERENCE_CELL_SIGNATURE`] (8 B), marching
//!      diagonally (+8 col, +1 row per interleaved field when `repeat_multiplier=2`).
//!   2. **16-byte timeslot blocks** — periodic structure before/after descramble; wrong line width
//!      (8 vs 9 blocks) misaligns block boundaries so boxes appear to slide.
//!   3. **Stream cursor drift** — polling `0x51` without re-arm reads a continuation offset; the whole
//!      raster shifts by an integer number of bytes (often multiples of 16 or 128).

use crate::capture::{ReferenceCellHit, REFERENCE_CELL_SIGNATURE};
use crate::reconstruct::TIMESLOTS_PER_BLOCK;

/// Flat `0x51` body length for subtype `0x2449`.
pub const BODY_LEN_2449: usize = 8064;

/// Strip tunnel status + 16-byte fw header when present; else truncate to `max_len`.
pub fn polled_body(raw: &[u8], max_len: usize) -> Vec<u8> {
    const FRAMING: usize = 18;
    if raw.len() >= FRAMING + max_len {
        raw[FRAMING..FRAMING + max_len].to_vec()
    } else {
        raw[..raw.len().min(max_len)].to_vec()
    }
}

/// Row-major `(row, col)` → linear index in a `width`-column raster.
#[inline]
pub fn flat_offset(row: usize, col: usize, width: usize) -> usize {
    row * width + col
}

/// Linear index → `(row, col)` for a `width`-column raster.
#[inline]
pub fn raster_coords(flat: usize, width: usize) -> (usize, usize) {
    (flat / width, flat % width)
}

/// One measured occurrence of the 8-byte reference signature with numeric context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureOccurrence {
    pub flat_offset: usize,
    pub row: usize,
    pub col: usize,
    /// Which 16-byte timeslot block within the row (col / 16).
    pub block_col: usize,
    /// `row % fields` when analysing interleaved field rows.
    pub field_row: usize,
    pub bytes: [u8; 8],
    /// Eight bytes immediately before the signature within the row (or from prior row if col < 8).
    pub before: [u8; 8],
    /// Eight bytes immediately after the signature within the row.
    pub after: [u8; 8],
}

/// Scan for [`REFERENCE_CELL_SIGNATURE`] with buffer offsets and neighbour bytes.
pub fn scan_signatures(body: &[u8], width: usize, fields: usize) -> Vec<SignatureOccurrence> {
    if width == 0 || body.len() < REFERENCE_CELL_SIGNATURE.len() {
        return Vec::new();
    }
    let height = body.len() / width;
    let sig = REFERENCE_CELL_SIGNATURE;
    let fields = fields.max(1);
    let mut out = Vec::new();
    for row in 0..height {
        let base = row * width;
        let row_slice = &body[base..base + width];
        for col in 0..row_slice.len().saturating_sub(sig.len() - 1) {
            if row_slice[col..col + sig.len()] != sig {
                continue;
            }
            let flat = base + col;
            let before = read_context(body, width, row, col.saturating_sub(8), 8);
            let after = read_context(body, width, row, col + sig.len(), 8);
            out.push(SignatureOccurrence {
                flat_offset: flat,
                row,
                col,
                block_col: col / TIMESLOTS_PER_BLOCK,
                field_row: row % fields,
                bytes: sig,
                before,
                after,
            });
        }
    }
    out
}

fn read_context(body: &[u8], width: usize, row: usize, col: usize, len: usize) -> [u8; 8] {
    let mut out = [0u8; 8];
    for (i, slot) in out.iter_mut().take(len).enumerate() {
        let c = col + i;
        let (r, cc) = if c < width {
            (row, c)
        } else {
            (row + 1, c - width)
        };
        let off = r * width + cc;
        if let Some(&b) = body.get(off) {
            *slot = b;
        }
    }
    out
}

/// Per 16×1 timeslot block within each row (one Hadamard group).
#[derive(Debug, Clone, Copy)]
pub struct TimeslotBlockStats {
    pub row: usize,
    pub block_col: usize,
    pub flat_offset: usize,
    pub mean: f64,
    pub std: f64,
    pub min: u8,
    pub max: u8,
}

/// Summarise every 16-byte block in a row-major raster.
pub fn timeslot_blocks(body: &[u8], width: usize) -> Vec<TimeslotBlockStats> {
    if width == 0 || !width.is_multiple_of(TIMESLOTS_PER_BLOCK) {
        return Vec::new();
    }
    let blocks_per_line = width / TIMESLOTS_PER_BLOCK;
    let height = body.len() / width;
    let mut out = Vec::with_capacity(height * blocks_per_line);
    for row in 0..height {
        for bc in 0..blocks_per_line {
            let col = bc * TIMESLOTS_PER_BLOCK;
            let off = flat_offset(row, col, width);
            if off + TIMESLOTS_PER_BLOCK > body.len() {
                break;
            }
            let slice = &body[off..off + TIMESLOTS_PER_BLOCK];
            let mean = slice.iter().map(|&b| b as f64).sum::<f64>() / TIMESLOTS_PER_BLOCK as f64;
            let var = slice
                .iter()
                .map(|&b| {
                    let d = b as f64 - mean;
                    d * d
                })
                .sum::<f64>()
                / TIMESLOTS_PER_BLOCK as f64;
            out.push(TimeslotBlockStats {
                row,
                block_col: bc,
                flat_offset: off,
                mean,
                std: var.sqrt(),
                min: *slice.iter().min().unwrap(),
                max: *slice.iter().max().unwrap(),
            });
        }
    }
    out
}

/// Mean absolute difference across aligned blocks — highlights jumping box regions.
pub fn block_mean_abs_delta(a: &[u8], b: &[u8], width: usize) -> Vec<(usize, usize, f64)> {
    let ba = timeslot_blocks(a, width);
    let bb = timeslot_blocks(b, width);
    ba.iter()
        .zip(bb.iter())
        .map(|(x, y)| {
            (
                x.row,
                x.block_col,
                (x.mean - y.mean).abs() + (x.std - y.std).abs(),
            )
        })
        .collect()
}

/// Estimate circular flat shift maximizing mean abs correlation (detects stream cursor drift).
pub fn estimate_flat_shift(prev: &[u8], curr: &[u8]) -> (i32, f64) {
    let n = prev.len().min(curr.len());
    if n == 0 {
        return (0, 0.0);
    }
    let max_shift = 256i32;
    let mut best = (0i32, 0.0f64);
    for shift in -max_shift..=max_shift {
        let sum: f64 = prev[..n]
            .iter()
            .enumerate()
            .map(|(i, &p)| {
                let j = (i as i32 + shift).rem_euclid(n as i32) as usize;
                (p as i32 - curr[j] as i32).unsigned_abs() as f64
            })
            .sum();
        // `n > 0` — the empty case returned above, so this never divides by zero.
        let mad = sum / n as f64;
        let score = 255.0 - mad;
        if score > best.1 + 1e-9
            || ((score - best.1).abs() < 1e-9 && shift.unsigned_abs() < best.0.unsigned_abs())
        {
            best = (shift, score);
        }
    }
    best
}

/// Discontinuity at 16-column block boundaries (avg |Δ| across interior vs boundary).
pub fn block_boundary_contrast(body: &[u8], width: usize) -> (f64, f64) {
    if width < 32 || !width.is_multiple_of(TIMESLOTS_PER_BLOCK) {
        return (0.0, 0.0);
    }
    let height = body.len() / width;
    let mut interior = 0.0f64;
    let mut boundary = 0.0f64;
    let mut ni = 0usize;
    let mut nb = 0usize;
    for row in 0..height {
        let base = row * width;
        for col in 1..width {
            let d = (body[base + col] as i32 - body[base + col - 1] as i32).unsigned_abs() as f64;
            if col % TIMESLOTS_PER_BLOCK == 0 {
                boundary += d;
                nb += 1;
            } else {
                interior += d;
                ni += 1;
            }
        }
    }
    (
        if ni > 0 { interior / ni as f64 } else { 0.0 },
        if nb > 0 { boundary / nb as f64 } else { 0.0 },
    )
}

/// Frame-to-frame motion of the first signature hit (if any).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureMotion {
    pub prev_flat: usize,
    pub curr_flat: usize,
    pub delta_flat: i32,
    pub delta_row: i32,
    pub delta_col: i32,
}

/// Compare signature at `index` when both frames have enough hits.
pub fn signature_motion_at(
    prev_hits: &[SignatureOccurrence],
    curr_hits: &[SignatureOccurrence],
    index: usize,
) -> Option<SignatureMotion> {
    let (p, c) = (prev_hits.get(index)?, curr_hits.get(index)?);
    Some(SignatureMotion {
        prev_flat: p.flat_offset,
        curr_flat: c.flat_offset,
        delta_flat: c.flat_offset as i32 - p.flat_offset as i32,
        delta_row: c.row as i32 - p.row as i32,
        delta_col: c.col as i32 - p.col as i32,
    })
}

/// Match each current hit to the nearest previous hit by flat offset.
pub fn match_signature_hits(
    prev: &[SignatureOccurrence],
    curr: &[SignatureOccurrence],
) -> Vec<(usize, usize, SignatureMotion)> {
    let mut out = Vec::new();
    for (ci, c) in curr.iter().enumerate() {
        if let Some((pi, p)) = prev
            .iter()
            .enumerate()
            .min_by_key(|(_, p)| (p.flat_offset as i32 - c.flat_offset as i32).unsigned_abs())
        {
            out.push((
                pi,
                ci,
                SignatureMotion {
                    prev_flat: p.flat_offset,
                    curr_flat: c.flat_offset,
                    delta_flat: c.flat_offset as i32 - p.flat_offset as i32,
                    delta_row: c.row as i32 - p.row as i32,
                    delta_col: c.col as i32 - p.col as i32,
                },
            ));
        }
    }
    out
}

/// Convert legacy hits to occurrences (no context bytes).
pub fn hits_to_occurrences(hits: &[ReferenceCellHit], body: &[u8], width: usize, fields: usize) -> Vec<SignatureOccurrence> {
    scan_signatures(body, width, fields)
        .into_iter()
        .filter(|o| hits.iter().any(|h| h.row == o.row && h.col == o.col))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_finds_signature_with_offsets() {
        let width = 144;
        let mut body = vec![0u8; width * 4];
        body[width + 16..width + 24].copy_from_slice(&REFERENCE_CELL_SIGNATURE);
        let hits = scan_signatures(&body, width, 2);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].flat_offset, width + 16);
        assert_eq!(hits[0].row, 1);
        assert_eq!(hits[0].col, 16);
        assert_eq!(hits[0].block_col, 1);
    }

    #[test]
    fn flat_shift_zero_on_identical() {
        let b = vec![42u8; 8064];
        let (shift, score) = estimate_flat_shift(&b, &b);
        assert_eq!(shift, 0);
        assert!(score > 250.0);
    }

    #[test]
    fn flat_shift_detects_rotation() {
        let mut a = vec![0u8; 100];
        (0..100).for_each(|i| a[i] = i as u8);
        let mut b = a.clone();
        b.rotate_right(16);
        let (shift, _) = estimate_flat_shift(&a, &b);
        assert_eq!(shift, 16);
    }
}
