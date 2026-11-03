//! Factory calibration blocks — the 0x2449 provisioned-sensor per-line correction the vendor folds
//! into the capture line-update (task #26/#27). Traced from `synaWudfBioUsb.dll`; see
//! `docs/calibration/calibration-impl-spec.md` and `docs/calibration/calibration-state-machine.md` for the byte-level
//! derivation.
//!
//! On a provisioned sensor the per-line calib diff comes from a FACTORY BLOCK read off the device
//! (wire opcode `0x6f`, tag 14 = the per-tag block table), NOT a live dark-frame capture. This
//! module implements the pure path: parse the `0x6f` TLV response → find factory block
//! [`CAL_DIFF_BLOCK_TAG`] (`0x80000003`) → produce the bit-packed per-line diff (the DLL's
//! `pStep3_diff_ptr`, from `syna_lib_cal_step3_line_diff@0x180075100`). That buffer replaces the
//! static `DAT_CAL_2449` fallback source in [`crate::line_update::line_update_prod33`], so a
//! calibrated arm folds the sensor's MEASURED correction instead of flat factory defaults.
//!
//! The single device step (the `0x6f` round-trip) is left to the caller (it owns the TLS session);
//! this module provides the request builder ([`factory_bits_request`]) and parses the raw response
//! payload. Everything here is pure + unit-tested; no hardware needed.
//!
//! NB step-3 stores the RAW per-line values (`syna_lib_cal_step3_line_diff@0x180075100` takes its
//! raw-store branch for product class '3'), and the line-update builder bit-packs them ONCE
//! (`syna_bitpack_calib_diff@0x180095d40`, single-array). [`cal_line_diff`] therefore returns the RAW
//! array; the single pack happens in `line_update_prod33`. (The earlier "double-bitpack" note — and the
//! matching Ghidra plates — were wrong; corrected 2026-07-21 against the decompile.)

use std::collections::HashMap;

use crate::wire::Cursor;

/// Wire opcode that reads a factory-bits data set (`syna_cmd_6f_get_factory_bits@0x18008ba20`).
pub const WIRE_OP_FACTORY_BITS: u8 = 0x6f;
/// Tag byte selecting the per-tag factory BLOCK TABLE for the **`0x80000003` fcv subtag-3 read**
/// (`0x6f` before calibration). Distinct from [`FACTORY_TAG_CAL_INIT`].
pub const FACTORY_TAG_BLOCK_TABLE: u8 = 0x0e; // 14
/// Tag byte for `syna_lib_cal_init_load_factory_bits@0x180077870` — the factory-block table
/// `syna_cal_get_factory_block_by_tag` searches during `syna_lib_run_calibration`.
pub const FACTORY_TAG_CAL_INIT: u8 = 0x0a; // 10
/// Factory block tag holding the step-3 per-line calibration diff (`syna_lib_cal_step3_line_diff`).
pub const CAL_DIFF_BLOCK_TAG: u32 = 0x8000_0003;
/// Per-block header before the per-line array in the `0x80000003` block: `const_lo, const_hi, 2 pad`
/// — `syna_lib_cal_step3_line_diff` strips these before bit-packing.
pub const CAL_DIFF_BLOCK_HEADER: usize = 4;
/// Fixed header of a `0x6f` TLV wire record before its variable-length data
/// (`reserved0:u32, data_len:u16, flags:u8, pad:u8, tag:u32`).
const TLV_RECORD_HEADER: usize = 0x0c;

/// The 9-byte `0x6f` request that reads factory data set `tag` (count byte 0 ⇒ 0x1000 response cap):
/// `[0x6f, 0, tag, 0, 0, 0,0,0,0]`. `syna_cmd_6f_get_factory_bits@0x18008ba20`.
pub fn factory_bits_request(tag: u8) -> [u8; 9] {
    [
        WIRE_OP_FACTORY_BITS,
        0x00,
        tag,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ]
}

/// One factory block parsed from a `0x6f` TLV response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactoryBlock {
    /// Block tag (search key), e.g. `0x80000003`. Wire record `+0x08`.
    pub tag: u32,
    /// Opaque per-block flags byte. Wire record `+0x06`.
    pub flags: u8,
    /// Block payload (`data_len` bytes). Wire record `+0x0c`.
    pub data: Vec<u8>,
}

fn round_up4(n: usize) -> usize {
    n.div_ceil(4) * 4
}

/// Parse the `0x6f` response PAYLOAD (the bytes after the 2-byte status word) into factory blocks.
/// Records are `[reserved0:u32, data_len:u16, flags:u8, pad, tag:u32, data[data_len]]`, each
/// occupying `0x0c + round_up4(data_len)` bytes back-to-back. Stops cleanly at the first truncated
/// record (never panics — the bounds-checked [`Cursor`] handles a short/garbled response).
pub fn parse_factory_blocks(payload: &[u8]) -> Vec<FactoryBlock> {
    let mut out = Vec::new();
    let mut c = Cursor::new(payload);
    while c.remaining() >= TLV_RECORD_HEADER {
        let (Ok(_reserved0), Ok(data_len), Ok(flags), Ok(_pad), Ok(tag)) = (
            c.read_u32_le(),
            c.read_u16_le(),
            c.read_u8(),
            c.read_u8(),
            c.read_u32_le(),
        ) else {
            break;
        };
        let dl = data_len as usize;
        let Ok(data) = c.read_bytes(dl) else { break };
        out.push(FactoryBlock {
            tag,
            flags,
            data: data.to_vec(),
        });
        // Records are 4-byte aligned: skip the pad after the data.
        let pad = round_up4(dl) - dl;
        if pad > 0 && c.skip(pad).is_err() {
            break;
        }
    }
    out
}

/// Legacy subtag-indexed map from a tag-14 (`0x0e`) `0x6f` payload — each entry is keyed by the
/// wire `subtag` u16 at record offset `+0x08`. Example binaries use subtag `3` for the per-line
/// factory calib blob; [`parse_factory_blocks`] is preferred for block-tag (`u32`) lookup.
pub fn parse_factory_bits_by_subtag(payload: &[u8]) -> HashMap<u16, Vec<u8>> {
    let mut rc = HashMap::new();
    if payload.len() < 8 {
        return rc;
    }
    let entries = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let mut p = 8usize;
    for _ in 0..entries {
        if p + 12 > payload.len() {
            break;
        }
        let len = u16::from_le_bytes([payload[p + 4], payload[p + 5]]) as usize;
        let subtag = u16::from_le_bytes([payload[p + 8], payload[p + 9]]);
        p += 12;
        if p + len > payload.len() {
            break;
        }
        rc.insert(subtag, payload[p..p + len].to_vec());
        p += len;
    }
    rc
}

/// Subtag-3 factory calib values from a tag-14 payload (4-byte header stripped), example fallback.
pub fn factory_cal_values_subtag3(payload: &[u8]) -> Vec<u8> {
    parse_factory_bits_by_subtag(payload)
        .get(&3)
        .map(|v| v.get(4..).unwrap_or(&[]).to_vec())
        .unwrap_or_default()
}

/// Block-table (`0x6f` tag `0x0e`) reply as [`FactoryBlock`]s — subtag-indexed layout (NOT TLV).
/// Subtag N maps to block tag `0x8000000N` (subtag 3 → `0x80000003` step-3 diff).
pub fn factory_block_table_from_subtag_response(payload: &[u8]) -> Vec<FactoryBlock> {
    parse_factory_bits_by_subtag(payload)
        .into_iter()
        .map(|(subtag, data)| FactoryBlock {
            tag: 0x8000_0000 | subtag as u32,
            flags: 0,
            data,
        })
        .collect()
}

/// Find the factory block with the given tag.
pub fn factory_block(blocks: &[FactoryBlock], tag: u32) -> Option<&FactoryBlock> {
    blocks.iter().find(|b| b.tag == tag)
}

/// The 56-byte (for `0x2449`) per-line factory calib blob folded into `prod33_body` — payload of
/// factory block [`CAL_DIFF_BLOCK_TAG`] after its 4-byte header (`syna_lib_cal_step3_line_diff`).
pub fn factory_calibration_values(blocks: &[FactoryBlock], width: usize) -> Vec<u8> {
    factory_block(blocks, CAL_DIFF_BLOCK_TAG)
        .and_then(|b| b.data.get(CAL_DIFF_BLOCK_HEADER..))
        .and_then(|s| s.get(..width))
        .map(<[u8]>::to_vec)
        .unwrap_or_default()
}

/// Parse a tag-14 (`0x0e`) `0x6f` response payload and return the per-line factory calib blob.
pub fn factory_calibration_values_from_response(payload: &[u8], width: usize) -> Vec<u8> {
    factory_calibration_values(&parse_factory_blocks(payload), width)
}

/// Produce step-3's per-line calibration diff (`pStep3_diff_ptr`) for a `width`-wide sensor from the
/// `0x80000003` factory block → the **raw** per-line diff (`pStep3_diff_ptr`): strip the
/// [`CAL_DIFF_BLOCK_HEADER`]-byte block header and take the next `width` bytes. This is the DAT-A/B
/// source that [`crate::line_update::line_update_prod33`] bit-packs **once** onto the wire (exactly as
/// it bit-packs the static [`crate::line_update::DAT_CAL_2449`] fallback). `None` if the block is
/// absent or shorter than `header + width`.
///
/// (Earlier this pre-bit-packed and `line_update_prod33` packed again — a *double* bit-pack that gave
/// width-8 garbage. The live DLL single-packs: DAT-A = width 5, min 119. Verified vs `dll.pcap` 0x43.)
pub fn cal_line_diff(blocks: &[FactoryBlock], width: usize) -> Option<Vec<u8>> {
    let block = factory_block(blocks, CAL_DIFF_BLOCK_TAG)?;
    cal_diff_from_line_array(block.data.get(CAL_DIFF_BLOCK_HEADER..)?, width)
}

/// Take the first `width` bytes of an already-header-stripped `0x80000003` per-line array as the raw
/// step-3 diff (`pStep3_diff_ptr`). The single bit-pack onto the wire happens in
/// [`crate::line_update::line_update_prod33`]. `None` if the array is shorter than `width`.
///
/// `width` is [`crate::capture_progs_9b::SensorTypeInfo::lines_per_calibration_data`] (56 for 0x2449,
/// matching the 56-byte [`crate::line_update::DAT_CAL_2449`] fallback this replaces).
pub fn cal_diff_from_line_array(per_line: &[u8], width: usize) -> Option<Vec<u8>> {
    Some(per_line.get(..width)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one `0x6f` TLV wire record (4-byte aligned data).
    fn record(tag: u32, flags: u8, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved0
        v.extend_from_slice(&(data.len() as u16).to_le_bytes()); // data_len
        v.push(flags);
        v.push(0); // pad
        v.extend_from_slice(&tag.to_le_bytes());
        v.extend_from_slice(data);
        while v.len() % 4 != 0 {
            v.push(0); // 4-byte-align the next record
        }
        v
    }

    #[test]
    fn parse_factory_bits_by_subtag_legacy_layout() {
        // Two entries: subtag 3 with 4-byte header + payload, subtag 7 empty body.
        let mut entry3 = vec![0u8; 12];
        entry3[4..6].copy_from_slice(&8u16.to_le_bytes()); // len
        entry3[8..10].copy_from_slice(&3u16.to_le_bytes()); // subtag
        entry3.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        let mut entry7 = vec![0u8; 12];
        entry7[8..10].copy_from_slice(&7u16.to_le_bytes());
        let mut payload = [0u32.to_le_bytes(), 2u32.to_le_bytes()].concat();
        payload.extend_from_slice(&entry3);
        payload.extend_from_slice(&entry7);
        let map = parse_factory_bits_by_subtag(&payload);
        assert_eq!(map.get(&3).unwrap(), &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert_eq!(
            factory_cal_values_subtag3(&payload),
            vec![0x55, 0x66, 0x77, 0x88]
        );
    }

    #[test]
    fn request_bytes_cal_init() {
        assert_eq!(
            factory_bits_request(FACTORY_TAG_CAL_INIT),
            [0x6f, 0, 0x0a, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn request_bytes() {
        assert_eq!(
            factory_bits_request(FACTORY_TAG_BLOCK_TABLE),
            [0x6f, 0, 0x0e, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn parses_multiple_blocks() {
        let mut payload = record(0x8000_0007, 0x11, &[1, 2, 3]); // odd len → padded
        payload.extend(record(CAL_DIFF_BLOCK_TAG, 0x22, &[9, 8, 7, 6]));
        let blocks = parse_factory_blocks(&payload);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].tag, 0x8000_0007);
        assert_eq!(blocks[0].flags, 0x11);
        assert_eq!(blocks[0].data, vec![1, 2, 3]);
        let cd = factory_block(&blocks, CAL_DIFF_BLOCK_TAG).unwrap();
        assert_eq!(cd.data, vec![9, 8, 7, 6]);
    }

    #[test]
    fn truncated_response_does_not_panic() {
        // A record claiming 100 data bytes but the payload ends early → parsed as empty, no panic.
        let mut payload = record(CAL_DIFF_BLOCK_TAG, 0, &[]);
        payload[4] = 100; // overwrite data_len with a bogus large value
        payload.truncate(TLV_RECORD_HEADER); // no data bytes present
        assert!(parse_factory_blocks(&payload).is_empty());
    }

    #[test]
    fn cal_line_diff_strips_header_and_bitpacks_width() {
        // Block = [const_lo, const_hi, pad, pad, <width per-line bytes>]. Only the width bytes after
        // the 4-byte header are bit-packed; extra trailing bytes are ignored.
        let width = 8;
        let per_line = [10u8, 11, 12, 13, 14, 15, 16, 17];
        let mut data = vec![0xaa, 0xbb, 0x00, 0x00]; // const_lo/hi + 2 pad
        data.extend_from_slice(&per_line);
        data.extend_from_slice(&[0xff, 0xff]); // trailing bytes beyond width → ignored
        let payload = record(CAL_DIFF_BLOCK_TAG, 0, &data);
        let blocks = parse_factory_blocks(&payload);

        let got = cal_line_diff(&blocks, width).expect("diff");
        // Returns the RAW width-wide per-line array (the single bit-pack happens in
        // line_update_prod33; the trailing bytes beyond `width` are ignored).
        assert_eq!(got, per_line);
    }

    #[test]
    fn cal_line_diff_none_when_block_absent_or_short() {
        let other = parse_factory_blocks(&record(0x8000_0007, 0, &[1, 2, 3, 4]));
        assert!(cal_line_diff(&other, 8).is_none()); // tag not present
        // Block present but shorter than header+width.
        let short = parse_factory_blocks(&record(CAL_DIFF_BLOCK_TAG, 0, &[1, 2, 3, 4, 5]));
        assert!(cal_line_diff(&short, 8).is_none());
    }
}
