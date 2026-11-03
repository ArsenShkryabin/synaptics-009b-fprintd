//! QM matcher data model — recovered by RE of `synaWudfBioUsb.dll` (Ghidra project `firmware-re`).
//!
//! Phase Q0 artifact: `#[repr(C)]` mirrors of the vendor `syna_qm_*` structs plus the named
//! constants (thresholds, angle units, decision codes) the engine uses. This file is a
//! DATA-MODEL reference; it is intentionally NOT wired into the crate module tree and carries no
//! algorithm logic. Every field/const cites the Ghidra address it was derived from.
//!
//! Layout note: several vendor structs are UNALIGNED / byte-packed (e.g. the match-result reads a
//! `u32` at file-offset 0x39). The `#[repr(C, packed)]` mirrors below reproduce the exact byte
//! offsets the getters read; do not assume natural alignment.
//!
//! Provenance summary (all in `synaWudfBioUsb.dll`, image base 0x180000000):
//!   - `syna_qm_match_core`               @ 0x180100620  (writes the result struct, applies threshold)
//!   - `syna_qm_result_get_*`             @ 0x1800a8950.. (one getter per result field)
//!   - `syna_qm_minutia_neighbor_match`   @ 0x180004690  (neighbor descriptor / xform)
//!   - `syna_qm_pair_neighbor_candidates` @ 0x1800035f0  (minutia record field offsets)
//!   - `syna_qm_build_neighbor_candidates`@ 0x180003830  (minutia-neighbors context)
//!   - `syna_qm_descriptor_hamming_dist`  @ 0x180003490  (64-bit binary descriptor, popcount LUT @0x18014e1a0)
//!   - `syna_qm_angle_diff_mod180`        @ 0x1800045d0  (orientation angle units)
//!   - `syna_qm_engine_ctx_new`           @ 0x1800ff0f0  (primitive engine ctx)
//!   - `syna_qm_engine_vtable_init`       @ 0x1800fe7b0  (engine object / vtable)

#![allow(dead_code)]

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Acceptance thresholds selected by match "level" (`engineState+0x20`) in
/// `syna_qm_match_core@0x180100620`. Decision is MATCH when `score > threshold`.
/// These are hardcoded-by-level in the DLL (NOT read from the flex table), but see
/// [`EngineStateConfig`] for the optional per-session override fields that MAY be flex-derived.
pub mod threshold {
    /// Level 1 (default) — `local_b8[0] = 0x4b0`. syna_qm_match_core@0x180100620.
    pub const LEVEL_1: u32 = 1200; // 0x4b0
    /// Level 2 — `local_b8[0] = 0x8cb`. syna_qm_match_core@0x180100620.
    pub const LEVEL_2: u32 = 2251; // 0x8cb
    /// Level 3 — `local_b8[0] = 0x9c5`. syna_qm_match_core@0x180100620.
    pub const LEVEL_3: u32 = 2501; // 0x9c5
    /// Fallback when level is not 1/2/3 — same as LEVEL_1. syna_qm_match_core@0x180100620.
    pub const DEFAULT: u32 = LEVEL_1;
}

/// Match "level" selector stored at `engineState+0x20`, mapped to a threshold in
/// `syna_qm_match_core@0x180100620`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MatchLevel {
    /// FAR/threshold tier 1 (loosest, 1200). Also the default for any unknown value.
    Level1 = 1,
    /// FAR/threshold tier 2 (2251).
    Level2 = 2,
    /// FAR/threshold tier 3 (tightest, 2501).
    Level3 = 3,
}

impl MatchLevel {
    /// Threshold this level applies (see `syna_qm_match_core@0x180100620`).
    pub const fn threshold(self) -> u32 {
        match self {
            MatchLevel::Level1 => threshold::LEVEL_1,
            MatchLevel::Level2 => threshold::LEVEL_2,
            MatchLevel::Level3 => threshold::LEVEL_3,
        }
    }
}

/// `MatchResult.decision` encoding. syna_qm_match_core@0x180100620 writes 1 into the field at
/// result+0x08 when `threshold < score`; the getter `syna_qm_result_get_decision@0x1800a8cd0`
/// returns it verbatim.
pub mod decision {
    /// No match (score did not exceed threshold). Field default 0.
    pub const NO_MATCH: u32 = 0;
    /// Match accepted (`score > threshold`). syna_qm_match_core@0x180100620.
    pub const MATCH: u32 = 1;
}

/// Orientation-angle unit. `syna_qm_angle_diff_mod180@0x1800045d0` reduces angle differences
/// modulo 0xb4 (180) with a 0x5a (90) fold — i.e. angles are UNDIRECTED ridge orientations in
/// DEGREES, range 0..=179. Stored per minutia at `SynaQmMinutia.angle_deg` (+0x0c), consumed as
/// a single byte.
pub const ANGLE_MODULUS_DEG: u32 = 180; // 0xb4
/// Fold offset used in the circular-distance calc. syna_qm_angle_diff_mod180@0x1800045d0.
pub const ANGLE_FOLD_DEG: u32 = 90; // 0x5a

/// Local-neighbor descriptor is a 64-bit BINARY vector compared by Hamming distance.
/// `syna_qm_descriptor_hamming_dist@0x180003490` is called with byteLen=8, uses the 256-entry
/// popcount LUT `g_abSynaQmPopcountTable@0x18014e1a0`, and returns `popcount(xor) * 2`
/// (so the distance range is 0..=128; lower = more similar).
pub const DESCRIPTOR_BYTES: usize = 8;
pub const DESCRIPTOR_BITS: usize = DESCRIPTOR_BYTES * 8; // 64
/// Max descriptor distance a neighbor pair may have and still be accepted.
/// syna_qm_pair_neighbor_candidates@0x1800035f0 (`uVar8 < 0x60`).
pub const DESCRIPTOR_ACCEPT_MAX_DIST: u32 = 0x60; // 96
/// Lowe-style ratio-test gate `(2nd_best*100)/(best+1) > 0x74`.
/// syna_qm_pair_neighbor_candidates@0x1800035f0.
pub const NEIGHBOR_RATIO_TEST_PCT: u32 = 0x74; // 116
/// Alt spatial gate: accept pair if squared coord distance `< 0x24`.
/// syna_qm_pair_neighbor_candidates@0x1800035f0.
pub const NEIGHBOR_SPATIAL_DIST2_MAX: u32 = 0x24; // 36

/// Min matched neighbors required for a local-structure match; below this the neighbor match
/// rejects with sentinel distance [`NEIGHBOR_REJECT_DIST`] and identity transform.
/// syna_qm_minutia_neighbor_match@0x180004690 (`if (iVar5 < 4)`).
pub const MIN_MATCHED_NEIGHBORS: i32 = 4;
/// Max neighbor candidates scored per minutia (top-N by distance).
/// syna_qm_minutia_neighbor_match@0x180004690 (`uVar15 = 0x19`).
pub const MAX_NEIGHBOR_CANDIDATES: usize = 25; // 0x19
/// Hard cap on candidate pairs generated. syna_qm_pair_neighbor_candidates@0x1800035f0
/// (`*param_2 == 100`) / build buffer 0xaf0 = 100*0x1c.
pub const MAX_CANDIDATE_PAIRS: usize = 100;
/// Sentinel "worst" average distance written on neighbor-match reject.
/// syna_qm_minutia_neighbor_match@0x180004690 (`*param_5 = 0x7fff`).
pub const NEIGHBOR_REJECT_DIST: u32 = 0x7fff;
/// Missing/uncomputed work-record feature — z-norm clamps to +1.6. syna_qm_score_features@0x1800088d0.
pub const FEATURE_SENTINEL: i32 = 0x7fff;

/// Fixed-point scale for the similarity transform (cos/sin/tx/ty). Q16: 0x10000 == 1.0.
/// syna_qm_minutia_neighbor_match@0x180004690 (identity cos = 0x10000).
pub const XFORM_FIXED_ONE: i32 = 0x10000;

/// Per-minutia neighbor-match score above which a minutia is treated as a strong anchor
/// (`workRec+0x38 > 0x7c4`). syna_qm_minutiae_match_kernel@0x180008e60.
pub const MINUTIA_STRONG_SCORE: u32 = 0x7c4; // 1988

/// `syna_qm_check_distance_range@0x18000b320`: first arg must be **strictly greater** than this
/// (used by `syna_qm_find_valid_match@0x180007a10` and `compute_features`).
pub const DISTANCE_RANGE_COUNT_MIN: u8 = 0x1e; // 30
/// `syna_qm_check_distance_range@0x18000b320`: second arg must be **strictly less** than this.
pub const DISTANCE_RANGE_DIST_MAX: u8 = 0x32; // 50

/// Minimum probe minutiae required to attempt a match.
/// syna_qm_match_core@0x180100620 (`local_58 < 10`).
pub const MIN_PROBE_MINUTIAE: i32 = 10;

/// Matcher/template version stamped by `syna_qm_engine_vtable_init@0x1800fe7b0` (`obj[0]=0xca`).
pub const QM_MATCHER_VERSION: u32 = 0xca; // 202

/// Sentinel meaning "config field unset / use engine default" for the optional override params
/// in [`EngineStateConfig`]. syna_qm_match_core@0x180100620 (`!= 0xffffff`).
pub const ENGINE_PARAM_UNSET: u32 = 0x00ff_ffff;

// ---------------------------------------------------------------------------
// Minutia + local descriptor (runtime, deserialized form)
// ---------------------------------------------------------------------------

/// A single minutia in the deserialized (runtime) template, stride **0x20 bytes**.
/// Field offsets from `syna_qm_pair_neighbor_candidates@0x1800035f0`:
/// - +0x00 descriptor pointer (read as `*(u64*)(entry+0)`, fed to the Hamming distance)
/// - +0x0c orientation angle  (read as `*(u32*)(entry+0xc)`, used as a byte, deg 0..179)
/// - +0x14 x coordinate       (`*(i32*)(entry+0x14)`)
/// - +0x18 y coordinate       (`*(i32*)(entry+0x18)`)
///
/// The 8-byte copy at +0x14 grabs (x,y) together into a candidate record.
///
/// NOTE: this is the in-memory form the matcher walks (contains a raw pointer). The AT-REST
/// serialized minutia inside a stored template body is a different, packed encoding produced by
/// the extractor and re-hydrated by the primitive engine — see [`SerializedTemplateRecord`]. That
/// packed layout is a Q1 deliverable (the extractor is a per-subtype vtable callback).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SynaQmMinutia {
    /// +0x00: pointer to this minutia's 64-bit binary local descriptor (device pointer at rest;
    /// mirrored here as a raw address). syna_qm_pair_neighbor_candidates@0x1800035f0.
    pub descriptor_ptr: u64,
    /// +0x08: unknown. Zero/scratch in observed paths.
    // TODO(verify): meaning of minutia+0x08 (quality? cluster id?).
    pub field_08: u32,
    /// +0x0c: orientation angle, DEGREES 0..=179 (undirected, mod 180). Consumed as a byte.
    /// syna_qm_pair_neighbor_candidates@0x1800035f0 + syna_qm_angle_diff_mod180@0x1800045d0.
    pub angle_deg: u32,
    /// +0x10: unknown.
    // TODO(verify): meaning of minutia+0x10 (type? quality?).
    pub field_10: u32,
    /// +0x14: x coordinate (image column). syna_qm_pair_neighbor_candidates@0x1800035f0.
    pub x: i32,
    /// +0x18: y coordinate (image row). syna_qm_pair_neighbor_candidates@0x1800035f0.
    pub y: i32,
    /// +0x1c: unknown.
    // TODO(verify): meaning of minutia+0x1c.
    pub field_1c: u32,
}
const _: () = assert!(core::mem::size_of::<SynaQmMinutia>() == 0x20);

/// A minutia's neighbor context (the object passed to `syna_qm_minutia_neighbor_match` as the
/// per-side arg, e.g. `*(ctx+0x10)` / `*(hdr+4)`).
/// From `syna_qm_build_neighbor_candidates@0x180003830`:
/// - +0x00 pointer to the neighbor minutiae array (`SynaQmMinutia[]`, stride 0x20)
/// - +0x08 total neighbor count (`*(u32*)(ctx+8)`, passed as the loop bound)
/// - +0x0c primary/near-neighbor count as a BYTE (`*(u8*)(ctx+0xc)`) — splits neighbors into a
///   "near" list [0..primary_count) and a "far" list [primary_count..count) for the
///   two-pass candidate build.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SynaQmMinutiaNeighbors {
    /// +0x00: pointer to `SynaQmMinutia[]`. syna_qm_pair_neighbor_candidates@0x1800035f0.
    pub neighbors_ptr: u64,
    /// +0x08: total neighbor count. syna_qm_build_neighbor_candidates@0x180003830.
    pub neighbor_count: u32,
    /// +0x0c: count of primary ("near") neighbors; the rest are "far". BYTE-sized.
    /// syna_qm_build_neighbor_candidates@0x180003830.
    pub primary_count: u8,
    _pad: [u8; 3],
}

/// One candidate neighbor correspondence, stride **0x1c (28) bytes**, emitted by
/// `syna_qm_pair_neighbor_candidates@0x1800035f0` and consumed by
/// `syna_qm_minutia_neighbor_match@0x180004690`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SynaQmNeighborCandidate {
    /// +0x00: probe minutia x. (copied as the (x,y) 8-byte pair)
    pub probe_x: i32,
    /// +0x04: probe minutia y.
    pub probe_y: i32,
    /// +0x08: gallery minutia x.
    pub gallery_x: i32,
    /// +0x0c: gallery minutia y.
    pub gallery_y: i32,
    /// +0x10: probe minutia angle (deg 0..179).
    pub probe_angle: u32,
    /// +0x14: gallery minutia angle (deg 0..179).
    pub gallery_angle: u32,
    /// +0x18: descriptor Hamming distance (0..128), the sort key. Lower = better.
    /// syna_qm_neighbor_cand_cmp_by_dist@0x1800045b0 sorts ascending on this.
    pub hamming_dist: i32,
}
const _: () = assert!(core::mem::size_of::<SynaQmNeighborCandidate>() == 0x1c);

/// 4-int Q16 fixed-point similarity transform produced per minutia by
/// `syna_qm_minutia_neighbor_match@0x180004690` (outXform[0..3]). On reject it is the identity
/// (cos = [`XFORM_FIXED_ONE`], sin/tx/ty = 0). tx/ty are integer translations (not Q16).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SynaQmSimilarityXform {
    /// `[0]` cos * 0x10000.
    pub cos_q16: i32,
    /// `[1]` sin * 0x10000.
    pub sin_q16: i32,
    /// `[2]` tx (translation x).
    pub tx: i32,
    /// `[3]` ty (translation y).
    pub ty: i32,
}

// ---------------------------------------------------------------------------
// Serialized (at-rest) template envelope
// ---------------------------------------------------------------------------

/// Envelope of a stored gallery template record as walked by `syna_qm_match_core@0x180100620`
/// (`param_3[i]` -> record pointer). Only the envelope fields the matcher reads are known here;
/// the `body` encoding (packed minutiae + descriptors + quality) is produced by the extractor
/// vtable and re-hydrated by the primitive engine — a Q1 deliverable.
///
/// Observed accesses:
/// - +0x04 `u32 blob_len`   — byte length of the template blob at +0x98; also gated by a
///   min-size param (`FUN_180001730(engine, 6, &min)`).
/// - +0x98 blob start       — first 0x0c bytes are copied out as a header, then the remaining
///   body is fed to `syna_qm_prim_match_one`.
///
/// The 0x0c-byte prefix at +0x98 is the on-wire template HEADER.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SerializedTemplateRecord {
    /// +0x00: unknown (record id / tag).
    // TODO(verify): meaning of template record +0x00.
    pub field_00: u32,
    /// +0x04: length in bytes of the blob at +0x98. syna_qm_match_core@0x180100620.
    pub blob_len: u32,
    // ... fields 0x08..0x98 not yet mapped (record header / crypto / metadata) ...
    // +0x98: blob = [SerializedTemplateHeader (0x0c)] [body: packed minutiae + descriptors].
}

/// The 0x0c-byte header prefixing the serialized template blob (at record+0x98).
/// Copied verbatim by `syna_qm_match_core@0x180100620` before the body is deserialized.
/// Field breakdown TBD in Q1 (candidates: magic/version, minutia count, image dims, quality).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SerializedTemplateHeader {
    // TODO(verify): all 12 bytes. Likely {version/magic, minutia_count, quality, dims...}.
    pub raw: [u8; 0x0c],
}
const _: () = assert!(core::mem::size_of::<SerializedTemplateHeader>() == 0x0c);

/// Offset of the template blob within a [`SerializedTemplateRecord`].
/// syna_qm_match_core@0x180100620.
pub const TEMPLATE_BLOB_OFFSET: usize = 0x98;
/// Size of the header prefixing the template blob body. syna_qm_match_core@0x180100620.
pub const TEMPLATE_HEADER_LEN: usize = 0x0c;

// ---------------------------------------------------------------------------
// Match result
// ---------------------------------------------------------------------------

/// Per-template match result, written by `syna_qm_match_core@0x180100620` and read back by the
/// `syna_qm_result_get_*` accessors. **Byte-packed / unaligned** — the getters read a `u32` at
/// odd offsets 0x39 and 0x3d, so this mirror is `#[repr(C, packed)]` to preserve exact offsets.
///
/// Offsets & provenance:
///   - +0x00 `tmpl_index`     gallery index — get_tmpl_index@0x1800a8950 (`*result`)
///   - +0x04 `score`          match score   — get_score@0x1800a8a00 (`result+4`)
///   - +0x08 `decision`       1 if `score>threshold` — get_decision@0x1800a8cd0 (`result+8`)
///   - +0x0c `strong_flag`    1 if secondary strong match — get_strong_flag@0x1800a8e30 (`result+0xc`)
///   - +0x10 `strong_score`   set with strong_flag (`local_c8[4]=local_18`) — match_core@0x180100620
///   - +0x34 `threshold_used` threshold applied this match (`local_c8[0xd]`) — match_core@0x180100620
///   - +0x38 `flag_38`        byte, cleared to 0 at match time — match_core@0x180100620
///   - +0x39 `quality_a`      from engineState+0x38 — get_quality_a@0x1800a8ee0 (`result+0x39`)
///   - +0x3d `quality_b`      from engineState+0x3c — get_quality_b@0x1800a8f90 (`result+0x3d`)
///   - +0x4a `valid`          result validity — get_valid@0x1800a8d80 (`result+0x4a`)
///
/// `score` type: unsigned 32-bit; compared directly against the (1200..2501) thresholds. Higher
/// score = better match (accept when `score > threshold`).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SynaQmMatchResult {
    /// +0x00: gallery/template index this result corresponds to.
    pub tmpl_index: u32,
    /// +0x04: match score (u32, higher = better).
    pub score: u32,
    /// +0x08: decision — [`decision::MATCH`] (1) or [`decision::NO_MATCH`] (0).
    pub decision: u32,
    /// +0x0c: strong-match flag (secondary corroborating match present).
    pub strong_flag: u32,
    /// +0x10: score/aux value recorded alongside the strong flag.
    // TODO(verify): exact semantics of strong_score (secondary score vs. alignment id).
    pub strong_score: u32,
    /// +0x14..+0x20: zeroed block (reserved / working fields cleared at match init).
    pub reserved_14: [u8; 0x0c],
    /// +0x20: zeroed at match init.
    // TODO(verify): meaning of result+0x20..+0x34 (per-match working state).
    pub reserved_20: [u8; 0x14],
    /// +0x34: threshold value applied for this comparison (one of the level thresholds).
    pub threshold_used: u32,
    /// +0x38: byte flag cleared to 0 during match.
    // TODO(verify): meaning of result+0x38.
    pub flag_38: u8,
    /// +0x39: quality metric A (source: engineState+0x38 = probe minutiae/quality stat).
    // TODO(verify): whether quality_a is minutiae count or a quality score.
    pub quality_a: u32,
    /// +0x3d: quality metric B (source: engineState+0x3c = probe minutiae count).
    // TODO(verify): whether quality_b is minutiae count or a quality score.
    pub quality_b: u32,
    /// +0x41..+0x4a: unmapped tail bytes.
    pub reserved_41: [u8; 0x09],
    /// +0x4a: result-valid flag (not written in the observed match path; default 0).
    // TODO(verify): where `valid` is set and what distinguishes it from `decision`.
    pub valid: u32,
}
const _: () = assert!(core::mem::size_of::<SynaQmMatchResult>() == 0x4e);

// ---------------------------------------------------------------------------
// Engine context / config
// ---------------------------------------------------------------------------

/// The **primitive matcher context** allocated by `syna_qm_engine_ctx_new@0x1800ff0f0`
/// (0x70 bytes). This is the handle the `syna_qm_prim_*` ops operate on — distinct from the
/// driver-level engine state (see [`EngineStateConfig`]). Only the fields ctx_new writes are
/// known; the rest is internal scratch initialized by `FUN_180001480`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SynaQmPrimEngineCtx {
    /// +0x00..+0x38: internal state (zeroed then filled by FUN_180001480). Layout Q1/Q2.
    pub internal: [u8; 0x38],
    /// +0x38: callback #1 (alloc helper, FUN_1800fea40). syna_qm_engine_ctx_new@0x1800ff0f0.
    pub cb_alloc: u64,
    /// +0x40: callback #2 (free helper, FUN_1800fea70).
    pub cb_free: u64,
    /// +0x48: callback #3 (log helper, FUN_1800fea90).
    pub cb_log: u64,
    /// +0x50..+0x70: internal.
    pub internal2: [u8; 0x20],
}
const _: () = assert!(core::mem::size_of::<SynaQmPrimEngineCtx>() == 0x70);

/// The driver-level engine state (`*(sessionCtx+0x240)`), configured before matching and read by
/// `syna_qm_match_core@0x180100620`. Not all offsets are mapped; the ones the matcher consumes:
///   - +0x20 `level`      match level -> threshold (see [`MatchLevel`]).
///   - +0x28 `image_ptr`  cached probe/gallery conditioned image buffer.
///   - +0x30 `width`      image width.
///   - +0x34 `height`     image height.
///   - +0x38 `quality_a`  copied into result+0x39.
///   - +0x3c `quality_b`  copied into result+0x3d (= deserialized minutia count).
///   - +0x40 `param_40`   optional tuning param; used only if `!= 0xffffff` (pushed via prim id 0).
///   - +0x54 `param_54`   optional tuning param; used only if `!= 0xffffff` (image-set arg).
///   - +0x70 `minutiae_ctx` sub-object holding the deserialized probe minutiae buffer.
///
/// The two `0xffffff`-sentinel override params (+0x40, +0x54) are the most likely place for
/// per-subtype (flex-derived) tuning to enter the matcher; the level thresholds themselves are
/// hardcoded in match_core. Where +0x40/+0x54 are populated (and whether from the flex table) is
/// not yet traced.
// TODO(verify): trace the setters of engineState+0x20/+0x40/+0x54 to confirm flex derivation.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EngineStateConfig {
    /// Match level selector (1/2/3). engineState+0x20. syna_qm_match_core@0x180100620.
    pub level: u32,
    /// Optional tuning override; sentinel [`ENGINE_PARAM_UNSET`] means "use engine default".
    /// engineState+0x40.
    pub param_40: u32,
    /// Optional tuning override; sentinel [`ENGINE_PARAM_UNSET`] means "use engine default".
    /// engineState+0x54.
    pub param_54: u32,
    /// Image width fed to the primitive engine. engineState+0x30.
    pub width: u32,
    /// Image height. engineState+0x34.
    pub height: u32,
    /// Quality stat A surfaced in the result. engineState+0x38.
    pub quality_a: u32,
    /// Quality stat B (deserialized minutia count). engineState+0x3c.
    pub quality_b: u32,
}

/// Selected primitive-engine config parameter IDs, from `FUN_180001730`/`FUN_1800015a0` calls in
/// `syna_qm_match_core@0x180100620`. These are the `id` argument to the engine get/set config ops.
pub mod prim_param_id {
    /// Threshold push target — `FUN_180001730(engine, 0xe, &threshold)` sets the accept threshold.
    /// syna_qm_match_core@0x180100620.
    pub const THRESHOLD: u32 = 0x0e;
    /// Min template-size query — `FUN_180001730(engine, 6, &min_size)`.
    pub const MIN_TEMPLATE_SIZE: u32 = 0x06;
    /// Some capability/enable flag queried before the loop — `FUN_180001730(engine, 0, &flag)`.
    // TODO(verify): exact meaning of prim param id 0.
    pub const ENABLE_FLAG: u32 = 0x00;
}

// ===========================================================================
// Q1: serialized template body format
//
// Recovered from the deserializer `syna_qm_deserialize_minutiae@0x180005a00` (the byte-exact mirror
// of the extractor's encoder) and the container `syna_asp_serialize_template@0x180102600`.
// See docs/qm/qm-pipeline.md "Serialized template format" for the full derivation.
// ===========================================================================

/// The at-rest template blob produced by `syna_asp_serialize_template@0x180102600`:
/// a size-prefixed wrapper around the template `body`.
///
/// Layout: `[u32 size][u32 pad][body: size bytes]`. The pointer to this blob is stored in the
/// enrolled-template record (`record+0x90` per `syna_qm_match_all@0x1800a78f0`).
/// Ghidra struct: `SynaAspTemplateBlob`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SynaAspTemplateBlob {
    /// +0x00: byte length of `body`. syna_asp_serialize_template@0x180102600.
    pub size: u32,
    /// +0x04: alignment padding.
    pub pad: u32,
    // +0x08: `body` follows inline (variable length) — see [`TemplateBody`] doc.
}

/// The first `TEMPLATE_HEADER_LEN` (0x0c) bytes of the template `body` are a header; the remainder
/// is a **tagged-node stream** walked by `syna_qm_template_body_reader_init@0x180006840` /
/// `syna_qm_tag_tree_find@0x180006750`. Nodes are keyed by a `u16` tag; the matcher reads only:
/// - tag [`node_tag::DIMS`] (0x69) → image width/height (`syna_qm_template_get_dims@0x180005d30`)
/// - tag [`node_tag::MINUTIA_COUNT`] (0x6b) → minutia count (`_get_minutia_count@0x180005dd0`)
///
/// The full per-subtype node schema is a data table (per device class) referenced from the ASP
/// op-registration table at `0x180285740`; only the two tags above are on the match path.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SerializedTemplateHeaderV2 {
    /// +0x00..+0x0c: 12-byte header. `*(body+4)` is checked non-zero before the node stream is
    /// parsed. Individual header fields are addressed by node tag, not fixed offset.
    pub raw: [u8; TEMPLATE_HEADER_LEN],
}
const _: () = assert!(core::mem::size_of::<SerializedTemplateHeaderV2>() == 0x0c);

/// Node tags in the template body stream (`u16`), matched by `syna_qm_tag_tree_find@0x180006750`.
pub mod node_tag {
    /// Image dimensions node — `syna_qm_template_get_dims@0x180005d30` reads (width, height).
    pub const DIMS: u16 = 0x69;
    /// Minutia count node — `syna_qm_template_get_minutia_count@0x180005dd0`.
    pub const MINUTIA_COUNT: u16 = 0x6b;
}

/// One minutia as stored in the **flat body** (10 bytes on disk), decoded by
/// `syna_qm_deserialize_minutiae@0x180005a00`. This is the AT-REST encoding (contrast with the
/// 0x20-byte runtime [`SynaQmMinutia`]).
///
/// The angle is NOT stored here — it is reconstructed from the group angle-bin boundaries that
/// follow the minutia array (see [`SerializedMinutiaBodyLayout`]). x and y are single bytes (both
/// fit the 144×56 sensor). The descriptor is copied verbatim (opaque 8 bytes).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct OnDiskMinutia {
    /// +0x00: 64-bit binary local-neighbor descriptor, stored verbatim (→ runtime min+0x00).
    /// syna_qm_deserialize_minutiae@0x180005a00.
    pub descriptor: [u8; DESCRIPTOR_BYTES],
    /// +0x08: x coordinate (image column), u8 (→ runtime min+0x14).
    pub x: u8,
    /// +0x09: y coordinate (image row), u8 (→ runtime min+0x18).
    pub y: u8,
}
const _: () = assert!(core::mem::size_of::<OnDiskMinutia>() == ON_DISK_MINUTIA_LEN);

/// Byte length of one [`OnDiskMinutia`] record in the flat body.
/// syna_qm_deserialize_minutiae@0x180005a00 (reads 8 + 1 + 1).
pub const ON_DISK_MINUTIA_LEN: usize = 10;

/// Documents the **flat minutia body** layout decoded by `syna_qm_deserialize_minutiae@0x180005a00`.
/// The body is a plain little-endian byte stream (NOT bit-packed), read strictly in this order:
///
/// | order | bytes            | field                                             |
/// |-------|------------------|---------------------------------------------------|
/// | 1     | 8                | template-level 64-bit descriptor (→ ctx+0x20)     |
/// | 2     | 1                | total minutia count `N`                           |
/// | 3     | `N`×10           | [`OnDiskMinutia`] records                         |
/// | 4     | 1                | group-1 split count `S`                           |
/// | 5     | 1                | field (→ ctx+0x0c)                                |
/// | 6     | 11               | group-1 angle-bin cumulative boundaries           |
/// | 7     | 11               | group-2 angle-bin cumulative boundaries           |
///
/// Total = `33 + 10·N` bytes. This is a documentation-only zero-field marker; the variable-length
/// body cannot be a fixed `#[repr(C)]` struct.
#[derive(Debug, Clone, Copy)]
pub struct SerializedMinutiaBodyLayout;

/// Fixed byte length of the flat body EXCLUDING the `N`×10 minutia array:
/// 8 (template desc) + 1 (count) + 1 (split) + 1 (field) + 11 + 11 (angle bins).
/// syna_qm_deserialize_minutiae@0x180005a00.
pub const FLAT_BODY_FIXED_LEN: usize = 8 + 1 + 1 + 1 + ANGLE_BIN_BOUNDARIES * 2; // 33

/// Template-level descriptor size (bytes) that prefixes the minutia array. Same width as a
/// per-minutia descriptor. syna_qm_deserialize_minutiae@0x180005a00.
pub const TEMPLATE_DESCRIPTOR_BYTES: usize = DESCRIPTOR_BYTES; // 8

// --- Angle quantization (steps 6–7 of the flat body) ----------------------

/// Orientation is quantized to 12 bins of 15° each (0,15,…,150,165). The stream stores 11 cumulative
/// count boundaries per group; the 12th (implicit) bin is the tail, assigned [`ANGLE_TAIL_DEG`].
/// syna_qm_deserialize_minutiae@0x180005a00 (`while uVar6 < 0xb`).
pub const ANGLE_BINS: usize = 12;
/// Number of cumulative boundary bytes stored per group (= `ANGLE_BINS - 1`).
/// syna_qm_deserialize_minutiae@0x180005a00.
pub const ANGLE_BIN_BOUNDARIES: usize = 11; // 0xb
/// Angle step per bin, in degrees. Reconstructed angle = `bin_index * ANGLE_BIN_STEP_DEG`.
/// syna_qm_deserialize_minutiae@0x180005a00 (`bin * 0xf`).
pub const ANGLE_BIN_STEP_DEG: u32 = 15; // 0xf
/// Angle assigned to the final (tail) bin — 165°. syna_qm_deserialize_minutiae@0x180005a00 (`0xa5`).
pub const ANGLE_TAIL_DEG: u32 = 0xa5; // 165
/// Number of minutia groups (split at `S`); each has its own angle-bin table.
/// syna_qm_deserialize_minutiae@0x180005a00.
pub const MINUTIA_GROUPS: usize = 2;

// ===========================================================================
// Q2: geometric consensus (Hough translation vote grid)
//
// From `syna_qm_geometric_consensus@0x18000c5f0` / `syna_qm_vote_grid_build@0x18000bf20` /
// `syna_qm_apply_xform_q16@0x180006b10`. See docs "Geometric consensus / scoring".
// The grid GATES the match (found/not-found); it does NOT itself become the score.
// ===========================================================================

/// Side length (in cells) of the square translation vote grid. Grid is 1 byte/cell,
/// `VOTE_GRID_SIDE² == 0x3840` (14400) bytes. syna_qm_vote_grid_build@0x18000bf20.
pub const VOTE_GRID_SIDE: usize = 120; // 0x78
/// Total vote-grid byte size. syna_qm_vote_grid_build@0x18000bf20 (`0x3840`).
pub const VOTE_GRID_BYTES: usize = VOTE_GRID_SIDE * VOTE_GRID_SIDE; // 14400
/// Centre bin index (grid origin maps here). syna_qm_vote_grid_build@0x18000bf20 (`0x3c`).
pub const VOTE_GRID_CENTER: i32 = 60; // 0x3c
/// Translation bin size in pixels (`>> 3`). Landing coord `c` maps to bin `CENTER − (dim/2)/8 + c/8`.
/// syna_qm_vote_grid_build@0x18000bf20.
pub const VOTE_TRANSLATION_BIN_PX: i32 = 8;
/// Vote step written when a transform first marks a bin (capped once per transform, then normalized
/// to a running transform count). syna_qm_vote_grid_build@0x18000bf20 (`+ 100`).
pub const VOTE_MARK_STEP: u8 = 100;

/// Per-minutia **Q16 similarity transform** record as consumed by the vote grid, stride 0x14 (5×i32).
/// `syna_qm_apply_xform_q16@0x180006b10` computes:
///   `x' = (cos·x − sin·y + tx + 0x8000) >> 16`, `y' = (cos·y + sin·x + ty + 0x8000) >> 16`
/// (`0x8000` = Q16 rounding). Compare with the 4-int [`SynaQmSimilarityXform`]; this variant adds a
/// trailing validity/score word checked by the grid builder.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SynaQmXformRecord {
    /// `[0]` cos·0x10000. syna_qm_apply_xform_q16@0x180006b10.
    pub cos_q16: i32,
    /// `[1]` sin·0x10000.
    pub sin_q16: i32,
    /// `[2]` tx (translation x, integer).
    pub tx: i32,
    /// `[3]` ty (translation y, integer).
    pub ty: i32,
    /// `[4]` validity/score word (transform used only if flagged valid).
    // TODO(verify): exact meaning (flag vs. per-transform score).
    pub valid_flag: i32,
}
const _: () = assert!(core::mem::size_of::<SynaQmXformRecord>() == 0x14);

/// Q16 fixed-point rounding addend used by `syna_qm_apply_xform_q16@0x180006b10` (0.5 in Q16).
pub const XFORM_Q16_ROUND: i32 = 0x8000;

// ===========================================================================
// Q2: statistical score (z-normalized features → MLP → 0..3000)
//
// From `syna_qm_score_features@0x1800088d0`, `syna_qm_mlp_forward@0x180002cd0`,
// `syna_qm_score_llr_to_scale@0x180002f30`. See docs "Statistical score".
// NOTE: the normalization stage uses IEEE-754 doubles — the score path is NOT pure-integer.
// ===========================================================================

/// Number of features gathered per anchor minutia. syna_qm_score_features@0x1800088d0.
pub const SCORE_FEATURES_PER_MINUTIA: usize = 17; // 0x11
/// Number of anchor minutiae scored (top-2). syna_qm_score_features@0x1800088d0.
pub const SCORE_ANCHOR_MINUTIAE: usize = 2;
/// Total feature-vector length fed to the MLP (`= 17·2`). syna_qm_score_features@0x1800088d0 (0x22).
pub const SCORE_FEATURE_VECTOR_LEN: usize = SCORE_FEATURES_PER_MINUTIA * SCORE_ANCHOR_MINUTIAE; // 34

/// Z-score scale factor applied after `(x − mean)/stddev`. syna_qm_score_features@0x1800088d0 (`·1.6`).
pub const SCORE_ZNORM_SCALE: f64 = 1.6;
/// Clamp bound for the normalized feature (`z ∈ [−1.6, 1.6]`, with a soft cap at 1.1 on the high
/// side before the ±1.6 clamp). syna_qm_score_features@0x1800088d0.
pub const SCORE_ZNORM_CLAMP: f64 = 1.6;
/// Fixed-point (Q10) scale the normalized feature is quantized to before the MLP (`z·1024`).
/// syna_qm_score_features@0x1800088d0.
pub const SCORE_FIXED_Q10: i32 = 1024;

/// Per-feature normalization table `g_adSynaQmFeatureNormTable@0x18014f160`: an array of
/// `{f64 mean, f64 stddev}` pairs (stride 0x10), indexed by feature. syna_qm_score_features@0x1800088d0.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FeatureNorm {
    /// mean (f64). g_adSynaQmFeatureNormTable@0x18014f160.
    pub mean: f64,
    /// stddev (f64). g_adSynaQmFeatureNormTable+0x8.
    pub stddev: f64,
}
const _: () = assert!(core::mem::size_of::<FeatureNorm>() == 0x10);

/// Final score mapping from the MLP log-likelihood, by `syna_qm_score_llr_to_scale@0x180002f30`:
/// `llr10 = llr >> 10; score = clamp((llr10 + LLR_BIAS)·SCORE_SCALE_MAX / LLR_SPAN, 0, SCORE_SCALE_MAX)`.
pub mod score_scale {
    /// Right-shift applied to the raw MLP output (Q10 → integer). syna_qm_score_llr_to_scale@0x180002f30.
    pub const LLR_SHIFT: u32 = 10;
    /// Bias added to `llr10` before scaling (also the negative clamp bound). 0x12c5.
    /// syna_qm_score_llr_to_scale@0x180002f30.
    pub const LLR_BIAS: i32 = 4805; // 0x12c5
    /// Upper clamp on `llr10` before scaling. 0x12ac.
    pub const LLR_MAX: i32 = 4780; // 0x12ac
    /// Denominator span (`= LLR_BIAS + LLR_MAX`). 0x2571.
    pub const LLR_SPAN: i32 = 9585; // 0x2571
    /// Maximum output score (top of the 0..3000 scale that the level thresholds live on).
    pub const SCORE_MAX: i32 = 3000;
}

/// Per-minutia score above which the minutia is a "strong anchor" (work record +0x38 > 0x7c4).
/// Duplicate of [`MINUTIA_STRONG_SCORE`], noted here as it is on the same 0..3000 scale as the
/// final score. syna_qm_score_features@0x1800088d0 / syna_qm_minutiae_match_kernel@0x180008e60.
pub const SCORE_STRONG_ANCHOR: u32 = MINUTIA_STRONG_SCORE; // 0x7c4 = 1988

// ===========================================================================
// Q3: scoring MLP model data (STATIC .rdata — single global model, not per-subtype)
//
// Installed by syna_qm_mlp_model_init@0x180002f80 -> syna_qm_mlp_descriptor_build@0x180002be0
// with hardcoded dims + weight pointer &g_aiSynaQmMlpWeights@0x18014acd0. Forward pass
// syna_qm_mlp_forward@0x180002cd0 (Q10 integer dot-products). See docs "MLP model data".
// ===========================================================================

/// MLP layer dimensions (input -> hidden -> output). Hardcoded in
/// `syna_qm_mlp_model_init@0x180002f80` (args 0x22, 0x14, 1 -> `dims[2]=2`).
pub mod mlp_dims {
    /// Input layer size (= 17 features x 2 anchor minutiae). syna_qm_mlp_model_init@0x180002f80 (0x22).
    pub const INPUT: usize = 34;
    /// Hidden layer size. syna_qm_mlp_model_init@0x180002f80 (0x14).
    pub const HIDDEN: usize = 20;
    /// Output layer size (LLR pair; score uses `out[0]`). syna_qm_mlp_descriptor_build@0x180002be0.
    pub const OUTPUT: usize = 2;
    /// Number of weight layers (input->hidden, hidden->output). syna_qm_mlp_forward@0x180002cd0.
    pub const WEIGHT_LAYERS: usize = 2;
}

/// MLP weight-blob provenance. Weights are STATIC `.rdata`, **Q10 int32** (`value as f64 / 1024`),
/// consumed by `syna_qm_mlp_forward@0x180002cd0`. Each neuron row is `[w0..w_{in-1}, bias]`
/// (`in_dim + 1` elements); the bias (last element) is accumulated as `bias * 0x400` (Q10).
pub mod mlp_weights {
    /// Image-base-relative VA of the layer-0 weight blob. `g_aiSynaQmMlpWeights@0x18014acd0`.
    pub const LAYER0_VA: u64 = 0x1_8014_acd0;
    /// VA of the layer-1 weight blob (= LAYER0_VA + 0xAF0). `g_aiSynaQmMlpWeights_layer1@0x18014b7c0`.
    pub const LAYER1_VA: u64 = 0x1_8014_b7c0;
    /// Layer-0 element count: HIDDEN * (INPUT + 1) = 20 * 35. syna_qm_mlp_descriptor_build@0x180002be0.
    pub const LAYER0_COUNT: usize = super::mlp_dims::HIDDEN * (super::mlp_dims::INPUT + 1); // 700
    /// Layer-1 element count: OUTPUT * (HIDDEN + 1) = 2 * 21. syna_qm_mlp_descriptor_build@0x180002be0.
    pub const LAYER1_COUNT: usize = super::mlp_dims::OUTPUT * (super::mlp_dims::HIDDEN + 1); // 42
    /// Total int32 elements across both layers (742 = 2968 bytes).
    pub const TOTAL_COUNT: usize = LAYER0_COUNT + LAYER1_COUNT; // 742
    /// Fixed-point shift for Q10 weights (`weight / 1024`). syna_qm_mlp_forward@0x180002cd0.
    pub const Q10_SHIFT: u32 = 10;
    /// Bias scale applied in the accumulator (Q10 bias -> Q20 to match Q10xQ10 products). `* 0x400`.
    pub const BIAS_SCALE: i32 = 0x400; // 1024
}

/// Runtime MLP descriptor laid out by `syna_qm_mlp_descriptor_build@0x180002be0` at
/// `primEngineWorkBuf+8`. Dims are consecutive ints; then weight pointers; then per-layer
/// activation scratch buffers carved from a trailing region. Ghidra struct `SynaQmMlpDescriptor`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SynaQmMlpDescriptor {
    /// +0x00: input dim (34).
    pub dim_in: i32,
    /// +0x04: hidden dim (20).
    pub dim_hidden: i32,
    /// +0x08: output dim (2).
    pub dim_out: i32,
    /// +0x0c: padding.
    pub pad_0c: i32,
    /// +0x10: layer-0 weight pointer (-> g_aiSynaQmMlpWeights@0x18014acd0).
    pub weights_layer0: u64,
    /// +0x18: layer-1 weight pointer (-> 0x18014b7c0).
    pub weights_layer1: u64,
    /// +0x20: input activation scratch (INPUT ints + guard).
    pub act_buf_in: u64,
    /// +0x28: hidden activation scratch (HIDDEN ints).
    pub act_buf_hidden: u64,
    /// +0x30: output activation scratch (OUTPUT ints).
    pub act_buf_out: u64,
}
const _: () = assert!(core::mem::size_of::<SynaQmMlpDescriptor>() == 0x38);

/// The 17 per-anchor-minutia feature source offsets within the work record (stride 0xb4), in the
/// exact order `syna_qm_score_features@0x1800088d0` assembles them into the 34-value vector (each
/// anchor contributes 17; both anchors share [`FEATURE_NORM_TABLE`]). The fields at these offsets
/// are COMPUTED geometry/quality quantities (filled by `syna_qm_compute_features@0x1800081f0` and
/// the neighbor-match pass), NOT subtype-selected constants. A value `>= 0x7fff` is a sentinel that
/// clamps that feature's normalized z to +1.6.
pub const FEATURE_WORKREC_OFFSETS: [u16; SCORE_FEATURES_PER_MINUTIA] = [
    0x98, 0x9c, 0x74, 0x78, 0x7c, 0x5c, 0x60, 0x8c, 0x90, 0x6c, 0x80, 0x84, 0x94, 0x68, 0x88, 0xa8,
    0xa4,
];

/// The 17 `{mean, stddev}` normalization pairs from `g_adSynaQmFeatureNormTable@0x18014f160`
/// (verbatim f64 values dumped from `.rdata`). Applied per feature as
/// `z = clamp((x - mean)*1.6/stddev, -1.6, 1.6)` then quantized Q10. Many rows have `mean == stddev`
/// (min-max normalization over `[0, 2*mean]`). All static -> the scorer is fully portable.
pub const FEATURE_NORM_TABLE: [FeatureNorm; SCORE_FEATURES_PER_MINUTIA] = [
    FeatureNorm {
        mean: 22.5,
        stddev: 22.5,
    }, // 0  (workrec +0x98)
    FeatureNorm {
        mean: 662.0,
        stddev: 584.0,
    }, // 1  (+0x9c)
    FeatureNorm {
        mean: 3350.0,
        stddev: 3350.0,
    }, // 2  (+0x74)
    FeatureNorm {
        mean: 3210.0,
        stddev: 3210.0,
    }, // 3  (+0x78)
    FeatureNorm {
        mean: 3530.5,
        stddev: 3530.5,
    }, // 4  (+0x7c)
    FeatureNorm {
        mean: 21.0,
        stddev: 21.0,
    }, // 5  (+0x5c)
    FeatureNorm {
        mean: 12.5,
        stddev: 12.5,
    }, // 6  (+0x60)
    FeatureNorm {
        mean: 98.5,
        stddev: 98.5,
    }, // 7  (+0x8c)
    FeatureNorm {
        mean: 39.0,
        stddev: 28.0,
    }, // 8  (+0x90)
    FeatureNorm {
        mean: 38.0,
        stddev: 34.0,
    }, // 9  (+0x6c)
    FeatureNorm {
        mean: 3728.0,
        stddev: 3728.0,
    }, // 10 (+0x80)
    FeatureNorm {
        mean: 3867.0,
        stddev: 3708.0,
    }, // 11 (+0x84)
    FeatureNorm {
        mean: 143.5,
        stddev: 143.5,
    }, // 12 (+0x94)
    FeatureNorm {
        mean: 37.0,
        stddev: 30.0,
    }, // 13 (+0x68)
    FeatureNorm {
        mean: 115.5,
        stddev: 115.5,
    }, // 14 (+0x88)
    FeatureNorm {
        mean: 35.5,
        stddev: 35.5,
    }, // 15 (+0xa8)
    FeatureNorm {
        mean: 679.0,
        stddev: 567.0,
    }, // 16 (+0xa4)
];

// ===========================================================================
// Q3: descriptor extractor provenance (MetViper neural net — NOT a static bit-packing)
//
// The 64-bit local-neighbor descriptor is produced by a learned neural network ("MetViper_QM"),
// so there is no "bit N = geometric quantity X" formula. The extractor op resolves statically but
// the MODEL is either a static embedded default or a firmware-supplied nnet. Bit-exact template
// reproduction requires GOLDEN VECTORS. See docs "Descriptor construction".
// ===========================================================================

/// Descriptor-extractor provenance addresses (all in `synaWudfBioUsb.dll`, image base 0x180000000).
/// The op table is FIXED for the 0xca engine (class id 1), so the extractor is not subtype-switched;
/// per-subtype variation enters only via the MetViper model selection.
pub mod descriptor_extractor {
    /// Device-op extractor callback installed at `aspCtx+0x50`. syna_asp_subobj_vtable_init@0x1801033f0.
    pub const EXTRACT_TEMPLATE_VA: u64 = 0x1_8010_4350; // syna_asp_dev_extract_template
    /// MetViper nnet runner that builds minutiae + 64-bit descriptors. syna_metviper_run_qm_nnet.
    pub const METVIPER_RUN_VA: u64 = 0x1_8010_db20;
    /// Model selector (static default vs firmware-parsed nnet). syna_get_embedded_fw_manifest_nnet.
    pub const MODEL_SELECTOR_VA: u64 = 0x1_8011_7430;
    /// Static embedded MetViper final-score weight blob (`AspFinalScoreNNetWeights`,
    /// `g_anSynaMetViperQmWeights_default@0x1801f3ce0`): **24482 int32, topology 677→36→2**. This is
    /// the extractor's final-score sub-net — DISTINCT from the ported match scorer
    /// ([`crate::qm::scorer_weights`], `0x18014acd0`, 742 int32, 34→20→2). The shared
    /// "AspFinalScoreNNetWeights" identifier is a copy-pasted template name, not a claim of identity.
    /// See `docs/qm/metviper-nnet-config.md`.
    pub const STATIC_WEIGHTS_VA: u64 = 0x1_801f_3ce0;
    /// Extractor input mask (per-input enable byte array). `g_abSynaMetViperQmInputMask@0x1801f27a0`
    /// (corrected 2026-07 — was mislabeled a "float config" blob; it is a byte mask).
    pub const STATIC_INPUT_MASK_VA: u64 = 0x1_801f_27a0;
    /// Extractor input scaling LUT (per-input scale, f64). `g_adSynaMetViperQmScalingLUT@0x1801f27b0`.
    pub const STATIC_SCALING_LUT_VA: u64 = 0x1_801f_27b0;
    /// Extractor final-score net topology (`SynaNnetConfig.layerDim0..`): 677 → 36 → 2.
    pub const EXTRACTOR_NN_INPUT: usize = 677;
    pub const EXTRACTOR_NN_HIDDEN: usize = 36;
    pub const EXTRACTOR_NN_OUTPUT: usize = 2;
    /// `SynaNnetConfig` (96 B, `syna_parse_nnet_config_text@0x18011a0f0`) key offsets:
    /// `layerDim0..5`@0x08, `inputPoolSize`@0x20, `inputFlags`@0x24, `supportsInputMask`@0x28,
    /// `recommendedThreshold`@0x2c, `tplUpdateThreshold`@0x30, `name`@0x38, `weights`ptr@0x48,
    /// `scalingFactorLUT`ptr@0x50, `inputMask`ptr@0x58. See `docs/qm/metviper-nnet-config.md`.
    pub const NNET_CONFIG_SIZE: usize = 96;
    /// Firmware nnet config parser (used when the device supplies its own model). syna_parse_nnet_config_text.
    pub const FW_NNET_PARSER_VA: u64 = 0x1_8011_a0f0;
    /// Embedded default model name (used when no firmware nnet config is present).
    pub const DEFAULT_MODEL_NAME: &str = "7fbMetViper_QM";
    /// Whether the descriptor bits are recoverable as a closed-form geometric packing. They are not:
    /// they are learned neural-net features. Bit-exact reproduction needs golden vectors.
    pub const DESCRIPTOR_IS_LEARNED_NN: bool = true;
}
