//! Per-minutia work record (stride 0xb4) — fields consumed by `syna_qm_score_features@0x1800088d0`.
//!
//! **Slot map (fully RE-verified against the DLL, 2026-08-02).** The record is filled in three DLL
//! stages, then read by `score_features`:
//!
//! 1. `syna_qm_minutia_neighbor_match@0x180004690` writes the transform (+0xc/+0x4/+0x8/+0x10),
//!    `+0x5c`=avg_dist, `+0x60`=match_count, `+0x64`=cand_count; then, when match_count > 3, calls
//!    `syna_qm_minutia_neighbor_compare(workRec+0x68, …)`.
//! 2. `neighbor_compare@0x180004380` (its `param_1` = **workRec+0x68**) runs three validated kernels
//!    over the descriptor-match streams:
//!      - `feature_mean_median(+0x68, +0x6c)` → `+0x68`=hamming **mean**, `+0x6c`=hamming **median**;
//!      - `feature_coverage_histogram(+0x70, +0x74)` → `+0x70`=coverage scalar, `+0x74..+0x84`=the
//!        **5 spatial-coverage buckets** (needs `coverage_stamp` + the descriptor grid);
//!      - `feature_avg_dist_dual(+0x98, +0x9c, +0xa0)` → `+0x98`=angle **avg_all**, `+0x9c`=angle
//!        **avg_class0**, `+0xa0`=count; and the `descriptor_match_loop` match / reject counts →
//!        `+0x88` / `+0x8c`.
//! 3. The kernel `syna_qm_minutiae_match_kernel@0x180008e60` then runs its propagation pass
//!    ([`WorkRecord::apply_kernel_propagation`]). `syna_qm_compute_features@0x1800081f0` runs after but
//!    (oracle-confirmed, NCOMPARE) writes only the consensus/alignment scratch — never a score feature.
//!
//! Every compare-tail slot is now computed **bit-exact** from the real grid-based
//! `descriptor_match_loop` streams via [`crate::geometry_features::neighbor_compare`] (oracle-validated,
//! NCOMPARE golden) — no approximations, no sentinels on an anchor. `compute_features@0x1800081f0`
//! (the descriptor-alignment pass) writes only the consensus scratch, never these feature slots.

use crate::geometry_features::CompareRecord;
use crate::similarity::SimilarityQ16;
use crate::types::{
    FEATURE_SENTINEL, FEATURE_WORKREC_OFFSETS, NEIGHBOR_REJECT_DIST, SCORE_FEATURES_PER_MINUTIA,
    XFORM_FIXED_ONE,
};

/// Work-record stride. syna_qm_minutiae_match_kernel@0x180008e60.
pub const WORK_RECORD_STRIDE: usize = 0xb4;

/// Work-record field offsets (stride 0xb4). Names/provenance verified against `score_features`
/// (`FEATURE_WORKREC_OFFSETS`) and the three `neighbor_compare` kernels — see module docs.
mod off {
    // Transform (syna_qm_minutia_neighbor_match).
    pub const XFORM_COS: u16 = 0x0c;
    pub const XFORM_TX: u16 = 0x04;
    pub const XFORM_TY: u16 = 0x08;
    pub const XFORM_SIN: u16 = 0x10;
    // neighbor_match scalars.
    pub const AVG_DIST: u16 = 0x5c; // feat 5
    pub const MATCH_COUNT: u16 = 0x60; // feat 6
    pub const CAND_COUNT: u16 = 0x64; // not a feature
    // neighbor_compare: feature_mean_median over the Hamming stream (param_1 = workRec+0x68).
    pub const HAMMING_MEAN: u16 = 0x68; // feat 13
    pub const HAMMING_MEDIAN: u16 = 0x6c; // feat 9
    // neighbor_compare: feature_coverage_histogram (scalar + 5 spatial-coverage-rank buckets).
    pub const COVERAGE_SCALAR: u16 = 0x70; // not a feature
    pub const COVERAGE_B0: u16 = 0x74; // feat 2
    pub const COVERAGE_B1: u16 = 0x78; // feat 3
    pub const COVERAGE_B2: u16 = 0x7c; // feat 4
    pub const COVERAGE_B3: u16 = 0x80; // feat 10
    pub const COVERAGE_B4: u16 = 0x84; // feat 11
    // neighbor_compare: feature_avg_dist_dual over the angle-delta stream (weighted by Hamming).
    pub const ANGLE_AVG_ALL: u16 = 0x98; // feat 0
    pub const ANGLE_AVG_CLASS0: u16 = 0x9c; // feat 1
    pub const ANGLE_COUNT: u16 = 0xa0; // not a feature (propagated to +0xac)
    // neighbor_compare: descriptor_match_loop match / reject counts.
    pub const MATCHLOOP_COUNT: u16 = 0x88; // feat 14
    pub const MATCHLOOP_REJECT: u16 = 0x8c; // feat 7
    // Kernel propagation targets (syna_qm_minutiae_match_kernel@0x180008e60).
    pub const PROP_MEAN: u16 = 0x90; // feat 8  = copy of +0x68
    pub const PROP_MATCHLOOP: u16 = 0x94; // feat 12 = copy of +0x88
    pub const PROP_AVG_CLASS0: u16 = 0xa4; // feat 16 = copy of +0x9c
    pub const PROP_AVG_ALL: u16 = 0xa8; // feat 15 = copy of +0x98
    pub const PROP_ANGLE_COUNT: u16 = 0xac; // non-feature copy of +0xa0
    // Per-minutia score written by score_features.
    pub const MATCH_SCORE: u16 = 0x38;
}

/// One 0xb4-byte work record for a probe minutia during matching.
#[derive(Debug, Clone)]
pub struct WorkRecord {
    bytes: [u8; WORK_RECORD_STRIDE],
}

impl Default for WorkRecord {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkRecord {
    pub fn new() -> Self {
        let mut bytes = [0u8; WORK_RECORD_STRIDE];
        for off in FEATURE_WORKREC_OFFSETS {
            write_i32(&mut bytes, off, FEATURE_SENTINEL);
        }
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; WORK_RECORD_STRIDE] {
        &self.bytes
    }

    fn get_i32(&self, off: u16) -> i32 {
        read_i32(&self.bytes, off)
    }

    fn set_i32(&mut self, off: u16, v: i32) {
        write_i32(&mut self.bytes, off, v);
    }

    /// Assemble the 17-value feature slice in `syna_qm_score_features@0x1800088d0` order.
    pub fn score_features(&self) -> [i32; SCORE_FEATURES_PER_MINUTIA] {
        let mut out = [FEATURE_SENTINEL; SCORE_FEATURES_PER_MINUTIA];
        for (i, &off) in FEATURE_WORKREC_OFFSETS.iter().enumerate() {
            out[i] = self.get_i32(off);
        }
        out
    }

    /// Write neighbor-match outputs. syna_qm_minutia_neighbor_match@0x180004690.
    pub fn apply_neighbor_match(
        &mut self,
        xf: &SimilarityQ16,
        avg_dist: i32,
        match_count: i32,
        cand_count: i32,
        rejected: bool,
    ) {
        if rejected {
            self.set_i32(off::XFORM_COS, XFORM_FIXED_ONE);
            self.set_i32(off::XFORM_SIN, 0);
            self.set_i32(off::XFORM_TX, 0);
            self.set_i32(off::XFORM_TY, 0);
            self.set_i32(off::AVG_DIST, NEIGHBOR_REJECT_DIST as i32);
        } else {
            self.set_i32(off::XFORM_COS, xf.cos);
            self.set_i32(off::XFORM_SIN, xf.sin);
            self.set_i32(off::XFORM_TX, xf.tx);
            self.set_i32(off::XFORM_TY, xf.ty);
            self.set_i32(off::AVG_DIST, avg_dist);
        }
        self.set_i32(off::MATCH_COUNT, match_count);
        self.set_i32(off::CAND_COUNT, cand_count);
    }

    /// Write the full `syna_qm_minutia_neighbor_compare@0x180004380` tail (workRec `+0x68..+0xa0`) from
    /// a [`CompareRecord`] computed by the **oracle-validated** [`crate::geometry_features::neighbor_compare`]
    /// (the real grid-based `descriptor_match_loop` streams reduced by `feature_mean_median` /
    /// `feature_avg_dist_dual` / `feature_coverage_histogram`). Every slot is bit-exact — no sentinels.
    pub fn apply_neighbor_compare(&mut self, r: &CompareRecord) {
        self.set_i32(off::HAMMING_MEAN, r.hamming_mean);
        self.set_i32(off::HAMMING_MEDIAN, r.hamming_median);
        self.set_i32(off::COVERAGE_SCALAR, r.coverage_scalar as i32);
        self.set_i32(off::COVERAGE_B0, r.coverage_buckets[0] as i32);
        self.set_i32(off::COVERAGE_B1, r.coverage_buckets[1] as i32);
        self.set_i32(off::COVERAGE_B2, r.coverage_buckets[2] as i32);
        self.set_i32(off::COVERAGE_B3, r.coverage_buckets[3] as i32);
        self.set_i32(off::COVERAGE_B4, r.coverage_buckets[4] as i32);
        self.set_i32(off::MATCHLOOP_COUNT, r.match_count);
        self.set_i32(off::MATCHLOOP_REJECT, r.reject_count);
        self.set_i32(off::ANGLE_AVG_ALL, r.angle_avg_all);
        self.set_i32(off::ANGLE_AVG_CLASS0, r.angle_avg_class0);
        self.set_i32(off::ANGLE_COUNT, r.angle_count);
    }

    /// The propagation pass `syna_qm_minutiae_match_kernel@0x180008e60` runs after `neighbor_match`
    /// and before `compute_features`, copying five compare-tail slots into their scoring positions:
    /// `+0x90←+0x68`, `+0x94←+0x88`, `+0xa4←+0x9c`, `+0xa8←+0x98`, `+0xac←+0xa0`. (`compute_features`
    /// only touches the consensus scratch, not these feature slots, so the copies are the final values.)
    pub fn apply_kernel_propagation(&mut self) {
        self.set_i32(off::PROP_MEAN, self.get_i32(off::HAMMING_MEAN));
        self.set_i32(off::PROP_MATCHLOOP, self.get_i32(off::MATCHLOOP_COUNT));
        self.set_i32(off::PROP_AVG_CLASS0, self.get_i32(off::ANGLE_AVG_CLASS0));
        self.set_i32(off::PROP_AVG_ALL, self.get_i32(off::ANGLE_AVG_ALL));
        self.set_i32(off::PROP_ANGLE_COUNT, self.get_i32(off::ANGLE_COUNT));
    }

    pub fn set_match_score(&mut self, score: i32) {
        self.set_i32(off::MATCH_SCORE, score);
    }
}

fn read_i32(buf: &[u8], off: u16) -> i32 {
    let o = off as usize;
    i32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]])
}

fn write_i32(buf: &mut [u8], off: u16, v: i32) {
    let o = off as usize;
    buf[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::similarity::SimilarityQ16;

    #[test]
    fn neighbor_compare_writes_verified_slots() {
        // A CompareRecord (as produced by geometry_features::neighbor_compare) lands in the RE-verified
        // slots, and the kernel propagation copies the right ones.
        let cr = CompareRecord {
            hamming_mean: 48,
            hamming_median: 32,
            coverage_scalar: 100,
            coverage_buckets: [0, 100, 100, 100, 199],
            match_count: 3,
            reject_count: 1,
            angle_avg_all: 5,
            angle_avg_class0: 515,
            angle_count: 3,
        };
        let mut wr = WorkRecord::new();
        wr.apply_neighbor_compare(&cr);
        assert_eq!(wr.get_i32(off::HAMMING_MEAN), 48);
        assert_eq!(wr.get_i32(off::HAMMING_MEDIAN), 32);
        assert_eq!(wr.get_i32(off::COVERAGE_B0), 0);
        assert_eq!(wr.get_i32(off::COVERAGE_B4), 199);
        assert_eq!(wr.get_i32(off::MATCHLOOP_COUNT), 3);
        assert_eq!(wr.get_i32(off::MATCHLOOP_REJECT), 1);
        assert_eq!(wr.get_i32(off::ANGLE_AVG_ALL), 5);
        assert_eq!(wr.get_i32(off::ANGLE_AVG_CLASS0), 515);
        assert_eq!(wr.get_i32(off::ANGLE_COUNT), 3);
        // Propagation: +0x90←+0x68, +0x94←+0x88, +0xa4←+0x9c, +0xa8←+0x98, +0xac←+0xa0.
        wr.apply_kernel_propagation();
        assert_eq!(wr.get_i32(off::PROP_MEAN), 48);
        assert_eq!(wr.get_i32(off::PROP_MATCHLOOP), 3);
        assert_eq!(wr.get_i32(off::PROP_AVG_CLASS0), 515);
        assert_eq!(wr.get_i32(off::PROP_AVG_ALL), 5);
        // Every compare-written feature is populated (no sentinel); +0x5c/+0x60 come from
        // apply_neighbor_match, exercised separately.
        for &o in &[0x68u16, 0x6c, 0x74, 0x78, 0x7c, 0x80, 0x84, 0x88, 0x8c, 0x90, 0x94, 0x98, 0x9c, 0xa4, 0xa8] {
            assert_ne!(wr.get_i32(o), FEATURE_SENTINEL, "slot {o:#x} sentinel");
        }
    }

    #[test]
    fn score_features_follow_workrec_offsets() {
        let mut wr = WorkRecord::new();
        wr.apply_neighbor_match(
            &SimilarityQ16 {
                cos: XFORM_FIXED_ONE,
                sin: 0,
                tx: 0,
                ty: 0,
            },
            42,
            7,
            10,
            false,
        );
        let feats = wr.score_features();
        assert_eq!(feats[5], 42);
        assert_eq!(feats[6], 7);
    }

    #[test]
    fn neighbor_match_reject_sets_sentinel() {
        let mut wr = WorkRecord::new();
        wr.apply_neighbor_match(
            &SimilarityQ16 {
                cos: 0,
                sin: 0,
                tx: 0,
                ty: 0,
            },
            0,
            2,
            3,
            true,
        );
        assert_eq!(wr.get_i32(off::AVG_DIST), NEIGHBOR_REJECT_DIST as i32);
        assert_eq!(wr.get_i32(off::XFORM_COS), XFORM_FIXED_ONE);
    }
}
