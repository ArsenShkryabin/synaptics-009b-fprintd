//! A pinned digest of the extract → match path, so a refactor that claims to be *bit-identical* can
//! be held to it.
//!
//! The determinism tests next door assert that two runs agree with each other, which a refactor
//! preserves even when it changes every value. These numbers were captured from the code before the
//! redundancy removals in `descriptor_pairs` / `find_best_gallery` / `MinutiaNeighbors` /
//! `describe_candidates_in_tiles`, so a change that alters the output fails here rather than being
//! discovered on the sensor.
//!
//! **If this test fails, the output changed.** That is the point. Do not re-bake the constants
//! without establishing that the new values are the correct ones — the whole reason these exist is
//! that "it still runs and is still deterministic" cannot tell a speed-up from a regression.
//!
//! Rule #7: synthetic textures, and none of this asserts anything about fingerprints — only that the
//! arithmetic did not move. On structureless noise the learned MetViper scorer does not rank a self-match
//! above a cross-match (here self=0, cross=2665) — a perfect synthetic self-match is out of its
//! real-fingerprint training distribution. The value being pinned is the arithmetic (the geometric
//! anchor counts + the bit-exact feature vector + the scores), not the verdict.
//!
//! Note the asymmetry in what a failure means here: these constants are a *snapshot*, whereas
//! `doh_field_oracle.rs` compares against the DLL. When the two disagree, the oracle wins and this
//! file gets re-baked with a provenance line — never the other way round.

use synaptics_prometheus_qm::extractor::{extract_template, ConditionedImage};
use synaptics_prometheus_qm::matcher::{diagnose, score};
use synaptics_prometheus_qm::types::MatchLevel;
use synaptics_prometheus_qm::Template;

const W: usize = 144;
const H: usize = 56;

/// Same generator as `detect_match.rs`: deterministic, and locally varied so descriptors differ.
fn varied_texture(seed: u32) -> Vec<u8> {
    let mut px = vec![0u8; W * H];
    for y in 0..H {
        for x in 0..W {
            let h = (x as u32)
                .wrapping_mul(2_654_435_761)
                .wrapping_add((y as u32).wrapping_mul(40_503))
                .wrapping_add(seed.wrapping_mul(2_246_822_519));
            px[y * W + x] = (((h >> 13) ^ (h >> 7)) & 0xff) as u8;
        }
    }
    px
}

fn template_of(seed: u32) -> Template {
    extract_template(ConditionedImage {
        pixels: &varied_texture(seed),
        width: W as u16,
        height: H as u16,
        stride: W as u16,
    })
    .expect("synthetic texture yields a template")
}

/// FNV-1a over every field of every minutia, in order. Order-sensitive on purpose: a change that
/// reshuffles sites is a change, even if the set is the same.
fn digest_template(t: &Template) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let byte = |b: u8, h: &mut u64| {
        *h ^= b as u64;
        *h = h.wrapping_mul(0x100_0000_01b3);
    };
    for m in &t.minutiae {
        byte(m.x, &mut h);
        byte(m.y, &mut h);
        for b in m.angle_deg.to_le_bytes() {
            byte(b, &mut h);
        }
        for b in m.descriptor {
            byte(b, &mut h);
        }
    }
    h
}

#[test]
fn extraction_output_is_unchanged() {
    let a = template_of(1);
    let b = template_of(2);
    // Counts first: they localise a failure to "different sites" vs "same sites, different values".
    //
    // Re-baked 2026-08-03 for the whole-field DoH validation (tests/doh_field_oracle.rs): the port's
    // separable convolution now reproduces `FUN_18000f3b0`/`FUN_18000f790` exactly — true convolution
    // (reversed kernel), out-of-frame taps dropped rather than halo-filled, and 32-bit wrapping
    // arithmetic per tap. Counts shift (32/28 → 26/22) because the field itself changed. The new
    // field is bit-exact against `syna_qm_doh_build_field@0x18000a100` on a captured frame, which the
    // old one was not, so these numbers are strictly better-grounded than the ones they replace.
    //
    // (Previously re-baked 2026-07-31 for the DLL-faithful NMS stage — two-gate threshold
    // thr1=0x15d8/thr2=0xa8, the `((engine+0x48>>6)²)>>20` min-distance, the `Lxx<0→Lyy>=0` class
    // polarity fix, and the `refine_subpixel_hessian` write-back; golden/nms.txt.)
    assert_eq!(a.minutiae.len(), 26, "template A minutia count");
    assert_eq!(b.minutiae.len(), 22, "template B minutia count");
    assert_eq!(digest_template(&a), 0x1619_c07a_8c44_0cd5, "template A digest");
    assert_eq!(digest_template(&b), 0x7e3c_334c_de5f_eb21, "template B digest");
}

#[test]
fn match_output_is_unchanged() {
    let a = template_of(1);
    let b = template_of(2);

    // Re-baked 2026-08-02 for Stage-5 Phase C — the full faithful match pipeline: (1) the neighbour-
    // compare tail is now the real grid-based `neighbor_compare` (oracle-validated, no approximations or
    // sentinels); (2) `match_count` (+0x60) is the DLL's pair-matcher inlier count `iVar5`, gating anchors
    // /compare on `iVar5 >= 4`; (3) `fit_two_point` (FUN_180006d60) got its argument layout corrected —
    // it fits from the probe-vector and gallery-vector (both probe points / both gallery points), FIT2-
    // oracle-verified — which is what lets a self-match resolve the identity transform (the old grouping
    // used per-correspondence displacement and degenerated on translations, wrongly yielding 0 anchors).
    //
    // Self-match `a` vs `a`: one anchor per minutia (every minutia fits identity), and the bit-exact
    // feature vector below (Hamming/avg 0 — a perfect descriptor self-match — plus the real
    // coverage/count reductions). Re-baked 2026-08-03 with the extraction numbers above: the matcher
    // arithmetic did not change, only the template it is fed.
    let d = diagnose(&a, &a, MatchLevel::Level2, W as i32, H as i32);
    assert_eq!(d.anchor_count, 26, "self-match anchor count");
    assert_eq!(
        &d.features[..17],
        &[0, 0, 1798, 1798, 1798, 0, 25, 0, 0, 0, 1798, 1798, 25, 0, 25, 0, 0],
        "anchor-0 feature vector"
    );
    assert_eq!(
        &d.features[17..34],
        &[0, 0, 1778, 1778, 1778, 0, 25, 0, 0, 0, 1778, 1778, 25, 0, 25, 0, 0],
        "anchor-1 feature vector"
    );
    // The learned MetViper scorer maps this unrealistically-perfect synthetic self-match vector (Hamming
    // 0 everywhere — out of its real-fingerprint training distribution) to 0, and a scrambled cross-match
    // to 2221: on structureless noise the scorer does NOT rank a self-match above a cross-match (see the
    // module header). The value being pinned is the arithmetic, not the verdict — a meaningful non-zero
    // self score needs a real capture (Phase F).
    assert_eq!(score(&a, &a, MatchLevel::Level1).score, 0, "self score");
    assert_eq!(score(&a, &b, MatchLevel::Level1).score, 2221, "cross score");
    assert_eq!(diagnose(&a, &b, MatchLevel::Level2, W as i32, H as i32).anchor_count, 19, "cross anchor count");
    assert!(!d.decision, "self decision");
}
