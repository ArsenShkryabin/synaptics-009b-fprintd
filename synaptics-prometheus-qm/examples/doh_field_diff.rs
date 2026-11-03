//! Diff the port's whole-field DoH against the DLL golden on a real captured frame.
//!
//! The oracle (`tools/qm-dll-oracle`, section 26) calls `syna_qm_doh_build_field@0x18000a100` on
//! `fixtures/qmflip_0000.u8` — reconstruct_roi + QmFlip of
//! `captures/bundles/20260803T152516Z_stream_3f/frames/0000` — and emits `golden/doh_field.txt`.
//! This runs `qm::detect::doh_response` on the same bytes and reports, per plane, the FNV-1a-64
//! fingerprint plus how many samples differ.
//!
//! ```text
//! cargo run -p synaptics-prometheus-qm --example doh_field_diff -- [ksize ...]
//! ```

use synaptics_prometheus_qm::detect::{doh_response, DohParams};

const IMAGE: &[u8] = include_bytes!("../../tools/qm-dll-oracle/fixtures/qmflip_0000.u8");
const W: usize = 144;
const H: usize = 56;

/// The `DOHFIELD_HASH` lines of `tools/qm-dll-oracle/golden/doh_field.txt`.
const GOLDEN: &[(&str, u64)] = &[
    ("response", 0xade7_8b5e_48f6_2844),
    ("lxx", 0xbee0_ea1f_d9e0_a1ef),
    ("lyy", 0xcf22_84ca_e9ee_4373),
    ("lx", 0xecbc_70bc_4729_71fa),
    ("ly", 0xe3bf_fa50_9ff1_fe21),
];

const GOLDEN_TXT: &str = include_str!("../../tools/qm-dll-oracle/golden/doh_field.txt");

/// The `DOHFIELD_ROW <plane> <y> : ...` rows the oracle dumps in full (the response plane).
fn golden_rows(plane: &str) -> Vec<Vec<i32>> {
    GOLDEN_TXT
        .lines()
        .filter_map(|l| {
            let rest = l.strip_prefix("DOHFIELD_ROW ")?;
            let (head, body) = rest.split_once(" : ")?;
            let (name, _y) = head.split_once(' ')?;
            (name == plane).then(|| body.split_whitespace().filter_map(|v| v.parse().ok()).collect())
        })
        .collect()
}

fn fnv1a64(v: &[i32]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for x in v {
        for b in x.to_le_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    h
}

fn main() {
    let ksizes: Vec<usize> = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse().ok())
        .collect();
    let ksizes = if ksizes.is_empty() { vec![5usize, 35] } else { ksizes };
    println!("image {W}x{H}, hash {:016x}", {
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for &b in IMAGE {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    });
    for ksize in ksizes {
        let f = doh_response(IMAGE, W, H, &DohParams { ksize, sigma: 0.0, scale: 1 });
        println!("--- ksize {ksize}");
        for (name, want) in GOLDEN {
            let plane: &[i32] = match *name {
                "response" => &f.response,
                "lxx" => &f.lxx,
                "lyy" => &f.lyy,
                "lx" => &f.lx,
                "ly" => &f.ly,
                _ => unreachable!(),
            };
            let got = fnv1a64(plane);
            let (lo, hi) = plane.iter().fold((i32::MAX, i32::MIN), |(l, h), &v| (l.min(v), h.max(v)));
            println!(
                "{name:9} {:016x} {} range [{lo}, {hi}]",
                got,
                if got == *want { "MATCH" } else { "differs" }
            );
        }
        // Where do the response mismatches live? A border-only band means the halo model differs;
        // interior mismatches mean the kernel chain does.
        let rows = golden_rows("response");
        if rows.len() != H {
            continue;
        }
        // Border width the zero-padded passes disturb: the Gaussian radius plus one derivative
        // radius per pass, and the second derivatives are two passes deep.
        let margin = ksize / 2 + 2;
        let response = &f.response;
        let mismatches: Vec<(usize, usize, i32, i32)> = rows
            .iter()
            .enumerate()
            .flat_map(|(y, row)| {
                row.iter().enumerate().filter_map(move |(x, &want)| {
                    let got = response[y * W + x];
                    (got != want).then_some((x, y, got, want))
                })
            })
            .collect();
        let interior: Vec<_> = mismatches
            .iter()
            .filter(|(x, y, ..)| {
                *x >= margin && x + margin < W && *y >= margin && y + margin < H
            })
            .collect();
        let bbox = mismatches.iter().fold(None, |acc: Option<[usize; 4]>, &(x, y, ..)| {
            Some(match acc {
                None => [x, x, y, y],
                Some([x0, x1, y0, y1]) => [x0.min(x), x1.max(x), y0.min(y), y1.max(y)],
            })
        });
        println!(
            "response diff: {}/{} samples ({} beyond a {margin}px border), bbox {:?}",
            mismatches.len(),
            W * H,
            interior.len(),
            bbox
        );
        for &&(x, y, got, want) in interior.iter().take(12) {
            println!("  inner ({x},{y}): port {got} dll {want}");
        }
    }
}
