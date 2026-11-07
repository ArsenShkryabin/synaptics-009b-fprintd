//! Whole-field DoH validated against the real `synaWudfBioUsb.dll` on a **captured frame**.
//!
//! The unit tests in `detect::field` pin the DLL's *kernels*; this pins the whole *composition* —
//! image→Q16 lift, halo/border model, Gaussian ksize selection, the derivative chain order and
//! `det(Hessian)` — on data that came off the sensor.
//!
//! Provenance chain (rebaked 2026-08-03 for conditioning-topology):
//!
//! * frame: `captures/bundles/20260803T152516Z_stream_3f/frames/0000`, subtype `0x2449`, EP-`0x82`
//!   stream. Descramble → `syna_ir_reconstruct_roi@0x1800b9430` (full-frame midrange) → QmFlip
//!   vertical reverse → `fixtures/qmflip_0000.u8` (byte-domain; mean ≈ 158).
//! * golden: `tools/qm-dll-oracle` section 26 calls `syna_qm_doh_build_field@0x18000a100` twice
//!   (mode 0 → `R`/`Lxx`/`Lyy`, mode 1 → `Lx`/`Ly`) and dumps `golden/doh_field.txt`.
//!
//! Per AGENTS.md #7 nothing here is a claim about what the frame *depicts*; it is a fixed byte
//! vector used as a non-degenerate input.

use std::path::Path;
use synaptics_prometheus_qm::detect::{config, doh_response, DohParams};

const W: usize = 144;
const H: usize = 56;

fn load_fixture_and_golden() -> Option<(Vec<u8>, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tools/qm-dll-oracle");
    let img_path = root.join("fixtures/qmflip_0000.u8");
    let gld_path = root.join("golden/doh_field.txt");
    let Ok(image) = std::fs::read(&img_path) else {
        eprintln!("skipping doh_field_oracle test: missing {}", img_path.display());
        return None;
    };
    let Ok(golden) = std::fs::read_to_string(&gld_path) else {
        eprintln!("skipping doh_field_oracle test: missing {}", gld_path.display());
        return None;
    };
    Some((image, golden))
}

/// FNV-1a-64 over the little-endian plane bytes — the same fingerprint `print_plane` computes in
/// `oracle.c`, so a hash equality here is a full-plane equality against the DLL.
fn fnv1a64(bytes: impl IntoIterator<Item = u8>) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    bytes.into_iter().fold(OFFSET_BASIS, |h, b| (h ^ u64::from(b)).wrapping_mul(PRIME))
}

fn plane_hash(plane: &[i32]) -> u64 {
    fnv1a64(plane.iter().flat_map(|v| v.to_le_bytes()))
}

/// `DOHFIELD_HASH <plane> : <hex>`.
fn golden_hash(golden: &str, plane: &str) -> u64 {
    let want = format!("DOHFIELD_HASH {plane} : ");
    let line = golden
        .lines()
        .find_map(|l| l.strip_prefix(&want))
        .unwrap_or_else(|| panic!("golden has no hash for `{plane}`"));
    u64::from_str_radix(line.trim(), 16).expect("hash is hex")
}

/// `DOHFIELD_RANGE <plane> : <min> <max>`.
fn golden_range(golden: &str, plane: &str) -> (i32, i32) {
    let want = format!("DOHFIELD_RANGE {plane} : ");
    let line = golden
        .lines()
        .find_map(|l| l.strip_prefix(&want))
        .unwrap_or_else(|| panic!("golden has no range for `{plane}`"));
    let mut it = line.split_whitespace().map(|v| v.parse().expect("range is decimal"));
    (it.next().unwrap(), it.next().unwrap())
}

/// `DOHFIELD_ROW <plane> <y> : v0 v1 …`, in emission order.
fn golden_rows(golden: &str, plane: &str) -> Vec<Vec<i32>> {
    golden
        .lines()
        .filter_map(|l| {
            let (head, body) = l.strip_prefix("DOHFIELD_ROW ")?.split_once(" : ")?;
            let (name, _y) = head.split_once(' ')?;
            (name == plane).then(|| body.split_whitespace().map(|v| v.parse().unwrap()).collect())
        })
        .collect()
}

fn field(image: &[u8]) -> synaptics_prometheus_qm::detect::DohField {
    doh_response(image, W, H, &DohParams::default())
}

#[test]
fn fixture_is_the_frame_the_dll_saw() {
    let Some((image, golden)) = load_fixture_and_golden() else {
        return;
    };
    assert_eq!(image.len(), W * H);
    let want = golden
        .lines()
        .find_map(|l| {
            l.strip_prefix("DOHFIELD_INPUT ")?
                .split_once("hash=")?
                .1
                .split_whitespace()
                .next()
        })
        .expect("DOHFIELD_INPUT hash");
    let want = u64::from_str_radix(want, 16).unwrap();
    assert_eq!(fnv1a64(image.iter().copied()), want);
}

#[test]
fn default_params_are_the_dlls() {
    // ksize comes from `geom_p10` via `syna_qm_gaussian_select_ksize@0x180010110`; the oracle logs
    // the same source value as `ksize_src=0x466`.
    let p = DohParams::default();
    assert_eq!(p.ksize, config::CONFIG_2449.gaussian_ksize());
    assert_eq!(p.ksize, 5);
    assert_eq!(p.scale, 1);
    assert_eq!(p.sigma, 0.0, "sigma 0 selects the DLL exp-LUT kernel, not an analytic Gaussian");
    if let Some((_image, golden)) = load_fixture_and_golden() {
        assert!(golden.contains("ksize_src=0x466"));
    }
}

/// Every plane the DLL exposes on the tile descriptor, bit-for-bit.
#[test]
fn doh_field_matches_oracle_golden() {
    let Some((image, golden)) = load_fixture_and_golden() else {
        return;
    };
    let f = field(&image);
    assert_eq!((f.width, f.height), (W, H));
    for (name, plane) in
        [("response", &f.response), ("lxx", &f.lxx), ("lyy", &f.lyy), ("lx", &f.lx), ("ly", &f.ly)]
    {
        let (lo, hi) = plane.iter().fold((i32::MAX, i32::MIN), |(l, h), &v| (l.min(v), h.max(v)));
        assert_eq!((lo, hi), golden_range(&golden, name), "{name} range differs from the DLL");
        assert_eq!(plane_hash(plane), golden_hash(&golden, name), "{name} plane differs from the DLL");
    }
}

/// The hash test says *whether*; this says *where*, so a future regression names a pixel instead of
/// a checksum. The oracle dumps `response` in full (it is the plane NMS maximises).
#[test]
fn doh_response_matches_oracle_golden_pixelwise() {
    let Some((image, golden)) = load_fixture_and_golden() else {
        return;
    };
    let f = field(&image);
    let rows = golden_rows(&golden, "response");
    assert_eq!(rows.len(), H, "golden should carry every response row");
    for (y, row) in rows.iter().enumerate() {
        assert_eq!(row.len(), W);
        for (x, &want) in row.iter().enumerate() {
            assert_eq!(f.response[y * W + x], want, "response mismatch at ({x},{y})");
        }
    }
}

/// The ksize mis-read this validation caught: with the NMS threshold `geom_p14` fed in as the
/// smoothing scale you get a 35-tap kernel, and the field is wrong nearly everywhere — so the
/// golden really does discriminate the two, it is not a vacuous comparison.
#[test]
fn wrong_gaussian_scale_is_rejected_by_the_golden() {
    let Some((image, golden)) = load_fixture_and_golden() else {
        return;
    };
    let f = doh_response(&image, W, H, &DohParams { ksize: 35, ..DohParams::default() });
    assert_ne!(plane_hash(&f.response), golden_hash(&golden, "response"));
}
