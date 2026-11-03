//! Analyse a stage-3 minutiae dump from the SYNA_DUMP_QM tap (synaTudor relinker), confirming the
//! DLL's class partition — the premise of the faithful neighbour split (gap #1) and candidate
//! ordering (gap #2). Run on the first successful live capture:
//!
//! `cargo run -p synaptics-prometheus-qm --example analyze_qm_dump -- captures/qm-oracle/qm_stage_00_03_detect_minutiae.bin`

use synaptics_prometheus_qm::oracle::DetectMinutiaeDump;

fn main() {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: analyze_qm_dump <qm_stage_00_03_detect_minutiae.bin>");
            std::process::exit(2);
        }
    };
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            std::process::exit(1);
        }
    };
    let dump = match DetectMinutiaeDump::parse(&bytes) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("parse error: {e}");
            std::process::exit(1);
        }
    };

    let endings = dump.minutiae.iter().filter(|m| m.class == 0).count();
    let bifurcations = dump.minutiae.len() - endings;
    println!("minutiae:      {}", dump.minutiae.len());
    println!("split byte:    {}  (DLL-stored leading class-0 count)", dump.split);
    println!("leading class0:{}", dump.leading_class0());
    println!("class dist:    {endings} endings (class0) / {bifurcations} bifurcations (class!=0)");
    println!(
        "class-ordered: {}  (endings-first, split == leading run)",
        if dump.is_class_partitioned() { "YES — gaps #1/#2 premise CONFIRMED" } else { "NO — investigate ordering" }
    );

    // A peek at the first few sites so positions/angles can be eyeballed against the port's detector.
    for (i, m) in dump.minutiae.iter().take(6).enumerate() {
        println!(
            "  [{i:2}] class={} tile={} ({:3},{:3}) angle={} score={}",
            m.class, m.tile, m.x, m.y, m.angle, m.score
        );
    }
}
