//! SYNA_PCAP capture — libpcap (DLT_USER0 / `SYNP`) compatible with synaTudor.
//!
//! Set env `SYNA_PCAP=/path/to/file.pcap` to record **all** vendor traffic:
//!
//! | EP   | Dir | `kind`           | Content |
//! |------|-----|------------------|---------|
//! | 0x01 | OUT | `WIRE_USB` (0)   | Wire bytes (pre-TLS cleartext; post-TLS TLS ciphertext) |
//! | 0x01 | OUT | `TLS_PLAINTEXT` (1) | Vendor cmd ‖ HMAC before CBC pad (`tls::wrap`) |
//! | 0x81 | IN  | `WIRE_USB` (0)   | Wire bytes (pre-TLS cleartext; post-TLS TLS ciphertext) |
//! | 0x81 | IN  | `TLS_PLAINTEXT` (1) | Vendor response ‖ HMAC after unpad (`tls::unwrap`) |
//! | 0x82 | IN  | `WIRE_USB` (0)   | Raw stream bulk (not TLS) |
//! | 0x83 | IN  | `WIRE_USB` (0)   | Raw interrupt events |
//!
//! Post-TLS cmd round-trips produce **both** wire and plain records; filter with
//! `extract_transfers.py --plain-only` for cmd/arg diff vs the DLL.
//!
//! Format matches [`vendor/synaTudor/libtudor/inc/tudor/pcap_log.h`](../../vendor/synaTudor/libtudor/inc/tudor/pcap_log.h).

use std::fs::File;
use std::io::{self, Write};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// Per-packet payload prefix magic (`SYNP` LE).
pub const SYNA_PCAP_PKT_MAGIC: u32 = 0x504e_5953;
/// Wire bytes from [`crate::transport::Transport`] (all EPs when `SYNA_PCAP` is set).
pub const SYNA_PCAP_WIRE_USB: u8 = 0;
/// TLS record body at the MAC-then-encrypt boundary (vendor ‖ HMAC, before CBC pad).
pub const SYNA_PCAP_TLS_PLAINTEXT: u8 = 1;

const PCAP_MAGIC_LE: u32 = 0xa1b2_c3d4;
const DLT_USER0: u32 = 147;

struct PcapState {
    file: File,
    t0: Instant,
}

static PCAP: OnceLock<Mutex<Option<PcapState>>> = OnceLock::new();

fn pcap_mutex() -> &'static Mutex<Option<PcapState>> {
    PCAP.get_or_init(|| Mutex::new(None))
}

#[cfg(test)]
fn reset_pcap_state() {
    let mut guard = pcap_mutex().lock().expect("pcap mutex");
    *guard = None;
}

/// True when `SYNA_PCAP` names a non-empty output path.
pub fn pcap_active() -> bool {
    std::env::var("SYNA_PCAP")
        .map(|p| !p.is_empty())
        .unwrap_or(false)
}

fn open_if_needed() -> io::Result<()> {
    let mut guard = pcap_mutex().lock().expect("pcap mutex");
    if guard.is_some() {
        return Ok(());
    }
    let path = match std::env::var("SYNA_PCAP") {
        Ok(p) if !p.is_empty() => p,
        _ => return Ok(()),
    };
    let mut file = File::create(&path)?;
    write_global_header(&mut file)?;
    log::info!("SYNA_PCAP: logging to {path} (DLT_USER0 / SYNP full capture)");
    *guard = Some(PcapState {
        file,
        t0: Instant::now(),
    });
    Ok(())
}

fn write_global_header(w: &mut File) -> io::Result<()> {
    let mut hdr = [0u8; 24];
    hdr[0..4].copy_from_slice(&PCAP_MAGIC_LE.to_le_bytes());
    hdr[4..6].copy_from_slice(&2u16.to_le_bytes());
    hdr[6..8].copy_from_slice(&4u16.to_le_bytes());
    hdr[16..20].copy_from_slice(&65535u32.to_le_bytes());
    hdr[20..24].copy_from_slice(&DLT_USER0.to_le_bytes());
    w.write_all(&hdr)
}

/// Log one transfer when `SYNA_PCAP` is set; no-op otherwise.
pub fn log_transfer(kind: u8, endpoint: u8, payload: &[u8]) {
    if payload.is_empty() {
        return;
    }
    if open_if_needed().is_err() {
        return;
    }
    let mut guard = match pcap_mutex().lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    let Some(state) = guard.as_mut() else {
        return;
    };

    let elapsed = state.t0.elapsed();
    let ts_sec = elapsed.as_secs() as u32;
    let ts_usec = elapsed.subsec_micros();

    let body_len = 8 + payload.len();
    if body_len > 0xffff {
        return;
    }

    let mut pkt_hdr = [0u8; 16];
    pkt_hdr[0..4].copy_from_slice(&ts_sec.to_le_bytes());
    pkt_hdr[4..8].copy_from_slice(&ts_usec.to_le_bytes());
    pkt_hdr[8..12].copy_from_slice(&(body_len as u32).to_le_bytes());
    pkt_hdr[12..16].copy_from_slice(&(body_len as u32).to_le_bytes());

    let mut syna_hdr = [0u8; 8];
    syna_hdr[0..4].copy_from_slice(&SYNA_PCAP_PKT_MAGIC.to_le_bytes());
    syna_hdr[4] = endpoint;
    syna_hdr[5] = kind;

    let _ = state.file.write_all(&pkt_hdr);
    let _ = state.file.write_all(&syna_hdr);
    let _ = state.file.write_all(payload);
    let _ = state.file.flush();
}

/// True when `buf` begins with a TLS 1.2 record header (wire ciphertext path).
pub fn looks_like_tls_record(buf: &[u8]) -> bool {
    buf.len() >= 3 && matches!(buf[0], 0x14..=0x17) && buf[1] == 0x03 && buf[2] == 0x03
}

/// Log raw USB wire bytes when `SYNA_PCAP` is active (all endpoints, including TLS ciphertext).
pub fn maybe_log_wire(endpoint: u8, payload: &[u8]) {
    if payload.is_empty() || !pcap_active() {
        return;
    }
    log_transfer(SYNA_PCAP_WIRE_USB, endpoint, payload);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn read_synp_packets(path: &std::path::Path) -> Vec<(u8, u8, Vec<u8>)> {
        let mut f = std::fs::File::open(path).expect("pcap exists");
        f.read_exact(&mut [0u8; 24]).unwrap();
        let mut out = Vec::new();
        loop {
            let mut rh = [0u8; 16];
            if f.read_exact(&mut rh).is_err() {
                break;
            }
            let caplen = u32::from_le_bytes(rh[8..12].try_into().unwrap()) as usize;
            let mut payload = vec![0u8; caplen];
            if f.read_exact(&mut payload).is_err() {
                break;
            }
            if payload.len() < 8 {
                continue;
            }
            let magic = u32::from_le_bytes(payload[0..4].try_into().unwrap());
            if magic != SYNA_PCAP_PKT_MAGIC {
                continue;
            }
            let ep = payload[4];
            let kind = payload[5];
            out.push((ep, kind, payload[8..].to_vec()));
        }
        out
    }

    #[test]
    fn synp_pcap_writes_plaintext_and_wire() {
        reset_pcap_state();
        let dir = std::env::temp_dir().join(format!("syna-pcap-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.pcap");
        let _ = std::fs::remove_file(&path);

        unsafe {
            std::env::set_var("SYNA_PCAP", &path);
        }
        log_transfer(SYNA_PCAP_TLS_PLAINTEXT, 0x01, &[0x75, 0x01, 0x02]);
        log_transfer(
            SYNA_PCAP_TLS_PLAINTEXT,
            0x81,
            &[0x00, 0x00, 0x4b, 0x00, 0x90, 0x01],
        );

        // TLS ApplicationData record header + dummy body (wire ciphertext).
        let mut tls_wire = vec![0x17u8, 0x03, 0x03, 0x00, 0x10];
        tls_wire.resize(21, 0xAA);
        maybe_log_wire(0x01, &tls_wire);
        log_transfer(SYNA_PCAP_TLS_PLAINTEXT, 0x01, &[0x6f, 0x00, 0x0a]);
        unsafe {
            std::env::remove_var("SYNA_PCAP");
        }

        let mut f = std::fs::File::open(&path).expect("pcap exists");
        let mut gh = [0u8; 24];
        f.read_exact(&mut gh).unwrap();
        assert_eq!(u32::from_le_bytes(gh[0..4].try_into().unwrap()), PCAP_MAGIC_LE);
        assert_eq!(u32::from_le_bytes(gh[20..24].try_into().unwrap()), DLT_USER0);

        let packets = read_synp_packets(&path);
        assert_eq!(packets.len(), 4);
        assert_eq!(
            packets[2],
            (0x01, SYNA_PCAP_WIRE_USB, tls_wire)
        );
        assert_eq!(
            packets[3],
            (0x01, SYNA_PCAP_TLS_PLAINTEXT, vec![0x6f, 0x00, 0x0a])
        );
    }
}
