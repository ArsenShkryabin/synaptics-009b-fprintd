//! Agent debug logging (NDJSON) for Cursor debug sessions.

use std::fs::OpenOptions;
use std::io::Write;

const LOG_PATH: &str = "/home/florian/src-laptop/synaptics-fp-re/.cursor/debug-0c91c4.log";
const SESSION_ID: &str = "0c91c4";

/// Append one NDJSON debug record. `data` must be a JSON object literal (without outer braces escaped).
pub fn log(hypothesis_id: &str, location: &str, message: &str, data: &str) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(LOG_PATH) {
        let _ = writeln!(
            f,
            r#"{{"sessionId":"{SESSION_ID}","hypothesisId":"{hypothesis_id}","location":"{location}","message":"{message}","data":{data},"timestamp":{ts}}}"#
        );
    }
}

/// Summarize a framed `0x02` capture command for parity debugging.
pub fn arm_cmd_stats(cmd: &[u8]) -> String {
    let bpl = cmd.get(1..3).map(|s| u16::from_le_bytes([s[0], s[1]])).unwrap_or(0);
    let req_lines = cmd.get(3..5).map(|s| u16::from_le_bytes([s[0], s[1]])).unwrap_or(0);
    let body = cmd.get(5..).unwrap_or(&[]);
    let mut line_update_len = 0u32;
    let mut line_update_transform_len = 0u32;
    let mut has_bw_reduction = false;
    let mut has_finger_detect = false;
    let mut has_chunk_2e = false;
    let mut unknown_chunks: Vec<u16> = Vec::new();
    let mut i = 0usize;
    while i + 4 <= body.len() {
        let ty = u16::from_le_bytes([body[i], body[i + 1]]);
        let len = u16::from_le_bytes([body[i + 2], body[i + 3]]) as usize;
        let end = i + 4 + len;
        if end > body.len() {
            break;
        }
        match ty {
            0x30 => line_update_len = len as u32,
            0x43 => line_update_transform_len = len as u32,
            0x15 => has_bw_reduction = true,
            0x26 | 0x4e => has_finger_detect = true,
            0x2e => has_chunk_2e = true,
            0x23 | 0x20 | 0x32 | 0x33 | 0x34 | 0x42 | 0x2f | 0x29 | 0x35 | 0x17 | 0x44 | 0x2b | 0x2d => {}
            _ if !unknown_chunks.contains(&ty) => unknown_chunks.push(ty),
            _ => {}
        }
        i = end;
    }
    format!(
        r#"{{"cmd_len":{},"bpl":{},"req_lines":{},"body_len":{},"line_update_len":{},"line_update_transform_len":{},"has_bw_reduction":{},"has_finger_detect":{},"has_chunk_2e":{},"unknown_chunks":{:?}}}"#,
        cmd.len(),
        bpl,
        req_lines,
        body.len(),
        line_update_len,
        line_update_transform_len,
        has_bw_reduction,
        has_finger_detect,
        has_chunk_2e,
        unknown_chunks
    )
}
