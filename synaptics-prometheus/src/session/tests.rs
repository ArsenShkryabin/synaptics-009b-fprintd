//! Unit tests for the session module (moved out of mod.rs; access via super).

use super::*;
use crate::capture::{
    run_wof, stop_cmd, wof, CaptureControl, CaptureIo, FrameCapturer, ReadMode, WofIo,
};
use crate::pre_arm::{PreArmMode, PreArmOutcome};
use std::collections::VecDeque;

#[test]
fn trace_labels_render_opcode_and_status_names() {
    // Command layer renders the Opcode name + value, unknown bytes fall back, and the reply
    // renders the Status via its Display (name + label).
    assert_eq!(opcode_label(&[Opcode::GetRomInfo.byte()]), "GetRomInfo(0x01)");
    assert_eq!(opcode_label(&[0x76, 0xaa]), "SendRecordHeader(0x76)");
    assert_eq!(opcode_label(&[0xfe]), "unknown(0xfe)");
    assert_eq!(opcode_label(&[]), "empty");
    // status word 0x0000 → OK; a short reply is flagged, not mis-decoded.
    assert!(reply_status_label(&[0x00, 0x00, 0x11]).starts_with("status 0x0000"));
    assert_eq!(reply_status_label(&[0x00]), "(short reply, 1B)");
}

/// A mock transport that shares the session keys, so it can DECRYPT each written command (to
/// assert the exact wire opcode) and ENCRYPT canned replies the way the sensor would.
struct MockTransport {
    keys: SessionKeys,
    sent: Vec<Vec<u8>>,         // decrypted plaintext commands, in order
    replies: VecDeque<Vec<u8>>, // decrypted plaintext replies to hand back, in order
    bulk: Vec<u8>,
    interrupts: VecDeque<Vec<u8>>,
}
impl Transport for MockTransport {
    fn write_cmd(&mut self, data: &[u8]) -> Result<()> {
        let (_, pt) = tls::unwrap(&self.keys, data)?;
        self.sent.push(pt);
        Ok(())
    }
    fn read_cmd(&mut self, _max: usize) -> Result<Vec<u8>> {
        let pt = self.replies.pop_front().unwrap_or_default();
        tls::wrap(&self.keys, RecordType::ApplicationData, &pt, [0x11; IV_LEN])
    }
    fn read_bulk(&mut self, _max: usize) -> Result<Vec<u8>> {
        Ok(std::mem::take(&mut self.bulk))
    }
    fn read_interrupt(&mut self, _max: usize, _timeout_ms: u64) -> Result<Vec<u8>> {
        Ok(self.interrupts.pop_front().unwrap_or_default())
    }
}

/// Deterministic host-side keys for the [`Session`] under test (derive is pure).
fn host_keys() -> SessionKeys {
    SessionKeys::derive(&[0x11; 48], &[0x22; 32], &[0x33; 32])
}

/// The sensor's view of the same keys: directions swapped, so the mock (playing the sensor) can
/// decrypt host→sensor commands with `tls::unwrap` and encrypt sensor→host replies with `tls::wrap`.
fn sensor_keys() -> SessionKeys {
    let k = host_keys();
    SessionKeys {
        sign: k.validation,
        validation: k.sign,
        encryption: k.decryption,
        decryption: k.encryption,
    }
}

/// Build a `[status:u16][tail…]` plaintext reply.
fn reply(status: u16, tail: &[u8]) -> Vec<u8> {
    let mut v = status.to_le_bytes().to_vec();
    v.extend_from_slice(tail);
    v
}

fn session_with(replies: Vec<Vec<u8>>) -> Session<MockTransport> {
    let mock = MockTransport {
        keys: sensor_keys(),
        sent: vec![],
        replies: replies.into(),
        bulk: vec![],
        interrupts: VecDeque::new(),
    };
    Session::new(mock, host_keys())
}

/// Decrypted commands the session sent (drains through the mock).
fn sent(s: &Session<MockTransport>) -> &[Vec<u8>] {
    &s.transport.sent
}

#[test]
fn arm_returns_device_status_word() {
    let mut s = session_with(vec![reply(0x0412, &[])]);
    assert_eq!(s.arm(&[0x02, 0xAA]).unwrap(), 0x0412);
    assert_eq!(
        sent(&s),
        &[vec![0x02, 0xAA]],
        "arm tunnels the program bytes verbatim"
    );
}

#[test]
fn reboot_sensor_sends_mode2_on_wire() {
    let mut s = session_with(vec![reply(0, &[])]);
    s.reboot_sensor().unwrap();
    assert_eq!(sent(&s), &[vec![Opcode::Reboot.byte(), 0x02, 0x00]]);
}

#[test]
fn capture_one_recovering_reboots_and_rearms_once_on_capture_fault() {
    // Arrange: `fw_upload_context = true` makes the pre-arm dedup-skip (no wire I/O), isolating the
    // stop→arm→reboot→re-arm sequence. The first arm reports 0x0450 (CaptureAlreadyArmed, in the
    // reboot-retry band); after a 0x05 reboot the re-arm reports 0x0000 and a full frame returns.
    let mut s = session_with(vec![
        reply(0x0000, &[]), // stop (0x04) before first arm
        reply(0x0450, &[]), // first arm → capture fault
        reply(0x0000, &[]), // reboot (0x05)
        reply(0x0000, &[]), // stop (0x04) after reboot
        reply(0x0000, &[]), // stop (0x04) before re-arm
        reply(0x0000, &[]), // re-arm → OK
    ]);
    s.fw_upload_context = true;
    s.transport.bulk = vec![0xAB; 8]; // frame bytes for the successful read (frame_size = 4×2)

    // Act.
    let capturer = FrameCapturer::new(4, 2);
    let frame = s
        .capture_one_recovering(&capturer, &[0x02, 0xAA], Some(PreArmMode::Standard))
        .expect("re-arm after reboot succeeds");

    // Assert: the recovered frame, and exactly one reboot between two arms.
    assert_eq!(frame.arm_status, 0x0000);
    assert_eq!(frame.bytes, vec![0xAB; 8]);
    let opcodes: Vec<u8> = sent(&s).iter().map(|c| c[0]).collect();
    assert_eq!(
        opcodes,
        vec![
            stop_cmd::ABORT,        // 0x04 pre first arm
            0x02,                   // first arm (fault 0x0450)
            Opcode::Reboot.byte(),  // 0x05 reboot
            stop_cmd::ABORT,        // 0x04 post-reboot clear
            stop_cmd::ABORT,        // 0x04 pre re-arm
            0x02,                   // re-arm (ok)
        ],
    );
    assert_eq!(
        sent(&s)[2],
        vec![Opcode::Reboot.byte(), 0x02, 0x00],
        "reboot is soft mode 2",
    );
}

#[test]
fn capture_one_recovering_passes_clean_capture_through_without_reboot() {
    // A first arm that reports OK must not trigger any reboot — the happy path is untouched.
    let mut s = session_with(vec![
        reply(0x0000, &[]), // stop (0x04) before arm
        reply(0x0000, &[]), // arm → OK
    ]);
    s.fw_upload_context = true;
    s.transport.bulk = vec![0xCD; 8];

    let capturer = FrameCapturer::new(4, 2);
    let frame = s
        .capture_one_recovering(&capturer, &[0x02, 0xAA], Some(PreArmMode::Standard))
        .expect("clean capture");

    assert_eq!(frame.arm_status, 0x0000);
    let opcodes: Vec<u8> = sent(&s).iter().map(|c| c[0]).collect();
    assert_eq!(opcodes, vec![stop_cmd::ABORT, 0x02], "no reboot on the happy path");
}

#[test]
fn stop_sends_soft_abort() {
    let mut s = session_with(vec![reply(0, &[])]);
    s.stop().unwrap();
    assert_eq!(sent(&s), &[vec![stop_cmd::ABORT]]); // 0x04
}

#[test]
fn teardown_polled_tunnels_stop_then_finalize() {
    // Two tunnels (STOP, FINALIZE) → two replies. Drive the CANONICAL executor over the session.
    let mut s = session_with(vec![reply(0, &[]), reply(0, &[])]);
    s.teardown(ReadMode::Polled, 6, 0x14, false).unwrap();
    assert_eq!(sent(&s), &[vec![stop_cmd::STOP], vec![stop_cmd::FINALIZE]]); // 0x04, 0x52
}

#[test]
fn teardown_stream_cancel_does_not_tunnel_before_stop() {
    // Stream teardown = cancel (drain, no tunnel) → STOP → FINALIZE. Only the two commands appear.
    let mut s = session_with(vec![reply(0, &[]), reply(0, &[])]);
    s.teardown(ReadMode::Stream, 6, 0x14, false).unwrap();
    assert_eq!(sent(&s), &[vec![stop_cmd::STOP], vec![stop_cmd::FINALIZE]]);
}

#[test]
fn wof_status_wire_opcode_and_remap() {
    // wof_status → wire opcode 0x77 (no-arg; syna_cmd_77); raw byte 1 remaps to 2.
    let mut s = session_with(vec![reply(0, &[0x01])]);
    assert_eq!(s.wof_status().unwrap(), 2, "raw WOF byte 1 remaps to 2");
    assert_eq!(sent(&s), &[vec![WOF_STATUS_CMD]]); // 0x77
}

#[test]
fn wof_arm_disarm_wire_sequence() {
    // arm: cfg57(0x57) → probe-DB(0x45) → 2× AFE(0x08) → record(0x76). disarm: same + a trailing
    // probe-DB re-init(0x45). (Faithful to syna_vfm_scm_wof_arm_disarm but UNTESTED — see wof::arm_command.)
    // fw_upload_context=true → the 0x800000 WOF-module upload is deduped (the provisioned-sensor
    // path), leaving this clean sequence; the fresh-upload path is covered separately below.
    let mut s = session_with(vec![reply(0, &[]); 11]);
    s.fw_upload_context = true;
    s.arm_wof(0x01).unwrap();
    s.disarm_wof().unwrap();
    let opcodes: Vec<u8> = sent(&s).iter().map(|c| c[0]).collect();
    assert_eq!(
        opcodes,
        vec![0x57, 0x45, 0x08, 0x08, 0x76, 0x57, 0x45, 0x08, 0x08, 0x76, 0x45],
    );
    // the arm record (5th command) = tag 0x03 + the 0x2449 flex block.
    assert_eq!(
        sent(&s)[4],
        wof::arm_command(0x03, wof::DEFAULT_LED_COLOR, 0, wof::WAKE_FLEX_2449),
    );
}

#[test]
fn db_prefix_not_deduped_when_provisioned() {
    let mut tail = vec![0u8; 0x24];
    tail[0x08] = 6;
    tail[0x09] = 0x14;
    tail[0x0a] = 1;
    let mut s = session_with(vec![reply(0, &tail), reply(0, &[]), reply(0, &[])]);
    s.fw_upload_context = true;
    let outcome = s.upload_db_prefix().unwrap();
    assert_ne!(outcome, PreArmOutcome::SkippedDedup);
    assert_eq!(sent(&s)[0][0], Opcode::GetRomInfo.byte());
}

#[test]
fn wof_module_deduped_when_provisioned() {
    // On a provisioned sensor the 0x800000 WOF-module upload is deduped (0x800000 ∉ exempt list):
    // no identity read, no 0x06 — zero wire traffic. This is why the clean sequence above holds.
    let mut s = session_with(vec![]);
    s.fw_upload_context = true;
    assert_eq!(s.upload_wof_module().unwrap(), PreArmOutcome::SkippedDedup);
    assert!(sent(&s).is_empty());
}

#[test]
fn wof_module_upload_reads_identity_when_fresh() {
    // Fresh session: the upload passes the dedup gate, reads the ROM identity (0x01) to select the
    // 0x800000 record for this sensor, then (if the extracted blob is present) sends probe-DB + 0x06.
    // Deterministic w.r.t. blob presence: it always issues 0x01 first and then either sends (blob
    // present) or hard-errors on the missing module — never deduped/unmatched for a 009b identity.
    let mut tail = vec![0u8; 0x24];
    tail[0x08] = 6; // id8
    tail[0x09] = 0x14; // id9 = fw 6.20 (009b)
    tail[0x0a] = 1; // id0a  (flags17 @ 0x17 = 0 → subkey 3, matching the WOF record)
    let mut s = session_with(vec![reply(0, &tail), reply(0, &[]), reply(0, &[])]);
    let outcome = s.upload_wof_module();
    assert_eq!(sent(&s)[0][0], Opcode::GetRomInfo.byte(), "reads identity first");
    // The WOF record MUST match this 009b identity: either the blob was present and we Sent it, or it
    // was absent and we hard-errored on the missing (but matched) module. A `SkippedNoModule`/dedup
    // would mean no match — the failure this test guards against.
    match outcome {
        Ok(PreArmOutcome::Sent) => {}
        Err(crate::error::Error::Malformed(m)) if m.contains("required pre-arm fw module missing") => {}
        other => panic!("009b identity must match a WOF record (Sent or missing-module error): {other:?}"),
    }
}

#[test]
fn run_wof_over_session_full_flow() {
    // IRQ fires; wof_status raw 0x02 remaps to 1 → matches mask 0x01 → detected; then the RAII
    // context tears down. Full opcode sequence: arm(5) → status(0x77) → cancel(drain) → disarm(6).
    let mut s = {
        let mut replies = vec![reply(0, &[]); 5]; // arm: cfg57, 0x45, 0x08, 0x08, 0x76
        replies.push(reply(0, &[0x02])); // wof_status raw 0x02 → 1 → matches mask
        replies.extend(vec![reply(0, &[]); 6]); // disarm: cfg57, 0x45, 0x08, 0x08, 0x76, 0x45
        let mock = MockTransport {
            keys: sensor_keys(),
            sent: vec![],
            replies: replies.into(),
            bulk: vec![],
            interrupts: vec![vec![0xAB]].into(), // one wake packet
        };
        let mut s = Session::new(mock, host_keys());
        s.fw_upload_context = true; // provisioned → WOF-module upload deduped (clean sequence)
        s
    };
    let detected = crate::capture::run_wof(&mut s, 0x01, || true).unwrap();
    assert!(detected);
    let opcodes: Vec<u8> = sent(&s).iter().map(|c| c[0]).collect();
    assert_eq!(
        opcodes,
        vec![
            0x57, 0x45, 0x08, 0x08, 0x76, // arm
            0x77, // wof_status
            0x57, 0x45, 0x08, 0x08, 0x76, 0x45, // disarm
        ],
    );
}

// ---- WOF sequence in isolation (mock session, no hardware) ------------------------------------
// Run: cargo test -p synaptics-prometheus wof_sequence

fn wof_arm_opcodes() -> Vec<u8> {
    vec![
        Opcode::SetU16Param.byte(),
        Opcode::DbInfo.byte(),
        Opcode::WriteHwReg32.byte(),
        Opcode::WriteHwReg32.byte(),
        Opcode::SendRecordHeader.byte(),
    ]
}

#[test]
fn wof_sequence_arm_preamble_in_isolation() {
    let mut s = session_with((0..5).map(|_| reply(0, &[])).collect());
    s.fw_upload_context = true;
    s.arm_wof(0x01).unwrap();
    assert_eq!(sent(&s).iter().map(|c| c[0]).collect::<Vec<_>>(), wof_arm_opcodes());
    let arm = sent(&s).last().unwrap();
    assert_eq!(arm[1], wof::arm_tag(0x01));
    assert!(arm.ends_with(wof::WAKE_FLEX_2449));
}

#[test]
fn wof_sequence_disarm_preamble_in_isolation() {
    let mut s = session_with((0..6).map(|_| reply(0, &[])).collect());
    s.fw_upload_context = true;
    s.disarm_wof().unwrap();
    assert_eq!(
        sent(&s).iter().map(|c| c[0]).collect::<Vec<_>>(),
        vec![
            Opcode::SetU16Param.byte(),
            Opcode::DbInfo.byte(),
            Opcode::WriteHwReg32.byte(),
            Opcode::WriteHwReg32.byte(),
            Opcode::SendRecordHeader.byte(),
            Opcode::DbInfo.byte(),
        ],
    );
    assert_eq!(sent(&s)[4][1], 0, "disarm 0x76 record tag must be 0");
}

#[test]
fn wof_sequence_timeout_still_disarms() {
    let mut s = session_with((0..11).map(|_| reply(0, &[])).collect());
    s.fw_upload_context = true;
    let detected = run_wof(&mut s, 0x01, || true).unwrap();
    assert!(!detected, "no IRQ → timeout without finger detection");
    assert_eq!(sent(&s).len(), 11, "arm(5) + disarm(6) only");
    let ops: Vec<u8> = sent(&s).iter().map(|c| c[0]).collect();
    assert_eq!(&ops[5..], &[0x57, 0x45, 0x08, 0x08, 0x76, 0x45]);
}

#[test]
fn capture_context_over_session_dearms_on_drop() {
    // A polled capture opened as a CaptureContext tears down (STOP 0x04 + FINALIZE 0x52) on drop.
    let mut s = session_with(vec![reply(0, &[]), reply(0, &[])]);
    {
        let _ctx = s.context(ReadMode::Polled, 6, 0x14, false);
    } // drop → teardown tunnels 0x04, 0x52
    assert_eq!(sent(&s), &[vec![stop_cmd::STOP], vec![stop_cmd::FINALIZE]]);
}

#[test]
fn map_subtype_classify_prod23_2449_paths() {
    use super::map_subtype_classify_prod23;
    assert_eq!(map_subtype_classify_prod23(0, STATUS_BYTE8_PROD3, 0x14), 10);
    assert_eq!(map_subtype_classify_prod23(0, STATUS_BYTE8_PROD3, 0x12), 2);
    assert_eq!(map_subtype_classify_prod23(0, STATUS_BYTE8_PROD3, 0x08), 0);
    assert_eq!(map_subtype_classify_prod23(1, STATUS_BYTE8_PROD3, 0x14), 1);
    assert_eq!(map_subtype_classify_prod23(2, STATUS_BYTE8_PROD3, 0x14), SUBTYPE_CLASSIFY_UNSET);
}
