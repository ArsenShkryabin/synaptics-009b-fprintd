//! Capture-time finger-presence detection (WOF vs capture finger-detect,
//! `syna_wbdi_wait_for_finger@0x18001c0a8`): the `CaptureFingerDetectIo` trait, plugin touch-status
//! cache (`syna_vfm_query_capture_touch_status@0x18004e9b0`), and wait helpers. Extracted from the
//! capture module; re-exported by `mod.rs`.

use super::*;
use crate::capture_prog::CaptureEvent;
use crate::presence_caps::SensorPresenceCaps;

/// Mask passed to `syna_wbdi_wait_for_finger` for Hello identify/enroll (`param_2 == 6`).
pub const WAIT_FINGER_MASK_HELLO: u8 = 0x06;

/// Busy bit in query_type==1 status (`touch class == 2`).
pub const CAPTURE_TOUCH_BUSY_BIT: u8 = 0x02;

/// Finger-latched bit — outer mask bit and inner `read_fp_data` gate (`syna_wbdi_read_fp_data@0x18001a818`).
pub const CAPTURE_TOUCH_LATCH_BIT: u8 = 0x04;

/// `capture_start` session-blob flag when WOF hint + finger-detect armed + `CCaptureImage+0xa0==0`.
pub const CAPTURE_START_WOF_HINT: u32 = 0x4;

/// Firmware-plugin selector for capture touch status (`palUsbProtocol` case `0x38` =
/// `0x938ae038 + 0x6c752000`).
pub const SYNA_PLUGIN_TOUCH_STATUS: u32 = 0x938a_e038;

/// How to turn cached EP-0x83 / plugin bytes into a touch-status mask byte.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TouchStatusPolicy {
    /// Map plugin touch class from cache byte 0 (`syna_vfm_query_capture_touch_status` mode 2).
    #[default]
    PluginClassByte0,
    /// Host-clocked Prometheus (`0x2449`): byte 0 is the **capture IRQ type** (0/2/3), not plugin
    /// class. Type-2 `FingerDown` fires spuriously ~100 ms after arm with or without a finger;
    /// latch only on type-3 `byte[2] & 4`, baseline delta, or trailing-byte change.
    CaptureIrqIgnoreType2,
}

/// Cached EP-0x83 bytes mirrored at `palUsbProtocol+0x20` (`syna_usb_extract_fields@0x1800f9ca0`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TouchPluginCache {
    /// Seven-byte plugin reply (5 from interrupt + bytes at transport `+0x25` / `+0x26`).
    pub fields: [u8; 7],
    /// Baseline for `fields[5]` (`SynaVfmCaptureSession+0x4c` in the DLL).
    pub baseline_b: u8,
    /// Baseline for `fields[6]` (`SynaVfmCaptureSession+0x4d`).
    pub baseline_c: u8,
    pub policy: TouchStatusPolicy,
}

impl Default for TouchPluginCache {
    fn default() -> Self {
        Self {
            fields: [0; 7],
            baseline_b: 0,
            baseline_c: 0,
            policy: TouchStatusPolicy::PluginClassByte0,
        }
    }
}

impl TouchPluginCache {
    /// Build a cache using per-SKU presence data ([`SensorPresenceCaps::spurious_type2_irq`]).
    pub fn for_presence_caps(caps: &SensorPresenceCaps) -> Self {
        Self {
            policy: if caps.spurious_type2_irq {
                TouchStatusPolicy::CaptureIrqIgnoreType2
            } else {
                TouchStatusPolicy::PluginClassByte0
            },
            ..Self::default()
        }
    }

    /// Snapshot current trailing bytes as baselines (call once after arm, before finger wait).
    pub fn snapshot_baselines(&mut self) {
        self.baseline_b = self.fields[5];
        self.baseline_c = self.fields[6];
    }

    /// Copy a completed EP-0x83 packet into the plugin field block (`palUsbProtocol_1800f9d40`).
    pub fn feed_interrupt(&mut self, packet: &[u8]) {
        let n = packet.len().min(5);
        self.fields[..n].copy_from_slice(&packet[..n]);
        if packet.len() > 5 {
            self.fields[5] = packet[5];
        }
        if packet.len() > 6 {
            self.fields[6] = packet[6];
        }
    }

    /// `syna_vfm_query_capture_touch_status@0x18004e9b0` with `query_type == 1`.
    pub fn query_capture_touch_status_query1(&self) -> u8 {
        query_capture_touch_status_query1(
            &self.fields,
            self.baseline_b,
            self.baseline_c,
            self.policy,
        )
    }

    /// Finger latched and ready for frame read on this policy.
    pub fn is_finger_latched(&self) -> bool {
        (self.query_capture_touch_status_query1() & CAPTURE_TOUCH_LATCH_BIT) != 0
    }
}

/// Map plugin / IRQ bytes to the status byte for Hello finger wait (`query_type == 1`).
///
/// Ground truth: `syna_vfm_query_capture_touch_status@0x18004e9b0`. On `0x2449` the first byte of
/// the EP-0x83 payload is the **capture event type**, which must not be confused with plugin touch
/// class 2 (busy).
pub fn query_capture_touch_status_query1(
    fields: &[u8; 7],
    baseline_b: u8,
    baseline_c: u8,
    policy: TouchStatusPolicy,
) -> u8 {
    let mut status = 0u8;
    if fields[5] != baseline_b {
        status |= CAPTURE_TOUCH_LATCH_BIT;
    }
    if fields[6] != baseline_c {
        status |= 0x08;
    }

    match policy {
        TouchStatusPolicy::PluginClassByte0 => match fields[0] {
            1 => status |= 0x01,
            2 => status |= CAPTURE_TOUCH_BUSY_BIT,
            3 => status |= CAPTURE_TOUCH_LATCH_BIT,
            _ => {}
        },
        // NOTE (2026-07-23, Ghidra-corrected): this policy previously ignored the type-2 FingerDown
        // and required bit 0x4. That is NOT what the DLL does — `syna_wbdi_wait_for_finger` uses
        // mask 0x06, so `syna_vfm_query_capture_touch_status` class-2 → bit 0x2 IS a finger hit.
        // Kept only so the enum/callers still compile; behaves identically to the DLL mapping now.
        // TODO: drop TouchStatusPolicy + SensorPresenceCaps::spurious_type2_irq entirely.
        TouchStatusPolicy::CaptureIrqIgnoreType2 => match fields[0] {
            1 => status |= 0x01,
            2 => status |= CAPTURE_TOUCH_BUSY_BIT,
            3 => status |= CAPTURE_TOUCH_LATCH_BIT,
            _ => {}
        },
    }
    status
}

/// Apply the DLL early-WOF hint bit to identify/enroll capture flags.
pub fn apply_capture_start_wof_hint(
    capture_flags: u32,
    scs_sensor: bool,
    finger_detect_armed: bool,
    wof_enable: bool,
) -> u32 {
    if scs_sensor && finger_detect_armed && !wof_enable {
        capture_flags | CAPTURE_START_WOF_HINT
    } else {
        capture_flags
    }
}

/// EP-0x83 interrupt wait for an already-armed capture with `FingerDetect(0x26)`.
pub trait CaptureFingerDetectIo {
    /// Read one interrupt packet (may be empty on timeout).
    fn read_capture_interrupt(&mut self, timeout_ms: u64) -> Result<Vec<u8>>;
}

/// Decode whether an EP-0x83 packet is a type-2 capture event (informational only).
///
/// Do **not** treat this as finger-present — on `0x2449` the type-2 IRQ is spurious; use
/// [`wait_capture_finger_detect`] + [`TouchPluginCache`] instead.
pub fn interrupt_matches_finger_detect(packet: &[u8], _mask: u8) -> bool {
    matches!(CaptureEvent::parse(packet), Some(CaptureEvent::FingerDown))
}

/// Inner `read_fp_data` touch latch — poll until latch bit `0x4` (and plugin busy clear when applicable).
pub fn wait_capture_touch_latched<IO: CaptureFingerDetectIo>(
    io: &mut IO,
    cache: &mut TouchPluginCache,
    poll_ms: u64,
    mut keep_going: impl FnMut() -> bool,
) -> Result<bool> {
    while keep_going() {
        let pkt = io.read_capture_interrupt(poll_ms)?;
        if !pkt.is_empty() {
            cache.feed_interrupt(&pkt);
        }
        let status = cache.query_capture_touch_status_query1();
        // Inner `read_fp_data` gate (`syna_wbdi_read_fp_data@0x18001a818`): latch bit 0x4 only —
        // class-3 `Complete` or a baseline delta. (Distinct from the outer wait, which uses the
        // 0x06 mask; this is the "frame is ready to read" gate.)
        if (status & CAPTURE_TOUCH_LATCH_BIT) != 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Wait for finger on the **capture finger-detect** path (`CCaptureImage+0xa0 == 0`).
pub fn wait_capture_finger_detect<IO: CaptureFingerDetectIo>(
    io: &mut IO,
    cache: &mut TouchPluginCache,
    mask: u8,
    poll_ms: u64,
    mut keep_going: impl FnMut() -> bool,
) -> Result<bool> {
    while keep_going() {
        let pkt = io.read_capture_interrupt(poll_ms)?;
        if !pkt.is_empty() {
            cache.feed_interrupt(&pkt);
        }
        let status = cache.query_capture_touch_status_query1();
        // GROUNDED (Ghidra + Frida, 2026-07-23): the DLL wake loop is `status & mask` (mask 0x06),
        // BUT its `status` comes from the plugin's *computed* touch class, NOT the EP-0x83 event
        // byte0. Byte0 (0/2/3 = Started/FingerDown/Complete) is only an IRQ *notification*; a
        // spurious FingerDown(2) fires ~immediately post-arm with no finger (confirmed at the
        // device), and the DLL's `wait_for_finger` still blocked ~2.7 s for a real touch (Frida).
        // So we must NOT map event byte0 -> class. The real finger signal here is the AFE
        // baseline-delta = bit 0x4 (query_type-1 `local_24/local_23 != [+0x4c/+0x4d]`), which needs
        // the plugin AFE bytes (+0x25/+0x26) — see the TODO on TouchPluginCache::feed_interrupt.
        // Gate on 0x4 only (safe: never false-positives on the spurious type-2). `mask` unused for
        // now; kept in the signature for when the plugin touch-status query is wired in.
        let _ = mask;
        if (status & CAPTURE_TOUCH_LATCH_BIT) != 0 {
            return Ok(true);
        }
    }
    Ok(false)
}
