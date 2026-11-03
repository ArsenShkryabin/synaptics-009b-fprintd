//! Capture-spec abstraction (Stage 2 — the spec is now the single arm backend).
//!
//! One source of truth for the *canonical* arm of each capture mode, plus a typed `0x02`-program
//! representation (`ArmProgram`) that is the substrate for the viewer's per-chunk arm-lab.
//! `CaptureConfig::resolve_arm` calls [`prod33_body`](super::CaptureConfig) **directly** (one call,
//! stride derived) — it no longer routes through the ~17 `upload_cmd_*` wrappers. Byte-parity with
//! the legacy [`build_upload_cmd_detailed`] router is KAT-guarded for Identify/Image/Stream/Calibrate;
//! Enroll intentionally diverges (its recon `0x23` is folded verbatim instead of being collapsed to
//! the identify recon=2 — the old `identify_with_cal` routing quirk).
//!
//! Layering: `CaptureMode -> canonical() -> ArmSpec (+ ArmOverrides) -> resolve_arm -> ArmProgram`.

use crate::calibration::CalResults;
use crate::capture::ReadMode;
use crate::capture_pipeline::UploadCmdBuildPath;
use crate::line_update::{RECON_FLAGS_DEFAULT, RECON_FLAGS_ENROLL, RECON_FLAGS_IMAGE};

use super::MeasuredCal;

/// Which measured-calibration deltas `resolve_arm` folds into the line-update — the typed successor
/// to Stage 1's `fold_calib: bool`. Equality is part of the re-arm predicate ([`ArmSpec`]).
///
/// The variants map one-to-one onto the legacy `upload_cmd_*` fold builders. Each *degrades to
/// [`Static`](FoldSource::Static)* when the data it needs is absent (`VendorCal*` with no
/// `vendor_cal`) — reproducing the old router, which armed the static line-update whenever there was
/// nothing measured to fold. The polled wire stride follows the fold: static ⇒ flex `bytes_per_line`
/// (160 on 0x2449), any measured fold ⇒ `line_width + 8` (152), exactly as the wrappers chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoldSource {
    /// No measured fold — the static `DAT_CAL_2449`/`DAT_FLAT40` fallback line-update
    /// (`upload_cmd_prod33_calibrated_recon` polled / `upload_cmd_prod33_sync` stream). Stride 160.
    Static,
    /// Factory `0x80000003` step-3 per-line diff only, no live calibration
    /// (`upload_cmd_image_calibrated`). DAT lines A/B measured, DAT line C static. Stride 152.
    FactoryDiff,
    /// Live vendor-cal step-3 diff + step-6 dark clean-slate, no `0x48` baseline
    /// (`upload_cmd_image_with_cal` polled / `upload_cmd_prod33_sync_with_cal` stream). Stride 152.
    VendorCal,
    /// Live vendor cal + the `0x48` last-frame baseline chunk (`upload_cmd_identify_with_cal`),
    /// emitted by default as the DLL does — the identify arm WITH `0x48` arms `status=0x0000` once the
    /// pre-arm sends (device 2026-08-07; the old reset was the deduped pre-arm, not `0x48`). Only when
    /// the supplied cal actually has a `baseline_frame`. Stride 152.
    VendorCalWithBaseline,
}

/// The five canonical capture modes. Each maps to exactly one canonical [`ArmSpec`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    /// Polled `0x51` identify (vfmCapture read_mode 2), recon=2, finger-detect, `0x48` baseline.
    Identify,
    /// Polled `0x51` enroll, recon `0x23` (host-match `MODE_DEFAULT|TRANSFORM2D|PERIPH_ENROLL`; the old
    /// router collapsed it to the identify recon=2 — see Stage 2 / [`RECON_FLAGS_ENROLL`]).
    Enroll,
    /// Polled recon=8 still image (`syna_capture_image`), no finger-detect.
    Image,
    /// EP-0x82 frames-sync stream (CALIBRATE-class, no `0x2e`/finger-detect).
    Stream,
    /// Frames-sync calibrate arm (`upload_cmd_calibrate`).
    Calibrate,
}

/// The arm knob surface — the union of what `prod33_body` actually gates on, plus read mode and sync
/// frame count. `PartialEq`/`Eq`: equality **is** the re-arm predicate (a changed spec needs a
/// teardown + re-arm; see the future `CaptureSession`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArmSpec {
    /// Read contract — selects the `0x51` poll vs EP-0x82 bulk read (and the calibrate arm).
    pub read: ReadMode,
    /// `prod33_body` `calibrate`: drops the `0x2e` recon + finger-detect chunks and the fingerdet reg patch.
    pub calibrate: bool,
    /// Written verbatim into the `0x2e` chunk (recon field-0 swaps on bit 8). Moot when `calibrate`.
    pub recon_flags: u32,
    /// Emit the `0x26` finger-detect chunk (`!calibrate && finger_detect`).
    pub finger_detect: bool,
    /// Emit the `0x2e` ImageReconstruction chunk (`!calibrate && include_chunk_2e`).
    pub include_chunk_2e: bool,
    /// Which measured-cal deltas to fold into the line-update (also picks the polled wire stride).
    pub fold: FoldSource,
    /// `req_lines` source for Stream/Calibrate arms.
    pub sync_frames: u32,
}

impl CaptureMode {
    /// The canonical arm for this mode — the single source of truth. Matches today's
    /// `FaithfulPreset` recipes byte-for-byte (KAT-guarded); Enroll's recon `0x23` is canonical here
    /// even though the old router collapsed it to identify recon=2 (fixed in Stage 2).
    pub const fn canonical(self) -> ArmSpec {
        match self {
            CaptureMode::Identify => ArmSpec {
                read: ReadMode::Polled,
                calibrate: false,
                recon_flags: RECON_FLAGS_DEFAULT,
                finger_detect: true,
                include_chunk_2e: true,
                // capture_type==4 identify folds vendor cal + the 0x48 baseline when a cal is present
                // (`upload_cmd_identify_with_cal`); degrades to the static arm with no cal.
                fold: FoldSource::VendorCalWithBaseline,
                sync_frames: 0,
            },
            CaptureMode::Enroll => ArmSpec {
                read: ReadMode::Polled,
                calibrate: false,
                recon_flags: RECON_FLAGS_ENROLL,
                finger_detect: true,
                include_chunk_2e: true,
                fold: FoldSource::VendorCalWithBaseline,
                sync_frames: 0,
            },
            CaptureMode::Image => ArmSpec {
                read: ReadMode::Polled,
                calibrate: false,
                recon_flags: RECON_FLAGS_IMAGE,
                finger_detect: false,
                include_chunk_2e: true,
                // recon=8 imaging folds step-3+step-6 with NO baseline (`upload_cmd_image_with_cal`).
                fold: FoldSource::VendorCal,
                sync_frames: 0,
            },
            CaptureMode::Stream => ArmSpec {
                read: ReadMode::Stream,
                calibrate: true,
                recon_flags: RECON_FLAGS_DEFAULT,
                finger_detect: false,
                include_chunk_2e: false,
                fold: FoldSource::VendorCal,
                sync_frames: 3,
            },
            CaptureMode::Calibrate => ArmSpec {
                read: ReadMode::Calibrate,
                calibrate: true,
                recon_flags: RECON_FLAGS_DEFAULT,
                finger_detect: false,
                include_chunk_2e: true,
                // The calibrate loop drives step-3 separately; the canonical arm folds nothing
                // (`upload_cmd_calibrate` passes `step3=None`).
                fold: FoldSource::Static,
                sync_frames: 4,
            },
        }
    }

    /// Canonical spec with per-field playground overrides applied (`None` = keep canonical). `read`
    /// and `calibrate` are intentionally not overridable — changing them is "a different mode".
    pub fn spec_with(self, ov: &ArmOverrides) -> ArmSpec {
        let mut s = self.canonical();
        if let Some(v) = ov.recon_flags {
            s.recon_flags = v;
        }
        if let Some(v) = ov.finger_detect {
            s.finger_detect = v;
        }
        if let Some(v) = ov.include_chunk_2e {
            s.include_chunk_2e = v;
        }
        if let Some(v) = ov.fold {
            s.fold = v;
        }
        if let Some(v) = ov.sync_frames {
            s.sync_frames = v;
        }
        s
    }
}

/// Playground overrides on a canonical [`ArmSpec`] — every `None` keeps the canonical value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArmOverrides {
    pub recon_flags: Option<u32>,
    pub finger_detect: Option<bool>,
    pub include_chunk_2e: Option<bool>,
    pub fold: Option<FoldSource>,
    pub sync_frames: Option<u32>,
}

/// One chunk of a decoded `0x02` capture program: raw type id, an enable flag (the arm-lab toggle),
/// and the verbatim payload. Kept as a raw `u16` (not [`crate::line_update::ChunkType`]) so it covers
/// every chunk — structural ones (`0x23/0x20/0x32/0x33/0x2f/0x29/0x35`) included — and round-trips.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmChunk {
    pub kind: u16,
    pub enabled: bool,
    pub payload: Vec<u8>,
}

/// A typed, editable `0x02` capture-program: `[0x02][bpl:u16][req_lines:u16]` header then the chunk
/// list. `parse`/`serialize` are inverses for all-enabled programs, so the arm the viewer *shows* is
/// exactly the arm it *sends*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmProgram {
    pub bpl: u16,
    pub req_lines: u16,
    pub chunks: Vec<ArmChunk>,
}

impl ArmProgram {
    /// `0x02` opcode byte.
    const OP: u8 = 0x02;

    /// Decode a framed `0x02` arm into its header + chunk list (all chunks marked enabled). Returns
    /// `None` if the byte stream isn't a `0x02` program or a chunk length overruns the buffer.
    pub fn parse(arm: &[u8]) -> Option<Self> {
        if arm.first() != Some(&Self::OP) || arm.len() < 5 {
            return None;
        }
        let bpl = u16::from_le_bytes([arm[1], arm[2]]);
        let req_lines = u16::from_le_bytes([arm[3], arm[4]]);
        let mut chunks = Vec::new();
        let mut i = 5usize;
        while i + 4 <= arm.len() {
            let kind = u16::from_le_bytes([arm[i], arm[i + 1]]);
            let len = u16::from_le_bytes([arm[i + 2], arm[i + 3]]) as usize;
            let start = i + 4;
            let end = start.checked_add(len)?;
            if end > arm.len() {
                return None; // truncated chunk
            }
            chunks.push(ArmChunk { kind, enabled: true, payload: arm[start..end].to_vec() });
            i = end;
        }
        Some(ArmProgram { bpl, req_lines, chunks })
    }

    /// Re-frame to wire bytes, emitting only enabled chunks. `serialize(parse(arm)) == arm` when every
    /// chunk is enabled.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + self.chunks.iter().map(|c| 4 + c.payload.len()).sum::<usize>());
        out.push(Self::OP);
        out.extend_from_slice(&self.bpl.to_le_bytes());
        out.extend_from_slice(&self.req_lines.to_le_bytes());
        for c in self.chunks.iter().filter(|c| c.enabled) {
            out.extend_from_slice(&c.kind.to_le_bytes());
            out.extend_from_slice(&(c.payload.len() as u16).to_le_bytes());
            out.extend_from_slice(&c.payload);
        }
        out
    }

    /// One-line status readout (`bpl=… req=… · 0x26·fdet(…) …`) — enabled chunks only.
    /// Shared by the capture-thread overlay and the arm-lab header.
    pub fn format_chunks(&self) -> String {
        use crate::line_update::arm_chunk_label;
        let list: Vec<String> = self
            .chunks
            .iter()
            .filter(|c| c.enabled)
            .map(|c| {
                let label = arm_chunk_label(c.kind);
                if label.is_empty() {
                    format!("{:#04x}({})", c.kind, c.payload.len())
                } else {
                    format!("{:#04x}·{label}({})", c.kind, c.payload.len())
                }
            })
            .collect();
        format!("bpl={} req={} · {}", self.bpl, self.req_lines, list.join(" "))
    }
}

impl super::CaptureConfig {
    /// Resolve a spec into the concrete arm program to send. **Stage 2**: builds the `0x02` body with
    /// a single [`prod33_body`](super::CaptureConfig) call — the spec's knobs flow straight in — then
    /// derives the wire stride/`req_lines` from `(read, fold)` and frames it. No longer routes through
    /// the ~17 `upload_cmd_*` wrappers.
    ///
    /// Byte-identical to the legacy [`build_upload_cmd_detailed`](crate::capture_pipeline) router for
    /// Identify/Image/Stream/Calibrate (KAT-guarded, `vendor_cal` present *and* absent). **Enroll
    /// diverges on purpose:** the old router folded an enroll-with-cal arm through
    /// `upload_cmd_identify_with_cal`, which hard-codes recon=2 — silently dropping enroll's recon `0x23`.
    /// Here `spec.recon_flags` is folded verbatim, so enroll keeps its `0x23`.
    ///
    /// Returns the typed [`ArmProgram`] (for the viewer's arm-lab). Callers that only need the wire
    /// bytes should use [`Self::resolve_arm_cmd`] — this wrapper parses the bytes back into chunks,
    /// which the byte-only path would immediately re-serialize.
    pub fn resolve_arm(
        &self,
        spec: &ArmSpec,
        factory_calibration_values: &[u8],
        vendor_cal: Option<&CalResults>,
    ) -> Option<(ArmProgram, UploadCmdBuildPath)> {
        let (bytes, path) = self.resolve_arm_cmd(spec, factory_calibration_values, vendor_cal)?;
        Some((ArmProgram::parse(&bytes)?, path))
    }

    /// Byte-returning core of [`Self::resolve_arm`]: builds the `0x02` wire command and its
    /// [`UploadCmdBuildPath`] without the parse-into-`ArmProgram` round-trip. Used by the
    /// `build_upload_cmd_detailed` router and the `dump_arm_bytes` tool, which want the `Vec<u8>`.
    pub fn resolve_arm_cmd(
        &self,
        spec: &ArmSpec,
        factory_calibration_values: &[u8],
        vendor_cal: Option<&CalResults>,
    ) -> Option<(Vec<u8>, UploadCmdBuildPath)> {
        // Bind the fold intent to the measured slices. `FactoryDiff`'s step-3 is computed here (owned)
        // so the borrow in `MeasuredCal` lives long enough for the `prod33_body` call below.
        let factory_step3: Option<Vec<u8>> = matches!(spec.fold, FoldSource::FactoryDiff)
            .then(|| {
                crate::factory_cal::cal_diff_from_line_array(
                    factory_calibration_values,
                    self.type_info.lines_per_calibration_data as usize,
                )
            })
            .flatten();
        let measured = match spec.fold {
            FoldSource::Static => MeasuredCal::default(),
            FoldSource::FactoryDiff => {
                MeasuredCal { step3_diff: factory_step3.as_deref(), ..MeasuredCal::default() }
            }
            FoldSource::VendorCal => vendor_cal
                .map(|c| MeasuredCal {
                    step3_diff: c.step3_diff.as_deref(),
                    step6_dark: c.line_c_source(),
                    baseline_frame: None,
                })
                .unwrap_or_default(),
            FoldSource::VendorCalWithBaseline => vendor_cal
                .map(|c| MeasuredCal {
                    step3_diff: c.step3_diff.as_deref(),
                    step6_dark: c.line_c_source(),
                    // The `0x48` last-frame baseline is emitted by default on identify/enroll arms —
                    // as the DLL does (`syna_capture_identify_enroll` folds it). The old "sending it
                    // resets the sensor" gate was disproven on device (2026-08-07): the reset was the
                    // *deduped pre-arm*, not the `0x48` content; with the pre-arm fix the `0x48` arm
                    // arms `status=0x0000`. Only `VendorCalWithBaseline` (Identify/Enroll) carries it —
                    // Image/Stream/Calibrate use `VendorCal`/`Static` (no baseline).
                    baseline_frame: c.baseline_frame.as_deref(),
                })
                .unwrap_or_default(),
        };

        let body = self.prod33_body(
            factory_calibration_values,
            &[],
            spec.calibrate,
            spec.recon_flags,
            spec.finger_detect,
            measured,
            spec.include_chunk_2e,
        )?;

        // Stride follows the fold, matching the legacy wrappers: a polled arm with nothing measured
        // uses the flex `bytes_per_line` (160); any measured fold — and every stream/calibrate arm —
        // uses `line_width + 8` (152, `sync_line_stride`). `req_lines` is 0 for polled, the sync
        // count for stream/calibrate.
        let measured_folds = measured.step3_diff.is_some()
            || measured.step6_dark.is_some()
            || measured.baseline_frame.is_some();
        let (bytes_per_line, req_lines) = match spec.read {
            ReadMode::Polled => {
                let stride = if measured_folds {
                    self.sync_line_stride() as u16
                } else {
                    self.bytes_per_line
                };
                (stride, 0)
            }
            // WakeOnFinger produces no capture arm of its own; framed as the stream mechanism the old
            // router mapped it to (`_ => Stream`). No canonical mode reaches it.
            ReadMode::Stream | ReadMode::Calibrate | ReadMode::WakeOnFinger => {
                (self.sync_line_stride() as u16, self.stream_req_lines(spec.sync_frames))
            }
        };
        let bytes = super::frame_cmd_02(&body, bytes_per_line, req_lines);

        let path = build_path(spec.read, spec.recon_flags, &measured);
        Some((bytes, path))
    }
}

/// Tag which legacy builder branch an arm corresponds to — purely for logging/parity (the byte
/// content is produced by `prod33_body`, not by dispatching on this).
fn build_path(read: ReadMode, recon_flags: u32, measured: &MeasuredCal<'_>) -> UploadCmdBuildPath {
    let has_step6 = measured.step6_dark.is_some();
    let has_step3 = measured.step3_diff.is_some();
    match read {
        ReadMode::Polled if !has_step3 && !has_step6 => UploadCmdBuildPath::PolledStaticRecon,
        ReadMode::Polled if has_step6 && recon_flags == RECON_FLAGS_IMAGE => {
            UploadCmdBuildPath::PolledImageWithCal
        }
        ReadMode::Polled if has_step6 => UploadCmdBuildPath::PolledIdentifyWithCal,
        // step-3 only, no step-6 — the factory-diff-only fold.
        ReadMode::Polled => UploadCmdBuildPath::PolledImageCalibratedOnly,
        _ if has_step3 || has_step6 => UploadCmdBuildPath::StreamSyncWithCal,
        _ => UploadCmdBuildPath::StreamSync,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture_pipeline::FaithfulPreset;
    use crate::capture_prog::CaptureConfig;

    fn cfg() -> CaptureConfig {
        // 0x190/0x4b → subtype 0x2449, st8=6 st9=0x14 (the laptop unit).
        CaptureConfig::for_silicon(0x190, 0x4b, 6, 0x14).expect("0x2449 cfg")
    }

    /// Synthetic calibration output — step-3 diff (56 = `lines_per_calibration_data`) + a step-6 dark
    /// clean-slate (`line_c_source`) + a settle frame. Content is arbitrary; the KATs only require that
    /// `resolve_arm` and the legacy builder fold *the same* slices, so the bytes match.
    fn synthetic_cal() -> CalResults {
        CalResults {
            step3_diff: Some((0..56).map(|i| (i * 5) as u8).collect()),
            step56_buf: Some(vec![0x80; 144 * 56]),
            baseline_frame: Some(vec![0x33; 152 * 56]),
            ..Default::default()
        }
    }

    /// Stage-1 KAT (still holds): with `vendor_cal = None` every `VendorCal*` fold degrades to static,
    /// so each canonical mode resolves byte-for-byte to today's `FaithfulPreset` arm.
    #[test]
    fn resolve_canonical_matches_faithful_preset_byte_for_byte() {
        let cfg = cfg();
        let fcv = vec![0u8; 64];
        for (mode, preset) in [
            (CaptureMode::Identify, FaithfulPreset::IdentifyVerify),
            (CaptureMode::Enroll, FaithfulPreset::EnrollTouch),
            (CaptureMode::Image, FaithfulPreset::PrintImage),
            (CaptureMode::Stream, FaithfulPreset::StreamSync),
        ] {
            let spec = mode.canonical();
            let (prog, _) = cfg.resolve_arm(&spec, &fcv, None).expect("resolve");
            let (want, _) =
                preset.default_arm(&cfg, &fcv, spec.sync_frames, None).expect("preset arm");
            assert_eq!(prog.serialize(), want, "canonical {mode:?} != preset {preset:?}");
        }
    }

    /// Stage-2 byte-parity: with a `vendor_cal` present, `resolve_arm` reproduces the legacy fold
    /// builders exactly for Identify/Image/Stream. (Enroll is intentionally excluded — see
    /// [`enroll_with_cal_keeps_enroll_recon`].)
    #[test]
    fn resolve_with_vendor_cal_matches_legacy_builders() {
        let cfg = cfg();
        let fcv = vec![0u8; 64];
        let cal = synthetic_cal();

        let (identify, path) =
            cfg.resolve_arm(&CaptureMode::Identify.canonical(), &fcv, Some(&cal)).unwrap();
        assert_eq!(
            identify.serialize(),
            cfg.upload_cmd_identify_with_cal(&fcv, &cal).unwrap(),
            "identify+cal != upload_cmd_identify_with_cal"
        );
        assert_eq!(path, UploadCmdBuildPath::PolledIdentifyWithCal);

        let (image, path) =
            cfg.resolve_arm(&CaptureMode::Image.canonical(), &fcv, Some(&cal)).unwrap();
        assert_eq!(
            image.serialize(),
            cfg.upload_cmd_image_with_cal(&fcv, &cal).unwrap(),
            "image+cal != upload_cmd_image_with_cal"
        );
        assert_eq!(path, UploadCmdBuildPath::PolledImageWithCal);

        let stream_spec = CaptureMode::Stream.canonical();
        let (stream, path) = cfg.resolve_arm(&stream_spec, &fcv, Some(&cal)).unwrap();
        assert_eq!(
            stream.serialize(),
            cfg.upload_cmd_prod33_sync_with_cal(&fcv, &cal, stream_spec.sync_frames).unwrap(),
            "stream+cal != upload_cmd_prod33_sync_with_cal"
        );
        assert_eq!(path, UploadCmdBuildPath::StreamSyncWithCal);
    }

    /// Intended Stage-2 diff #1: enroll-with-cal folds the enroll recon (`0x23` =
    /// `MODE_DEFAULT|TRANSFORM2D|PERIPH_ENROLL`, byte-exact vs the DLL), not the identify recon=2 the
    /// old router collapsed it to via `upload_cmd_identify_with_cal`.
    #[test]
    fn enroll_with_cal_keeps_enroll_recon() {
        let cfg = cfg();
        let fcv = vec![0u8; 64];
        let cal = synthetic_cal();
        let (enroll, _) =
            cfg.resolve_arm(&CaptureMode::Enroll.canonical(), &fcv, Some(&cal)).unwrap();
        let (identify, _) =
            cfg.resolve_arm(&CaptureMode::Identify.canonical(), &fcv, Some(&cal)).unwrap();
        // Only the recon differs (0x23 vs 2), so the arms differ...
        assert_ne!(enroll.serialize(), identify.serialize(), "enroll must not equal identify");
        // ...and the enroll arm is NOT the old recon-2 identify fold the router produced for it.
        assert_ne!(
            enroll.serialize(),
            cfg.upload_cmd_identify_with_cal(&fcv, &cal).unwrap(),
            "enroll+cal regressed to the recon-2 identify fold"
        );
    }

    /// Intended Stage-2 diff #2: the calibrated-image fold (factory step-3 only, no live cal) is a
    /// distinct arm — reachable via a `FactoryDiff` override — matching `upload_cmd_image_calibrated`
    /// and differing from the plain (static) Image arm.
    #[test]
    fn calibrated_image_via_factory_diff_override() {
        let cfg = cfg();
        let fcv = vec![0u8; 64];
        let spec = CaptureMode::Image
            .spec_with(&ArmOverrides { fold: Some(FoldSource::FactoryDiff), ..Default::default() });
        let (calibrated, path) = cfg.resolve_arm(&spec, &fcv, None).unwrap();
        assert_eq!(
            calibrated.serialize(),
            cfg.upload_cmd_image_calibrated(&fcv).unwrap(),
            "factory-diff image != upload_cmd_image_calibrated"
        );
        assert_eq!(path, UploadCmdBuildPath::PolledImageCalibratedOnly);

        let (plain, _) = cfg.resolve_arm(&CaptureMode::Image.canonical(), &fcv, None).unwrap();
        assert_ne!(
            calibrated.serialize(),
            plain.serialize(),
            "calibrated-image must differ from static Image"
        );
    }

    #[test]
    fn resolve_calibrate_matches_upload_cmd_calibrate() {
        let cfg = cfg();
        let fcv = vec![0u8; 64];
        let spec = CaptureMode::Calibrate.canonical();
        let (prog, _) = cfg.resolve_arm(&spec, &fcv, None).expect("resolve");
        let want = cfg
            .upload_cmd_calibrate(&fcv, &[], spec.sync_frames as usize, None)
            .expect("calibrate arm");
        assert_eq!(prog.serialize(), want);
    }

    /// `serialize ∘ parse == identity` when all chunks are enabled — the property that makes the
    /// viewer's decoded chunk list exactly the bytes sent.
    #[test]
    fn arm_program_round_trips() {
        let cfg = cfg();
        let fcv = vec![0u8; 64];
        for mode in [
            CaptureMode::Identify,
            CaptureMode::Enroll,
            CaptureMode::Image,
            CaptureMode::Stream,
            CaptureMode::Calibrate,
        ] {
            let (prog, _) = cfg.resolve_arm(&mode.canonical(), &fcv, None).expect("resolve");
            let bytes = prog.serialize();
            assert_eq!(ArmProgram::parse(&bytes).expect("reparse"), prog, "round-trip {mode:?}");
        }
    }

    /// A disabled chunk drops out of the serialized arm (the arm-lab toggle works).
    #[test]
    fn disabling_a_chunk_shortens_the_arm() {
        let cfg = cfg();
        let fcv = vec![0u8; 64];
        let (mut prog, _) = cfg.resolve_arm(&CaptureMode::Stream.canonical(), &fcv, None).unwrap();
        let full = prog.serialize().len();
        let victim = prog.chunks.last_mut().expect("has chunks");
        let victim_len = 4 + victim.payload.len();
        victim.enabled = false;
        assert_eq!(prog.serialize().len(), full - victim_len);
    }

    #[test]
    fn override_changes_only_targeted_field() {
        let base = CaptureMode::Identify.canonical();
        let s = CaptureMode::Identify
            .spec_with(&ArmOverrides { finger_detect: Some(false), ..Default::default() });
        assert_eq!(s, ArmSpec { finger_detect: false, ..base });
    }
}
