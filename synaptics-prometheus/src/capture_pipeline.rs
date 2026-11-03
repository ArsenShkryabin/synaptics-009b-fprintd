//! DLL-faithful capture pipeline types — arm recipe × read mechanism × host post-process.
//!
//! Ground truth: [`docs/capture/capture-paths.md`](../docs/capture/capture-paths.md). Proven pairings are encoded
//! in the type system; unverified combinations use [`ExperimentalPipeline`] only.
//!
//! # Three axes (do not conflate)
//! - **Arm** — `syna_build_capture_cmd02@0x180086110` chunks (`0x2e`, `0x26`, line-update)
//! - **Read** — polled `0x51` (`syna_capture_image@0x180099540`) vs EP-0x82
//!   (`syna_capture_frames_sync@0x18006ae20`) vs identify runtime (`vfmCapture@0x180053bb0`)
//! - **Host** — flat reassembly only on polled; cf640 only on stream
//!   (`syna_capture_and_reconstruct@0x1800984f0`)

use crate::calibration::CalResults;
use crate::capture_prog::capture_spec::CaptureMode;
use crate::capture_prog::{ArmOverrides, ArmSpec, CaptureConfig, FoldSource};
use crate::line_update::{
    CAPTURE_FLAGS_ENROLL, CAPTURE_FLAGS_IDENTIFY, CAPTURE_FLAGS_IMAGE, RECON_FLAGS_DEFAULT,
    RECON_FLAGS_ENROLL, RECON_FLAGS_IMAGE,
};

/// Ghidra entry for a faithful preset (for status bar / logging).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GhidraEntry {
    pub symbol: &'static str,
    pub address: &'static str,
}

impl GhidraEntry {
    pub const CAPTURE_IMAGE: Self = Self {
        symbol: "syna_capture_image",
        address: "0x180099540",
    };
    pub const IDENTIFY_ENROLL: Self = Self {
        symbol: "syna_capture_identify_enroll",
        address: "0x180053400",
    };
    pub const FRAMES_SYNC: Self = Self {
        symbol: "syna_capture_frames_sync",
        address: "0x18006ae20",
    };
    pub const VFM_CAPTURE: Self = Self {
        symbol: "vfmCapture",
        address: "0x180053bb0",
    };
    pub const CAPTURE_AND_RECONSTRUCT: Self = Self {
        symbol: "syna_capture_and_reconstruct",
        address: "0x1800984f0",
    };

    pub fn label(self) -> String {
        format!("{}@{}", self.symbol, self.address)
    }
}

// ---------------------------------------------------------------------------
// Layer 1 — arm recipes
// ---------------------------------------------------------------------------

/// Full arm recipe (experimental only — faithful roles use typed arms).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArmRecipe {
    /// `syna_build_capture_cmd02@0x180086110` capture_flags word.
    pub capture_flags: u32,
    /// Written verbatim into the `0x2e` chunk by `syna_append_chunk_2e_image_recon@0x180094990`.
    pub recon_flags: u32,
    /// When false, `0x26` finger-detect chunk is omitted (`capture_flag::SKIP_FINGER_DETECT`).
    pub finger_detect: bool,
    /// Fold measured vendor cal into line-update (`upload_cmd_image_with_cal`).
    pub fold_calib: bool,
    /// Omit the `0x2e` chunk entirely (EXPT — no DLL entry for polled print without 0x2e).
    pub omit_chunk_2e: bool,
}

impl ArmRecipe {
    /// `syna_capture_image@0x180099540` — capture_flags hardcoded `0xa0030`.
    pub const PRINT_IMAGE: Self = Self {
        capture_flags: CAPTURE_FLAGS_IMAGE,
        recon_flags: RECON_FLAGS_IMAGE,
        finger_detect: false,
        fold_calib: false,
        omit_chunk_2e: false,
    };

    /// `syna_capture_identify_enroll@0x180053400` verify mode — never sets `0x80000`.
    pub const IDENTIFY_VERIFY: Self = Self {
        capture_flags: CAPTURE_FLAGS_IDENTIFY,
        recon_flags: RECON_FLAGS_DEFAULT,
        finger_detect: true,
        fold_calib: false,
        omit_chunk_2e: false,
    };

    /// Identify enroll mode 3 — recon flags 4.
    pub const IDENTIFY_ENROLL: Self = Self {
        capture_flags: CAPTURE_FLAGS_ENROLL,
        recon_flags: RECON_FLAGS_ENROLL,
        finger_detect: true,
        fold_calib: false,
        omit_chunk_2e: false,
    };

    /// Print image + vendor cal fold (task #27 path).
    pub const PRINT_IMAGE_CALIBRATED: Self = Self {
        capture_flags: CAPTURE_FLAGS_IMAGE,
        recon_flags: RECON_FLAGS_IMAGE,
        finger_detect: false,
        fold_calib: true,
        omit_chunk_2e: false,
    };

    /// Metadata for [`crate::capture_prog::CaptureConfig::upload_cmd_prod33_sync_with_cal`] — the
    /// faithful frames-sync arm: **CALIBRATE-class, no `0x2e` recon and no finger-detect**
    /// (`recon_flags` is moot). Folds measured step-3/step-6 outputs from
    /// `syna_lib_run_calibration@0x1800731d0` into the line-update (see
    /// `docs/calibration/calibration-state-machine.md`). Host cf640 runs only on no-`0x2e` raw.
    pub const FRAMES_SYNC_IMAGING: Self = Self {
        capture_flags: CAPTURE_FLAGS_IDENTIFY,
        recon_flags: RECON_FLAGS_DEFAULT,
        finger_detect: false,
        fold_calib: true,
        omit_chunk_2e: true,
    };

    /// Imaging-class arm (recon=8 `PRINT_IMAGE` / `syna_capture_image@0x180099540`) vs
    /// identify/enroll-class. Keyed on `recon_flags == RECON_FLAGS_IMAGE` — NOT `!finger_detect`,
    /// which would also match the stream calibrate arm [`FRAMES_SYNC_IMAGING`]. Drives the polled
    /// cal-fold routing in [`build_polled_upload_cmd`]: imaging → `upload_cmd_image_with_cal`,
    /// identify → `upload_cmd_identify_with_cal`.
    #[must_use]
    pub const fn is_imaging(&self) -> bool {
        self.recon_flags == RECON_FLAGS_IMAGE
    }
}

/// Stream calibrate arm — no `0x2e` chunk (`upload_cmd_calibrate` / frames_sync path).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StreamArmRecipe {
    pub sync_frames: u32,
}

// ---------------------------------------------------------------------------
// Layer 2 — read mechanism
// ---------------------------------------------------------------------------

/// Wire read path.
///
/// **read_mode → capture_type mapping** (`syna_capture_identify_enroll@0x180053400`, decompiled
/// 2026-07): the 0x02 builder's capture type (`param_3` of `syna_build_capture_cmd02@0x180086110`) is
/// derived from `nRead_mode`, not the WBF purpose:
///
/// | nRead_mode | capture_type | meaning                              | 0x48 last-frame chunk? |
/// |-----------:|:------------:|--------------------------------------|:----------------------:|
/// | 1          | 3            | verify (1:1)                         | no                     |
/// | **2**      | **4**        | **Hello polled `0x51` identify (OURS)** | **yes (+ provisioned)** |
/// | 3          | 6            | enroll                               | (adds `0x2e` f=4)      |
///
/// So the [`ReadMechanism::Polled`] identify path we build is capture_type 4 → it carries the `0x48`
/// last-captured-frame baseline chunk (`syna_append_chunk_48_last_frame@0x180095ae0`; see
/// [`crate::line_update::ChunkType::Baseline`]). read_mode 2 also sets capture_flags `|= 0x840`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadMechanism {
    /// Chunked read over EP-0x81 (cmd/resp), one frame chunk per command:
    /// - `syna_capture_image@0x180099540` (`0x51`, reduced still body), and
    /// - `vfmCapture` `read_mode==2` (`syna_read_frame_chunk@0x18005cf00`, `0x51`) /
    ///   `read_mode==3` (`syna_scs_read_frame_chunk_alt@0x18005d090`, SCS `0x31`).
    ///
    /// NOTE: WH verify uses `read_mode==2` when `syna_eiv_config.nMatcher_submode` (`dev+0x1e0`)
    /// is 2 — set by `syna_eiv_set_matcher_submode` before each capture, default 2 at init.
    /// Purpose (`WINBIO_PURPOSE`) does not write `read_mode`. EP-0x82 is the `else` branch when
    /// `read_mode` ∉ {2,3}. See `docs/capture/capture-paths.md` Path 3.
    Polled,
    /// EP-0x82 bulk — `syna_capture_frames_sync@0x18006ae20` (Path 2 stream) and
    /// `vfmCapture` `read_mode` else (`syna_read_frame_blocking@0x1800682f0`).
    Stream,
}

/// Marker: polled print still path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PolledPrint;

/// Marker: identify runtime path (`vfmCapture`). Modeled as polled (`read_mode==2`, `0x51`) when
/// `nMatcher_submode==2` (Ghidra default on provisioned path). See `docs/capture/capture-paths.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PolledIdentify;

/// Marker: enroll runtime path (`vfmCapture`, `read_mode==3` → wire `0x78` on caps that select it).
/// On 0x2449 provisioned Hello, [`crate::capture::MatcherSubmode::for_subtype_2449_provisioned`]
/// still yields `read_mode==2` (`0x51`) — see Wine sandbox enroll trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PolledEnroll;

/// Marker: stream calibrate read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StreamCalibrate;

/// Role-specific polled pipeline (arm frozen per Ghidra entry).
pub trait PolledRole {
    type Arm: Copy;
}

impl PolledRole for PolledPrint {
    type Arm = ArmRecipe;
}

impl PolledRole for PolledIdentify {
    type Arm = ArmRecipe;
}

impl PolledRole for PolledEnroll {
    type Arm = ArmRecipe;
}

// ---------------------------------------------------------------------------
// Layer 3 — host post-process (capture thread)
// ---------------------------------------------------------------------------

/// Host stage on the polled *read* path. The stream `cf640` reconstruct
/// (`syna_capture_and_reconstruct`) is not here — but that does NOT mean the polled frame is never
/// de-scrambled: the DLL de-spreads it later, in the matcher IR-recon
/// (`syna_ir_recon_condition_frame`@0x1800b96f0 mode 2 → `transform16`), the same timeslot kernel
/// stream cf640 uses. See `docs/capture/0x51-conditioning.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolledHostStage {
    /// Flat body as read from wire.
    #[default]
    FlatBody,
    /// 8 zero bytes prepended per row — display helper matching `syna_capture_image` dest layout.
    DllReassembly,
}

/// Host stage on the stream path — cf640 legal here only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum StreamHostStage {
    /// EP-0x82 bytes only (viewer SYNC-RAW).
    RawBuffer,
    /// `syna_capture_and_reconstruct@0x1800984f0` equivalent (line-avg + ref-row + cf640@+8).
    #[default]
    StreamReconstruct,
}


/// Unrestricted host post-process for experimental pipelines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostPostProcess {
    #[default]
    None,
    /// Polled DLL dest layout helper.
    DllReassembly,
    /// Polled per-line `transform16` de-spread. NOT merely diagnostic: the DLL runs the equivalent
    /// in the matcher IR-recon (`syna_ir_recon_condition_frame` mode 2), just not on the capture
    /// thread — so this is DLL-faithful matcher-input conditioning. Required for enroll/identify.
    DiagnosticDescramble,
    /// Stream path cf640 — only valid with [`ReadMechanism::Stream`].
    StreamReconstruct,
}

/// UI-side diagnostics — always labeled "not in DLL".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DiagnosticOverlay {
    pub descramble: bool,
    pub conditioning: bool,
}

// ---------------------------------------------------------------------------
// Faithful pipelines (compile-time invariants)
// ---------------------------------------------------------------------------

/// EP-0x82 path; [`StreamHostStage::StreamReconstruct`] exists only here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamPipeline {
    pub arm: StreamArmRecipe,
    pub host: StreamHostStage,
    pub read: StreamCalibrate,
    pub ghidra: GhidraEntry,
}

impl StreamPipeline {
    /// Calibrate dark-frame — host reconstruct is DLL default on stream callback.
    pub fn calibrate_dark(sync_frames: u32) -> Self {
        Self {
            arm: StreamArmRecipe { sync_frames },
            host: StreamHostStage::StreamReconstruct,
            read: StreamCalibrate,
            ghidra: GhidraEntry::FRAMES_SYNC,
        }
    }

    /// Raw EP-0x82 buffer only (viewer SYNC-RAW).
    pub fn sync_raw(sync_frames: u32) -> Self {
        Self {
            arm: StreamArmRecipe { sync_frames },
            host: StreamHostStage::RawBuffer,
            read: StreamCalibrate,
            ghidra: GhidraEntry::FRAMES_SYNC,
        }
    }

    /// EP-0x82 identify-class imaging + host [`StreamHostStage::StreamReconstruct`]
    /// (`upload_cmd_prod33_sync` + `syna_capture_and_reconstruct@0x1800984f0`).
    pub fn frames_sync_reconstruct(sync_frames: u32) -> Self {
        Self {
            arm: StreamArmRecipe { sync_frames },
            host: StreamHostStage::StreamReconstruct,
            read: StreamCalibrate,
            ghidra: GhidraEntry::FRAMES_SYNC,
        }
    }
}

/// Polled `0x51` path — no `StreamReconstruct` host stage at type level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolledPipeline<R: PolledRole> {
    pub arm: R::Arm,
    pub host: PolledHostStage,
    pub read: R,
    pub ghidra: GhidraEntry,
}

impl PolledPipeline<PolledPrint> {
    /// `syna_capture_image@0x180099540` — arm frozen to [`ArmRecipe::PRINT_IMAGE`].
    pub fn capture_image() -> Self {
        Self {
            arm: ArmRecipe::PRINT_IMAGE,
            host: PolledHostStage::FlatBody,
            read: PolledPrint,
            ghidra: GhidraEntry::CAPTURE_IMAGE,
        }
    }

    /// Print image with vendor cal fold.
    pub fn capture_image_calibrated() -> Self {
        Self {
            arm: ArmRecipe::PRINT_IMAGE_CALIBRATED,
            host: PolledHostStage::FlatBody,
            read: PolledPrint,
            ghidra: GhidraEntry::CAPTURE_IMAGE,
        }
    }
}

impl PolledPipeline<PolledIdentify> {
    /// Identify verify — `vfmCapture`, `read_mode==2` when `nMatcher_submode==2` (DLL default).
    pub fn identify_verify() -> Self {
        Self {
            arm: ArmRecipe::IDENTIFY_VERIFY,
            host: PolledHostStage::FlatBody,
            read: PolledIdentify,
            ghidra: GhidraEntry::VFM_CAPTURE,
        }
    }
}

impl PolledPipeline<PolledEnroll> {
    /// Enroll touch — `vfmCapture`, `read_mode==3` on caps rows that select alt reader (`0x78`).
    pub fn enroll_touch() -> Self {
        Self {
            arm: ArmRecipe::IDENTIFY_ENROLL,
            host: PolledHostStage::FlatBody,
            read: PolledEnroll,
            ghidra: GhidraEntry::VFM_CAPTURE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaithfulPipeline {
    Stream(StreamPipeline),
    PolledPrint(PolledPipeline<PolledPrint>),
    PolledIdentify(PolledPipeline<PolledIdentify>),
    PolledEnroll(PolledPipeline<PolledEnroll>),
}

impl FaithfulPipeline {
    pub fn preset_print() -> Self {
        Self::PolledPrint(PolledPipeline::capture_image())
    }

    pub fn preset_print_cal() -> Self {
        Self::PolledPrint(PolledPipeline::capture_image_calibrated())
    }

    pub fn preset_identify() -> Self {
        Self::PolledIdentify(PolledPipeline::identify_verify())
    }

    pub fn preset_enroll() -> Self {
        Self::PolledEnroll(PolledPipeline::enroll_touch())
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::PolledPrint(_) => "PrintImage",
            Self::PolledIdentify(_) => "IdentifyVerify",
            Self::PolledEnroll(_) => "EnrollTouch",
            Self::Stream(_) => "StreamSync",
        }
    }

    pub fn ghidra_entry(self) -> GhidraEntry {
        match self {
            Self::PolledPrint(p) => p.ghidra,
            Self::PolledIdentify(p) => p.ghidra,
            Self::PolledEnroll(p) => p.ghidra,
            Self::Stream(p) => p.ghidra,
        }
    }

    pub fn read_mechanism(self) -> ReadMechanism {
        match self {
            Self::Stream(_) => ReadMechanism::Stream,
            Self::PolledPrint(_) | Self::PolledIdentify(_) | Self::PolledEnroll(_) => {
                ReadMechanism::Polled
            }
        }
    }

    pub fn arm_recipe(self) -> ArmRecipe {
        match self {
            Self::PolledPrint(p) => p.arm,
            Self::PolledIdentify(p) => p.arm,
            Self::PolledEnroll(p) => p.arm,
            Self::Stream(_) => ArmRecipe::FRAMES_SYNC_IMAGING,
        }
    }

    pub fn sync_frames(self) -> u32 {
        match self {
            Self::Stream(s) => s.arm.sync_frames,
            _ => 0,
        }
    }

    pub fn stream_host(self) -> Option<StreamHostStage> {
        match self {
            Self::Stream(s) => Some(s.host),
            _ => None,
        }
    }

    /// Short status-bar fragment (no EXPT prefix).
    pub fn status_line(self) -> String {
        let entry = self.ghidra_entry().label();
        match self {
            Self::PolledPrint(p) => format!(
                "{} · PolledPrint · recon=0x{:x} · host={:?}",
                entry, p.arm.recon_flags, p.host
            ),
            Self::PolledIdentify(p) => format!(
                "{} · PolledIdentify · recon=0x{:x} · host={:?}",
                entry, p.arm.recon_flags, p.host
            ),
            Self::PolledEnroll(p) => format!(
                "{} · PolledEnroll · recon=0x{:x} · host={:?}",
                entry, p.arm.recon_flags, p.host
            ),
            Self::Stream(s) => format!(
                "{} · Stream · frames={} · host={:?}",
                entry, s.arm.sync_frames, s.host
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Experimental escape hatch
// ---------------------------------------------------------------------------

/// EXPT — any arm × read × host combo; UI must show `EXPT` badge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExperimentalPipeline {
    pub arm: ArmRecipe,
    pub read: ReadMechanism,
    pub host: HostPostProcess,
    pub diag: DiagnosticOverlay,
    pub sync_frames: u32,
}

impl ExperimentalPipeline {
    /// Deliberately unconstrained — no `build()` rejection.
    pub fn explore(arm: ArmRecipe, read: ReadMechanism, host: HostPostProcess) -> Self {
        Self {
            arm,
            read,
            host,
            diag: DiagnosticOverlay::default(),
            sync_frames: 1,
        }
    }

    pub fn status_line(&self) -> String {
        format!(
            "EXPT · read={:?} · recon=0x{:x} · host={:?} · omit_2e={} · diag={:?}",
            self.read, self.arm.recon_flags, self.host, self.arm.omit_chunk_2e, self.diag
        )
    }
}

/// Builder for [`ExperimentalPipeline`] only — faithful presets use const constructors.
#[derive(Debug, Clone)]
pub struct ExperimentalBuilder {
    arm: ArmRecipe,
    read: ReadMechanism,
    host: HostPostProcess,
    sync_frames: u32,
    omit_chunk_2e: bool,
}

impl Default for ExperimentalBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ExperimentalBuilder {
    pub fn new() -> Self {
        Self {
            arm: ArmRecipe::IDENTIFY_VERIFY,
            read: ReadMechanism::Polled,
            host: HostPostProcess::None,
            sync_frames: 1,
            omit_chunk_2e: false,
        }
    }

    pub fn recon_flags(mut self, f: u32) -> Self {
        self.arm.recon_flags = f;
        self
    }

    pub fn finger_detect(mut self, on: bool) -> Self {
        self.arm.finger_detect = on;
        self
    }

    pub fn fold_calib(mut self, on: bool) -> Self {
        self.arm.fold_calib = on;
        self
    }

    pub fn omit_chunk_2e(mut self, on: bool) -> Self {
        self.omit_chunk_2e = on;
        self.arm.omit_chunk_2e = on;
        self
    }

    pub fn read(mut self, r: ReadMechanism) -> Self {
        self.read = r;
        self
    }

    pub fn host(mut self, h: HostPostProcess) -> Self {
        self.host = h;
        self
    }

    pub fn sync_frames(mut self, n: u32) -> Self {
        self.sync_frames = n;
        self
    }

    pub fn build(self) -> ExperimentalPipeline {
        ExperimentalPipeline {
            arm: self.arm,
            read: self.read,
            host: self.host,
            diag: DiagnosticOverlay::default(),
            sync_frames: self.sync_frames,
        }
    }
}

/// Unified pipeline for live_viewer / A/B examples.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pipeline {
    Faithful(FaithfulPipeline),
    Experimental(ExperimentalPipeline),
}

impl Pipeline {
    pub fn is_experimental(&self) -> bool {
        matches!(self, Self::Experimental(_))
    }

    pub fn status_line(&self) -> String {
        match self {
            Self::Faithful(f) => f.status_line(),
            Self::Experimental(e) => e.status_line(),
        }
    }

    pub fn read_mechanism(&self) -> ReadMechanism {
        match self {
            Self::Faithful(f) => f.read_mechanism(),
            Self::Experimental(e) => e.read,
        }
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::Faithful(FaithfulPipeline::preset_identify())
    }
}

/// Default faithful preset for provisioned 0x2449 (`read_mode=2`, Hello wire path).
pub const DEFAULT_FAITHFUL_PRESET: FaithfulPreset = FaithfulPreset::IdentifyVerify;

/// Named faithful presets for UI pickers — each maps 1:1 to a DLL entry + arm + read + host chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaithfulPreset {
    PrintImage,
    IdentifyVerify,
    ImageCalibrated,
    EnrollTouch,
    StreamSync,
}

impl FaithfulPreset {
    pub const ALL: [Self; 5] = [
        Self::PrintImage,
        Self::IdentifyVerify,
        Self::ImageCalibrated,
        Self::EnrollTouch,
        Self::StreamSync,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::PrintImage => "Print / image (syna_capture_image)",
            Self::IdentifyVerify => "Identify verify (vfmCapture)",
            Self::ImageCalibrated => "Image + vendor cal fold",
            Self::EnrollTouch => "Enroll touch (vfmCapture)",
            Self::StreamSync => "Stream / frames-sync (EP-0x82)",
        }
    }

    /// Short, stable CLI/token name (e.g. `--preset stream`). Distinct from [`Self::label`] (the
    /// verbose UI text) so the command line stays terse and scriptable.
    pub fn cli_name(self) -> &'static str {
        match self {
            Self::PrintImage => "print",
            Self::IdentifyVerify => "identify",
            Self::ImageCalibrated => "image-cal",
            Self::EnrollTouch => "enroll",
            Self::StreamSync => "stream",
        }
    }

    /// Parse a [`Self::cli_name`] back to a preset (case-insensitive). Returns `None` for an unknown
    /// token; callers list [`Self::ALL`]'s `cli_name`s in the error.
    pub fn from_cli_name(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.cli_name().eq_ignore_ascii_case(s))
    }

    pub fn ghidra_entry(self) -> GhidraEntry {
        self.pipeline(3).ghidra_entry()
    }

    pub fn pipeline(self, sync_frames: u32) -> FaithfulPipeline {
        match self {
            Self::PrintImage => FaithfulPipeline::preset_print(),
            Self::IdentifyVerify => FaithfulPipeline::preset_identify(),
            Self::ImageCalibrated => FaithfulPipeline::preset_print_cal(),
            Self::EnrollTouch => FaithfulPipeline::preset_enroll(),
            Self::StreamSync => {
                FaithfulPipeline::Stream(StreamPipeline::frames_sync_reconstruct(sync_frames))
            }
        }
    }

    pub fn as_pipeline(self, sync_frames: u32) -> Pipeline {
        Pipeline::Faithful(self.pipeline(sync_frames))
    }

    pub fn is_stream(self) -> bool {
        matches!(self.pipeline(3).read_mechanism(), ReadMechanism::Stream)
    }

    /// **The default capture-init arm for this preset** — the single shared entry the live viewer's
    /// capture thread and the HW smoke test both build from, so the test guards the real capture path
    /// rather than a bespoke arm.
    ///
    /// Resolves the preset's [`ReadMechanism`] + [`ArmRecipe`] and calls [`build_upload_cmd_detailed`]
    /// — exactly what the viewer does via `pipeline_to_capture_params` (which copies
    /// [`FaithfulPipeline::arm_recipe`]) → `build_arm`. `vendor_cal` is the calibration output from
    /// [`crate::session::Session::bootstrap`]; when present, the polled builder folds it
    /// (`upload_cmd_identify_with_cal`), which is what actually makes the sensor return a `0x51` body.
    pub fn default_arm(
        self,
        cfg: &CaptureConfig,
        factory_calibration_values: &[u8],
        sync_frames: u32,
        vendor_cal: Option<&CalResults>,
    ) -> Option<(Vec<u8>, UploadCmdBuildPath)> {
        let pipe = self.pipeline(sync_frames);
        build_upload_cmd_detailed(
            cfg,
            factory_calibration_values,
            pipe.read_mechanism(),
            &pipe.arm_recipe(),
            pipe.sync_frames().max(sync_frames),
            vendor_cal,
        )
    }
}

// ---------------------------------------------------------------------------
// Shared arm builders (stream × poll)
// ---------------------------------------------------------------------------

/// Which [`build_upload_cmd_detailed`] branch produced the arm (logging / parity tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadCmdBuildPath {
    /// Polled static recon arm ([`CaptureConfig::upload_cmd_prod33_calibrated_recon`]).
    PolledStaticRecon,
    /// Polled identify-class vendor cal fold ([`CaptureConfig::upload_cmd_identify_with_cal`]).
    PolledIdentifyWithCal,
    /// Polled imaging-class full vendor cal fold ([`CaptureConfig::upload_cmd_image_with_cal`]).
    PolledImageWithCal,
    /// Polled factory-cal diff only ([`CaptureConfig::upload_cmd_image_calibrated`]).
    PolledImageCalibratedOnly,
    /// Stream frames-sync without measured cal fold ([`CaptureConfig::upload_cmd_prod33_sync`]).
    StreamSync,
    /// Stream frames-sync with step-3/step-6 fold ([`CaptureConfig::upload_cmd_prod33_sync_with_cal`]).
    StreamSyncWithCal,
}

/// Build a framed `0x02` upload for an arm recipe × read mechanism pairing.
///
/// Shared by `examples/polled_identify`, `examples/stream_empty_frames`, and `live_viewer`.
/// When `vendor_cal` is present, polled paths prefer identify-class cal fold (pcap parity);
/// stream paths fold measured cal only when [`ArmRecipe::fold_calib`] is set.
pub fn build_upload_cmd(
    cfg: &CaptureConfig,
    factory_calibration_values: &[u8],
    read: ReadMechanism,
    arm: &ArmRecipe,
    sync_frames: u32,
    vendor_cal: Option<&CalResults>,
) -> Option<Vec<u8>> {
    build_upload_cmd_detailed(
        cfg,
        factory_calibration_values,
        read,
        arm,
        sync_frames,
        vendor_cal,
    )
    .map(|(cmd, _)| cmd)
}

/// Like [`build_upload_cmd`], but returns which builder branch was selected.
///
/// **Single arm backend (Phase 4).** This is now a thin adapter over
/// [`CaptureConfig::resolve_arm`]: it maps the `(ReadMechanism, ArmRecipe, vendor_cal)` routing onto
/// an [`ArmSpec`] and delegates. The old `build_polled_upload_cmd`/`build_stream_upload_cmd` (which
/// dispatched to the ~7 `upload_cmd_*` wrappers) are gone; the wrappers remain for the RE probes but
/// are no longer the router's backend. Byte-parity per branch is pinned by the `detailed_*_matches_direct`
/// KATs below and, against the DLL, by `tests/dll_arm_parity.rs`.
pub fn build_upload_cmd_detailed(
    cfg: &CaptureConfig,
    factory_calibration_values: &[u8],
    read: ReadMechanism,
    arm: &ArmRecipe,
    sync_frames: u32,
    vendor_cal: Option<&CalResults>,
) -> Option<(Vec<u8>, UploadCmdBuildPath)> {
    let spec = spec_for_recipe(read, arm, sync_frames, vendor_cal.is_some());
    cfg.resolve_arm_cmd(&spec, factory_calibration_values, vendor_cal)
}

/// Map the legacy `(ReadMechanism, ArmRecipe, has_cal)` routing onto a canonical [`ArmSpec`],
/// reproducing every branch of the old `build_polled`/`build_stream` byte-for-byte:
/// - **Stream**: `VendorCal` iff `fold_calib && has_cal`, else `Static` (the old `upload_cmd_prod33_sync`).
/// - **Polled + cal + imaging** → `Image`/`VendorCal` (`upload_cmd_image_with_cal`).
/// - **Polled + cal + !imaging** → `Identify`/`VendorCalWithBaseline` (`upload_cmd_identify_with_cal`).
/// - **Polled + fold_calib, no cal** → `Image`/`FactoryDiff` (`upload_cmd_image_calibrated` — recon=8,
///   no finger-detect, step-3 only; note it IGNORES the recipe's recon/finger, as the old path did).
/// - **Polled, static** → the recipe's own recon/finger, `Static` (`upload_cmd_prod33_calibrated_recon`).
///
/// The cal paths intentionally take the mode's canonical recon/finger (not the recipe's) — that is the
/// exact quirk of the old wrappers. `omit_chunk_2e` was never honoured by this router (the polled
/// wrappers always emit `0x2e`), so it stays `include_chunk_2e = true`; stream drops `0x2e` via
/// `calibrate`. The stride/`req_lines` and `UploadCmdBuildPath` fall out of `resolve_arm`.
fn spec_for_recipe(read: ReadMechanism, arm: &ArmRecipe, sync_frames: u32, has_cal: bool) -> ArmSpec {
    match read {
        ReadMechanism::Stream => {
            let fold = if arm.fold_calib && has_cal {
                FoldSource::VendorCal
            } else {
                FoldSource::Static
            };
            CaptureMode::Stream.spec_with(&ArmOverrides {
                sync_frames: Some(sync_frames),
                fold: Some(fold),
                ..Default::default()
            })
        }
        ReadMechanism::Polled if has_cal && arm.is_imaging() => {
            CaptureMode::Image.spec_with(&ArmOverrides {
                fold: Some(FoldSource::VendorCal),
                ..Default::default()
            })
        }
        ReadMechanism::Polled if has_cal => CaptureMode::Identify.spec_with(&ArmOverrides {
            fold: Some(FoldSource::VendorCalWithBaseline),
            ..Default::default()
        }),
        ReadMechanism::Polled if arm.fold_calib => CaptureMode::Image.spec_with(&ArmOverrides {
            fold: Some(FoldSource::FactoryDiff),
            ..Default::default()
        }),
        ReadMechanism::Polled => CaptureMode::Identify.spec_with(&ArmOverrides {
            recon_flags: Some(arm.recon_flags),
            finger_detect: Some(arm.finger_detect),
            include_chunk_2e: Some(true),
            fold: Some(FoldSource::Static),
            ..Default::default()
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::line_update::{capture_flag, recon_flag, RECON_FLAGS_DEFAULT, RECON_FLAGS_ENROLL};

    #[test]
    fn capture_flags_image_matches_ghidra() {
        // syna_capture_image@0x180099540 hardcodes 0xa0030
        assert_eq!(
            CAPTURE_FLAGS_IMAGE,
            capture_flag::EMIT_REPLY_CONFIG
                | capture_flag::RECON_DOWNSTREAM
                | capture_flag::SKIP_FINGER_DETECT
                | capture_flag::RECON_MODE8_IMAGE
        );
        assert_eq!(ArmRecipe::PRINT_IMAGE.recon_flags, recon_flag::MODE_ALT_FIELD0);
    }

    #[test]
    fn identify_never_mode8() {
        assert_eq!(ArmRecipe::IDENTIFY_VERIFY.recon_flags, recon_flag::MODE_DEFAULT);
        assert_eq!(
            ArmRecipe::IDENTIFY_VERIFY.capture_flags & capture_flag::RECON_MODE8_IMAGE,
            0
        );
    }

    #[test]
    fn faithful_print_is_polled() {
        assert_eq!(
            FaithfulPipeline::preset_print().read_mechanism(),
            ReadMechanism::Polled
        );
    }

    #[test]
    fn default_pipeline_is_polled_identify() {
        let p = Pipeline::default();
        assert_eq!(p.read_mechanism(), ReadMechanism::Polled);
        match p {
            Pipeline::Faithful(FaithfulPipeline::PolledIdentify(p)) => {
                assert_eq!(p.arm.recon_flags, RECON_FLAGS_DEFAULT);
                assert!(p.arm.finger_detect);
            }
            other => panic!("expected polled identify default, got {other:?}"),
        }
    }

    #[test]
    fn default_faithful_preset_arm_contract() {
        // The shared "default capture init" (`FaithfulPreset::default_arm`, driven by the HW smoke
        // test `pipeline_smoke_hw::polled_init_produces_nonzero_frame`) must resolve to the same
        // polled identify recipe the live viewer's default preset propagates via
        // `pipeline_to_capture_params` — recon=2, finger-detect, polled. Guards silent drift between
        // the viewer's preset and what the test exercises.
        assert_eq!(DEFAULT_FAITHFUL_PRESET, FaithfulPreset::IdentifyVerify);
        let pipe = DEFAULT_FAITHFUL_PRESET.pipeline(3);
        assert_eq!(pipe.read_mechanism(), ReadMechanism::Polled);
        let arm = pipe.arm_recipe();
        assert_eq!(arm.recon_flags, RECON_FLAGS_DEFAULT);
        assert!(arm.finger_detect);
    }

    #[test]
    fn is_imaging_keys_on_recon_mode8_not_finger_detect() {
        // Only the recon=8 print recipes are imaging-class. Crucially the stream calibrate arm
        // FRAMES_SYNC_IMAGING has finger_detect=false but is NOT imaging — guards the discriminator
        // against the `!finger_detect` false-positive that would misroute calibrate arms.
        assert!(ArmRecipe::PRINT_IMAGE.is_imaging());
        assert!(ArmRecipe::PRINT_IMAGE_CALIBRATED.is_imaging());
        assert!(!ArmRecipe::IDENTIFY_VERIFY.is_imaging());
        assert!(!ArmRecipe::IDENTIFY_ENROLL.is_imaging());
        assert!(!ArmRecipe::FRAMES_SYNC_IMAGING.is_imaging());
    }

    #[test]
    fn polled_cal_fold_routes_by_recipe_class_not_cal_presence() {
        // Regression: with vendor_cal present, PRINT_IMAGE must reach its recon=8 builder instead
        // of collapsing to identify. Both recipes carry the SAME `vendor_cal`; only the recipe
        // class decides the branch. Uses a POPULATED cal so the fold is real and the build-path label
        // reflects it (an all-`None` cal folds nothing → both would label `PolledStaticRecon`, since
        // `resolve_arm`'s path is keyed on actual fold content, not the routing branch).
        let cfg = CaptureConfig::for_silicon(0x190, 0x4b, 6, 0x14).expect("2449 resolves");
        let cal = test_cal();

        let (_, image_path) = build_upload_cmd_detailed(
            &cfg,
            &[],
            ReadMechanism::Polled,
            &ArmRecipe::PRINT_IMAGE,
            0,
            Some(&cal),
        )
        .expect("print-image arm builds");
        assert_eq!(image_path, UploadCmdBuildPath::PolledImageWithCal);

        let (_, identify_path) = build_upload_cmd_detailed(
            &cfg,
            &[],
            ReadMechanism::Polled,
            &ArmRecipe::IDENTIFY_VERIFY,
            0,
            Some(&cal),
        )
        .expect("identify arm builds");
        assert_eq!(identify_path, UploadCmdBuildPath::PolledIdentifyWithCal);
    }

    #[test]
    fn enroll_touch_preset_is_polled_enroll_arm() {
        let fp = FaithfulPreset::EnrollTouch.pipeline(3);
        assert_eq!(fp.read_mechanism(), ReadMechanism::Polled);
        assert_eq!(fp.arm_recipe().recon_flags, RECON_FLAGS_ENROLL);
        assert!(fp.arm_recipe().finger_detect);
    }

    #[test]
    fn stream_sync_preset_metadata() {
        let fp = FaithfulPreset::StreamSync.pipeline(3);
        assert_eq!(fp.read_mechanism(), ReadMechanism::Stream);
        assert_eq!(fp.stream_host(), Some(StreamHostStage::StreamReconstruct));
        assert_eq!(fp.sync_frames(), 3);
        let arm = fp.arm_recipe();
        // Faithful frames-sync arm = CALIBRATE-class: NO 0x2e recon, NO finger-detect (recon_flags
        // moot). Host cf640 runs only on no-0x2e raw — see docs/capture/capture-paths.md.
        assert!(arm.omit_chunk_2e);
        assert!(!arm.finger_detect);
        assert!(arm.fold_calib);
    }

    #[test]
    fn stream_sync_buffer_size_51224_at_three_frames() {
        let cfg = CaptureConfig::for_silicon(0x190, 0x4b, 6, 0x14).expect("resolves");
        assert_eq!(cfg.stream_buffer_size(3), 51224);
        assert_eq!(cfg.stream_req_lines(3), 337);
    }

    #[test]
    fn build_upload_cmd_polled_static_matches_identify_recipe() {
        let cfg = CaptureConfig::for_silicon(0x190, 0x4b, 6, 0x14).expect("resolves");
        let fcv: Vec<u8> = vec![0; 64];
        let arm = ArmRecipe::IDENTIFY_VERIFY;
        let direct = cfg
            .upload_cmd_prod33_calibrated_recon(&fcv, &[], arm.recon_flags, arm.finger_detect)
            .expect("direct");
        let shared = build_upload_cmd(
            &cfg,
            &fcv,
            ReadMechanism::Polled,
            &arm,
            0,
            None,
        )
        .expect("shared");
        assert_eq!(direct, shared);
    }

    #[test]
    fn build_upload_cmd_stream_sync_matches_direct() {
        let cfg = CaptureConfig::for_silicon(0x190, 0x4b, 6, 0x14).expect("resolves");
        let fcv: Vec<u8> = vec![0; 64];
        let arm = ArmRecipe::FRAMES_SYNC_IMAGING;
        let direct = cfg.upload_cmd_prod33_sync(&fcv, &[], 3).expect("direct");
        let shared = build_upload_cmd(
            &cfg,
            &fcv,
            ReadMechanism::Stream,
            &arm,
            3,
            None,
        )
        .expect("shared");
        assert_eq!(direct, shared);
    }

    // ---- Phase-3 safety net: build_upload_cmd_detailed == the direct upload_cmd_* it routes to,
    // for EVERY branch. Locks the routing so the Phase-4 collapse onto resolve_arm stays byte-exact. ----

    fn test_cfg() -> CaptureConfig {
        CaptureConfig::for_silicon(0x190, 0x4b, 6, 0x14).expect("resolves")
    }

    /// A vendor cal with realistically-sized step-3 (56 B) + step-6 dark (56×152) so the with-cal
    /// paths actually fold. Content is arbitrary — both sides read the SAME cal, so bytes match.
    fn test_cal() -> CalResults {
        CalResults {
            step3_diff: Some(vec![0x7e; 56]),
            step56_buf: Some(vec![0x80; 56 * 152]),
            ..Default::default()
        }
    }

    fn detailed(
        cfg: &CaptureConfig,
        read: ReadMechanism,
        arm: &ArmRecipe,
        sync: u32,
        cal: Option<&CalResults>,
    ) -> (Vec<u8>, UploadCmdBuildPath) {
        build_upload_cmd_detailed(cfg, &[0u8; 64], read, arm, sync, cal).expect("detailed")
    }

    #[test]
    fn detailed_polled_image_with_cal_matches_direct() {
        let cfg = test_cfg();
        let cal = test_cal();
        let (bytes, path) = detailed(&cfg, ReadMechanism::Polled, &ArmRecipe::PRINT_IMAGE, 0, Some(&cal));
        assert_eq!(path, UploadCmdBuildPath::PolledImageWithCal);
        assert_eq!(bytes, cfg.upload_cmd_image_with_cal(&[0u8; 64], &cal).expect("direct"));
    }

    #[test]
    fn detailed_polled_identify_with_cal_matches_direct() {
        let cfg = test_cfg();
        let cal = test_cal();
        let (bytes, path) =
            detailed(&cfg, ReadMechanism::Polled, &ArmRecipe::IDENTIFY_VERIFY, 0, Some(&cal));
        assert_eq!(path, UploadCmdBuildPath::PolledIdentifyWithCal);
        assert_eq!(bytes, cfg.upload_cmd_identify_with_cal(&[0u8; 64], &cal).expect("direct"));
    }

    #[test]
    fn detailed_polled_image_calibrated_only_matches_direct() {
        let cfg = test_cfg();
        // fold_calib recipe, NO vendor cal → the step-3-only (FactoryDiff) image-calibrated arm.
        let (bytes, path) =
            detailed(&cfg, ReadMechanism::Polled, &ArmRecipe::PRINT_IMAGE_CALIBRATED, 0, None);
        assert_eq!(path, UploadCmdBuildPath::PolledImageCalibratedOnly);
        assert_eq!(bytes, cfg.upload_cmd_image_calibrated(&[0u8; 64]).expect("direct"));
    }

    #[test]
    fn detailed_polled_static_recon_matches_direct() {
        let cfg = test_cfg();
        let arm = ArmRecipe::IDENTIFY_VERIFY; // fold_calib=false, no cal → PolledStaticRecon
        let (bytes, path) = detailed(&cfg, ReadMechanism::Polled, &arm, 0, None);
        assert_eq!(path, UploadCmdBuildPath::PolledStaticRecon);
        assert_eq!(
            bytes,
            cfg.upload_cmd_prod33_calibrated_recon(&[0u8; 64], &[], arm.recon_flags, arm.finger_detect)
                .expect("direct")
        );
    }

    #[test]
    fn detailed_stream_sync_with_cal_matches_direct() {
        let cfg = test_cfg();
        let cal = test_cal();
        let (bytes, path) =
            detailed(&cfg, ReadMechanism::Stream, &ArmRecipe::FRAMES_SYNC_IMAGING, 3, Some(&cal));
        assert_eq!(path, UploadCmdBuildPath::StreamSyncWithCal);
        assert_eq!(bytes, cfg.upload_cmd_prod33_sync_with_cal(&[0u8; 64], &cal, 3).expect("direct"));
    }

    #[test]
    fn detailed_stream_sync_static_matches_direct() {
        let cfg = test_cfg();
        // No cal → static sync (StreamSync), regardless of fold_calib.
        let (bytes, path) =
            detailed(&cfg, ReadMechanism::Stream, &ArmRecipe::FRAMES_SYNC_IMAGING, 3, None);
        assert_eq!(path, UploadCmdBuildPath::StreamSync);
        assert_eq!(bytes, cfg.upload_cmd_prod33_sync(&[0u8; 64], &[], 3).expect("direct"));
    }
}
