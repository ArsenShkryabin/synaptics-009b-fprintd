//! # synaptics-prometheus
//!
//! User-space driver for the **Synaptics Prometheus / Validity** fingerprint sensor family
//! (USB `06cb:0090/0097/009a/009b/009d`, …). Storage and match strategy is **SKU-specific**
//! (EOH/MOH vs MOC) — see `docs/bringup/storage-mode-by-sku.md`.
//!
//! Built from a clean-room-adjacent reverse engineering of MSI's `synaWudfBioUsb.dll`
//! (see the `docs/` tree next to this crate). Every magic constant and opcode carries a
//! `// ghidra: <fn>@<addr>` reference back to the decompilation, so the implementation is
//! auditable against the DLL.
//!
//! ## Safety posture
//! **Read-only by construction.** The default build compiles in *no* state-mutating
//! command path — no flash erase/write, no partition-flash-with-subblocks, no record
//! create/delete, no enrollment. Those live behind the `writes` feature and an explicit
//! API. You cannot accidentally wipe a paired sensor with the default build.
//!
//! ## Multi-sensor
//! The family differs in only three axes — machine binding, init/handshake, firmware
//! source — each modelled as a trait in [`devices`]. Adding a sensor is one registry row.
//!
//! ## Status
//! Foundation: transport + protocol + pre-TLS reads (RomInfo/flash-info/sensor-id) and
//! the shared crypto constants. The TLS session bring-up (ECDH handshake) and template-DB
//! enumeration are the next milestones.

/// 009b ROM-exit `0x06` init blobs (`init_hardcoded`); bytes pending static RE.
pub mod blobs_9b;
/// Captured init blobs for older Prometheus (`0097/009a/009d`) — python-validity origin.
pub mod blobs_9a;
pub mod artifact;
pub mod bringup;
pub mod calibrate;
pub mod calibration;
pub mod capture;
/// Load exact stage taps from a recorded capture-bundle frame directory (saFX by stage kind).
pub mod capture_stage;
/// Where the pairing cert store lives — one canonical XDG location instead of a copy per worktree.
pub mod certstore;
/// Pure host conditioning + raster helpers (reshape/destride/conditioning), shared by the viewer
/// pipeline nodes and reflective/headless runs.
pub mod conditioning;
/// Matcher IR post-process (`syna_ir_normalize_frame` / `syna_ir_reconstruct_roi`) — what QM sees
/// after descramble on the polled identify/enroll path. Not the host z-score diagnostic.
pub mod ir_normalize;
// `display` (contrast/gamma mapping) and `pipeline_graph` (the reflective stage-node pipeline that
// drives the viewer's auto-generated UI) moved OUT into the `synaptics-pipeline-graph` crate, which
// sits above this driver. Keeping them out means a minimal binary on this crate never compiles the
// graph/UI layer. See that crate for `DisplayParams` / `StagePipeline` / the node system.
/// SensorCaptureProg selection + `0x02` capture-command construction (the imaging unlock).
pub mod capture_prog;
/// Timeslot-program chunk codec (split/merge), shared by capture_prog + the imaging path.
pub mod chunk_codec;
/// Ghidra-faithful capture pipeline types (arm × read × host); see `docs/capture/capture-paths.md`.
pub mod capture_pipeline;
/// @generated silicon→subtype table + capture programs (0x190 family) from `synaWudfBioUsb.dll`.
pub mod capture_progs_9b;
/// Secure-session crypto (AES/HMAC/PRF) — re-exported from the `synaptics-crypto` crate.
pub use synaptics_crypto::crypto;
/// Template-database commands: read-only queries (stats/records/users) + `writes`-gated enroll/delete.
pub mod db;
pub mod device;
pub mod devices;
pub mod enroll;
/// Error/status model — re-exported from the leaf `synaptics-core` crate (was `crate::error`).
pub use synaptics_core::error;
pub mod factory_cal;
pub mod flex_cal_gen;
pub mod flex_params;
/// Swappable host-side template extraction/matching interface (algorithm-neutral).
pub mod host_biometric;
/// Grayscale image container + self-contained PGM/PNG encoders (extracted from `reconstruct`).
pub mod image_io;
/// Host enroll/verify orchestration (capture-source agnostic); live driver is finger-gated.
pub mod biometric_flow;
/// Data-driven firmware-module registry lifted from the DLL (device support + `0x06` selection).
pub mod fw_registry;
/// The TLS session handshake (ClientHello…Finished) — re-exported from `synaptics-crypto`.
pub use synaptics_crypto::handshake;
/// Pre-TLS USDK5 work-key (WRKP) init handshake (009b / Metallica-5.3): pinned root-key ECDH.
pub mod init;
/// Timeslot-program disassembly + the `line_update` calibration patch (imaging enable).
pub mod line_update;
pub mod matching;
/// Cert-store parse + unseal — re-exported from the `synaptics-crypto` crate.
pub use synaptics_crypto::pairing;
pub mod presence_caps;
pub mod wake_flex;
/// Opt-in pcapng wire logging — re-exported from the `synaptics-core` crate.
pub use synaptics_core::pcap_log;
pub mod pre_arm;
/// Command protocol (Opcode + response parsers) — re-exported from the `synaptics-proto` crate.
pub use synaptics_proto::proto;
/// QM backend adapter — research only, gated behind the `qm` feature (IP/patent gate).
#[cfg(feature = "qm")]
pub mod qm_adapter;
pub mod reconstruct;
pub mod scm_regs;
pub mod session;
pub mod session_cal;
/// Opaque host-side enrolled-template store keyed by (user, finger subtype).
pub mod template_store;
/// TLS record layer + session keys — re-exported from the `synaptics-crypto` crate.
pub use synaptics_crypto::tls;
/// USB transport (Transport trait + nusb backend) — re-exported from the `synaptics-transport` crate.
pub use synaptics_transport::transport;
pub mod vendor;
/// Bounds-checked little-endian byte cursor shared by the response parsers (panic-free framing).
/// Re-exported from the leaf `synaptics-core` crate (was `crate::wire`).
pub use synaptics_core::wire;
pub mod xpfwext;

pub use presence_caps::{FingerPresenceStrategy, SensorPresenceCaps};
pub use session::{BootstrapOptions, DeviceContext, Session};
pub use wake_flex::{WofDeviceClass, wake_flex_block};
pub use capture_prog::{CaptureConfig, CaptureMode};
pub use capture_prog::windsor::{WindsorReconConfig, WINDSOR_RECON_CONFIG_TAG};
pub use device::RawDevice;
pub use devices::{MachineBinding, MachineGuidBinding, DmiBinding, SensorProfile};
pub use bringup::{BringUpPlan, infer_fw_upload_context};
pub use error::{Error, Result, Status};
pub use pairing::{CertStore, Pairing};
pub use proto::Opcode;
pub use tls::{RecordType, SessionKeys};
pub use host_biometric::{
    ConditionedImage, HostBiometricBackend, HostBiometricError, MatchLevel, MatchOutcome,
};
pub use xpfwext::Xpfwext;

#[cfg(feature = "qm")]
pub use qm_adapter::QmBackend;
#[cfg(feature = "qm")]
pub use synaptics_prometheus_qm as qm;
#[cfg(feature = "nusb-backend")]
pub use transport::NusbTransport;
