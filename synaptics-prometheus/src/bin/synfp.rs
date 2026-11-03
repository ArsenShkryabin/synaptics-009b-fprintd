//! `synfp` — a small subcommand CLI for playing with / probing a Synaptics Prometheus sensor.
//!
//! One ergonomic entry point over the driver's existing APIs (no new protocol logic). Works
//! family-wide: the `009b` MSI unit (Windows cert-store pairing) and the python-validity-paired
//! `009a` (flash cert-store + DMI binding).
//!
//! ```text
//!   synfp info                 # rom/flash/sensor id, family + imaging capability   (no session)
//!   synfp modes                # capture modes + arm recipe for this silicon         (no session)
//!   synfp flash 1 --size 4096  # dump a flash partition region                       (no session)
//!   synfp fwext                # firmware blobs present on device vs wanted/missing   (no session)
//!   synfp db                   # enumerate the on-chip template DB                    (session)
//!   synfp png -o f.png         # record an image; --finger to wait for a touch       (session)
//! ```
//!
//! Pairing source is auto-selected by family; override with `--pairing flash|file`, `--certstore
//! <path>`, or `SYNA_HW_BINDING` (raw GWK binding bytes; empty string = Windows seat key).

use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand, ValueEnum};
use rand_core::Rng;

use synaptics_prometheus::capture::{CaptureOpts, CaptureOutcome, CaptureSession, MatcherSubmode};
// NB: the flat `CaptureMode` re-export is a near-stub; the 5-mode enum lives in `capture_spec`.
use synaptics_prometheus::capture_prog::capture_spec::CaptureMode;
use synaptics_prometheus::image_io::Image;
use synaptics_prometheus::devices::{DmiBinding, InitModel, MachineBinding};
use synaptics_prometheus::proto::{Opcode, SensorId};
use synaptics_prometheus::scm_regs::ScmReg;
use synaptics_prometheus::session_cal;
use synaptics_prometheus::reconstruct::{
    PolledStage, polled_stage_image, recon_params, reconstruct_sync_frame,
};
use synaptics_prometheus::session::{BootstrapOptions, Session, os_rng};
use synaptics_prometheus::transport::NusbTransport;
use synaptics_prometheus::{
    CaptureConfig, Error, RawDevice, Result, SensorProfile, capture_progs_9b, certstore, db,
    fw_registry, line_update, pairing, pre_arm,
};

/// The five canonical capture modes, in a stable order for `synfp modes`.
const ALL_MODES: [CaptureMode; 5] = [
    CaptureMode::Identify,
    CaptureMode::Enroll,
    CaptureMode::Image,
    CaptureMode::Stream,
    CaptureMode::Calibrate,
];

#[derive(Parser)]
#[command(
    name = "synfp",
    about = "Probe / play with a Synaptics Prometheus fingerprint sensor"
)]
struct Cli {
    /// Pairing cert-store file (for the Windows-paired `009b`); default resolves the XDG copy.
    #[arg(long, global = true)]
    certstore: Option<String>,
    /// Where to source the TLS pairing from.
    #[arg(long, value_enum, default_value_t = PairingSource::Auto, global = true)]
    pairing: PairingSource,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Copy, Clone, ValueEnum)]
enum PairingSource {
    /// Older family → sensor flash + DMI binding; `009b` → cert-store file.
    Auto,
    /// Read the sealed cert-store from flash partition 1 (python-validity / on-flash pairing).
    Flash,
    /// Read the cert-store from a file (Windows registry export).
    File,
}

#[derive(Subcommand)]
enum Command {
    /// ROM info, flash IC + partitions, sensor id, device family, imaging capability. No session.
    Info,
    /// The capture modes and each one's arm recipe for this silicon. No session.
    Modes,
    /// Dump a region of a flash partition. No session.
    Flash(FlashArgs),
    /// Firmware blobs present on the device vs. wanted (ROM-exit / pre-arm / WOF) and missing. No session.
    Fwext,
    /// Enumerate the on-chip template DB (StgWindsor container → users → fingers). Opens a session.
    Db,
    /// Record an image to PNG. Opens a session, arms a capture, polls a frame. See `--finger`.
    Png(PngArgs),
    /// Reboot the sensor's capture firmware (`0x05` mode 2). Clears ALL die state (stale arm, on-chip
    /// calibration-RAM, finger-detect/WOE) — the device re-enumerates. Opens a session.
    Reboot,
    /// Analog-gain (AGC) search: step the AFE PGA gain down until the no-finger frame's middle band
    /// stops clipping — the DLL/registry `SCM_PGA_AGC_*_GAIN` trim, run on-device instead of read from
    /// the Windows registry. No finger needed; prints per-iteration progress.
    Agc(AgcArgs),
    /// Run the pv/DLL dark-field calibrate loop (accumulate-and-fold) and report the no-finger
    /// middle-clip before vs after. This is the real fix for the 009a blown-out middle: the unfolded
    /// frames-sync frame clips because it lacks the pre-ADC dark-field subtraction; the calibrate loop
    /// builds `calib_data` and the folded capture de-clips. No finger needed. Older type-1 family only.
    Calibrate(CalibrateArgs),
    /// One-time: re-seal the pairing without the machine binding → a portable cert-store, so later
    /// `--pairing file` runs need no root/DMI serial. Reads flash + DMI binding (needs root once).
    RebindPairing(RebindArgs),
}

#[derive(Args)]
struct FlashArgs {
    /// Partition id (e.g. 1 = cert-store, 2 = fwext, 4 = template DB).
    partition: u8,
    /// Byte offset within the partition.
    #[arg(long, default_value_t = 0)]
    addr: u32,
    /// Number of bytes to read.
    #[arg(long, default_value_t = 0x1000)]
    size: u32,
    /// Write raw bytes to this file instead of hex-dumping to stdout.
    #[arg(short, long)]
    out: Option<String>,
}

#[derive(Args)]
struct PngArgs {
    /// Output PNG path.
    #[arg(short, long, default_value = "capture.png")]
    out: String,
    /// Wait for a finger (identify arm). WITHOUT this flag: no-finger blank/still image (image arm).
    #[arg(long)]
    finger: bool,
    /// Emit an earlier pipeline stage instead of the default QM-input (conditioned) image.
    #[arg(long, value_enum, default_value_t = Stage::Conditioned)]
    stage: Stage,
    /// Do not fold a dark reference at the dark-removed/conditioned stages (DLL no-reference branch).
    #[arg(long)]
    no_dark_ref: bool,
    /// Seconds to wait for a frame (finger placement window when `--finger`).
    #[arg(long, default_value_t = 20)]
    timeout_s: u64,
}

#[derive(Args)]
struct AgcArgs {
    /// Run the gain-search feedback loop (disables the HW AGC and steps the analog gain down).
    /// Default: dump the AGC register state + one no-finger frame's middle-clip %, write nothing.
    #[arg(long)]
    search: bool,
    /// Gain decrement per iteration (raw AFE register step), applied to all four island gains.
    #[arg(long, default_value_t = 4)]
    step: u8,
    /// Stop when at most this percent of the middle-band pixels are clipped (>= 250).
    #[arg(long, default_value_t = 2.0)]
    target: f64,
    /// Maximum iterations before giving up.
    #[arg(long, default_value_t = 20)]
    max_iters: u32,
    /// Also write the final (raw) frame to this PNG.
    #[arg(short, long)]
    out: Option<String>,
}

#[derive(Args)]
struct CalibrateArgs {
    /// Also write the post-calibrate (folded) frame to this PNG.
    #[arg(short, long)]
    out: Option<String>,
}

#[derive(Args)]
struct RebindArgs {
    /// Output cert-store path. Default: the canonical XDG location `synfp --pairing file` reads.
    #[arg(short, long)]
    out: Option<String>,
}

/// CLI mirror of [`PolledStage`]; the default (`conditioned`) is the buffer that feeds QM.
#[derive(Copy, Clone, ValueEnum)]
enum Stage {
    /// Raw sensor body, no processing.
    Raw,
    /// Timeslot de-spread only (no dark-reference fold).
    Descrambled,
    /// De-spread with the dark/device-pattern reference folded out.
    DpRemoved,
    /// Conditioned QM input (the default) — the buffer the matcher consumes.
    Conditioned,
}

impl Stage {
    fn to_polled(self) -> PolledStage {
        match self {
            Stage::Raw => PolledStage::Raw,
            Stage::Descrambled => PolledStage::Descrambled,
            Stage::DpRemoved => PolledStage::DarkRemoved,
            Stage::Conditioned => PolledStage::Conditioned,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Stage::Raw => "raw",
            Stage::Descrambled => "descrambled",
            Stage::DpRemoved => "dp-removed",
            Stage::Conditioned => "conditioned-qm-input",
        }
    }
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    match &cli.cmd {
        Command::Info => cmd_info(),
        Command::Modes => cmd_modes(),
        Command::Flash(a) => cmd_flash(a),
        Command::Fwext => cmd_fwext(),
        Command::Db => cmd_db(&cli),
        Command::Png(a) => cmd_png(&cli, a),
        Command::Reboot => cmd_reboot(&cli),
        Command::Agc(a) => cmd_agc(&cli, a),
        Command::Calibrate(a) => cmd_calibrate(&cli, a),
        Command::RebindPairing(a) => cmd_rebind(&cli, a),
    }
}

// ---------------------------------------------------------------------------
// Cleartext subcommands (no TLS session).
// ---------------------------------------------------------------------------

/// Read the `0x75` silicon id as `(major, minor)`. Returns `(0, 0)` and logs to stderr on failure
/// so the caller can still print the rest of the device info rather than aborting.
fn read_silicon(dev: &mut RawDevice<NusbTransport>) -> (u16, u16) {
    match dev
        .cmd_raw(Opcode::GetSensorId, &[])
        .and_then(|r| SensorId::parse(&r.payload))
    {
        Ok(s) => (s.major, s.minor),
        Err(e) => {
            eprintln!("# warning: 0x75 sensor-id read failed: {e}");
            (0, 0)
        }
    }
}

fn cmd_info() -> Result<()> {
    let (mut dev, (vid, pid)) = RawDevice::open_any()?;
    let profile = SensorProfile::for_id(vid, pid);
    println!(
        "device:  {vid:04x}:{pid:04x}  {}",
        profile.map(|p| p.name).unwrap_or("(unprofiled)")
    );
    if let Some(p) = profile {
        let init = match p.init {
            InitModel::StaticBlob => "static-0x06 → plain TLS (0090/0097/009a/009d)",
            InitModel::Usdk5Handshake => "static-0x06 + USDK5 WRKP handshake (009b)",
        };
        println!(
            "family:  init={init}  template_db=0x{:x}",
            p.flash.template_db_size()
        );
    }

    match dev.get_rom_info() {
        Ok(ri) => println!(
            "rominfo: fw {}.{} build={} product=0x{:02x} ts=0x{:08x}",
            ri.major, ri.minor, ri.build, ri.product, ri.timestamp
        ),
        Err(e) => println!("rominfo: ERROR {e}"),
    }
    match dev.get_flash_info() {
        Ok(fi) => {
            println!(
                "flash:   jedec={:04x}:{:04x} blocks=0x{:x}×0x{:x} ({} partitions)",
                fi.jedec.0,
                fi.jedec.1,
                fi.blocks,
                fi.block_size,
                fi.partitions.len()
            );
            for p in &fi.partitions {
                println!(
                    "   part id={:#04x} type={:#04x} flags={:#06x} addr={:#010x} size={:#010x}",
                    p.id, p.type_, p.flags, p.addr, p.size
                );
            }
        }
        Err(e) => println!("flash:   ERROR {e}"),
    }

    let (major, minor) = read_silicon(&mut dev);
    println!("silicon: major=0x{major:04x} minor=0x{minor:04x}");
    match CaptureConfig::for_silicon(major, minor, 0, 0) {
        Some(cfg) => {
            let model = capture_progs_9b::SILICON_TABLE
                .iter()
                .find(|r| r.major == major && (minor & r.minor_mask) == r.minor_val)
                .map(|r| r.model)
                .unwrap_or("?");
            println!(
                "imaging: subtype=0x{:04x} ({model}) → program {}×{}, bytes_per_line={}, lines_2d={}",
                cfg.subtype, cfg.prog.width, cfg.prog.height, cfg.bytes_per_line, cfg.lines_2d
            );
        }
        None => println!("imaging: no capture program resolves for this silicon"),
    }
    Ok(())
}

fn cmd_modes() -> Result<()> {
    let (mut dev, _) = RawDevice::open_any()?;
    let (major, minor) = read_silicon(&mut dev);
    let cfg = CaptureConfig::for_silicon(major, minor, 0, 0);
    match &cfg {
        Some(c) => println!(
            "silicon 0x{major:04x}/0x{minor:04x} → subtype 0x{:04x}: capture program available\n",
            c.subtype
        ),
        None => println!(
            "silicon 0x{major:04x}/0x{minor:04x}: NO capture program resolves — modes below are nominal\n"
        ),
    }
    for mode in ALL_MODES {
        let s = mode.canonical();
        println!(
            "{:<9} read={:?} recon_flags=0x{:06x} finger_detect={} chunk_2e={} calibrate={} fold={:?}",
            format!("{mode:?}"),
            s.read,
            s.recon_flags,
            s.finger_detect,
            s.include_chunk_2e,
            s.calibrate,
            s.fold,
        );
    }
    Ok(())
}

fn cmd_flash(a: &FlashArgs) -> Result<()> {
    let (mut dev, _) = RawDevice::open_any()?;
    let data = dev.read_flash(a.partition, a.addr, a.size)?;
    println!(
        "# read partition {} @0x{:x} len={} ({} bytes returned)",
        a.partition,
        a.addr,
        a.size,
        data.len()
    );
    match &a.out {
        Some(path) => {
            std::fs::write(path, &data)
                .map_err(|e| Error::Malformed(format!("write {path}: {e}")))?;
            println!("# wrote {} bytes → {path}", data.len());
        }
        None => hexdump(&data),
    }
    Ok(())
}

fn cmd_fwext() -> Result<()> {
    let (mut dev, _) = RawDevice::open_any()?;

    println!("# present on device (fwext partition 2):");
    match dev.get_fw_modules(2) {
        Ok(Some(fw)) => {
            println!(
                "  fwext {}.{} buildtime=0x{:08x}, {} module(s):",
                fw.major,
                fw.minor,
                fw.buildtime,
                fw.modules.len()
            );
            for m in &fw.modules {
                println!(
                    "    type=0x{:04x} subtype=0x{:04x} {}.{} size={}",
                    m.type_, m.subtype, m.major, m.minor, m.size
                );
            }
        }
        Ok(None) => {
            println!("  (none — fwext partition unreadable in this state, e.g. ROM/unprovisioned)")
        }
        Err(e) => println!("  ERROR {e}"),
    }

    // Wanted blobs for this identity, and whether the host has the bytes to supply them.
    let plan = dev.plan_rom_exit()?;
    let id = &plan.identity;
    println!(
        "\n# wanted for identity id8={} id9={} id4=0x{:x} id0a=0x{:x} subkey={}:",
        id.id8, id.id9, id.id4, id.id0a, id.subkey
    );
    let mut wanted: Vec<(&str, &fw_registry::FwModuleRecord)> = Vec::new();
    wanted.extend(
        fw_registry::rom_exit_modules(fw_registry::REGISTRY, id)
            .into_iter()
            .map(|r| ("rom-exit", r)),
    );
    for (label, flag) in [
        ("pre-arm", fw_registry::FwWantFlags::PRE_ARM),
        ("pre-arm-mode2", fw_registry::FwWantFlags::PRE_ARM_MODE2),
    ] {
        if let Some(r) = fw_registry::select_pre_arm(fw_registry::REGISTRY, id, flag) {
            wanted.push((label, r));
        }
    }
    if let Some(r) = fw_registry::select_wof_module(fw_registry::REGISTRY, id) {
        wanted.push(("wof", r));
    }

    if wanted.is_empty() {
        println!("  (none — this silicon wants no ROM-exit/pre-arm/WOF modules, e.g. 009b)");
    }
    let mut missing = 0usize;
    for (role, rec) in &wanted {
        let have = pre_arm::resolve_payload(rec).is_some();
        if !have {
            missing += 1;
        }
        println!(
            "  {:<14} flags=0x{:08x} len={:<6} src=0x{:016x}  host_bytes={}",
            role,
            rec.flags.bits(),
            rec.len,
            rec.src_addr,
            if have { "present" } else { "MISSING" }
        );
    }
    println!(
        "\n# {} wanted, {missing} missing on host (data/fw_modules/)",
        wanted.len()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Session subcommands (TLS).
// ---------------------------------------------------------------------------

/// Open a TLS session, sourcing the pairing per `--pairing` (auto by family) and the binding from
/// DMI (older family) / `SYNA_HW_BINDING` / empty (Windows `009b`).
fn bootstrap_session(cli: &Cli) -> Result<Session<NusbTransport>> {
    let (mut dev, (vid, pid)) = RawDevice::open_any()?;
    let profile = SensorProfile::for_id(vid, pid);
    println!(
        "# {vid:04x}:{pid:04x} {}",
        profile.map(|p| p.name).unwrap_or("(unprofiled)")
    );

    let use_flash = match cli.pairing {
        PairingSource::Flash => true,
        PairingSource::File => false,
        // Auto: the 009b always uses the Windows cert-store file. The older family stores its pairing
        // in flash (bound to the DMI serial, root-only), but a one-time `synfp rebind-pairing` re-seals
        // it into a portable cert-store — so prefer that file when it exists (runs as a normal user,
        // no root/DMI), falling back to flash + DMI only when no cert-store is present.
        PairingSource::Auto => {
            let usdk5 = matches!(profile.map(|p| p.init), Some(InitModel::Usdk5Handshake));
            let have_certstore = cli.certstore.is_some() || certstore::default_path().is_file();
            !usdk5 && !have_certstore
        }
    };

    let (cert_store, binding, src) = if use_flash {
        let store = dev.read_flash(1, 0, 0x1000)?;
        let binding = match std::env::var("SYNA_HW_BINDING") {
            Ok(s) => s.into_bytes(),
            Err(_) => DmiBinding::from_sysfs().map_err(|e| {
                Error::Malformed(format!(
                    "DMI binding needs the root-only DMI serial ({e}). Run once as root to make a \
                     portable cert-store: `sudo synfp rebind-pairing` — then `synfp` works as a \
                     normal user. (Or pass `--pairing file --certstore <path>` / set SYNA_HW_BINDING.)"
                ))
            })?
            .hw_key(),
        };
        (store, binding, "flash partition 1 + DMI binding")
    } else {
        let path = cli
            .certstore
            .clone()
            .unwrap_or_else(|| "certstore.bin".into());
        let store = synaptics_prometheus::certstore::read(&path)
            .map_err(|e| Error::Malformed(format!("read cert-store {path}: {e}")))?;
        let binding = std::env::var("SYNA_HW_BINDING")
            .map(String::into_bytes)
            .unwrap_or_default();
        (store, binding, "cert-store file + seat binding")
    };
    println!("# pairing: {src} ({} binding bytes)", binding.len());

    let transport = dev.into_transport();
    let sess = Session::establish(transport, &cert_store, &binding)?;
    println!("# ✓ session established");
    Ok(sess)
}

/// `synfp reboot` — full capture-firmware reboot (`0x05` mode 2). Clears all die state; the device
/// re-enumerates. The routine graceful shutdown ([`Session::drop`]) is a lighter stop+drain; use this
/// when you want a hard reset (e.g. after a fault, or to clear on-chip calibration/finger-detect state).
fn cmd_reboot(cli: &Cli) -> Result<()> {
    let mut sess = bootstrap_session(cli)?;
    // The reboot re-enumerates the device, so there is nothing to gracefully shut down afterwards.
    sess.set_shutdown_on_drop(false);
    sess.reboot_sensor()?;
    println!("# sensor rebooted (0x05 mode 2) — the device will re-enumerate");
    Ok(())
}

/// The two analog-island gain registers per AGC stage, from the canonical DLL register-name table
/// `g_scm_register_name_table@0x18013d478` (see [`ScmReg`]). `AI0`/`AI1` are the two analog islands
/// (zones). Reducing these lowers the pre-ADC analog gain so the naturally-brighter middle rows stop
/// saturating at 255. NB: the earlier probe stepped `0x80002078`/`0x80002150` — those are the *legacy
/// alias* table's addresses (`0x80002078` is actually [`ScmReg::ScmCf3ClkCtrl`], reads 0). Use these.
/// The direct AFE analog-gain registers to step. With the HW AGC disabled (`*_AGC_CTRL == 0`, true on
/// 0x0199), the `*_AGC_*_GAIN` registers are inert — the live pre-ADC gain is set by these direct AFE
/// config registers. `SCM_AFE_VGA` (variable-gain amp), `SCM_AFE_LNA2` (2nd low-noise amp) and
/// `SCM_AFE_LPF_VGA` (low-pass-filter VGA) are the gain-bearing ones.
const AGC_GAIN_REGS: [ScmReg; 3] =
    [ScmReg::ScmAfeVga, ScmReg::ScmAfeLna2, ScmReg::ScmAfeLpfVga];

/// The AFE config block to dump for diagnosis — which registers hold a live value tells us where the
/// pre-ADC analog gain actually lives (vs the disabled AGC loop's inert gain registers).
const AGC_DUMP_REGS: [ScmReg; 12] = [
    ScmReg::ScmAfeMasterCfg,
    ScmReg::ScmAfeLna2,
    ScmReg::ScmAfeVga,
    ScmReg::ScmAfeLpf,
    ScmReg::ScmAfeLpfVga,
    ScmReg::ScmAfeRms,
    ScmReg::ScmAfeCarr,
    ScmReg::ScmAfePdetCtrl,
    ScmReg::ScmAfePdetGain,
    ScmReg::ScmAfeLia,
    ScmReg::ScmAfePower1,
    ScmReg::ScmAfePower2,
];

/// Percent of the middle-band (rows `h/3..2h/3`) pixels clamped at/above 250 — the blown-out-middle
/// metric the AGC minimizes.
fn middle_clip_pct(img: &Image) -> f64 {
    let (w, h) = (img.width, img.height);
    if w == 0 || h < 3 {
        return 0.0;
    }
    let (y0, y1) = (h / 3, 2 * h / 3);
    let mut clipped = 0usize;
    let mut total = 0usize;
    for y in y0..y1 {
        for x in 0..w {
            total += 1;
            if img.pixels.get(y * w + x).copied().unwrap_or(0) >= 250 {
                clipped += 1;
            }
        }
    }
    if total == 0 {
        0.0
    } else {
        100.0 * clipped as f64 / total as f64
    }
}

/// Capture one no-finger frames-sync (EP-0x82) frame and return the RAW averaged image (no fold, no
/// conditioning) — the buffer whose middle band clips when the analog gain runs hot.
fn capture_nofinger_raw(
    sess: &mut Session<NusbTransport>,
    cfg: &CaptureConfig,
    factory_cal: &[u8],
    st8: u16,
    st9: u16,
) -> Result<Image> {
    let mut cap = CaptureSession::new(sess, cfg.clone(), factory_cal.to_vec(), None, st8, st9);
    let spec = CaptureMode::Stream.canonical();
    let (prog, _) = cap
        .resolve(&spec)
        .ok_or_else(|| Error::Malformed("agc: no frames-sync program resolves".into()))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let outcome =
        cap.capture(&prog, CaptureOpts::stream(spec.sync_frames), || Instant::now() < deadline)?;
    let raw = match outcome {
        CaptureOutcome::Stream(raw) if raw.is_ok() => raw,
        CaptureOutcome::Stream(raw) => {
            return Err(Error::Malformed(format!(
                "agc: frames-sync not ok (status=0x{:04x}, {}B)",
                raw.arm_status,
                raw.bytes.len()
            )));
        }
        _ => return Err(Error::Malformed("agc: no frame".into())),
    };
    let layout = cap.config().sync_layout(spec.sync_frames);
    // Diagnostic: dump the RAW EP-0x82 wire bytes (all frames, pre-average) to distinguish a real
    // sensor pedestal from a reconstruction artifact. SYNA_DUMP_RAW=<path>.
    if let Some(p) = std::env::var_os("SYNA_DUMP_RAW") {
        let _ = std::fs::write(&p, &raw.bytes);
        eprintln!(
            "# SYNA_DUMP_RAW: wrote {}B wire (stride {}, frames {}) -> {}",
            raw.bytes.len(),
            layout.wire_stride(),
            spec.sync_frames,
            std::path::Path::new(&p).display()
        );
    }
    let averaged = layout.average_second_frame(&raw.bytes).ok_or_else(|| {
        Error::Malformed("agc: frames-sync average failed (short EP-0x82 read?)".into())
    })?;
    let stride = layout.wire_stride();
    let (w, h) = (layout.line_width, layout.lines_2d);
    let mut pixels = Vec::with_capacity(w * h);
    for row in 0..h {
        let base = row * stride + synaptics_prometheus::capture_prog::SYNC_LINE_HEADER;
        pixels.extend_from_slice(&averaged[base..base + w]);
    }
    Ok(Image { width: w, height: h, pixels })
}

/// `synfp agc` — analog-gain diagnosis / feedback loop for the blown-out-middle 009a frame.
///
/// Default (dump-only): print the AGC register block ([`AGC_DUMP_REGS`]) + one no-finger frame's
/// middle-clip %, so we can see whether the HW AGC is enabled and at what gain — WITHOUT the earlier
/// mistake of poking the legacy-alias addresses. `--search` then disables the HW AGC ([`ScmReg::ScmVgaAgcCtrl`]
/// / [`ScmReg::ScmPgaAgcCtrl`]) and steps all four island gains ([`AGC_GAIN_REGS`]) down until the
/// middle band stops clipping. `synfp reboot` restores the sensor defaults. Older type-1 family only.
///
/// NB: the DLL's own 009a path (Lenovo `syna_lib_cal_step6_woe_cleanslate`, subtype `0x199` branch) does
/// NOT drive this analog AGC — it applies a host-side digital scale `(px-128)*num/den`. This loop is an
/// empirical analog-gain fix; digital scaling alone cannot recover pixels already saturated at 255.
fn cmd_agc(cli: &Cli, a: &AgcArgs) -> Result<()> {
    let mut sess = bootstrap_session(cli)?;
    let ctx = sess
        .bootstrap_with(BootstrapOptions::default())
        .map_err(|e| capture_hint(e, None))?;
    let cfg = ctx.cfg.clone();
    if line_update::key_calibration_line(cfg.subtype).is_none() {
        return Err(Error::Malformed(
            "agc: only the older type-1 family (0x0199 etc., frames-sync capture) is wired".into(),
        ));
    }
    let (st8, st9) = match sess.tunnel(&[0x17]) {
        Ok(pt) if pt.len() >= 12 => (pt[2 + 8] as u16, pt[2 + 9] as u16),
        _ => (0, 0),
    };

    // Dump the AGC register block: which registers actually hold a value tells us whether the HW AGC
    // is running (CTRL != 0 => enabled, gains are AGC-managed) or off (fixed default gain).
    println!("# AGC register block (g_scm_register_name_table@0x18013d478):");
    for reg in AGC_DUMP_REGS {
        match sess.tunnel_read_hw_reg32(reg.addr()) {
            Ok(v) => println!("#   {:<28} {:#010x} = {v:#010x}", reg.scm_name(), reg.addr()),
            Err(e) => println!("#   {:<28} {:#010x} = <err: {e}>", reg.scm_name(), reg.addr()),
        }
    }
    // Snapshot the island gains NOW (idle, post-bootstrap) — they read 0 once a capture powers the AFE
    // down, so this is the only place we see the live seed values.
    let mut gain_seed: Vec<(ScmReg, u8)> = Vec::new();
    for reg in AGC_GAIN_REGS {
        let v = (sess.tunnel_read_hw_reg32(reg.addr())? & 0xff) as u8;
        gain_seed.push((reg, v));
    }
    let baseline = capture_nofinger_raw(&mut sess, &cfg, &ctx.factory_cal_values, st8, st9)?;
    let base_clip = middle_clip_pct(&baseline);
    println!("# no-finger middle-clip: {base_clip:.1}%");
    log::info!("AGC dump: baseline middle-clip {base_clip:.1}%");

    if !a.search {
        println!("# (dump only — pass --search to run the gain-reduction loop)");
        return Ok(());
    }

    // Belt-and-braces: ensure the HW AGC stays disabled so it can't overwrite the AFE gain we set.
    for ctrl in [ScmReg::ScmVgaAgcCtrl, ScmReg::ScmPgaAgcCtrl] {
        sess.tunnel_write_hw_reg32(ctrl.addr(), 0)?;
    }

    // Seed from the idle snapshot taken before the baseline capture (the gain regs read 0 once a
    // capture powers the AFE down). Step only the non-zero islands down; island-1 is dormant (0).
    let mut gains: Vec<(ScmReg, u8, u8)> =
        gain_seed.iter().map(|&(reg, v0)| (reg, v0, v0)).collect();
    let start: String = gains
        .iter()
        .filter(|(_, v0, _)| *v0 != 0)
        .map(|(r, v0, _)| format!("{}={v0:#04x}", r.scm_name()))
        .collect::<Vec<_>>()
        .join(" ");
    println!("# search: start {start}; target middle-clip <= {:.1}%, step {}", a.target, a.step);

    // Stick-check: does a gain write even survive idle / a capture? Write (seed-step) to each
    // non-zero island, read back BEFORE any capture, then again AFTER one capture.
    for (reg, v0, _) in gains.iter().filter(|(_, v0, _)| *v0 != 0) {
        sess.tunnel_write_hw_reg32(reg.addr(), u32::from(v0.saturating_sub(a.step)))?;
    }
    for (reg, v0, _) in gains.iter().filter(|(_, v0, _)| *v0 != 0) {
        let rb = sess.tunnel_read_hw_reg32(reg.addr())? & 0xff;
        println!(
            "#   stick-check {}: wrote {:#04x}, idle read-back {rb:#04x}",
            reg.scm_name().trim_start_matches("SCM_"),
            v0.saturating_sub(a.step)
        );
    }
    let probe = capture_nofinger_raw(&mut sess, &cfg, &ctx.factory_cal_values, st8, st9)?;
    println!("#   stick-check: middle-clip after write {:.1}%", middle_clip_pct(&probe));
    for (reg, _v0, _) in gains.iter().filter(|(_, v0, _)| *v0 != 0) {
        let rb = sess.tunnel_read_hw_reg32(reg.addr())? & 0xff;
        println!(
            "#   stick-check {}: post-capture read-back {rb:#04x}",
            reg.scm_name().trim_start_matches("SCM_")
        );
    }
    let mut result = base_clip;
    for iter in 0..a.max_iters {
        for (reg, _v0, v) in &gains {
            sess.tunnel_write_hw_reg32(reg.addr(), u32::from(*v))?;
        }
        let img = capture_nofinger_raw(&mut sess, &cfg, &ctx.factory_cal_values, st8, st9)?;
        let sat = middle_clip_pct(&img);
        let now: String = gains
            .iter()
            .filter(|(_, v0, _)| *v0 != 0)
            .map(|(r, _, v)| format!("{}={v:#04x}", r.scm_name().trim_start_matches("SCM_")))
            .collect::<Vec<_>>()
            .join(" ");
        println!("#   iter {iter}: {now} -> middle-clip {sat:.1}%");
        log::info!("AGC iter {iter}: {now} -> middle-clip {sat:.1}%");
        result = sat;
        if sat <= a.target {
            break;
        }
        // Step every non-zero island down; stop when they've all hit the floor.
        let mut any_above_floor = false;
        for (_reg, v0, v) in &mut gains {
            if *v0 != 0 && *v != 0 {
                *v = v.saturating_sub(a.step);
                any_above_floor = true;
            }
        }
        if !any_above_floor {
            log::warn!("AGC: all island gains at floor, still {sat:.1}% clipped");
            break;
        }
    }
    let final_state: String = gains
        .iter()
        .filter(|(_, v0, _)| *v0 != 0)
        .map(|(r, _, v)| format!("{}={v:#04x}", r.scm_name().trim_start_matches("SCM_")))
        .collect::<Vec<_>>()
        .join(" ");
    println!("# AGC result: {final_state}, middle-clip {result:.1}% (was {base_clip:.1}%)");
    log::info!("AGC result: {final_state} middle-clip {result:.1}%");
    if let Some(out) = &a.out {
        let img = capture_nofinger_raw(&mut sess, &cfg, &ctx.factory_cal_values, st8, st9)?;
        let png = img.to_png_annotated(&[("stage", "raw"), ("note", "after AGC gain search")], None);
        std::fs::write(out, &png).map_err(|e| Error::Malformed(format!("write {out}: {e}")))?;
        println!("# wrote {}x{} → {out}", img.width, img.height);
    }
    Ok(())
}

fn cmd_db(cli: &Cli) -> Result<()> {
    let mut sess = bootstrap_session(cli)?;

    // StgWindsor container (Windows Hello name; python-validity uses its own containers).
    let mk_storage = |name: &str, nul: bool| -> Vec<u8> {
        let mut nb = name.as_bytes().to_vec();
        if nul {
            nb.push(0);
        }
        let mut c = vec![0x4bu8, 0x00, 0x00];
        c.extend_from_slice(&(nb.len() as u16).to_le_bytes());
        c.extend_from_slice(&nb);
        c
    };
    let mut storage: Option<db::UserStorage> = None;
    for (label, nul) in [("no-NUL", false), ("NUL", true)] {
        match sess.tunnel(&mk_storage("StgWindsor", nul)) {
            Ok(pt) if pre_arm::reply_status(&pt) == 0 => match db::UserStorage::parse(&pt[2..]) {
                Ok(s) => {
                    println!(
                        "StgWindsor ({label}): dbid={} users={}",
                        s.dbid,
                        s.users.len()
                    );
                    storage = Some(s);
                    break;
                }
                Err(e) => println!("StgWindsor ({label}) parse: {e}"),
            },
            Ok(pt) => println!(
                "StgWindsor ({label}): status=0x{:04x}",
                pre_arm::reply_status(&pt)
            ),
            Err(e) => println!("StgWindsor ({label}): {e}"),
        }
    }

    if let Some(s) = storage {
        let mut user_dbids: Vec<u16> = s.users.iter().map(|u| u.dbid).collect();
        if let Ok(rc) = sess.tunnel(&db::cmd_get_record_children(s.dbid))
            && pre_arm::reply_status(&rc) == 0
            && let Ok(children) = db::RecordChildren::parse(&rc[2..])
        {
            user_dbids = children.children.iter().map(|c| c.dbid).collect();
        }
        let mut total = 0usize;
        for uid in &user_dbids {
            match sess.tunnel(&db::cmd_get_user(*uid)) {
                Ok(ur) if pre_arm::reply_status(&ur) == 0 => match db::User::parse(&ur[2..]) {
                    Ok(user) => {
                        total += user.fingers.len();
                        println!(
                            "  user dbid={} fingers={} sid={}B",
                            user.dbid,
                            user.fingers.len(),
                            user.identity.len()
                        );
                        for f in &user.fingers {
                            println!(
                                "      finger dbid={} subtype=0x{:02x} ({}) storage={} template={}B",
                                f.dbid,
                                f.subtype,
                                db::finger_name(f.subtype),
                                f.storage,
                                f.value_size
                            );
                        }
                    }
                    Err(e) => println!("  user {uid} parse: {e}"),
                },
                Ok(ur) => println!(
                    "  get_user({uid}): status=0x{:04x}",
                    pre_arm::reply_status(&ur)
                ),
                Err(e) => println!("  get_user({uid}): {e}"),
            }
        }
        println!(
            "=> {total} enrolled print(s) across {} user(s)",
            user_dbids.len()
        );
    }
    if let Ok(pt) = sess.tunnel(&db::cmd_db_info())
        && pre_arm::reply_status(&pt) == 0
        && let Ok(info) = db::DbInfo::parse(&pt[2..])
    {
        println!(
            "db_info: total={} used={} free={} records={}",
            info.total, info.used, info.free, info.records
        );
    }
    Ok(())
}

/// Annotate a capture/calibration failure with the likely cause on non-`009b` silicon: our capture
/// path is `009b` (`0x2449`)-tuned, so another subtype's arm can reset the device.
fn capture_hint(e: Error, subtype: Option<u16>) -> Error {
    let sub = subtype
        .map(|s| format!(" for subtype 0x{s:04x}"))
        .unwrap_or_default();
    Error::Malformed(format!(
        "{e} — capture/calibration{sub} failed (the device may have reset). synfp's capture path \
         currently targets the 009b (0x2449) die; other subtypes need their own capture program \
         (see `synfp fwext` for the wanted/missing blobs)."
    ))
}

/// `synfp calibrate` — run the pv/DLL dark-field calibrate loop and report the no-finger middle-clip
/// before (unfolded) vs after (folded). The real fix for the 009a blown-out middle: the unfolded
/// frames-sync frame clips because it lacks the pre-ADC dark-field subtraction; the loop accumulates
/// `calib_data` and the folded capture de-clips. Cross-checked DLL-faithful (pv `calibrate()` ↔ DLL
/// step-6 `syna_cal_accumulate_darkfield_scaled@0x1800748b0`). No finger. Older type-1 family only.
fn cmd_calibrate(cli: &Cli, a: &CalibrateArgs) -> Result<()> {
    let mut sess = bootstrap_session(cli)?;
    let ctx = sess
        .bootstrap_with(BootstrapOptions::default())
        .map_err(|e| capture_hint(e, None))?;
    let cfg = ctx.cfg.clone();
    if line_update::key_calibration_line(cfg.subtype).is_none() {
        return Err(Error::Malformed(
            "calibrate: only the older type-1 family (0x0199 etc., frames-sync calibrate) is wired"
                .into(),
        ));
    }
    let factory = ctx.factory_cal_values.clone();
    let width = cfg.type_info.line_width as usize;

    // DIAGNOSTIC (SYNA_CALIB_DATA=<file>): skip the loop and do ONE no-stop folded capture with the
    // given (known-good, e.g. pv's) calib_data — isolates "does folding correct content reset?" from
    // "is our accumulated content wrong?".
    if let Some(p) = std::env::var_os("SYNA_CALIB_DATA") {
        let cd = std::fs::read(&p).map_err(|e| Error::Malformed(format!("read calib_data: {e}")))?;
        println!("# diagnostic: folding external calib_data {} B ({:?})", cd.len(), p);
        let (frame, stride, h) =
            session_cal::capture_calibrate_frame(&mut sess, &cfg, &factory, &cd)?;
        let clip = middle_clip_pct(&averaged_to_image(&frame, stride, width, h));
        println!("# folded (external calib_data) middle-clip: {clip:.1}%");
        return Ok(());
    }

    // Baseline: one UNFOLDED prime frame (empty calib_data) — the blown-out-middle reference. GATED off
    // by default: it arms the empty prime, and the loop's own first (prime) arm is ALSO empty — an
    // identical re-arm the sensor rejects 0x0450 (the DLL never sends two identical arms). Set
    // SYNA_CAL_BASELINE=1 to take it (e.g. under SYNA_CAL_FRAMES_SYNC where the loop reboots between).
    let clip_before = if std::env::var_os("SYNA_CAL_BASELINE").is_some() {
        let (before, stride, h) =
            session_cal::capture_calibrate_frame(&mut sess, &cfg, &factory, &[])?;
        let c = middle_clip_pct(&averaged_to_image(&before, stride, width, h));
        println!("# unfolded (pre-calibrate) middle-clip: {c:.1}%");
        log::info!("calibrate: baseline middle-clip {c:.1}%");
        c
    } else {
        f64::NAN
    };

    // Run the pv/DLL accumulate-and-fold loop → calib_data.
    let calib_data = session_cal::run_calibrate_loop(&mut sess, &cfg, &factory)?;
    println!("# calibrate loop done: calib_data {} B", calib_data.len());
    log::info!("calibrate: calib_data {} B", calib_data.len());

    let _ = clip_before; // baseline gated off by default (SYNA_CAL_BASELINE=1)

    // The calib_data is the dark-field correction to FOLD into the polled IDENTIFY (finger) arm — NOT a
    // standalone folded calibrate capture (folding a calibrate/frames-sync arm resets this die; pv/DLL
    // fold only the polled identify arm). Persist it so the finger identify capture folds it. The legible
    // before/after is the FINGER identify frame (finger-gated), not a no-finger folded frame.
    let cd_path = a
        .out
        .clone()
        .unwrap_or_else(|| "captures/009a-calib-data.bin".to_string());
    std::fs::write(&cd_path, &calib_data)
        .map_err(|e| Error::Malformed(format!("write {cd_path}: {e}")))?;
    println!("# calib_data saved → {cd_path} ({} B)", calib_data.len());
    println!("# fold it on the finger identify path (finger-gated):");
    println!("#   SYNA_CALIB_DATA={cd_path} synfp png --finger -o finger.png");
    Ok(())
}

/// Extract an [`Image`] from a line-averaged frames-sync buffer (`lines_2d × stride`, 8-byte wire
/// header per row).
fn averaged_to_image(averaged: &[u8], stride: usize, width: usize, height: usize) -> Image {
    let mut pixels = Vec::with_capacity(width * height);
    for row in 0..height {
        let base = row * stride + synaptics_prometheus::capture_prog::SYNC_LINE_HEADER;
        if base + width <= averaged.len() {
            pixels.extend_from_slice(&averaged[base..base + width]);
        } else {
            pixels.extend(std::iter::repeat_n(0u8, width));
        }
    }
    Image { width, height, pixels }
}

fn cmd_png(cli: &Cli, a: &PngArgs) -> Result<()> {
    if a.finger {
        // Rule #1: a finger-present capture is finger-DEPENDENT. The user runs this at the sensor.
        println!(
            "# --finger: place and hold a finger on the sensor when prompted ({}s window)",
            a.timeout_s
        );
    } else {
        println!(
            "# no-finger blank/still capture (frames-sync on the older type-1 family, else the \
             polled image arm; nothing is asserted about content)"
        );
    }
    let mut sess = bootstrap_session(cli)?;

    // Bootstrap resolves the capture config + folds calibration (dark/settle — no finger needed).
    let ctx = sess
        .bootstrap_with(BootstrapOptions::default())
        .map_err(|e| capture_hint(e, None))?;
    let cfg = ctx.cfg.clone();
    let subtype = cfg.subtype;
    let blocks_per_line = cfg.descramble_blocks_per_line();

    // st8/st9 (sensor-state bytes) feed the capture-program status match.
    let (st8, st9) = match sess.tunnel(&[0x17]) {
        Ok(pt) if pt.len() >= 12 => (pt[2 + 8] as u16, pt[2 + 9] as u16),
        _ => (0, 0),
    };

    let mut cap = CaptureSession::new(
        &mut sess,
        cfg,
        ctx.factory_cal_values,
        ctx.vendor_cal,
        st8,
        st9,
    );

    // Gain correction (older type-1 family, e.g. 0x0199): bootstrap DEFERS calibration for product '0'
    // (running step 6 at open destabilises the no-finger path). For the FINGER capture, run step 6 on
    // demand so the polled 0x4e identify folds the fresh clean-slate — this is the DEFAULT now that
    // reboot-on-drop leaves the die clean (see `Session::drop`). Best-effort: on step-6 failure fall
    // back to the unfolded (uncorrected) identify. `SYNA_NO_GAIN` forces the plain unfolded identify.
    if a.finger
        && std::env::var_os("SYNA_NO_GAIN").is_none()
        && line_update::key_calibration_line(subtype).is_some()
        && !cap.has_vendor_cal()
    {
        match cap.capture_vendor_cal() {
            Ok(()) => println!("# gain correction: step-6 clean-slate captured (folding the identify)"),
            Err(e) => eprintln!("# gain correction skipped (step-6 failed: {e}) — unfolded identify"),
        }
    }

    // With a finger → identify arm (finger-detect chunk + finger-gate); without → image arm.
    // Older product-'0' family (0x0199 etc.): the recon=8 image mode is set only by the DLL's
    // `syna_capture_image` and these dies REJECT it (ESHUTDOWN); the DLL captures them with recon=2
    // (`syna_build_capture_cmd02`: recon 0x80000→8 image-only, else →2). So force the no-finger image
    // arm to recon=2 for this family.
    // The older product-'0' family (0x0199 etc.) has NO polled no-finger image mode: its no-finger
    // capture is the frames-sync / CALIBRATE arm (recon=2, no finger-detect — the shape our step-6
    // dark arm proved works on the 009a), and its finger capture is the IDENTIFY arm. So: no-finger on
    // that family → frames-sync (EP-0x82); everything else → the polled 0x51 path.
    let use_stream = !a.finger && line_update::key_calibration_line(subtype).is_some();

    let spec = if a.finger {
        CaptureMode::Identify.canonical()
    } else if use_stream {
        CaptureMode::Stream.canonical()
    } else {
        CaptureMode::Image.canonical()
    };
    let (prog, _) = cap
        .resolve(&spec)
        .ok_or_else(|| Error::Malformed("no capture program resolves for this silicon".into()))?;
    let opts = if a.finger {
        // EXPERIMENT (SYNA_NO_PREARM=1): send the polled IDENTIFY arm with no Mode2 pre-arm — lets the
        // 0x26/0x4e bisect run without the pre-arm fw-module lookup (and matches the user's pre-arm-off
        // reset test).
        let pre_arm = std::env::var_os("SYNA_NO_PREARM").is_none();
        CaptureOpts::polled(MatcherSubmode::PolledIdentify, pre_arm)
    } else if use_stream {
        CaptureOpts::stream(spec.sync_frames)
    } else {
        CaptureOpts::polled_image(MatcherSubmode::PolledIdentify, false)
    };

    // SYNA_PRIME_ARM: the DLL primes with an UNFOLDED arm before a folded one — decrypted 009a
    // calibrate trace (captures/lenovo-009a-pairing): 944B prime (`0x30`=20, no fold) → 2000B blank
    // reply → 13712B folded (`0x30`=12788) → frame reply, back-to-back, NO teardown. Our cold folded
    // identify faults the die; the prime is the missing baseline context. Build the unfolded prime by
    // resolving with the `SYNA_CALIB_DATA` fold source removed, then send prime → folded back-to-back
    // via `capture_primed` (no stop/teardown between — the normal re-arm path's teardown clears the
    // prime). Extrapolated from the calibrate trace to the polled identify path.
    let prime_prog = if a.finger && std::env::var_os("SYNA_PRIME_ARM").is_some() {
        let saved = std::env::var_os("SYNA_CALIB_DATA");
        // SAFETY: single-threaded CLI setup; the env is only read by the resolve just below.
        unsafe { std::env::remove_var("SYNA_CALIB_DATA") };
        let prime = cap.resolve(&spec).map(|(p, _)| p);
        if let Some(v) = saved {
            unsafe { std::env::set_var("SYNA_CALIB_DATA", v) };
        }
        prime
    } else {
        None
    };

    let deadline = Instant::now() + Duration::from_secs(a.timeout_s);
    let outcome = match &prime_prog {
        Some(prime) => {
            log::info!(target: "syna::cmd", "prime → folded (DLL prime-before-fold, no teardown)");
            cap.capture_primed(prime, &prog, opts, || Instant::now() < deadline)
                .map_err(|e| capture_hint(e, Some(subtype)))?
        }
        None => cap
            .capture(&prog, opts, || Instant::now() < deadline)
            .map_err(|e| capture_hint(e, Some(subtype)))?,
    };

    let img = match outcome {
        CaptureOutcome::Polled(f) => {
            // Canonical polled pipeline (shared with the viewer).
            let dark_ref = if a.no_dark_ref { None } else { Some(f.body.as_slice()) };
            polled_stage_image(
                &f.body,
                f.header.width,
                f.header.height,
                blocks_per_line,
                dark_ref,
                a.stage.to_polled(),
            )
        }
        CaptureOutcome::Stream(raw) => {
            // Frames-sync (EP-0x82) reconstruction — the stream pipeline, not the polled stages.
            if !raw.is_ok() {
                return Err(Error::Malformed(format!(
                    "frames-sync arm not ok (status=0x{:04x}, {}B)",
                    raw.arm_status,
                    raw.bytes.len()
                )));
            }
            let layout = cap.config().sync_layout(spec.sync_frames);
            match recon_params(cap.config().prog.program) {
                Some(params) => reconstruct_sync_frame(&raw.bytes, layout, params).ok_or_else(|| {
                    Error::Malformed("frames-sync reconstruction failed (short EP-0x82 read?)".into())
                })?,
                None => {
                    // Older type-1 family: its capture program carries no `0x42` recon chunk, so there
                    // is no on-chip descramble to invert. Reproduce python-validity's `average()` for the
                    // `interleave>1` case: skip raw frame 0, average frame 1's `repeat_multiplier` line
                    // pairs, then strip the 8-byte wire header per line → a `line_width × lines_2d` frame.
                    let averaged = layout.average_second_frame(&raw.bytes).ok_or_else(|| {
                        Error::Malformed("frames-sync average failed (short EP-0x82 read?)".into())
                    })?;
                    let stride = layout.wire_stride();
                    let w = layout.line_width;
                    let h = layout.lines_2d;
                    let mut pixels = Vec::with_capacity(w * h);
                    for row in 0..h {
                        let base = row * stride + synaptics_prometheus::capture_prog::SYNC_LINE_HEADER;
                        pixels.extend_from_slice(&averaged[base..base + w]);
                    }
                    // The older-family capture program carries no `0x42` recon chunk, so there is no
                    // on-chip descramble to invert. This frames-sync frame is a CALIBRATION/dark frame
                    // (pv's `average()` for type-1 does not descramble it either); its per-column
                    // structure is the dark fixed-pattern, removed later by dark-subtraction against
                    // `calib_data`, NOT by a timeslot de-spread. (The timeslot de-spread IS applied — via
                    // the matcher `ir_recon_transform_image` — on the POLLED finger frame, where the input
                    // is dark-subtracted first; applying it to this raw DC-heavy dark frame instead
                    // AMPLIFIES the fixed pattern, measured colVAR 107→300. See `polled_stage_image`.)
                    Image { width: w, height: h, pixels }
                }
            }
        }
        CaptureOutcome::NoFrame { arm_status } => {
            return Err(Error::Malformed(format!(
                "no frame (arm_status=0x{arm_status:04x}) — {}",
                if a.finger {
                    "no finger within the window?"
                } else {
                    "arm rejected"
                }
            )));
        }
    };

    let meta = [
        (
            "provenance",
            "synfp png — processed frame, NOT validated as a fingerprint",
        ),
        ("stage", a.stage.label()),
        (
            "arm",
            if a.finger {
                "identify (finger)"
            } else if use_stream {
                "frames-sync (no-finger, EP-0x82)"
            } else {
                "image (no-finger, polled 0x51)"
            },
        ),
    ];
    let png = img.to_png_annotated(&meta, None);
    std::fs::write(&a.out, &png).map_err(|e| Error::Malformed(format!("write {}: {e}", a.out)))?;
    println!(
        "# wrote {}×{} {} image → {} ({} bytes). Stage={}; describe what is measured, not what it resembles (rule #7).",
        img.width,
        img.height,
        a.stage.label(),
        a.out,
        png.len(),
        a.stage.label()
    );
    Ok(())
}

/// One-time: read the (DMI-bound) pairing from flash, re-seal the host key under the empty binding,
/// and write a portable cert-store. Needs root once (the DMI serial); afterwards `--pairing file`
/// runs need neither root nor the serial. The output holds the host TLS key sealed only under the
/// public hardcoded seat key, so it is effectively the bare host key — written `0600`, keep private.
/// Default output path for `rebind-pairing`. Under `sudo` this targets the INVOKING user's
/// `~/.config/synaptics-fp-re/certstore.bin` (via `SUDO_USER`), not root's — so the file the later
/// as-a-user `synfp` run resolves is where its config search actually looks. Falls back to the
/// current user's config path.
fn rebind_default_out() -> std::path::PathBuf {
    if let Some(user) = std::env::var_os("SUDO_USER") {
        // getpwnam isn't in std; `/home/<user>` is correct on our targets — fall through if absent.
        let home = std::path::PathBuf::from("/home").join(&user);
        if home.is_dir() {
            return home
                .join(".config")
                .join(certstore::APP_DIR)
                .join(certstore::FILE);
        }
    }
    certstore::config_path().unwrap_or_else(|| std::path::PathBuf::from(certstore::FILE))
}

/// Hand a freshly written cert-store (and the app dir we created) back to the invoking user when
/// running under `sudo`, so they can read it without root — a root-owned 0600 file would defeat the
/// purpose. No-op when not sudo'd (`SUDO_UID` unset) or on any chown failure.
fn chown_to_invoking_user(path: &std::path::Path) {
    let Some(uid) = std::env::var("SUDO_UID").ok().and_then(|s| s.parse::<u32>().ok()) else {
        return;
    };
    let gid = std::env::var("SUDO_GID").ok().and_then(|s| s.parse::<u32>().ok());
    let _ = std::os::unix::fs::chown(path, Some(uid), gid);
    // The app dir (…/synaptics-fp-re); leave a pre-existing ~/.config alone.
    if let Some(dir) = path.parent() {
        let _ = std::os::unix::fs::chown(dir, Some(uid), gid);
    }
}

fn cmd_rebind(cli: &Cli, a: &RebindArgs) -> Result<()> {
    let (mut dev, (vid, pid)) = RawDevice::open_any()?;
    let profile = SensorProfile::for_id(vid, pid);
    println!(
        "# {vid:04x}:{pid:04x} {}",
        profile.map(|p| p.name).unwrap_or("(unprofiled)")
    );

    let use_flash = match cli.pairing {
        PairingSource::Flash => true,
        PairingSource::File => false,
        PairingSource::Auto => !matches!(profile.map(|p| p.init), Some(InitModel::Usdk5Handshake)),
    };
    let (sealed, from_binding) = if use_flash {
        let store = dev.read_flash(1, 0, 0x1000)?;
        let binding = match std::env::var("SYNA_HW_BINDING") {
            Ok(s) => s.into_bytes(),
            Err(_) => DmiBinding::from_sysfs()
                .map_err(|e| Error::Malformed(format!("DMI binding (run as root once?): {e}")))?
                .hw_key(),
        };
        (store, binding)
    } else {
        let path = cli
            .certstore
            .clone()
            .unwrap_or_else(|| "certstore.bin".into());
        let store = certstore::read(&path)
            .map_err(|e| Error::Malformed(format!("read cert-store {path}: {e}")))?;
        let binding = std::env::var("SYNA_HW_BINDING")
            .map(String::into_bytes)
            .unwrap_or_default();
        (store, binding)
    };

    // Re-seal under the empty binding → opens on any host with no DMI serial.
    let mut iv = [0u8; 16];
    os_rng().fill_bytes(&mut iv);
    let portable = pairing::rebind_cert_store(&sealed, &from_binding, b"", iv)?;

    let out = a
        .out
        .clone()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(rebind_default_out);
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&out, &portable)
        .map_err(|e| Error::Malformed(format!("write {}: {e}", out.display())))?;
    // The file is the unbound host key — restrict to the owner.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o600)).ok();
    // Run under sudo, hand the file (and the dir we created) back to the invoking user so they can
    // read it without root — otherwise a root-owned 0600 file defeats the whole point.
    chown_to_invoking_user(&out);

    println!(
        "# ✓ portable cert-store → {} ({} bytes, mode 0600)",
        out.display(),
        portable.len()
    );
    println!("# holds the host key under the UNBOUND seat key — keep it private.");
    println!("# now runs without root/DMI, e.g.:  synfp --pairing file db");
    Ok(())
}

/// Bytes per hex row, and the cap on rows printed to stdout (use `-o` to dump the rest).
const HEX_ROW: usize = 16;
const MAX_HEX_ROWS: usize = 64;

fn hexdump(data: &[u8]) {
    use std::fmt::Write as _;
    let mut line = String::with_capacity(10 + HEX_ROW * 3);
    for (i, chunk) in data.chunks(HEX_ROW).take(MAX_HEX_ROWS).enumerate() {
        line.clear();
        let _ = write!(line, "{:08x} ", i * HEX_ROW);
        for b in chunk {
            let _ = write!(line, " {b:02x}");
        }
        println!("{line}");
    }
    let shown = MAX_HEX_ROWS * HEX_ROW;
    if data.len() > shown {
        println!(
            "... ({} more bytes; use -o to dump all)",
            data.len() - shown
        );
    }
}
