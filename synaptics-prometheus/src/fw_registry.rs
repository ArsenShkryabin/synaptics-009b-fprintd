//! Firmware-module registry — the data-driven device-support table lifted from the vendor DLL.
//!
//! The USDK5 driver keeps an in-memory table of firmware *module* records, and at various
//! lifecycle points selects the record(s) matching the connected sensor's identity and uploads them
//! via opcode `0x06` (`06 ‖ record_data`, wValue `0x22`). ROM exit uses two passes:
//! `want` [`FwWantFlags::INIT`] (`0x4000`) then [`FwWantFlags::DRIVE_OUT_OF_ROM`] (`0x1`).
//!
//! This module brings that whole table into Rust so the driver is data-driven across the family
//! (add a sensor → the table already knows what, if anything, it needs). It mirrors:
//!  - the device-id whitelist `g_supported_device_id_table@0x180141c50` ([`crate::fw_registry::DEVICE_ID_MAP`]),
//!  - the record array `@0x180163c60` (75 × 0x50-byte records → [`crate::fw_registry::REGISTRY`]), and
//!  - the selector `syna_select_fw_blob_by_identity@0x180099fc0` ([`crate::fw_registry::select`]).
//!
//! **Payloads are not embedded.** Each [`crate::fw_registry::FwModuleRecord`] carries its identity/flags/length and the
//! DLL address (`src_addr`) of its ~0.1–12 KB module body, but not the ~492 KB of vendor firmware
//! bytes themselves (clean-room + size). `payload` is `None` until a specific device that needs a
//! module has its bytes supplied (extract from the DLL at `src_addr`/`len`, or reuse
//! python-validity's for the older family). Our only hardware target, 009b (fw 6.20), selects **no**
//! ROM-exit module at all (see the table), so it needs no payload — proving the mechanism.
//!
//! Provenance: every value here was extracted from `synaWudfBioUsb.dll` (MSI 5.5.11.1086); see
//! docs/bringup/init-sequence.md §2026-07-11.

use crate::proto::SensorStatus;

/// The wildcard sentinel the DLL uses in record match fields (`0xffff`).
pub const WILDCARD: u32 = 0xffff;

bitflags::bitflags! {
    /// Firmware-module **want-flags** — the `record[+0x2c]` capability bitmask matched by
    /// `syna_select_fw_blob_by_identity@0x180099fc0` (byte-identical in lenovo-sgx `@0x1800941d0`)
    /// with `(record.flags & want) == want`.
    ///
    /// One bit-space, two roles: a **record's** `flags` = capabilities it satisfies (often a
    /// composite, e.g. `PRE_ARM | PRE_ARM_MODE2` = `0x400080`); a requested **`want`** = the bits an
    /// upload site requires (usually one bit).
    ///
    /// **Corroboration:** only bits tied to a DLL call site are named (Ghidra-cited below). Composite
    /// component bits with no call site (`0x2/0x40/0x100/0x10000/0x100000`) are deliberately **not**
    /// named — records keep them verbatim via [`FwWantFlags::from_bits_retain`]. There is **no vendor
    /// enum** for these bits; the *module* a want loads is what's vendor-named (start/ondemand:
    /// irfix/auth/enroll/qmatcher/…). See `docs/bringup/fw-wants-flags.md`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FwWantFlags: u32 {
        /// `0x1` — 2nd ROM-exit pass. `syna_drive_out_of_rom@0x180068970`.
        const DRIVE_OUT_OF_ROM = 0x0000_0001;
        /// `0x4` — flag-4 config (several `scsCommands_*` DB paths). Dedup-exempt.
        const FLAG4            = 0x0000_0004;
        /// `0x8` — DB-prefix config. `syna_upload_fw_module_flag8@0x180068430`. Dedup-exempt.
        const DB_PREFIX        = 0x0000_0008;
        /// `0x10` — dedup-exempt bit. **Weak:** only seen in the dedup-exempt set; no caller passing
        /// it as a literal `want` was found.
        const FLAG10           = 0x0000_0010;
        /// `0x80` — pre-arm ondemand load, identify mode 1/3.
        /// `syna_capture_send_pre_arm_rom_config@0x1800685c0` (param4 [`PRE_ARM_FILTER_KEY`]).
        const PRE_ARM          = 0x0000_0080;
        /// `0x200` — `syna_upload_fw_module_flag200@0x1800684d0`. **Weak:** vtable-only, no direct
        /// `.text` caller found (may be legacy/indirect).
        const FLAG200          = 0x0000_0200;
        /// `0x4000` — device open / init (start modules). `syna_open_init_decide_format@0x18006e830`.
        /// Dedup-exempt.
        const INIT             = 0x0000_4000;
        /// `0x80000` — recon-mode-2 imaging arm (loads the irfix/imgrecon imager).
        /// `syna_recon_mode2_upload80000_dispatch@0x18006b450`. NB: no `cat0` row carries this —
        /// it selects from the recon/capture table, not [`REGISTRY`].
        const RECON2           = 0x0008_0000;
        /// `0x400000` — pre-arm mode-2 (pairs with [`Self::PRE_ARM`] as the `0x400080` record).
        /// `syna_capture_send_pre_arm_rom_config_mode2@0x180068800`.
        const PRE_ARM_MODE2    = 0x0040_0000;
        /// `0x800000` — WOF wake-module load. `syna_vfm_scm_wof_arm_disarm@0x18004ed90`.
        const WOF              = 0x0080_0000;
        /// `0x2000000` — **lenovo-sgx-only** *record* capability (absent from 009b; not a 009b want;
        /// likely SGX/TEE). Named for cross-DLL table parity, not because 009b requests it.
        const SGX              = 0x0200_0000;
    }
}

impl FwWantFlags {
    /// Uploads exempt from the `ctx+0x2d0` fw-info-valid dedup — re-sent every open/arm.
    /// `syna_upload_selected_fw_blob@0x180068bf0`: `{0x4, 0x8, 0x10, 0x4000}`.
    pub const ALWAYS_RESEND: FwWantFlags = FwWantFlags::FLAG4
        .union(FwWantFlags::DB_PREFIX)
        .union(FwWantFlags::FLAG10)
        .union(FwWantFlags::INIT);

    /// A record with `self` flags **satisfies** a requested `want` iff it contains every requested
    /// bit — the DLL's `(record.flags & want) == want`.
    #[inline]
    pub fn satisfies(self, want: FwWantFlags) -> bool {
        self.contains(want)
    }

    /// True if a `want` upload bypasses the dedup gate (re-sent every time).
    #[inline]
    pub fn is_always_resend(self) -> bool {
        self.intersects(Self::ALWAYS_RESEND)
    }
}

/// Registry composite flag on 009b idx39 (`0x400000|0x80`, @`0x1801a14d0`, len `0x2904`) — a *record*
/// value, **not** a literal `want`; matched when `want ∈ {DB_PREFIX, PRE_ARM_MODE2, FLAG200}` via
/// `(flags & want)==want`. Distinct from the pure-`PRE_ARM` row `@0x1801a3de0` (smaller — wins the
/// standard pre-arm tie-break).
pub const REGISTRY_FLAGS_CONFIG_400080: u32 = 0x0040_0080;
/// Registry row `@0x1801a5030` (`0x00100050`) — no `want` literal in `.text`; loses every tie-break.
/// **Dead for 009b** unless a dynamic/indirect caller is found.
pub const REGISTRY_FLAGS_UNUSED_100050: u32 = 0x0010_0050;
/// Registry row `@0x1801a7cf0` (`0x00000100`) — same: no upload `want=0x100` in the DLL. **Dead.**
pub const REGISTRY_FLAGS_UNUSED_100: u32 = 0x0000_0100;
/// `param4` / `record+0x30` filter passed by both pre-arm helpers (`syna_rom_exit_send_config`).
pub const PRE_ARM_FILTER_KEY: u32 = 0x22020;

/// One firmware-module record (the DLL's 0x50-byte record, metadata only — see module docs).
/// Match fields hold [`WILDCARD`] where the DLL accepts any value.
#[derive(Debug, Clone)]
pub struct FwModuleRecord {
    /// `+0x10` — sensor `id[8]` (ROM-identity byte 8). All records in this DLL: `6`.
    pub id8: u32,
    /// `+0x14` — sensor `id[9]` = firmware minor (e.g. `0x14` = fw 6.20 = 009b).
    pub id9: u32,
    /// `+0x18` — sensor `id[4]` (u32). `WILDCARD` on most; `0x48/0x8e/0xa4` on a few.
    pub id4: u32,
    /// `+0x1c` — sensor `id[0xf]`. `WILDCARD` throughout this DLL.
    pub id0f: u32,
    /// `+0x3c` — sensor `id[0xa]`. **Mandatory match, no wildcard** (the outer filter).
    pub id0a: u32,
    /// `+0x40` — sensor `id[0x19]` (u16). `WILDCARD` throughout this DLL.
    pub id19: u32,
    /// `+0x38` — sensor subtype (== `ctx+0x128`). `WILDCARD` throughout this DLL.
    pub subtype: u32,
    /// `+0x30` — matched against the selector's `param4`. `0` throughout this DLL.
    pub param30: u32,
    /// `+0x34` — subkey; matched against `FUN_18009a350` (for id8==6: `3` if `flags17&0x20==0`
    /// else `2`). Splits the table into a "3" half (records 0–49) and a "2" half (50–74).
    pub subkey: u32,
    /// `+0x2c` — capability flags. A `want` is satisfied iff `flags.contains(want)` (the DLL's
    /// `(flags & want) == want`). ROM-exit bits: [`FwWantFlags::DRIVE_OUT_OF_ROM`] / [`FwWantFlags::INIT`].
    /// Composites may carry bits we haven't named (kept via `from_bits_retain`).
    pub flags: FwWantFlags,
    /// `+0x44` — module payload length.
    pub len: u32,
    /// `+0x48` — address of the module body inside the DLL image (for on-demand extraction).
    pub src_addr: u64,
    /// The module bytes to send as `0x06`, once supplied. `None` = not bundled (extract on demand).
    pub payload: Option<&'static [u8]>,
}

/// Build a record with the fields that are constant across this DLL's table baked in
/// (`id8=6`, `id0f=id19=subtype=WILDCARD`, `param30=0`, `payload=None`).
const fn rec(
    id9: u32,
    id4: u32,
    id0a: u32,
    subkey: u32,
    flags: u32,
    len: u32,
    src_addr: u64,
) -> FwModuleRecord {
    FwModuleRecord {
        id8: 6,
        id9,
        id4,
        id0f: WILDCARD,
        id0a,
        id19: WILDCARD,
        subtype: WILDCARD,
        param30: 0,
        subkey,
        flags: FwWantFlags::from_bits_retain(flags),
        len,
        src_addr,
        payload: None,
    }
}

/// Supported-sensor whitelist: USB/ROM `product` byte (`status[0x0b]`) → device-id.
/// From `g_supported_device_id_table@0x180141c50` (zero-terminated). All map to device-id 1.
pub const DEVICE_ID_MAP: &[(u8, u32)] = &[(0x2b, 1), (0x2d, 1), (0x30, 1), (0x32, 1), (0x33, 1)];

/// Map a sensor `product` byte to its device-id, or `None` if unsupported.
pub fn device_id_for(product: u8) -> Option<u32> {
    DEVICE_ID_MAP
        .iter()
        .find(|(p, _)| *p == product)
        .map(|(_, id)| *id)
}

/// The firmware-module table (`@0x180163c60`, 75 records). `rec(id9, id4, id0a, subkey, flags, len,
/// src_addr)`. ROM-exit records are the ones with flag `0x1` (idx 2, fw 6.03) or `0x4000`
/// (idx 19/55, fw 6.07). **No fw-6.20 (id9=0x14 / 009b) record carries either → 009b needs none.**
pub const REGISTRY: &[FwModuleRecord] = &[
    rec(0x01, WILDCARD, 1, 3, 0x00100050, 0x1634, 0x180163ec0),
    rec(0x01, WILDCARD, 1, 3, 0x00000004, 0x2674, 0x180165500),
    rec(0x03, WILDCARD, 1, 3, 0x00000001, 0x0594, 0x180167b80), // bit0: drive_out_of_rom (fw6.03)
    rec(0x03, WILDCARD, 1, 3, 0x00000050, 0x29e4, 0x180168120),
    rec(0x03, WILDCARD, 1, 3, 0x00000004, 0x2b34, 0x18016ab10),
    rec(0x03, 0x48, 1, 3, 0x00010008, 0x0634, 0x18016d650),
    rec(0x03, 0x48, 1, 3, 0x00100000, 0x14e4, 0x18016dc90),
    rec(0x04, WILDCARD, 2, 3, 0x00000004, 0x2704, 0x18016f180),
    rec(0x05, WILDCARD, 1, 3, 0x00000050, 0x26a4, 0x180171890),
    rec(0x05, WILDCARD, 2, 3, 0x00000004, 0x2714, 0x180173f40),
    rec(0x06, WILDCARD, 1, 3, 0x00000080, 0x1094, 0x180176660),
    rec(0x06, WILDCARD, 1, 3, 0x00000050, 0x26c4, 0x180177700),
    rec(0x06, WILDCARD, 1, 3, 0x00000004, 0x2834, 0x180179dd0),
    rec(0x06, 0x8e, 1, 3, 0x00010008, 0x06c4, 0x18017c610),
    rec(0x06, WILDCARD, 1, 3, 0x00800000, 0x0604, 0x18017cce0),
    rec(0x07, WILDCARD, 1, 3, 0x00400080, 0x2fb4, 0x18017d2f0),
    rec(0x07, WILDCARD, 1, 3, 0x00000080, 0x1b94, 0x1801802b0),
    rec(0x07, WILDCARD, 1, 3, 0x00000050, 0x2a64, 0x180181e50),
    rec(0x07, WILDCARD, 1, 3, 0x00000100, 0x0e84, 0x1801848c0),
    rec(0x07, 0xa4, 1, 3, 0x00004000, 0x01f4, 0x180185750), // bit14: flag4000 (fw6.07, subkey3)
    rec(0x07, WILDCARD, 1, 3, 0x00000004, 0x2dd4, 0x180185950),
    rec(0x07, 0xa4, 1, 3, 0x00010008, 0x0a84, 0x180188730),
    rec(0x07, WILDCARD, 1, 3, 0x00800000, 0x0384, 0x1801891c0),
    rec(0x08, WILDCARD, 1, 3, 0x00000080, 0x1144, 0x180189550),
    rec(0x08, WILDCARD, 1, 3, 0x00400000, 0x1cb4, 0x18018a6a0),
    rec(0x08, WILDCARD, 1, 3, 0x00000050, 0x29b4, 0x18018c360),
    rec(0x08, WILDCARD, 1, 3, 0x00000004, 0x2994, 0x18018ed20),
    rec(0x08, WILDCARD, 1, 3, 0x00800000, 0x0394, 0x1801916c0),
    rec(0x0a, WILDCARD, 1, 3, 0x00400080, 0x13c4, 0x180191a60),
    rec(0x0a, WILDCARD, 1, 3, 0x00000080, 0x0d64, 0x180192e30),
    rec(0x0a, WILDCARD, 2, 3, 0x00000004, 0x2704, 0x180193ba0),
    rec(0x0b, WILDCARD, 1, 3, 0x00000002, 0x0934, 0x1801962b0),
    rec(0x0b, WILDCARD, 1, 3, 0x00400080, 0x2a04, 0x180196bf0),
    rec(0x0b, WILDCARD, 1, 3, 0x00000080, 0x11f4, 0x180199600),
    rec(0x0b, WILDCARD, 1, 3, 0x00000050, 0x2814, 0x18019a800),
    rec(0x0b, WILDCARD, 1, 3, 0x00000100, 0x0fc4, 0x18019d020),
    rec(0x0b, WILDCARD, 1, 3, 0x00000004, 0x17d4, 0x18019dff0),
    rec(0x0b, WILDCARD, 1, 3, 0x00100000, 0x1684, 0x18019f7d0),
    rec(0x0b, WILDCARD, 1, 3, 0x00800000, 0x0664, 0x1801a0e60),
    rec(0x14, WILDCARD, 1, 3, 0x00400080, 0x2904, 0x1801a14d0), // cfg via want=8/0x400000/0x200 — not literal
    rec(0x14, WILDCARD, 1, 3, 0x00000080, 0x1244, 0x1801a3de0), // standard pre-arm (want=0x80)
    rec(0x14, WILDCARD, 1, 3, 0x00100050, 0x2cb4, 0x1801a5030), // dead on 009b (no matching want in .text)
    rec(0x14, WILDCARD, 1, 3, 0x00000100, 0x0e24, 0x1801a7cf0), // dead on 009b (no want=0x100 upload)
    rec(0x14, WILDCARD, 1, 3, 0x00000004, 0x16a4, 0x1801a8b20),
    rec(0x14, WILDCARD, 1, 3, 0x00800000, 0x0644, 0x1801aa1d0),
    rec(0x15, WILDCARD, 1, 3, 0x00000080, 0x1084, 0x1801aa820),
    rec(0x15, WILDCARD, 1, 3, 0x00400000, 0x1bc4, 0x1801ab8b0),
    rec(0x15, WILDCARD, 1, 3, 0x00100050, 0x2c04, 0x1801ad480),
    rec(0x15, WILDCARD, 1, 3, 0x00000100, 0x0e44, 0x1801b0090),
    rec(0x15, WILDCARD, 1, 3, 0x00000004, 0x15a4, 0x1801b0ee0),
    rec(0x03, WILDCARD, 1, 2, 0x00000050, 0x13e4, 0x1801b2490),
    rec(0x03, WILDCARD, 1, 2, 0x00000004, 0x2624, 0x1801b3880),
    rec(0x07, WILDCARD, 1, 2, 0x00400080, 0x2f44, 0x1801b5eb0),
    rec(0x07, WILDCARD, 1, 2, 0x00000080, 0x1a14, 0x1801b8e00),
    rec(0x07, WILDCARD, 1, 2, 0x00000050, 0x2a64, 0x1801ba820),
    rec(0x07, 0xa4, 1, 2, 0x00004000, 0x01e4, 0x1801bd290), // bit14: flag4000 (fw6.07, subkey2)
    rec(0x07, WILDCARD, 1, 2, 0x00000004, 0x2ce4, 0x1801bd480),
    rec(0x07, 0xa4, 1, 2, 0x00010008, 0x0a84, 0x1801c0170),
    rec(0x08, WILDCARD, 1, 2, 0x00000080, 0x1144, 0x1801c0c00),
    rec(0x08, WILDCARD, 1, 2, 0x00400000, 0x1cb4, 0x1801c1d50),
    rec(0x08, WILDCARD, 1, 2, 0x00000050, 0x27c4, 0x1801c3a10),
    rec(0x08, WILDCARD, 1, 2, 0x00000004, 0x2994, 0x1801c61e0),
    rec(0x0b, WILDCARD, 1, 2, 0x00400080, 0x2a04, 0x1801c8b80),
    rec(0x0b, WILDCARD, 1, 2, 0x00000080, 0x11f4, 0x1801cb590),
    rec(0x0b, WILDCARD, 1, 2, 0x00000050, 0x2814, 0x1801cc790),
    rec(0x0b, WILDCARD, 1, 2, 0x00000004, 0x17d4, 0x1801cefb0),
    rec(0x14, WILDCARD, 1, 2, 0x00400080, 0x2904, 0x1801d0790), // fw6.20 (009b) — config, not ROM-exit
    rec(0x14, WILDCARD, 1, 2, 0x00000080, 0x1244, 0x1801d30a0),
    rec(0x14, WILDCARD, 1, 2, 0x00100050, 0x2cb4, 0x1801d42f0),
    rec(0x14, WILDCARD, 1, 2, 0x00000004, 0x16a4, 0x1801d6fb0),
    rec(0x15, WILDCARD, 1, 2, 0x00000002, 0x0844, 0x1801d8660),
    rec(0x15, WILDCARD, 1, 2, 0x00000080, 0x0eb4, 0x1801d8eb0),
    rec(0x15, WILDCARD, 1, 2, 0x00400000, 0x12a4, 0x1801d9d70),
    rec(0x15, WILDCARD, 1, 2, 0x00100050, 0x2c04, 0x1801db020),
    rec(0x15, WILDCARD, 1, 2, 0x00000004, 0x15a4, 0x1801ddc30),
];

/// The sensor-identity view the selector matches against — extracted from the `0x01` sensor-status
/// response (the ROM-identity struct the DLL keeps at `*(ctx+0x28)`).
#[derive(Debug, Clone)]
pub struct SensorIdentity {
    pub id4: u32,
    pub id8: u8,
    pub id9: u8,
    pub id0a: u8,
    pub id0f: u8,
    pub id19: u16,
    /// `subkey` = `FUN_18009a350`: for id8==6, `3` if `flags17&0x20==0` else `2`; else `0`.
    pub subkey: u32,
    /// Sensor subtype (`ctx+0x128`, from the `0x35` config query). `None` when not yet queried —
    /// then only records with a `WILDCARD` subtype can match (which is all of them in this DLL).
    pub subtype: Option<u32>,
}

impl SensorIdentity {
    /// Build the identity from a parsed [`SensorStatus`] (its payload is the ROM-identity struct).
    pub fn from_status(s: &SensorStatus) -> Self {
        let p = &s.payload; // SensorStatus::parse guarantees len >= 0x24
        let id8 = p[8];
        let flags17 = p[0x17];
        let subkey = if id8 == 6 {
            if flags17 & 0x20 == 0 { 3 } else { 2 }
        } else {
            0
        };
        SensorIdentity {
            id4: u32::from_le_bytes([p[4], p[5], p[6], p[7]]),
            id8,
            id9: p[9],
            id0a: p[0x0a],
            id0f: p[0x0f],
            id19: u16::from_le_bytes([p[0x19], p[0x1a]]),
            subkey,
            subtype: None,
        }
    }
}

/// Select the best record matching `id` under `want_flags`/`deny_flags`/`param4` — a faithful port
/// of `syna_select_fw_blob_by_identity@0x180099fc0`. Returns `None` if nothing matches, or on the
/// two genuine-ambiguity cases the DLL bails on.
pub fn select<'a>(
    records: &'a [FwModuleRecord],
    id: &SensorIdentity,
    want_flags: FwWantFlags,
    deny_flags: FwWantFlags,
    param4: u32,
) -> Option<&'a FwModuleRecord> {
    let mut best: Option<&FwModuleRecord> = None;
    let mut have_exact_subtype = false; // bVar2
    let mut have_exact_id19 = false; // iVar6 == 1
    let matches_w = |key: u32, val: u32| key == WILDCARD || key == val;

    for r in records {
        // Mandatory id[0xa] gate (no wildcard), then the flag test, then the wildcard-able keys.
        if r.id0a != id.id0a as u32 {
            continue;
        }
        if !r.flags.satisfies(want_flags) || r.flags.intersects(deny_flags) {
            continue;
        }
        if !matches_w(r.id8, id.id8 as u32)
            || !matches_w(r.id9, id.id9 as u32)
            || !matches_w(r.id4, id.id4)
            || !matches_w(r.id0f, id.id0f as u32)
            || !matches_w(r.id19, id.id19 as u32)
        {
            continue;
        }
        if r.subtype != WILDCARD && id.subtype != Some(r.subtype) {
            continue;
        }
        if r.param30 != WILDCARD && r.param30 != param4 {
            continue;
        }
        // subkey: the sensor side (id.subkey) is never WILDCARD in this DLL, so it must equal the
        // record's subkey.
        if id.subkey != WILDCARD && id.subkey != r.subkey {
            continue;
        }

        let exact_subtype = id.subtype == Some(r.subtype);
        let exact_id19 = r.id19 == id.id19 as u32;
        let mut chosen = r;
        if let Some(b) = best {
            // The DLL bails on a genuine tie between a subtype-exact and an id19-exact candidate.
            if exact_subtype && !exact_id19 && have_exact_id19 {
                return None;
            }
            if !exact_subtype && exact_id19 && have_exact_subtype {
                return None;
            }
            chosen = b;
            if r.len < b.len
                && (exact_subtype || !have_exact_subtype)
                && (exact_id19 || !have_exact_id19)
            {
                chosen = r;
            }
        }
        best = Some(chosen);
        if exact_subtype {
            have_exact_subtype = true;
        }
        if exact_id19 {
            have_exact_id19 = true;
        }
    }
    best
}

/// Pre-capture ROM config module for [`FwWantFlags::PRE_ARM`] or [`FwWantFlags::PRE_ARM_MODE2`].
///
/// Tries [`PRE_ARM_FILTER_KEY`] first (DLL literal), then `param4=0` because the static DLL table
/// lifted into [`REGISTRY`] stores `record+0x30=0` for all rows (runtime fw-partition tables may
/// differ). Returns `None` if nothing matches.
pub fn select_pre_arm<'a>(
    records: &'a [FwModuleRecord],
    id: &SensorIdentity,
    want_flags: FwWantFlags,
) -> Option<&'a FwModuleRecord> {
    select(records, id, want_flags, FwWantFlags::empty(), PRE_ARM_FILTER_KEY)
        .or_else(|| select(records, id, want_flags, FwWantFlags::empty(), 0))
}

/// The WOF wake firmware module for this sensor (`want_flags=0x800000`, `deny_flags=0`, `param4=0`)
/// — a faithful call of `syna_select_fw_blob_by_identity(ctx, container, 0x800000, 0, 0)` from the
/// WOF-arm path. Identity-keyed, so it resolves the right module across the device family (009b =
/// `rec(0x14,…,0x00800000,0x0644,0x1801aa1d0)`). `None` if the sensor ships no WOF module
/// (e.g. fw 6.20 on the subkey-2 half — `flags17&0x20` set — has no `0x800000` row; only subkey 3 does).
pub fn select_wof_module<'a>(
    records: &'a [FwModuleRecord],
    id: &SensorIdentity,
) -> Option<&'a FwModuleRecord> {
    select(records, id, FwWantFlags::WOF, FwWantFlags::empty(), 0)
}

/// The ROM-exit module(s) this sensor needs, in the DLL's order (the `0x4000` pass then the `1`
/// pass; `deny_flags=0`, `param4=0`). **Empty for 009b** — its firmware ships no ROM-exit module.
pub fn rom_exit_modules<'a>(
    records: &'a [FwModuleRecord],
    id: &SensorIdentity,
) -> Vec<&'a FwModuleRecord> {
    [FwWantFlags::INIT, FwWantFlags::DRIVE_OUT_OF_ROM]
        .into_iter()
        .filter_map(|want| select(records, id, want, FwWantFlags::empty(), 0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(id9: u8, id4: u32, id0a: u8, subkey: u32) -> SensorIdentity {
        SensorIdentity {
            id4,
            id8: 6,
            id9,
            id0a,
            id0f: 0,
            id19: 0,
            subkey,
            subtype: None,
        }
    }

    #[test]
    fn table_shape_matches_the_dll() {
        assert_eq!(REGISTRY.len(), 75);
        let total: u64 = REGISTRY.iter().map(|r| r.len as u64).sum();
        assert_eq!(total, 503_708, "total payload len must match the DLL");
        assert_eq!(
            REGISTRY.iter().filter(|r| r.flags.contains(FwWantFlags::DRIVE_OUT_OF_ROM)).count(),
            1
        );
        assert_eq!(
            REGISTRY.iter().filter(|r| r.flags.contains(FwWantFlags::INIT)).count(),
            2
        );
    }

    #[test]
    fn nine_b_selects_the_wof_module() {
        // 009b (id9=0x14, subkey 3) → the single 0x800000 WOF wake-module @0x1801aa1d0, len 0x644.
        let id = ident(0x14, WILDCARD, 1, 3);
        let m = select_wof_module(REGISTRY, &id).expect("009b has a WOF module");
        assert!(m.flags.contains(FwWantFlags::WOF));
        assert_eq!(m.src_addr, 0x1801aa1d0);
        assert_eq!(m.len, 0x0644);
        // The DLL table carries five WOF modules (id9 = 6/7/8/0x0b/0x14, all subkey 3).
        assert_eq!(
            REGISTRY.iter().filter(|r| r.flags.contains(FwWantFlags::WOF)).count(),
            5,
        );
    }

    #[test]
    fn nine_b_needs_no_rom_exit_module() {
        // 009b = fw 6.20 (id9=0x14), id0a=1, subkey 3 (flags17 bit5 clear) — the whole point.
        let id = ident(0x14, WILDCARD, 1, 3);
        assert!(rom_exit_modules(REGISTRY, &id).is_empty());
        // ...and the same with subkey 2 (flags17 bit5 set).
        let id2 = ident(0x14, WILDCARD, 1, 2);
        assert!(rom_exit_modules(REGISTRY, &id2).is_empty());
    }

    #[test]
    fn fw603_selects_the_bit0_module() {
        // fw 6.03 (id9=3) → the single drive_out_of_rom (bit0) record @0x180167b80.
        let id = ident(0x03, WILDCARD, 1, 3);
        let m = rom_exit_modules(REGISTRY, &id);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].flags, FwWantFlags::DRIVE_OUT_OF_ROM);
        assert_eq!(m[0].src_addr, 0x180167b80);
    }

    #[test]
    fn fw607_selects_the_bit14_module_by_subkey() {
        // fw 6.07 (id9=7) with id4=0xa4 → the flag4000 (bit14) record, picked by subkey.
        let m3 = rom_exit_modules(REGISTRY, &ident(0x07, 0xa4, 1, 3));
        assert_eq!(m3.len(), 1);
        assert_eq!((m3[0].flags, m3[0].src_addr), (FwWantFlags::INIT, 0x180185750));
        let m2 = rom_exit_modules(REGISTRY, &ident(0x07, 0xa4, 1, 2));
        assert_eq!((m2[0].flags, m2[0].src_addr), (FwWantFlags::INIT, 0x1801bd290));
        // Without the id4=0xa4 discriminator, no bit14 record matches.
        assert!(rom_exit_modules(REGISTRY, &ident(0x07, 0x1234, 1, 3)).is_empty());
    }

    #[test]
    fn device_id_whitelist() {
        assert_eq!(device_id_for(0x33), Some(1)); // 009b
        assert_eq!(device_id_for(0x30), Some(1));
        assert_eq!(device_id_for(0xff), None);
    }

    /// When `data/fw_modules/` is populated locally, verify blobs against the committed manifest.
    #[test]
    fn manifest_matches_local_blobs_if_present() {
        use sha2::{Digest, Sha256};
        use std::path::Path;

        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("data/fw_modules");
        let manifest_path = dir.join("MANIFEST.json");
        if !manifest_path.exists() {
            return;
        }
        let text = std::fs::read_to_string(&manifest_path).expect("read MANIFEST.json");
        for row in REGISTRY {
            let name = format!("fwmod_{:016x}.bin", row.src_addr);
            let blob_path = dir.join(&name);
            if !blob_path.exists() {
                continue;
            }
            let blob = std::fs::read(&blob_path).expect("read blob");
            assert_eq!(
                blob.len(),
                row.len as usize,
                "{name} length mismatch vs REGISTRY"
            );
            // digest 0.11 returns `Array`, which (unlike GenericArray) has no LowerHex impl.
            let digest: String =
                Sha256::digest(&blob).iter().map(|b| format!("{b:02x}")).collect();
            assert!(
                text.contains(&digest),
                "{name} sha256 {digest} missing from MANIFEST.json"
            );
        }
    }

    /// Guard against the task-#29-masking scenario: a `data/fw_modules/` that exists but is EMPTY of
    /// vendor blobs (only the committed `MANIFEST.json` present). The `resolve_payload` no-op that
    /// followed silently skipped the pre-arm for a week. The vendor blobs are gitignored, so the tree
    /// is legitimately either fully checked out or absent — a PARTIAL set is the bug. If ANY blob is
    /// present we require ALL manifest modules to be present; if NONE are present the tree simply isn't
    /// checked out (skip). Complements [`manifest_matches_local_blobs_if_present`], which checks the
    /// *content* of whatever blobs happen to be there but tolerates missing ones.
    #[test]
    fn fw_module_dir_is_all_or_nothing() {
        use std::path::Path;

        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("data/fw_modules");
        let text = std::fs::read_to_string(dir.join("MANIFEST.json"))
            .expect("MANIFEST.json is committed (data/fw_modules/MANIFEST.json) and readable");
        let manifest: serde_json::Value =
            serde_json::from_str(&text).expect("MANIFEST.json parses as JSON");
        let modules = manifest["modules"].as_array().expect("MANIFEST has a modules[] array");
        assert!(!modules.is_empty(), "MANIFEST.json lists no modules");

        let missing: Vec<&str> = modules
            .iter()
            .map(|m| m["filename"].as_str().expect("each module row has a string filename"))
            .filter(|name| !dir.join(name).exists())
            .collect();

        // No blobs at all ⇒ vendor tree not checked out; `resolve_payload` handles per-record absence
        // (and errors loudly if a *required* one is requested at runtime).
        if missing.len() == modules.len() {
            return;
        }
        assert!(
            missing.is_empty(),
            "data/fw_modules/ is PARTIALLY populated ({} present, {} MISSING) — this is the \
             empty/partial-dir regression that silently no-ops the pre-arm (task #29). Copy the full \
             vendor blob set into data/fw_modules/. Missing: {missing:?}",
            modules.len() - missing.len(),
            missing.len(),
        );
    }

    #[test]
    fn want_flag_constants_match_dll_literals() {
        assert_eq!(FwWantFlags::FLAG4.bits(), 4);
        assert_eq!(FwWantFlags::RECON2.bits(), 0x80000);
        assert_eq!(FwWantFlags::DB_PREFIX.bits(), 8);
        assert_eq!(FwWantFlags::PRE_ARM.bits(), 0x80);
        assert_eq!(FwWantFlags::WOF.bits(), 0x0080_0000);
        // The dedup-exempt set is exactly {0x4, 0x8, 0x10, 0x4000}.
        assert_eq!(FwWantFlags::ALWAYS_RESEND.bits(), 0x4 | 0x8 | 0x10 | 0x4000);
        assert!(FwWantFlags::FLAG4.is_always_resend());
        assert!(FwWantFlags::INIT.is_always_resend());
        assert!(!FwWantFlags::PRE_ARM.is_always_resend());
        // satisfies() mirrors (record & want) == want, incl. the 0x400080 composite record.
        let composite = FwWantFlags::from_bits_retain(REGISTRY_FLAGS_CONFIG_400080);
        assert!(composite.satisfies(FwWantFlags::PRE_ARM));
        assert!(composite.satisfies(FwWantFlags::PRE_ARM_MODE2));
        assert!(!composite.satisfies(FwWantFlags::WOF));
        // Un-named composite component bits still round-trip (from_bits_retain).
        assert_eq!(
            FwWantFlags::from_bits_retain(REGISTRY_FLAGS_UNUSED_100050).bits(),
            0x0010_0050
        );
    }
}
