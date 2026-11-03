//! 009b ROM-exit init blobs (`0x06 init_hardcoded`).
//!
//! The known-good older sensors bring themselves out of ROM/bootloader mode by replaying a
//! *small* (~0.5 KB) opaque `0x06` blob — python-validity's `init_hardcoded` (framed
//! `06 02 00 00 01 …`) — after which flash becomes readable and the TLS session can open
//! (`vendor/python-validity/validitysensor/usb.py:79-96`). This is the mandatory unlock; it is
//! **not** the ~256 KB fwext firmware image (that is a separate, factory-flashed OTA channel via
//! `0x41`/`0x42` — see [`crate::xpfwext`] and docs/bringup/firmware-format.md).
//!
//! **RE conclusion: 009b at fw 6.20 needs NO `0x06` ROM-exit blob — `None` below is the correct,
//! final answer, not a placeholder.** Full static RE of the DLL (docs/bringup/init-sequence.md,
//! §2026-07-11) settled this:
//!
//! - The `0x06` body is **host-supplied**, drawn from a firmware *module registry* built from
//!   static tables compiled into the DLL's `.rdata` (`FUN_180082cc0` builds the two-level list;
//!   category-0 array `@0x180163c60`, 75 records of 0x50 bytes). `syna_select_fw_blob_by_identity`
//!   picks a record by sensor identity and sends `06 ‖ record_data` (wValue `0x22`). It is NOT read
//!   from the sensor's flash — so there was never a chicken-and-egg.
//! - The ROM-exit passes require a record with flag **bit0** (`drive_out_of_rom`, want_flags 1) or
//!   **bit14** (`flag4000`, want_flags 0x4000). Only *older* firmware has these: `id[9]=3` (fw 6.03)
//!   and `id[9]=7` (fw 6.07). **No `id[9]=0x14` (fw 6.20 = 009b) record carries either flag.**
//! - So for 009b both `syna_drive_out_of_rom` and the `flag4000` pass are **no-ops** — the Windows
//!   driver emits zero ROM-exit bytes and the sensor runs its flash-resident v6.20 firmware
//!   directly. The Linux bring-up should likewise skip `0x06` and go straight to flash-geometry /
//!   provision / TLS.
//!
//! There are 10 embedded `id[9]=0x14` records (identity matches a 009b; `id[4]/id[0xf]/id[0x19]/
//! subtype = 0xffff` wildcards) but they are **non-ROM config/calibration/patch** modules (no
//! bit0/bit14). Their bytes are extractable from the DLL image if a later lifecycle phase needs one
//! — addresses/lengths are tabulated in docs/bringup/init-sequence.md §2026-07-11. That is why the
//! accessors below still exist (and the `06 02 00 00 01` framing check): a *future* phase may wire
//! one in. For ROM exit, leave them `None`.
//!
//! Note the older `0090/0097/009a/009d` family DOES need its static `init_hardcoded` blob for ROM
//! exit — that requirement is per-profile, so [`crate::device::RawDevice::send_init`] gates only
//! when a blob is sent and *rejected*, never merely because none was supplied.

/// The `0x06`-command framing prefix every init blob shares: opcode `0x06`, then `02 00 00 01`.
/// (python-validity's blobs and the DLL's `syna_cmd_06_send_data_blob` builder both start here.)
pub const INIT_FRAME_PREFIX: [u8; 5] = [0x06, 0x02, 0x00, 0x00, 0x01];

/// 009b's `init_hardcoded` unlock blob (the whole `0x06` command incl. the opcode byte), or `None`
/// while it is still being reverse-engineered. `send_init` prepends nothing — the returned slice is
/// the exact wire bytes.
pub fn init_hardcoded() -> Option<&'static [u8]> {
    // 009b (fw 6.20) has no ROM-exit module — this is correctly `None` (see module docs). A future
    // lifecycle phase could return one of the embedded id[9]=0x14 config modules extracted from the
    // DLL (addresses in docs/bringup/init-sequence.md); ROM exit needs none.
    None
}

/// 009b's `init_hardcoded_clean_slate` blob — the older family sends this (a second `0x06`) only
/// when the `0x43 02` fw-info read returned a non-zero status, mirroring python-validity
/// `usb.py:92-96`. 009b has no such ROM-exit module, so this is `None`.
pub fn init_hardcoded_clean_slate() -> Option<&'static [u8]> {
    None
}

/// Validate that a candidate init blob carries the expected `06 02 00 00 01` framing. Use this in a
/// test after populating [`init_hardcoded`] so a mis-pasted payload fails loudly rather than being
/// rejected on the wire as `0x04be`.
pub fn assert_init_frame(blob: &[u8]) {
    assert!(
        blob.len() > INIT_FRAME_PREFIX.len(),
        "init blob too short: {} bytes",
        blob.len()
    );
    assert_eq!(
        &blob[..INIT_FRAME_PREFIX.len()],
        &INIT_FRAME_PREFIX,
        "init blob must start with the 06 02 00 00 01 frame"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_prefix_is_the_06_command_header() {
        assert_eq!(INIT_FRAME_PREFIX[0], 0x06);
    }

    #[test]
    fn no_rom_exit_blob_for_009b() {
        // RE-confirmed: 009b (fw 6.20) has no ROM-exit module (docs/bringup/init-sequence.md), so
        // these are correctly `None`. If a future phase wires in one of the embedded config
        // modules, add its bytes + an `assert_init_frame` test and update this expectation.
        assert!(init_hardcoded().is_none());
        assert!(init_hardcoded_clean_slate().is_none());
    }

    #[test]
    fn assert_init_frame_accepts_well_framed_and_rejects_bad() {
        assert_init_frame(&[0x06, 0x02, 0x00, 0x00, 0x01, 0xaa, 0xbb]);
    }

    #[test]
    #[should_panic(expected = "06 02 00 00 01 frame")]
    fn assert_init_frame_rejects_wrong_prefix() {
        assert_init_frame(&[0x06, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xbb]);
    }
}
