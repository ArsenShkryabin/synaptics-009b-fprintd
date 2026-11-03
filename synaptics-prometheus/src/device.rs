//! `RawDevice` — the pre-TLS command layer over a [`Transport`].
//!
//! These are the commands that work in ROM/bootloader mode before a secure session
//! exists (RomInfo, flash/fw info, sensor id). Post-handshake commands ride inside the
//! TLS record layer (`crate::session`, WIP). Read-only: no write/destructive opcode is
//! reachable from here.

use crate::error::{Error, Result};
use crate::fw_registry::{self, FwModuleRecord, SensorIdentity};
use crate::proto::{FlashInfo, FwInfo, Opcode, Response, RomInfo, SensorStatus};
use crate::transport::Transport;

/// Read-only view collected by [`RawDevice::bringup_prefix`] — steps 3–6 of the vendor
/// ROM→working init (docs/bringup/init-sequence.md), everything before the `0x06` module uploads.
#[derive(Debug, Clone)]
pub struct BringupPrefix {
    /// `0x45` get_db_info probe (step 3). `0x0000` or `0x0401` (AlreadyInState) are both benign.
    pub db_info_status: u16,
    /// `0x01` sensor status (step 4) — identity + provisioning/format bits.
    pub status: SensorStatus,
    /// `0x43 02` firmware/module table for partition 2 (step 6). `None` if the partition holds no
    /// firmware / is unreadable (non-zero status, e.g. `0x04af`/`0x04b0` in ROM mode).
    pub fw_p2: Option<FwInfo>,
}

pub struct RawDevice<T: Transport> {
    transport: T,
    pub max_response: usize,
}

/// Result of [`RawDevice::send_init`] — the ROM-exit sequence mirroring python-validity's
/// `Usb.send_init` (`vendor/python-validity/validitysensor/usb.py:79-96`).
#[derive(Debug, Clone)]
pub struct SendInitReport {
    /// `0x01` ROM/ASIC identity (must succeed for anything else to run).
    pub rom_info: RomInfo,
    /// `0x19` init step accepted.
    pub init_step_ok: bool,
    /// Wire status of `0x43 02` (fwext partition info). A non-zero value in ROM mode (e.g.
    /// `0x04af`) is expected and is what triggers the clean-slate follow-up.
    pub fw_p2_status: u16,
    /// Wire status of the `0x06 init_hardcoded` send, or `None` if no blob was available to send.
    pub init_blob_status: Option<u16>,
    /// Wire status of the `0x06 init_hardcoded_clean_slate` send, or `None` if it was not sent.
    pub clean_slate_status: Option<u16>,
    /// `Some(reason)` only when an init blob was sent and the sensor *rejected* it. `None` on the
    /// normal path — including 009b, which correctly sends no `0x06` at all.
    pub gate: Option<&'static str>,
}

/// What the firmware-module registry says a sensor needs to leave ROM — from
/// [`RawDevice::plan_rom_exit`].
#[derive(Debug, Clone)]
pub struct RomExitPlan {
    /// Device-id from the whitelist, or `None` if the sensor's `product` byte is unsupported.
    pub device_id: Option<u32>,
    /// The identity the registry selection was keyed on.
    pub identity: SensorIdentity,
    /// The ROM-exit `0x06` modules to upload, in the DLL's order. **Empty for 009b.**
    pub modules: Vec<&'static FwModuleRecord>,
}

impl<T: Transport> RawDevice<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            max_response: 100 * 1024,
        }
    }

    /// Send a raw request (opcode byte + args), read and status-check the response.
    pub fn transact(&mut self, request: &[u8]) -> Result<Response> {
        let opcode = *request.first().unwrap_or(&0);
        self.transport.write_cmd(request)?;
        let raw = self.transport.read_cmd(self.max_response)?;
        Response::parse(opcode, &raw)
    }

    /// Send a request built from an [`Opcode`] + little-endian args, requiring status ok.
    pub fn cmd(&mut self, op: Opcode, args: &[u8]) -> Result<Response> {
        let mut req = Vec::with_capacity(1 + args.len());
        req.push(op.byte());
        req.extend_from_slice(args);
        self.transact(&req)?.ok(op.byte())
    }

    /// Same as [`cmd`](Self::cmd) but returns the response even on non-zero status
    /// (for probes where a non-zero status is meaningful, e.g. "no such partition").
    pub fn cmd_raw(&mut self, op: Opcode, args: &[u8]) -> Result<Response> {
        let mut req = Vec::with_capacity(1 + args.len());
        req.push(op.byte());
        req.extend_from_slice(args);
        self.transact(&req)
    }

    // ---- typed pre-TLS reads --------------------------------------------------

    /// `0x01` — ROM/ASIC identity.
    pub fn get_rom_info(&mut self) -> Result<RomInfo> {
        let r = self.cmd(Opcode::GetRomInfo, &[])?;
        RomInfo::parse(&r.payload)
    }

    /// `0x3e` — flash IC id + partition table. Returns the parsed table on status ok.
    pub fn get_flash_info(&mut self) -> Result<FlashInfo> {
        let r = self.cmd(Opcode::GetFlashInfo, &[])?;
        FlashInfo::parse(&r.payload)
    }

    /// `0x43` — firmware/partition header. `Ok(None)` if the partition holds no firmware
    /// (non-zero status such as `0x04af`/`0x04b0`).
    pub fn get_fw_info(&mut self, partition: u8) -> Result<Option<Response>> {
        let r = self.cmd_raw(Opcode::GetFwInfo, &[partition])?;
        if r.status.is_ok() {
            Ok(Some(r))
        } else {
            Ok(None)
        }
    }

    // ---- vendor ROM→working init prefix (read-only steps 3–6) --------------------------------
    // Reproduces the pre-unlock portion of `syna_open_init_decide_format` over the bulk path.
    // Steps 1–2 (plugin caps query) are skipped — that data is derivable from USB enumeration;
    // steps 7–9 (fw-module table load + the two `0x06` upload passes) are NOT done here (they
    // mutate device RAM and need the module blobs). See docs/bringup/init-sequence.md.

    /// `0x45` — get_db_info probe (init step 3). Returns the raw wire status without failing:
    /// `0x0000` and `0x0401` (AlreadyInState) are both benign; other values are informational.
    /// ghidra: `syna_init_probe_db_info` → `syna_cmd_45_db_info`.
    pub fn probe_db_info(&mut self) -> Result<u16> {
        Ok(self.cmd_raw(Opcode::DbInfo, &[])?.status.wire())
    }

    /// `0x01` — sensor status (init step 4): identity + provisioning/format bits.
    /// ghidra: `syna_read_sensor_status` → `syna_cmd_01_get_rom_info` +
    /// `syna_parse_status_response@0x180060720`.
    pub fn read_sensor_status(&mut self) -> Result<SensorStatus> {
        let r = self.cmd(Opcode::GetRomInfo, &[])?;
        SensorStatus::parse(&r.payload)
    }

    /// `0x43 <partition>` — firmware/module table (init step 6). `Ok(None)` if the partition has
    /// no firmware (non-zero status). ghidra: `syna_read_fw_info_partition` →
    /// `syna_cmd_43_get_fw_info`.
    pub fn get_fw_modules(&mut self, partition: u8) -> Result<Option<FwInfo>> {
        let r = self.cmd_raw(Opcode::GetFwInfo, &[partition])?;
        if r.status.is_ok() {
            Ok(Some(FwInfo::parse(&r.payload)?))
        } else {
            Ok(None)
        }
    }

    /// Run the **read-only** ROM→working init prefix (steps 3–6) and report what the sensor
    /// exposes: db-info probe status, sensor identity/provisioning status, and the partition-2
    /// firmware module table. Non-destructive — issues only `0x45`, `0x01`, `0x43 02`. It stops
    /// before the `0x06` unlock ([`send_init`](Self::send_init)), which needs the 009b init blob.
    pub fn bringup_prefix(&mut self) -> Result<BringupPrefix> {
        let db_info_status = self.probe_db_info()?; // step 3: 0x45
        let status = self.read_sensor_status()?; // step 4: 0x01
        let fw_p2 = self.get_fw_modules(2)?; // step 6: 0x43 02
        Ok(BringupPrefix {
            db_info_status,
            status,
            fw_p2,
        })
    }

    // ---- non-destructive init / control (needed to lift the sensor out of ROM mode) ----
    // These are control ops the vendor driver issues on every boot. They do NOT mutate the
    // template DB or flash *data* (that is the `writes`-gated erase/write/partition path);
    // `write_hw_reg32` pokes a hardware control register (e.g. the flash-power enable).

    /// `0x19` — init step (part of `send_init`). Control command.
    pub fn init_step(&mut self) -> Result<Response> {
        self.cmd(Opcode::InitStep, &[])
    }

    /// `0x07` — read a 32-bit hardware register. `pack('<BLB', 7, addr, 4)`.
    pub fn read_hw_reg32(&mut self, addr: u32) -> Result<u32> {
        let mut args = addr.to_le_bytes().to_vec();
        args.push(4);
        let r = self.cmd(Opcode::ReadHwReg32, &args)?;
        if r.payload.len() < 4 {
            return Err(Error::ShortResponse {
                opcode: Opcode::ReadHwReg32.byte(),
                got: r.payload.len() + 2,
                need: 6,
            });
        }
        Ok(u32::from_le_bytes([
            r.payload[0],
            r.payload[1],
            r.payload[2],
            r.payload[3],
        ]))
    }

    /// `0x08` — write a 32-bit hardware register. `pack('<BLLB', 8, addr, val, 4)`.
    /// Control op (pokes a HW register); not a flash/DB data write.
    pub fn write_hw_reg32(&mut self, addr: u32, val: u32) -> Result<()> {
        let mut args = addr.to_le_bytes().to_vec();
        args.extend_from_slice(&val.to_le_bytes());
        args.push(4);
        self.cmd(Opcode::WriteHwReg32, &args)?;
        Ok(())
    }

    /// `0x40` — read a region of a flash partition. `pack('<BBBHLL', 0x40, part, 1, 0, addr, size)`.
    /// Pure read (the cert-store lives in partition 1).
    ///
    /// The reply carries its own header *after* the status word: `[len:u32 le][pad:u16][data:len]`.
    /// [`Response::parse`] already strips the 2-byte status, so the returned payload starts with the
    /// 6-byte `len‖pad` header — we skip it and return exactly the `len` flash bytes (matching
    /// python-validity `flash.read_flash`: `sz,=unpack('<xxLxx', rsp[:8]); return rsp[8:8+sz]`).
    /// First exercised against real flash on a python-validity-paired `009a` (our `009b` flash is
    /// dark), which is where the missing header-strip surfaced as a cert-store parse failure.
    pub fn read_flash(&mut self, partition: u8, addr: u32, size: u32) -> Result<Vec<u8>> {
        let mut args = vec![partition, 1u8, 0u8, 0u8];
        args.extend_from_slice(&addr.to_le_bytes());
        args.extend_from_slice(&size.to_le_bytes());
        let payload = self.cmd(Opcode::ReadFlash, &args)?.payload;
        /// `len:u32 ‖ pad:u16` in-reply header (the status word is stripped upstream).
        const READ_REPLY_HDR: usize = 6;
        let len = payload
            .get(0..4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
            .ok_or_else(|| Error::Malformed("0x40 read reply too short for length header".into()))?;
        payload
            .get(READ_REPLY_HDR..READ_REPLY_HDR + len)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| {
                Error::Malformed(format!(
                    "0x40 read reply truncated: header declares {len}B but only {}B follow",
                    payload.len().saturating_sub(READ_REPLY_HDR)
                ))
            })
    }

    /// Read and parse the sensor's on-flash **cert-store** (partition 1) — the host TLS
    /// identity Windows provisioned. **Non-destructive** (pure `0x40` read).
    ///
    /// Guarded: first checks `get_flash_info`. If the partition table is empty (the `ff:ff`
    /// "flash not accessible" state), this returns an error **instead of** doing what
    /// python-validity's `init_flash` does there — reformat + re-pair, which would destroy the
    /// Windows enrollment. Only reads when partition 1 actually exists.
    pub fn read_cert_store(&mut self) -> Result<crate::pairing::CertStore> {
        let fi = self.get_flash_info()?;
        if fi.partitions.is_empty() {
            return Err(Error::Unimplemented(
                "flash not accessible (0 partitions / jedec ff:ff) — cert store unreadable in \
                 this state; refusing to format (that would wipe the Windows pairing). Needs the \
                 flash powered/loaded first (e.g. a genuine cold boot).",
            ));
        }
        let raw = self.read_flash(1, 0, 0x1000)?;
        crate::pairing::parse_cert_store(&raw)
    }

    /// Enable the flash controller's power domain: `write_hw_reg32(0x8000205c, 7)` then read back
    /// `0x80002080` (expected 2 or 3). Returns the read-back value.
    ///
    /// **Provisioning-only.** The vendor driver issues this over an *established TLS session* while
    /// (re)flashing firmware (python-validity `upload_fwext.py:34`), never during a normal ROM
    /// exit. It is NOT part of [`send_init`](Self::send_init): sent in ROM mode it returns `0x0404`
    /// (the earlier bring-up bug — see docs/bringup/init-flow-vs-impl.md §3). Kept here so the firmware
    /// re-flash path (behind the `writes` feature) can call it; do not use it to "wake" the flash.
    pub fn flash_power_enable(&mut self) -> Result<u32> {
        self.write_hw_reg32(0x8000_205c, 7)?;
        self.read_hw_reg32(0x8000_2080)
    }

    /// `0x06` — send a variable-length data blob, framing the opcode for a *payload-without-opcode*
    /// (`06 ‖ data`; ghidra: `syna_cmd_06_send_data_blob@0x180088140`). This is the generic `0x06`
    /// primitive; the ROM-exit `init_hardcoded` blobs already include their own `0x06 02 00 00 01`
    /// framing and are sent verbatim by [`send_init`](Self::send_init) instead. Control/init write,
    /// not a flash/DB data write.
    pub fn send_data_blob(&mut self, data: &[u8]) -> Result<Response> {
        let mut req = Vec::with_capacity(1 + data.len());
        req.push(Opcode::SendDataBlob.byte());
        req.extend_from_slice(data);
        self.transact(&req)
    }

    /// `0x1a` — commit / cleanup. Bare one-byte command (`syna_cmd_1a_commit_or_skip`
    /// sends `[0x1a]`, wValue 2; or skips the round-trip entirely if state is already clear).
    pub fn commit(&mut self) -> Result<Response> {
        self.cmd_raw(Opcode::Commit, &[])
    }

    /// Consult the embedded firmware-module registry and upload any ROM-exit `0x06` modules
    /// (`want=0x4000` then `want=1`). ghidra: `syna_upload_fw_modules_flag4000` +
    /// `syna_drive_out_of_rom`.
    pub fn drive_out_of_rom(&mut self) -> Result<Vec<crate::bringup::RomExitUpload>> {
        let modules = self.plan_rom_exit()?.modules;
        crate::bringup::upload_rom_exit_modules(self, &modules)
    }

    /// Consult the embedded firmware-module registry ([`crate::fw_registry`], a faithful port of the
    /// DLL's `syna_select_fw_blob_by_identity`) to decide which `0x06` ROM-exit modules THIS sensor
    /// needs. Reads sensor status (`0x01`), builds the identity, checks the device-id whitelist, and
    /// selects. Device-agnostic: for the older `0090/97/9a` family it yields their init module(s);
    /// for 009b it yields **nothing** (fw 6.20 ships no ROM-exit module). Non-destructive.
    pub fn plan_rom_exit(&mut self) -> Result<RomExitPlan> {
        let status = self.read_sensor_status()?;
        let identity = SensorIdentity::from_status(&status);
        let device_id = fw_registry::device_id_for(status.device_id);
        let modules = fw_registry::rom_exit_modules(fw_registry::REGISTRY, &identity);
        Ok(RomExitPlan {
            device_id,
            identity,
            modules,
        })
    }

    /// Bring the sensor out of ROM/bootloader mode — the vendor `send_init` happy path, byte-for
    /// byte as python-validity does it (`vendor/python-validity/validitysensor/usb.py:79-96`):
    ///
    /// ```text
    /// 0x01  (rom info, must succeed)
    /// 0x19  (init step)
    /// 0x43 02  (fwext partition info — status captured, non-zero is fine in ROM mode)
    /// 0x06  init_hardcoded        (the unlock)
    /// 0x06  init_hardcoded_clean_slate   (only if 0x43 02 returned non-zero)
    /// ```
    ///
    /// After the `0x06` unlock succeeds, flash becomes readable and the TLS session can open; this
    /// method stops at the unlock and the caller proceeds to the session layer.
    ///
    /// The init blobs are passed in (rather than hard-wired) so this stays sensor-agnostic: the
    /// older `0090/0097/009a/009d` family passes its static blobs, **009b passes `None`** — RE
    /// confirmed 009b (fw 6.20) ships no ROM-exit module and its Windows driver sends zero `0x06`
    /// bytes (docs/bringup/init-sequence.md §2026-07-11; [`crate::blobs_9b`]). Each `Some` slice is
    /// the **full `0x06` command incl. opcode + `02 00 00 01` framing** and is sent verbatim (do
    /// NOT route it through [`send_data_blob`](Self::send_data_blob), which prepends a `0x06`).
    ///
    /// When `init_hardcoded` is `None` the `0x06` step is simply skipped — no gate — and the caller
    /// proceeds to flash-geometry / provision / TLS. `gate` is set only when a blob was sent and
    /// the sensor *rejected* it. Non-destructive: no flash-erase/write, no partition-flash, no DB
    /// mutation.
    pub fn send_init(
        &mut self,
        init_hardcoded: Option<&[u8]>,
        clean_slate: Option<&[u8]>,
    ) -> Result<SendInitReport> {
        let rom_info = self.get_rom_info()?; // 0x01
        let init_step_ok = self.init_step().is_ok(); // 0x19
                                                     // 0x43 02 — fwext partition info. Its status decides the clean-slate follow-up; a non-zero
                                                     // value (0x04af/0x04b0 in ROM mode) is expected, so read it without failing.
        let fw_p2 = self.cmd_raw(Opcode::GetFwInfo, &[2])?;
        let fw_p2_ok = fw_p2.status.is_ok();
        let fw_p2_status = fw_p2.status.wire();

        // 0x06 init_hardcoded — the unlock, when the sensor needs one. 009b (fw 6.20) does NOT: its
        // DLL ships no ROM-exit module, so `init_hardcoded` is `None` and 0x06 is skipped (no gate).
        // The older family passes its static blob here.
        let (init_blob_status, clean_slate_status, gate) = match init_hardcoded {
            None => (None, None, None),
            Some(blob) => {
                // Blob already carries the opcode + framing; send verbatim.
                let resp = self.transact(blob)?;
                // Clean-slate follow-up only if the fwext read failed (python-validity usb.py:92-96).
                let cs_status = match (fw_p2_ok, clean_slate) {
                    (false, Some(cs)) => Some(self.transact(cs)?.status.wire()),
                    _ => None,
                };
                let gate = (!resp.status.is_ok()).then_some(
                    "0x06 init_hardcoded rejected — wrong bytes for this sensor's fw/keys (see \
                     init_blob_status).",
                );
                (Some(resp.status.wire()), cs_status, gate)
            }
        };

        Ok(SendInitReport {
            rom_info,
            init_step_ok,
            fw_p2_status,
            init_blob_status,
            clean_slate_status,
            gate,
        })
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
    pub fn into_transport(self) -> T {
        self.transport
    }
}

#[cfg(feature = "nusb-backend")]
impl RawDevice<crate::transport::NusbTransport> {
    /// Open the first connected supported sensor and wrap it.
    pub fn open_any() -> Result<(Self, (u16, u16))> {
        let ids = crate::devices::SensorProfile::all_ids();
        let (t, id) = crate::transport::NusbTransport::open_any(&ids)?;
        Ok((Self::new(t), id))
    }

    /// Open a specific `(vid, pid)`.
    pub fn open(vid: u16, pid: u16) -> Result<Self> {
        Ok(Self::new(crate::transport::NusbTransport::open(vid, pid)?))
    }
}

// Silence unused-import warnings on non-default backends.
#[allow(unused_imports)]
use Error as _Error;

#[cfg(test)]
mod send_init_tests {
    use super::*;
    use crate::transport::Transport;
    use std::collections::VecDeque;

    /// A scripted transport: records every command written, replays canned responses FIFO.
    struct ScriptedTransport {
        writes: Vec<Vec<u8>>,
        responses: VecDeque<Vec<u8>>,
    }

    impl ScriptedTransport {
        fn new(responses: Vec<Vec<u8>>) -> Self {
            Self {
                writes: Vec::new(),
                responses: responses.into(),
            }
        }
    }

    impl Transport for ScriptedTransport {
        fn write_cmd(&mut self, data: &[u8]) -> Result<()> {
            self.writes.push(data.to_vec());
            Ok(())
        }
        fn read_cmd(&mut self, _max: usize) -> Result<Vec<u8>> {
            self.responses
                .pop_front()
                .ok_or_else(|| Error::Usb("scripted transport: no more responses".into()))
        }
        fn read_bulk(&mut self, _max: usize) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
        fn read_interrupt(&mut self, _max: usize, _timeout_ms: u64) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    fn ok_status() -> Vec<u8> {
        vec![0x00, 0x00]
    }
    fn rom_info_resp() -> Vec<u8> {
        // status ok + >= 0x10 payload bytes so RomInfo::parse succeeds.
        let mut v = ok_status();
        v.extend_from_slice(&[0u8; 0x12]);
        v
    }

    #[test]
    fn happy_path_sends_01_19_4302_then_06_verbatim() {
        // 0x01, 0x19, 0x43 02 (ok → no clean-slate), 0x06 init.
        let responses = vec![rom_info_resp(), ok_status(), ok_status(), ok_status()];
        let mut dev = RawDevice::new(ScriptedTransport::new(responses));
        let blob: &[u8] = &[0x06, 0x02, 0x00, 0x00, 0x01, 0xaa, 0xbb];
        let r = dev.send_init(Some(blob), None).unwrap();

        assert!(r.gate.is_none(), "unexpected gate: {:?}", r.gate);
        assert_eq!(r.init_blob_status, Some(0));
        assert_eq!(r.clean_slate_status, None);

        let w = &dev.transport_mut().writes;
        assert_eq!(w[0], vec![0x01]);
        assert_eq!(w[1], vec![0x19]);
        assert_eq!(w[2], vec![0x43, 0x02]);
        assert_eq!(
            w[3], blob,
            "0x06 init blob must be sent verbatim, not re-framed"
        );
        assert_eq!(w.len(), 4);
    }

    #[test]
    fn no_blob_skips_06_without_gating() {
        // 009b path: no ROM-exit blob → 0x06 skipped, and that is NOT a gate.
        let responses = vec![rom_info_resp(), ok_status(), ok_status()];
        let mut dev = RawDevice::new(ScriptedTransport::new(responses));
        let r = dev.send_init(None, None).unwrap();

        assert!(r.gate.is_none(), "no-blob must not gate: {:?}", r.gate);
        assert_eq!(r.init_blob_status, None);
        let w = &dev.transport_mut().writes;
        assert_eq!(w.len(), 3, "no 0x06 may be sent when the blob is None");
        assert!(w.iter().all(|c| c[0] != 0x06));
    }

    #[test]
    fn rejected_blob_sets_gate() {
        // Older-family path where the sent blob is rejected → gate set.
        let responses = vec![
            rom_info_resp(),
            ok_status(),
            ok_status(),      // 0x43 02 ok → no clean-slate
            vec![0xbe, 0x04], // 0x06 → 0x04be InitBlobRejected
        ];
        let mut dev = RawDevice::new(ScriptedTransport::new(responses));
        let blob: &[u8] = &[0x06, 0x02, 0x00, 0x00, 0x01, 0x11];
        let r = dev.send_init(Some(blob), None).unwrap();

        assert_eq!(r.init_blob_status, Some(0x04be));
        assert!(r.gate.is_some(), "a rejected blob must gate");
    }

    #[test]
    fn clean_slate_follows_a_nonzero_fwinfo() {
        // 0x43 02 → 0x04af (fwext not loaded) triggers the clean-slate blob.
        let responses = vec![
            rom_info_resp(),
            ok_status(),
            vec![0xaf, 0x04], // 0x43 02 → 0x04af
            ok_status(),      // 0x06 init
            ok_status(),      // 0x06 clean-slate
        ];
        let mut dev = RawDevice::new(ScriptedTransport::new(responses));
        let init: &[u8] = &[0x06, 0x02, 0x00, 0x00, 0x01, 0x11];
        let clean: &[u8] = &[0x06, 0x02, 0x00, 0x00, 0x01, 0x22];
        let r = dev.send_init(Some(init), Some(clean)).unwrap();

        assert_eq!(r.fw_p2_status, 0x04af);
        assert_eq!(r.clean_slate_status, Some(0));
        let w = &dev.transport_mut().writes;
        assert_eq!(w[3], init);
        assert_eq!(w[4], clean);
        assert_eq!(w.len(), 5);
    }

    /// `read_flash` must strip the in-reply `[len:u32][pad:u16]` header and return exactly the
    /// declared flash bytes — regression for the `009a` cert-store parse failure (the header used
    /// to leak into the returned buffer, e.g. a 0x1000 read came back as 0x1006 bytes).
    #[test]
    fn read_flash_strips_len_pad_header() {
        let data: Vec<u8> = (0..0x40u16).map(|i| i as u8).collect();
        // wire reply: status(00 00) ‖ len:u32 le ‖ pad:u16 ‖ data
        let mut reply = ok_status();
        reply.extend_from_slice(&(data.len() as u32).to_le_bytes());
        reply.extend_from_slice(&[0xff, 0xff]); // pad — must not leak through
        reply.extend_from_slice(&data);
        // extra trailing bytes past `len` (as real hardware zero-pads the USB frame) are dropped.
        reply.extend_from_slice(&[0xaa; 8]);

        let mut dev = RawDevice::new(ScriptedTransport::new(vec![reply]));
        let got = dev.read_flash(1, 0, data.len() as u32).unwrap();
        assert_eq!(got, data, "returned bytes must be exactly the declared flash region");
        assert_eq!(dev.transport_mut().writes[0][0], Opcode::ReadFlash.byte());
    }

    /// A reply whose declared `len` exceeds the bytes actually delivered is an error, not a panic.
    #[test]
    fn read_flash_rejects_truncated_reply() {
        let mut reply = ok_status();
        reply.extend_from_slice(&0x1000u32.to_le_bytes()); // claims 4096B
        reply.extend_from_slice(&[0x00, 0x00]); // pad
        reply.extend_from_slice(&[0u8; 16]); // …but only 16B follow
        let mut dev = RawDevice::new(ScriptedTransport::new(vec![reply]));
        assert!(matches!(dev.read_flash(1, 0, 0x1000), Err(Error::Malformed(_))));
    }
}
