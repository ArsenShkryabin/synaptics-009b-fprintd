//! `Session` post-TLS device bring-up: the `bootstrap` orchestration (calibration + factory-cal +
//! subtype classify), sensor reboot, hw-register tunnels, silicon/status probes, and the factory
//! block-table fetch. Split out of the session impl as a separate inherent-impl block; the
//! mod.rs-local classify register map + `map_subtype_classify_prod23` are reached via `super::`.

use super::{
    classify_reg, map_subtype_classify_prod23, BootstrapOptions, DeviceContext, Session, INTR_MAX,
    STATUS_BYTE8_PROD3, SUBTYPE_CLASSIFY_UNSET,
};
use crate::calibration::{
    flex_cal_for_subtype, run_calibration, CalResults, FlexCal, ProductClass,
};
use crate::capture::{wof, CaptureControl, CaptureIo, ReadMode};
use crate::capture_prog::CaptureConfig;
use crate::error::{Error, Result, Status};
use crate::factory_cal::{
    factory_bits_request, factory_block_table_from_subtag_response, factory_cal_values_subtag3,
    factory_calibration_values, FACTORY_TAG_BLOCK_TABLE, FACTORY_TAG_CAL_INIT,
};
use crate::fw_registry;
use crate::proto::{Opcode, SensorId, SensorStatus};
use crate::session_cal::SessionCalIo;
use crate::transport::Transport;

impl<T: Transport> Session<T> {
    pub fn refresh_fw_upload_context(&mut self) -> Result<bool> {
        // The `ctx+0x2d0` dedup flag is decided PRE-TLS and never re-set post-TLS. The DLL sets it
        // only in `syna_open_init_decide_format`, right after the *pre-TLS* fw-info partition-2 read
        // (`0x43 02`); no post-TLS path writes it (`syna_scs_fw_upload_context@0x180069590` only
        // reads it). For provisioned 009b that pre-TLS read is invalid (dark flash → status `0x04af`),
        // so the flag stays 0 and the DLL uploads the `0x80` pre-arm module on every arm.
        //
        // `Session::establish` already captured that pre-TLS outcome into `self.fw_upload_context`
        // (via `seed_upload_context_from_rom_reply`). We must NOT re-probe partition 2 here: post-TLS
        // the `0x43 02` read *succeeds*, which would wrongly flip the flag true and dedup away the
        // pre-arm upload the DLL sends (pcap-parity priority C). So only refresh the cached identity.
        let rom = self.tunnel(&[Opcode::GetRomInfo.byte()])?;
        if rom.len() >= 4
            && self.cached_identity.is_none()
            && let Ok(status) = SensorStatus::parse(&rom[2..])
        {
            self.cached_identity = Some(fw_registry::SensorIdentity::from_status(&status));
        }
        Ok(self.fw_upload_context)
    }

    /// Post-TLS device/context init — canonical DLL bring-up through vendor calibration.
    pub fn bootstrap(&mut self) -> Result<DeviceContext> {
        self.bootstrap_with(BootstrapOptions::default())
    }

    /// Soft sensor reboot — `syna_vfm_reboot_sensor_mode0@0x18004ecf0` → `syna_scs_reboot_sensor(0)`.
    /// Wire builder clamps mode **0 → 2** (`syna_cmd_05_reboot@0x180088010`). May invalidate the
    /// in-flight capture program; callers typically STOP/drain then retry bootstrap.
    pub fn reboot_sensor(&mut self) -> Result<()> {
        log::info!("session: sending 0x05 firmware reboot (mode 2)");
        /// DLL passes 0; firmware receives mode 2 (minimum clamp).
        const WIRE_MODE: u16 = 2;
        let cmd = [Opcode::Reboot.byte(), (WIRE_MODE & 0xff) as u8, (WIRE_MODE >> 8) as u8];
        let status = Self::status_of(&self.tunnel(&cmd)?);
        if status != 0 {
            return Err(Error::Status {
                opcode: Opcode::Reboot.byte(),
                status: Status::from_wire(status),
            });
        }
        Ok(())
    }

    /// Like [`Self::bootstrap`] with explicit options (cal skip, etc.).
    ///
    /// Die cleanliness is provided by [`Session::drop`], which reboots the capture firmware when the
    /// session ends — clearing any stale `0x02` arm, on-chip calibration-RAM writes, and
    /// finger-detect/WOE state so the *next* session's bootstrap starts from a known-clean die. We
    /// cannot reboot *inside* bootstrap: the `0x05` reboot re-enumerates the USB device (it is only
    /// valid as a session-ending operation — python-validity likewise reboots at close, raising
    /// `RebootException`). python-validity also reboots at close, so a pv→synfp handoff is clean too.
    pub fn bootstrap_with(&mut self, opts: BootstrapOptions) -> Result<DeviceContext> {
        match self.bootstrap_once(opts) {
            Ok(ctx) => Ok(ctx),
            Err(e) if opts.reboot_on_capture_fault && e.requests_sensor_reboot_retry() => {
                log::warn!(
                    "bootstrap failed ({e}); syna_vfm_reboot_sensor_mode0 + one retry (DLL init recovery)"
                );
                let _ = self.reboot_sensor();
                std::thread::sleep(std::time::Duration::from_millis(400));
                CaptureIo::stop(self)?;
                self.drain_stale_interrupts();
                self.bootstrap_once(opts)
            }
            Err(e) => Err(e),
        }
    }

    pub(crate) fn bootstrap_once(&mut self, opts: BootstrapOptions) -> Result<DeviceContext> {
        let (st8_u8, st9_u8) = self.sensor_status_bytes()?;
        let subtype_classify = self.classify_subtype_prod23(st8_u8, st9_u8)?;
        let fw_upload_context = self.refresh_fw_upload_context()?;
        let (major, minor, st8, st9) = self.probe_silicon()?;
        let cfg = CaptureConfig::for_silicon(major, minor, st8, st9).ok_or_else(|| {
            Error::Malformed(format!(
                "no capture program for silicon {major}.{minor}/{st8}/{st9}"
            ))
        })?;
        CaptureIo::stop(self)?;
        self.drain_stale_interrupts();
        let (factory_cal_values, factory_blocks) = self.fetch_factory_block_table(&cfg)?;
        // DLL bootstrap reads tag 0x0a (cal-init) after 0x0e; payload unused on 0x2449 but required
        // for wire parity (`syna_lib_generate_calibration@0x180066370`).
        let _ = self.tunnel(&factory_bits_request(FACTORY_TAG_CAL_INIT));
        // Vendor calibration at bootstrap runs the DLL step machine for the 0x2449 family
        // (product '2'/'3'). For product '0' (0x0199) we **DEFER** it: running step 6 (a frames-sync
        // dark capture) at open puts its reset risk on the reliable no-finger path, which does not need
        // the fold. The gain-corrected FINGER capture triggers step 6 lazily via
        // `CaptureSession::capture_vendor_cal` (synfp `png --finger`), so the no-finger frames-sync path
        // stays unfolded and reliable. `run_calibration` still gates each step on flex cap_bits and
        // skips step 7 (settle) for product '0' (its folded frames-sync settle faults the die).
        let product = ProductClass::from_product_byte(self.sensor_product_byte()?);
        let vendor_cal = if opts.skip_calibration || product == ProductClass::Prod0 {
            None
        } else {
            let flex = flex_cal_for_subtype(cfg.subtype).unwrap_or(FlexCal::FLEX_2449);
            let mut cal_io = SessionCalIo::new(self, &cfg, factory_cal_values.clone());
            cal_io.cached_factory_blocks = Some(factory_blocks);
            match run_calibration(&mut cal_io, &flex, product, subtype_classify) {
                Ok(r) => Some(r),
                Err(e) if std::env::var("STATIC_FOLD_FALLBACK").is_ok() => {
                    log::warn!("vendor calibration failed ({e}) — STATIC_FOLD_FALLBACK");
                    None
                }
                Err(e) => return Err(e),
            }
        };
        // Step-7 settle (0x2449 only — product '0' defers calibration) is a frames-sync arm; disarm
        // with the stream teardown (`syna_capture_frames_sync` → `syna_capture_session_reset`).
        if vendor_cal.is_some() {
            let (st8_teardown, st9_teardown) = self.status_bytes_for_teardown();
            CaptureControl::teardown(self, ReadMode::Stream, st8_teardown, st9_teardown, false)?;
            self.drain_stale_interrupts();
        }
        Ok(DeviceContext {
            cfg,
            factory_cal_values,
            vendor_cal,
            subtype_classify,
            fw_upload_context,
            st8,
            st9,
        })
    }

    /// `0x08` write-hw-reg32 over the tunneled session (`syna_write_hw_reg_0x08@0x18005e560`).
    pub fn tunnel_write_hw_reg32(&mut self, addr: u32, val: u32) -> Result<()> {
        let cmd = wof::hw_reg_write_command(addr, val);
        let status = Self::status_of(&self.tunnel(&cmd)?);
        if status != 0 {
            return Err(Error::Status {
                opcode: Opcode::WriteHwReg32.byte(),
                status: Status::from_wire(status),
            });
        }
        Ok(())
    }

    /// `0x07` read-hw-reg32 over the tunneled session (`syna_read_hw_reg_0x07`).
    pub fn tunnel_read_hw_reg32(&mut self, addr: u32) -> Result<u32> {
        let mut args = addr.to_le_bytes().to_vec();
        args.push(4);
        let mut cmd = vec![Opcode::ReadHwReg32.byte()];
        cmd.extend_from_slice(&args);
        let pt = self.tunnel(&cmd)?;
        if Self::status_of(&pt) != 0 {
            return Err(Error::Status {
                opcode: Opcode::ReadHwReg32.byte(),
                status: Status::from_wire(Self::status_of(&pt)),
            });
        }
        let payload = pt.get(2..).ok_or_else(|| Error::Malformed("short hw-reg read".into()))?;
        if payload.len() < 4 {
            return Err(Error::ShortResponse {
                opcode: Opcode::ReadHwReg32.byte(),
                got: payload.len() + 2,
                need: 6,
            });
        }
        Ok(u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]))
    }

    /// Prod-23 subtype classify → `ctx+0x280` (`syna_classify_subtype_prod23@0x18006fa60`).
    pub fn classify_subtype_prod23(&mut self, st8: u8, st9: u8) -> Result<i32> {
        if st8 != STATUS_BYTE8_PROD3 {
            return Ok(SUBTYPE_CLASSIFY_UNSET);
        }
        self.tunnel_write_hw_reg32(
            classify_reg::PROD23_POWER_CLOCK,
            classify_reg::PROD23_PEEK_SUB,
        )?;
        let readback = self.tunnel_read_hw_reg32(classify_reg::PROD23_READBACK)?;
        Ok(map_subtype_classify_prod23(readback, st8, st9))
    }

    /// Status bytes `[8]`/`[9]` from `GetRomInfo` (for classify before full silicon probe).
    ///
    /// Also debug-logs the full parsed bring-up flag set the DLL derives in
    /// `syna_open_init_decide_format@0x18006e830` — `valid` (`[0xa]`), `device_id` (`[0xb]`),
    /// `flags17` (`[0x17]`), the **provisioned** bit (`ctx+0x274`, `(flags17&0x02)==0`), and the
    /// **format/wipe gate** (`ctx+0x27c`, `format_mode` = `(flags17&0x40)==0`, which arms the
    /// destructive partition-format path on mismatch). These are otherwise consumed silently here.
    /// The sensor's product byte — `SensorStatus.device_id` (`0x01` payload `[0x0b]`, = `RomInfo.product`),
    /// the value the DLL gates calibration on at `*(ctx->pStatus+0xb)`: `'0'`=0x30 (0x0199 type-1 family),
    /// `'3'`=0x33 (0x2449). Read live rather than guessed from the subtype.
    pub(crate) fn sensor_product_byte(&mut self) -> Result<u8> {
        let rom = self.tunnel(&[Opcode::GetRomInfo.byte()])?;
        let status = SensorStatus::parse(
            rom.get(2..).ok_or_else(|| Error::Malformed("GetRomInfo reply too short".into()))?,
        )?;
        Ok(status.device_id)
    }

    pub(crate) fn sensor_status_bytes(&mut self) -> Result<(u8, u8)> {
        let rom = self.tunnel(&[Opcode::GetRomInfo.byte()])?;
        let status = SensorStatus::parse(rom.get(2..).ok_or_else(|| {
            Error::Malformed("GetRomInfo reply too short".into())
        })?)?;
        log::debug!(
            "bring-up status: valid={} device_id=0x{:02x} flags17=0x{:02x} \
             provisioned={} format_wipe_gate={} (flag_274={}) keys=[08:0x{:02x} 09:0x{:02x} 0f:0x{:02x}]",
            status.valid,
            status.device_id,
            status.flags17,
            status.is_provisioned(),
            status.format_mode,
            status.flag_274,
            status.key_08,
            status.key_09,
            status.key_0f,
        );
        Ok((status.key_08, status.key_09))
    }

    /// Silicon id + status bytes for [`CaptureConfig::for_silicon`].
    pub(crate) fn probe_silicon(&mut self) -> Result<(u16, u16, u16, u16)> {
        let (mut major, mut minor, mut st8, mut st9) = (0u16, 0u16, 0u16, 0u16);
        if let Ok(pt) = self.tunnel(&[Opcode::GetSensorId.byte()])
            && let Ok(id) = SensorId::parse(&pt[2.min(pt.len())..])
        {
            major = id.major;
            minor = id.minor;
        }
        if let Ok(pt) = self.tunnel(&[Opcode::GetSensorState.byte()])
            && pt.len() >= 12
        {
            st8 = pt[2 + 8] as u16;
            st9 = pt[2 + 9] as u16;
        }
        if st8 == 0 && st9 == 0 {
            if let Ok((rom8, rom9)) = self.sensor_status_bytes() {
                st8 = u16::from(rom8);
                st9 = u16::from(rom9);
            } else if let Some(id) = &self.cached_identity {
                st8 = id.id8 as u16;
                st9 = id.id9 as u16;
            }
        }
        Ok((major, minor, st8, st9))
    }

    /// Status bytes `[8]`/`[9]` for [`CaptureControl::teardown`] / [`crate::capture::needs_finalize`].
    pub fn status_bytes_for_teardown(&mut self) -> (u16, u16) {
        if let Ok((_, _, st8, st9)) = self.probe_silicon()
            && (st8 != 0 || st9 != 0)
        {
            return (st8, st9);
        }
        if let Some(id) = &self.cached_identity {
            return (id.id8 as u16, id.id9 as u16);
        }
        // Provisioned 0x2449 laptop default when probes fail (still needs FINALIZE).
        (STATUS_BYTE8_PROD3 as u16, 0x14)
    }

    /// Run vendor calibration on demand — the same measured steps as [`Self::bootstrap`]'s calibration
    /// branch (`run_calibration` → step-3 diff, step-6 raw dark, step-7 settle) plus the step-7 stream
    /// teardown. For callers that bootstrapped with `skip_calibration` (or `STATIC_FOLD`) but later need
    /// the measured cal fold — e.g. the live viewer entering `0x51`/polled mode without a calib frame.
    /// The returned [`CalResults`] feeds the polled/stream cal-fold builders
    /// (`upload_cmd_identify_with_cal` / `upload_cmd_prod33_sync_with_cal`).
    pub fn capture_vendor_cal(
        &mut self,
        cfg: &CaptureConfig,
        factory_cal_values: &[u8],
    ) -> Result<CalResults> {
        let flex = flex_cal_for_subtype(cfg.subtype).unwrap_or(FlexCal::FLEX_2449);
        // Real product byte + subtype-classify for the DLL-faithful step gating (see the bootstrap
        // calibration branch). The product-'0' step-6/7 divergence lives inside `run_calibration`.
        let product = ProductClass::from_product_byte(self.sensor_product_byte()?);
        let (st8, st9) = self.sensor_status_bytes()?;
        let subtype_classify = self.classify_subtype_prod23(st8, st9)?;
        let cal = if product == ProductClass::Prod0 {
            // 009a (type-1 die): run the WORKING pv-faithful calibrate loop (unfolded arms + EP-0x82 read,
            // host accumulate — session_cal::run_calibrate_loop) to produce the dark clean-slate, and
            // persist it for the 0x85-line fold (SYNA_CALIB_DATA). Return it as CalResults WITHOUT
            // step56_buf: for this family the fold is the `calib_data` param → 0x85 delta lines, NOT
            // step6_dark → DAT line C (line_update_prod33: "no line-C" for the older family). Setting
            // step56_buf wrongly emits DAT line C and FAULTS the die. The 0x85 fold builder itself still
            // crashes (differs from pv even with pv's exact calib_data) — TODO — so the identify runs
            // UNFOLDED for now (works); the calib_data is computed + persisted for when the fold is fixed.
            // pv `calibrate()` (sensor.py:656) EARLY-RETURNS on `check_clean_slate()`: on a warm boot
            // with the flash partition-6 clean-slate present it loads calib_data from file and runs NO
            // in-session captures. Our loop always ran (EP-0x82 captures + a stop/drain teardown),
            // leaving the die in a post-teardown state pv never has at identify time — a candidate for
            // the folded-identify fault. SYNA_SKIP_CAL_LOOP replicates pv's warm boot: reuse the
            // persisted calib_data, skip the in-session calibrate captures. (E1: isolates whether the
            // fold fault is the calibrate-loop teardown state vs the fold itself.)
            let calib_path = "captures/009a-calib-data.bin";
            let warm_boot = std::env::var_os("SYNA_SKIP_CAL_LOOP").is_some()
                && std::path::Path::new(calib_path).exists();
            if warm_boot {
                log::info!(
                    "SYNA_SKIP_CAL_LOOP: pv-faithful warm boot — reusing persisted {calib_path}, \
                     skipping in-session calibrate captures"
                );
            } else {
                let calib_data =
                    crate::session_cal::run_calibrate_loop(self, cfg, factory_cal_values)?;
                let _ = std::fs::write(calib_path, &calib_data);
            }
            CalResults::default()
        } else {
            let mut cal_io = SessionCalIo::new(self, cfg, factory_cal_values.to_vec());
            run_calibration(&mut cal_io, &flex, product, subtype_classify)?
        };
        // Leave the die idle for the next polled arm. Product '0' skipped step 7 and step 6 left a
        // frames-sync arm; the stream teardown (`syna_capture_session_reset`) FAULTS this die, so use a
        // plain `0x04` stop + drain. 0x2449 uses the stream teardown (tears down its step-7 settle arm).
        if product == ProductClass::Prod0 {
            CaptureIo::stop(self)?;
            self.drain_stale_interrupts();
        } else {
            let (st8, st9) = self.status_bytes_for_teardown();
            CaptureControl::teardown(self, ReadMode::Stream, st8, st9, false)?;
            self.drain_stale_interrupts();
        }
        Ok(cal)
    }

    /// `0x6f` tag [`FACTORY_TAG_BLOCK_TABLE`] → per-line factory calib values + parsed blocks.
    pub(crate) fn fetch_factory_block_table(
        &mut self,
        cfg: &CaptureConfig,
    ) -> Result<(Vec<u8>, Vec<crate::factory_cal::FactoryBlock>)> {
        let pt = self.tunnel(&factory_bits_request(FACTORY_TAG_BLOCK_TABLE))?;
        if Self::status_of(&pt) != 0 {
            return Ok((Vec::new(), Vec::new()));
        }
        let payload = &pt[2..];
        let blocks = factory_block_table_from_subtag_response(payload);
        let from_blocks =
            factory_calibration_values(&blocks, cfg.type_info.line_width as usize);
        let fcv = if from_blocks.is_empty() {
            factory_cal_values_subtag3(payload)
        } else {
            from_blocks
        };
        Ok((fcv, blocks))
    }

    /// Best-effort EP-0x83 drain after session stop (matches example binaries).
    pub(crate) fn drain_stale_interrupts(&mut self) {
        for _ in 0..10 {
            if self
                .transport
                .read_interrupt(INTR_MAX, 50)
                .map(|b| b.is_empty())
                .unwrap_or(true)
            {
                break;
            }
        }
    }
}
