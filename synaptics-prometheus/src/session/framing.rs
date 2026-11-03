//! Free helpers used by the `Session` impl: TLS-framing (handshake_msg / plaintext_record /
//! parse_flight1), the fw-upload-context seed, record scanning, and rand. Extracted from the session
//! module; `pub(crate)` so the impl (in `mod.rs`) reaches them. Uses parent types via `super`.

use super::*;
pub(crate) fn seed_upload_context_from_rom_reply<T: Transport>(
    transport: &mut T,
    rom_raw: &[u8],
) -> Result<(bool, Option<SensorIdentity>)> {
    let resp = Response::parse(Opcode::GetRomInfo.byte(), rom_raw)?;
    let status = SensorStatus::parse(&resp.payload)?;
    let identity = fw_registry::SensorIdentity::from_status(&status);
    // Faithful to `syna_open_init_decide_format@0x18006e830`: the pre-TLS fw-info-partition-2 read is
    // issued only inside the read gate (`provision_state ∈ {3,5,7,8}` AND `is_provisioned()`). On our
    // cold 009b the provision-state nibble is 0 (unpaired), so the DLL never issues the read and
    // `ctx+0x2d0` stays 0 the whole session — which is why the mode2 pre-arm re-uploads on every arm.
    // Issuing the read outside the gate (as we used to) both diverges from the DLL wire order and, via
    // the old `is_provisioned() && fw_p2.is_some()` predicate, wrongly deduped the pre-arm (the `0x48`
    // identify-arm reset). Gate the read on the same predicate `infer_fw_upload_context` uses.
    let fw_p2 = if bringup::fw_info_read_gate_open(&status) {
        transport.write_cmd(&[Opcode::GetFwInfo.byte(), 2])?;
        let fw_raw = transport.read_cmd(REPLY_MAX)?;
        let fw_resp = Response::parse(Opcode::GetFwInfo.byte(), &fw_raw)?;
        if fw_resp.status.is_ok() {
            Some(FwInfo::parse(&fw_resp.payload)?)
        } else {
            None
        }
    } else {
        None
    };
    let fw_upload_context = bringup::infer_fw_upload_context(&status, fw_p2.as_ref());
    Ok((fw_upload_context, Some(identity)))
}

/// Find the first TLS record of type `t` in a (possibly multi-record) reply buffer. Record framing:
/// `type:u8 ‖ version:u16 ‖ len:u16be ‖ payload`.
pub(crate) fn first_record(buf: &[u8], t: u8) -> Option<Vec<u8>> {
    let mut i = 0;
    while i + 5 <= buf.len() {
        let len = ((buf[i + 3] as usize) << 8) | buf[i + 4] as usize;
        if buf[i] == t {
            return buf.get(i..i + 5 + len).map(<[u8]>::to_vec);
        }
        i += 5 + len;
    }
    None
}

// --- handshake glue (used only by Session::establish) ------------------------------------------

/// 32 random bytes (the client random / other nonces).
pub(crate) fn rand32() -> [u8; 32] {
    let mut b = [0u8; 32];
    os_rng().fill_bytes(&mut b);
    b
}

/// Build a handshake message: `type ‖ len:u24be ‖ body`.
pub(crate) fn handshake_msg(t: u8, body: &[u8]) -> Vec<u8> {
    let n = body.len();
    let mut v = vec![t, (n >> 16) as u8, (n >> 8) as u8, n as u8];
    v.extend_from_slice(body);
    v
}

/// Build a plaintext TLS record: `type ‖ 3 ‖ 3 ‖ len:u16be ‖ payload`.
pub(crate) fn plaintext_record(t: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![t, 3, 3, (payload.len() >> 8) as u8, payload.len() as u8];
    v.extend_from_slice(payload);
    v
}

/// Parse the server's first flight: scan handshake records for the ServerHello and feed every
/// handshake message into the transcript `tr`. Returns the 32-byte server random.
pub(crate) fn parse_flight1(reply: &[u8], tr: &mut Transcript) -> Option<[u8; 32]> {
    let mut sr = None;
    let mut i = 0;
    while i + 5 <= reply.len() {
        let t = reply[i];
        let len = ((reply[i + 3] as usize) << 8) | reply[i + 4] as usize;
        let body = &reply[i + 5..(i + 5 + len).min(reply.len())];
        if t == RecordType::Handshake as u8 {
            let mut j = 0;
            while j + 4 <= body.len() {
                let ht = body[j];
                let hl = ((body[j + 1] as usize) << 16)
                    | ((body[j + 2] as usize) << 8)
                    | body[j + 3] as usize;
                let msg = &body[j..(j + 4 + hl).min(body.len())];
                if ht == HS_SERVER_HELLO {
                    sr = parse_server_hello(&msg[4..]).ok();
                }
                tr.update(msg);
                j += 4 + hl;
            }
        }
        i += 5 + len;
    }
    sr
}

#[cfg(feature = "nusb-backend")]
impl Session<crate::transport::NusbTransport> {
    /// USB product IDs tried by example binaries when opening the first matching Prometheus device.
    pub const DEFAULT_USB_IDS: &[(u16, u16)] = &[(0x06cb, 0x009b), (0x06cb, 0x009a)];

    /// USB-reset, open the first matching device, read the cert store, and complete TLS pairing.
    /// Non-destructive (no flash write). Default seat binding (`b""`).
    ///
    /// Applies the default [`StaleStatePolicy`] ([`StaleStatePolicy::Hard`]) to clear any sensor
    /// state left by a prior process — see [`Self::open_nusb_with_policy`].
    ///
    /// `cert_store_path` goes through [`certstore::resolve`](crate::certstore::resolve), so a tool
    /// run from a directory with no `certstore.bin` picks up the one under `~/.config` instead of
    /// failing — and an explicit path that does exist still wins. The file actually opened is
    /// logged, because "which pairing material did it use" is not something to have to guess at.
    pub fn open_nusb(cert_store_path: &str) -> Result<Self> {
        Self::open_nusb_with_policy(cert_store_path, StaleStatePolicy::default())
    }

    /// Like [`Self::open_nusb`], but with an explicit [`StaleStatePolicy`] for the startup
    /// stale-state clear. The open-time USB port reset always happens; `policy` selects the
    /// additional firmware/arm clearing on top.
    pub fn open_nusb_with_policy(
        cert_store_path: &str,
        policy: StaleStatePolicy,
    ) -> Result<Self> {
        use crate::transport::NusbTransport;
        let cert = crate::certstore::read(cert_store_path)
            .map_err(|e| Error::Malformed(e.to_string()))?;
        log::info!("session open: open transport (with reset fallback), stale-state policy = {policy:?}");
        let (t, _) = NusbTransport::open_any(Self::DEFAULT_USB_IDS)
            .or_else(|_| NusbTransport::reset_and_open_any(Self::DEFAULT_USB_IDS))?;
        let mut session = Self::establish(t, &cert, b"")?;
        session.apply_stale_state_policy(&cert, policy)?;
        Ok(session)
    }

    /// Clear sensor state a prior process may have left, per `policy`. The open-time USB port reset
    /// has already run; this is the *additional* clearing. See [`StaleStatePolicy`].
    fn apply_stale_state_policy(&mut self, cert: &[u8], policy: StaleStatePolicy) -> Result<()> {
        use crate::capture::CaptureIo;
        use crate::transport::NusbTransport;
        match policy {
            StaleStatePolicy::None => {}
            StaleStatePolicy::Soft => {
                // 0x04 CaptureStop + drain — clears a stale arm without a re-enumerate.
                log::info!("stale-state Soft: 0x04 CaptureStop + drain");
                CaptureIo::stop(self)?;
            }
            StaleStatePolicy::Hard => {
                log::info!("stale-state Hard: 0x05 reboot + re-open + re-establish + stop");
                // 0x05 firmware reboot, then re-open + re-establish (the reboot re-enumerates), then
                // the soft clear. Best-effort reboot: the open-time USB reset already ran, so a
                // failed reboot still leaves a cleaner device than we started with.
                if let Err(e) = self.reboot_sensor() {
                    log::warn!(
                        "stale-state Hard: 0x05 reboot failed ({e}); USB reset already applied, \
                         re-establishing anyway"
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(super::REBOOT_SETTLE_MS));
                let (t, _) = NusbTransport::reset_and_open_any(Self::DEFAULT_USB_IDS)?;
                *self = Self::establish(t, cert, b"")?;
                CaptureIo::stop(self)?;
            }
        }
        Ok(())
    }
}

