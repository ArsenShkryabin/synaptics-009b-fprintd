//! USB transport for Synaptics Prometheus sensors.
//!
//! Wire endpoints are common across the whole family (see docs/STATUS.md "Protocol"):
//!   * EP1 OUT  (0x01) — command requests
//!   * EP0x81 IN        — command responses (`u16 status ‖ payload` at the proto layer; see `proto`)
//!   * EP0x82 IN        — bulk image / large data
//!   * EP0x83 IN        — interrupt events (finger down, capture complete)
//!
//! The [`Transport`] trait keeps the backend swappable (default: pure-Rust `nusb`).

use synaptics_core::error::Result;

pub const EP_CMD_OUT: u8 = 0x01;
pub const EP_CMD_IN: u8 = 0x81;
pub const EP_BULK_IN: u8 = 0x82;
pub const EP_INTR_IN: u8 = 0x83;

/// The sensor's USB endpoints, as a named enum so trace logs carry both the symbolic name and the
/// wire address (`{:?}` gives the name, `as u8` the address). Values mirror the `EP_*` consts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Endpoint {
    /// EP1 OUT — command requests.
    CmdOut = EP_CMD_OUT,
    /// EP0x81 IN — command responses.
    CmdIn = EP_CMD_IN,
    /// EP0x82 IN — bulk image / large data.
    BulkIn = EP_BULK_IN,
    /// EP0x83 IN — interrupt events (finger down, capture complete).
    IntrIn = EP_INTR_IN,
}

/// Format the first `max` bytes of `data` as space-separated hex for a trace line, noting any
/// remaining byte count. Only called when trace logging is enabled (the `log` macros are lazy).
pub fn hex_preview(data: &[u8], max: usize) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(max.min(data.len()) * 3 + 16);
    for b in data.iter().take(max) {
        let _ = write!(s, "{b:02x} ");
    }
    let s = s.trim_end().to_string();
    if data.len() > max {
        format!("{s} … (+{} more)", data.len() - max)
    } else {
        s
    }
}

/// Low-level byte pipe to a sensor. One request → one response on the command pipe.
pub trait Transport {
    /// Write a raw command to EP1 OUT.
    fn write_cmd(&mut self, data: &[u8]) -> Result<()>;
    /// Read a raw response from EP0x81 IN (up to `max` bytes).
    fn read_cmd(&mut self, max: usize) -> Result<Vec<u8>>;
    /// Read bulk data from EP0x82 IN.
    fn read_bulk(&mut self, max: usize) -> Result<Vec<u8>>;
    /// Like [`Self::read_bulk`] with an explicit wall-clock bound (default impl ignores `timeout_ms`).
    fn read_bulk_timed(&mut self, max: usize, timeout_ms: u64) -> Result<Vec<u8>> {
        let _ = timeout_ms;
        self.read_bulk(max)
    }
    /// Read one interrupt event from EP0x83 IN (best-effort; returns empty on timeout).
    fn read_interrupt(&mut self, max: usize, timeout_ms: u64) -> Result<Vec<u8>>;
}

#[cfg(feature = "nusb-backend")]
mod nusb_backend {
    use super::*;
    use log::trace;
    use synaptics_core::error::Error;
    use nusb::transfer::RequestBuffer;

    use std::sync::mpsc;

    /// Target string for USB-layer trace logs (`RUST_LOG=syna::usb=trace`).
    const USB: &str = "syna::usb";

    /// `nusb`-backed transport. Pure-Rust, no libusb.
    pub struct NusbTransport {
        interface: nusb::Interface,
        _device: nusb::Device,
        pub timeout_ms: u64,
        /// Lazily-started **persistent** EP-`0x83` interrupt reader. See [`Self::read_interrupt`].
        intr: Option<mpsc::Receiver<std::result::Result<Vec<u8>, String>>>,
    }

    impl NusbTransport {
        /// Open the first device matching `(vid, pid)` and claim interface 0.
        pub fn open(vid: u16, pid: u16) -> Result<Self> {
            let info = nusb::list_devices()
                .map_err(|e| Error::Usb(e.to_string()))?
                .find(|d| d.vendor_id() == vid && d.product_id() == pid)
                .ok_or(Error::DeviceNotFound { vid, pid })?;
            let device = info.open().map_err(|e| Error::Usb(e.to_string()))?;
            let interface = device
                .claim_interface(0)
                .map_err(|e| Error::Usb(e.to_string()))?;
            Ok(Self {
                interface,
                _device: device,
                timeout_ms: 15_000,
                intr: None,
            })
        }

        /// Open the first device matching any `(vid, pid)` in `ids` (device discovery).
        pub fn open_any(ids: &[(u16, u16)]) -> Result<(Self, (u16, u16))> {
            let info = nusb::list_devices()
                .map_err(|e| Error::Usb(e.to_string()))?
                .find(|d| ids.contains(&(d.vendor_id(), d.product_id())))
                .ok_or(Error::NoSupportedDevice)?;
            let ids = (info.vendor_id(), info.product_id());
            let device = info.open().map_err(|e| Error::Usb(e.to_string()))?;
            let interface = device
                .claim_interface(0)
                .map_err(|e| Error::Usb(e.to_string()))?;
            Ok((
                Self {
                    interface,
                    _device: device,
                    timeout_ms: 15_000,
                    intr: None,
                },
                ids,
            ))
        }

        /// USB-reset the sensor, then open it fresh — a clean-slate un-stick for a wedged device.
        ///
        /// A capture aborted mid-flight (e.g. an interrupted `capture`/`capture_image` run) can
        /// leave the sensor with a capture still armed or an endpoint stalled, so the next session
        /// reads stale/idle frames or hangs. A protocol-level clear would need a working session, and
        /// the firmware's own reset opcodes (`0x77`/`0x72`) are ambiguous ("erase-style") and unsafe
        /// under our non-destructive rule. A USB port reset ([`nusb::Device::reset`]) is the safe,
        /// state-independent hammer: it forces the device to re-enumerate, dropping all capture/pipe
        /// state without touching sensor flash. `reset()` invalidates the handle, so we drop it, wait
        /// for the device to reappear, and re-open. Linux/macOS only (reset is unsupported on Windows).
        pub fn reset_and_open_any(ids: &[(u16, u16)]) -> Result<(Self, (u16, u16))> {
            /// How long to wait for the device to re-appear after a reset re-enumeration.
            const REENUM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
            /// Poll interval while waiting for re-enumeration.
            const REENUM_POLL: std::time::Duration = std::time::Duration::from_millis(100);

            // Reset the currently-present matching device (if any), then drop the handle.
            if let Some(info) = nusb::list_devices()
                .map_err(|e| Error::Usb(e.to_string()))?
                .find(|d| ids.contains(&(d.vendor_id(), d.product_id())))
                && let Ok(device) = info.open()
            {
                // A reset error (e.g. device already gone) is non-fatal — we still try to re-open.
                let _ = device.reset();
                drop(device);
            }

            // Re-enumeration takes a moment and the device gets a new address; retry until it returns.
            let deadline = std::time::Instant::now() + REENUM_TIMEOUT;
            loop {
                match Self::open_any(ids) {
                    Ok(ok) => return Ok(ok),
                    Err(e) => {
                        if std::time::Instant::now() >= deadline {
                            return Err(e);
                        }
                        std::thread::sleep(REENUM_POLL);
                    }
                }
            }
        }
    }

    impl Transport for NusbTransport {
        fn write_cmd(&mut self, data: &[u8]) -> Result<()> {
            trace!(
                target: USB,
                "OUT {:?}(0x{:02x}) {}B: {}",
                Endpoint::CmdOut,
                Endpoint::CmdOut as u8,
                data.len(),
                hex_preview(data, 32),
            );
            synaptics_core::pcap_log::maybe_log_wire(EP_CMD_OUT, data);
            out_transfer(&self.interface, EP_CMD_OUT, data, 3000)?;
            Ok(())
        }

        fn read_cmd(&mut self, max: usize) -> Result<Vec<u8>> {
            let data = in_cmd_transfer(&self.interface, EP_CMD_IN, max, 3000)?;
            trace!(
                target: USB,
                "IN  {:?}(0x{:02x}) {}B: {}",
                Endpoint::CmdIn,
                Endpoint::CmdIn as u8,
                data.len(),
                hex_preview(&data, 32),
            );
            synaptics_core::pcap_log::maybe_log_wire(EP_CMD_IN, &data);
            Ok(data)
        }

        fn read_bulk(&mut self, max: usize) -> Result<Vec<u8>> {
            // Bounded by `timeout_ms` so a capture that yields no image (identify matches on-chip)
            // does not hang. Returns empty on timeout.
            let data = in_transfer(&self.interface, EP_BULK_IN, max, self.timeout_ms)?;
            trace!(
                target: USB,
                "IN  {:?}(0x{:02x}) {}B (bulk): {}",
                Endpoint::BulkIn,
                Endpoint::BulkIn as u8,
                data.len(),
                hex_preview(&data, 16),
            );
            if synaptics_core::pcap_log::pcap_active() {
                synaptics_core::pcap_log::log_transfer(
                    synaptics_core::pcap_log::SYNA_PCAP_WIRE_USB,
                    EP_BULK_IN,
                    &data,
                );
            }
            Ok(data)
        }

        fn read_bulk_timed(&mut self, max: usize, timeout_ms: u64) -> Result<Vec<u8>> {
            let data = in_transfer(&self.interface, EP_BULK_IN, max, timeout_ms)?;
            trace!(
                target: USB,
                "IN  {:?}(0x{:02x}) {}B (bulk/timed): {}",
                Endpoint::BulkIn,
                Endpoint::BulkIn as u8,
                data.len(),
                hex_preview(&data, 16),
            );
            if synaptics_core::pcap_log::pcap_active() {
                synaptics_core::pcap_log::log_transfer(
                    synaptics_core::pcap_log::SYNA_PCAP_WIRE_USB,
                    EP_BULK_IN,
                    &data,
                );
            }
            Ok(data)
        }

        fn read_interrupt(&mut self, max: usize, timeout_ms: u64) -> Result<Vec<u8>> {
            // A **persistent** background reader owns EP-0x83 and continuously re-submits a single
            // interrupt-IN transfer, buffering every completed packet into a channel. `read_interrupt`
            // just drains that channel with a wall-clock timeout.
            //
            // Why not submit-per-call (the previous `in_transfer` helper): that spawned a fresh
            // transfer on every call and, on timeout, *orphaned* it still queued on the endpoint. In a
            // tight poll loop (the identify capture reads EP-0x83 every ~30 ms while host-clocking the
            // frame with 0x51) dozens of orphaned transfers pile up on the pipe; when the finger-down
            // packet finally arrives the USB stack delivers it to the OLDEST pending transfer — an
            // orphan whose receiver was already dropped — so the event is silently lost and
            // `saw_finger` stays false. That race is exactly the intermittent "type-2 never fires"
            // symptom (it only worked when an orphan happened not to swallow it). One long-lived
            // transfer means every packet is captured exactly once and queued, so a finger-down raised
            // while the caller is busy on a 0x51 round-trip is still there on the next drain.
            let rx = self.intr.get_or_insert_with(|| {
                let iface = self.interface.clone();
                let (tx, rx) = mpsc::channel();
                let buf_len = max.max(64);
                std::thread::spawn(move || {
                    loop {
                        let comp = pollster::block_on(
                            iface.interrupt_in(EP_INTR_IN, RequestBuffer::new(buf_len)),
                        );
                        match comp.status {
                            Ok(()) => {
                                // A zero-length completion is a benign poll tick; skip it so it doesn't
                                // read as a spurious empty event, and keep listening.
                                if !comp.data.is_empty() && tx.send(Ok(comp.data)).is_err() {
                                    break; // transport dropped
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(Err(e.to_string()));
                                break; // endpoint gone / device closed — stop the reader
                            }
                        }
                    }
                });
                rx
            });
            match rx.recv_timeout(std::time::Duration::from_millis(timeout_ms)) {
                Ok(Ok(data)) => {
                    trace!(
                        target: USB,
                        "IN  {:?}(0x{:02x}) {}B (intr/wake): {}",
                        Endpoint::IntrIn,
                        Endpoint::IntrIn as u8,
                        data.len(),
                        hex_preview(&data, 16),
                    );
                    synaptics_core::pcap_log::maybe_log_wire(EP_INTR_IN, &data);
                    Ok(data)
                }
                Ok(Err(e)) => Err(Error::Usb(e)),
                Err(mpsc::RecvTimeoutError::Timeout) => Ok(Vec::new()),
                // Reader thread ended (after forwarding its error, or transport shutdown).
                Err(mpsc::RecvTimeoutError::Disconnected) => Ok(Vec::new()),
            }
        }
    }

    /// Run a bulk IN transfer with a wall-clock timeout. `nusb`'s block-on has no per-transfer
    /// timeout, so the transfer runs on a helper thread (the `Interface` is an `Arc` clone) and we
    /// bound the wait with `recv_timeout`. On timeout we return an empty buffer (best-effort read);
    /// the orphaned transfer completes and is dropped by the helper thread. This one-shot pattern is
    /// fine for the bulk image pipe (read once per capture); the tightly-polled EP-0x83 interrupt
    /// pipe uses the persistent reader in [`NusbTransport::read_interrupt`] instead, which must not
    /// orphan transfers.
    fn in_transfer(
        interface: &nusb::Interface,
        ep: u8,
        max: usize,
        timeout_ms: u64,
    ) -> Result<Vec<u8>> {
        let iface = interface.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let comp = pollster::block_on(iface.bulk_in(ep, RequestBuffer::new(max)));
            let _ = tx.send(match comp.status {
                Ok(()) => Ok(comp.data),
                Err(e) => Err(e.to_string()),
            });
        });
        match rx.recv_timeout(std::time::Duration::from_millis(timeout_ms)) {
            Ok(Ok(data)) => Ok(data),
            Ok(Err(e)) => Err(Error::Usb(e)),
            Err(_) => Ok(Vec::new()), // timeout — best-effort empty read
        }
    }

    fn out_transfer(
        interface: &nusb::Interface,
        ep: u8,
        data: &[u8],
        timeout_ms: u64,
    ) -> Result<()> {
        let iface = interface.clone();
        let buf = data.to_vec();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let comp = pollster::block_on(iface.bulk_out(ep, buf));
            let _ = tx.send(match comp.status {
                Ok(()) => Ok(()),
                Err(e) => Err(e.to_string()),
            });
        });
        match rx.recv_timeout(std::time::Duration::from_millis(timeout_ms)) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(Error::Usb(e)),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(Error::Usb("USB bulk_out command timed out".into())),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(Error::Usb("USB bulk_out helper disconnected".into())),
        }
    }

    fn in_cmd_transfer(
        interface: &nusb::Interface,
        ep: u8,
        max: usize,
        timeout_ms: u64,
    ) -> Result<Vec<u8>> {
        let iface = interface.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let comp = pollster::block_on(iface.bulk_in(ep, RequestBuffer::new(max)));
            let _ = tx.send(match comp.status {
                Ok(()) => Ok(comp.data),
                Err(e) => Err(e.to_string()),
            });
        });
        match rx.recv_timeout(std::time::Duration::from_millis(timeout_ms)) {
            Ok(Ok(data)) => Ok(data),
            Ok(Err(e)) => Err(Error::Usb(e)),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(Error::Usb("USB bulk_in command timed out".into())),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(Error::Usb("USB bulk_in helper disconnected".into())),
        }
    }
}

#[cfg(feature = "nusb-backend")]
pub use nusb_backend::NusbTransport;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_enum_values_match_consts() {
        // Trace logs render `{:?}(0x{:02x})`; the enum's address must equal the wire const.
        assert_eq!(Endpoint::CmdOut as u8, EP_CMD_OUT);
        assert_eq!(Endpoint::CmdIn as u8, EP_CMD_IN);
        assert_eq!(Endpoint::BulkIn as u8, EP_BULK_IN);
        assert_eq!(Endpoint::IntrIn as u8, EP_INTR_IN);
        assert_eq!(format!("{:?}", Endpoint::CmdOut), "CmdOut");
    }

    #[test]
    fn hex_preview_truncates_with_remainder() {
        assert_eq!(hex_preview(&[0x76, 0x03, 0x00], 8), "76 03 00");
        assert_eq!(hex_preview(&[0xaa; 5], 2), "aa aa … (+3 more)");
        assert_eq!(hex_preview(&[], 8), "");
    }
}
