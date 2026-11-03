# synaptics-009b-fprintd

> **Linux driver & drop-in `fprintd` D-Bus service for Synaptics Prometheus `06cb:009b` (MSI SecurePad)**

Fully functional biometric authentication (fingerprint enrollment, verification, `sudo`, lock screen, PAM) for Linux systems.

---

## 🎯 The Problem

The **Synaptics `06cb:009b`** fingerprint sensor is widely used across MSI laptops, including:
- **MSI PS63 Modern** (8RC, 8RD, 8M)
- **MSI Modern 14 / Modern 15**
- **MSI Prestige 14 / Prestige 15**
- **MSI Creator 15**
- **MSI GS66 Stealth** (and related variants)

For years, this device was completely unsupported on Linux:
1. **Match-on-Host (MoH):** The hardware does not match fingerprints internally; it delivers raw frame data over an encrypted TLS transport, requiring host-side neural matching.
2. **Die Type-2 Stream:** Unlike older ThinkPad sensors (`009a`, `0097`) that use polled `0x51` commands, `009b` uses a continuous **EP `0x82` frames-sync stream**. Attempting to send polled commands faults and resets the sensor.
3. **Upstream `libfprint`:** Does not support the device out-of-the-box.

---

## 💡 The Solution

This project provides a complete, autonomous Linux driver stack:
- **Core Engine (`syna-tool`):** High-performance Rust binary handling USB transport (`nusb`), TLS encryption, stream frame descrambling, capacitive column noise normalization (`condition_onchip`), and neural minutiae matching (QuantumMatcher).
- **System D-Bus Daemon (`syna-fprintd`):** Drop-in replacement for `fprintd.service` implementing the standard `net.reactivated.Fprint.Manager` and `net.reactivated.Fprint.Device` interfaces.
- **Zero USB Resets:** Fixed the aggressive USB port reset loops present in experimental code; devices open cleanly in <10ms with zero kernel xHCI churn.
- **System Integration:** Fully compatible with standard Linux utilities (`fprintd-enroll`, `fprintd-verify`, `fprintd-list`), `pam_fprintd.so` for `sudo`, Polkit, SDDM, and Hyprland/GNOME/KDE lock screens.
- **No Windows Required:** Automatically downloads the official 1.2 MB driver package directly from Microsoft Update Catalog to extract neural model weights.

---

## 🚀 Quick Start (Installation)

### 1. Clone the repository
```bash
git clone https://github.com/ArsenShkryabin/synaptics-009b-fprintd.git
cd synaptics-009b-fprintd
```

### 2. Run the automated installer
```bash
sudo ./install.sh
```

The script will automatically:
- Download the official driver CAB from Microsoft Update Catalog and extract model weights.
- Locate or configure the sensor pairing material.
- Compile `syna-tool` in release mode.
- Install `syna-fprintd`, the systemd service, udev rules, and PAM configurations.
- Start and enable `fprintd.service`.

---

## 🖐️ Enrolling Fingerprints

Once installed, use the standard Linux fingerprint commands:

### Enroll your finger (e.g. left index finger):
```bash
fprintd-enroll -f left-index-finger
```
Touch the sensor 5–6 times with slight shifts until it reports `enroll-completed`.

### Verify your fingerprint:
```bash
fprintd-verify
```
Touch the scanner. It will output `Verify result: verify-match (done)`.

### List registered fingers:
```bash
fprintd-list $USER
```

---

## 🔒 PAM & Lock Screen Configuration

- **`sudo`:** Authenticate with your fingerprint without typing your password.
- **Hyprland / Omarchy Lock Screen:** Handled automatically via `/etc/pam.d/omarchy-lock-fingerprint`. Touch the sensor while locked to instantly unlock.
- **SDDM / GDM:** Supported through standard `pam_fprintd.so`.

---

## 🛠 Architecture & AI-Agent Notes

For developers and AI coding agents (Claude, Cursor, OpenCode):

- `synaptics-prometheus`: Driver crate handling session establishment, stream arming, and frame capture.
- `synaptics-prometheus-qm`: Reverse-engineered QuantumMatcher host biometric engine.
- `daemon/syna-fprintd`: Python D-Bus daemon bridging `net.reactivated.Fprint` to `syna-tool`.
- `tools/extract_qm_models.py`: Carves neural network weights (`metviper_weights.bin`, `metviper_mask.bin`, `metviper_lut.bin`) directly from `synaWudfBioUsb.dll`.
- `tools/extract_fw_modules.py`: Extracts ROM config modules.

---

## 📜 License

GPL-3.0-or-later. Derived from reverse-engineering research by the open-source community (`heeen/rustics`). No proprietary binaries or captured biometric templates are stored in this repository.
