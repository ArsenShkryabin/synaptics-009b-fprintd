# synaptics-009b-fprintd

[![CI](https://github.com/ArsenShkryabin/synaptics-009b-fprintd/actions/workflows/ci.yml/badge.svg)](https://github.com/ArsenShkryabin/synaptics-009b-fprintd/actions/workflows/ci.yml)
[![Release: v0.2.0](https://img.shields.io/badge/release-v0.2.0-blue.svg)](https://github.com/ArsenShkryabin/synaptics-009b-fprintd/releases/tag/v0.2.0)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2024%20Edition-orange.svg)](https://www.rust-lang.org/)
[![Arch Linux AUR](https://img.shields.io/badge/AUR-synaptics--009b--fprintd--git-1793d1.svg)](aur/PKGBUILD)

> **Autonomous Linux driver, drop-in `fprintd` D-Bus service & Touch ID-style GUI for Synaptics Prometheus `06cb:009b` (MSI SecurePad)**

Fully functional biometric authentication (fingerprint enrollment, verification, `sudo`, lock screen, PAM) with **100% Linux-native USB pairing**, zero Windows dependencies, and Apple Touch ID-style guided setup.

---

## 💻 Supported Hardware

| Laptop Model | USB Device ID | Silicon Generation | Capture Mode | Linux Status |
| :--- | :--- | :--- | :--- | :--- |
| **MSI PS63 Modern** (8RC, 8RD, 8M) | `06cb:009b` | Die Type-2 (`0x2449`) | EP `0x82` Stream | **Working** ✅ |
| **MSI Modern 14 / Modern 15** | `06cb:009b` | Die Type-2 (`0x2449`) | EP `0x82` Stream | **Working** ✅ |
| **MSI Prestige 14 / Prestige 15** | `06cb:009b` | Die Type-2 (`0x2449`) | EP `0x82` Stream | **Working** ✅ |
| **MSI Creator 15** | `06cb:009b` | Die Type-2 (`0x2449`) | EP `0x82` Stream | **Working** ✅ |
| **MSI GS66 Stealth** (and variants) | `06cb:009b` | Die Type-2 (`0x2449`) | EP `0x82` Stream | **Working** ✅ |
| *Other Synaptics `06cb:009b` laptops* | `06cb:009b` | Die Type-2 (`0x2449`) | EP `0x82` Stream | **Compatible** ✅ |

---

## 🎯 The Problem

The **Synaptics `06cb:009b`** fingerprint sensor is built into the glass touchpad of numerous MSI laptops. For over 5 years (since 2019), it was officially considered unsupported on Linux:
1. **Match-on-Host (MoH):** The hardware does not match fingerprints internally; it delivers encrypted frame data over TLS, requiring host-side neural matching.
2. **Die Type-2 Stream:** Unlike older ThinkPad sensors (`009a`, `0097`) that use polled `0x51` commands, `009b` uses a continuous **EP `0x82` frames-sync stream**. Attempting to send polled commands faults and resets the sensor.
3. **Upstream `libfprint`:** Marked the device as *"unlikely to ever be supported"*.

---

## 💡 The Solution

This project provides an autonomous, production-ready Linux driver stack:
- **Core Engine (`syna-tool`):** High-performance Rust binary handling USB transport (`nusb`), TLS encryption, stream frame descrambling, capacitive column noise normalization (`condition_onchip`), and neural minutiae matching (QuantumMatcher).
- **System D-Bus Daemon (`syna-fprintd`):** Drop-in replacement for `fprintd.service` implementing standard `net.reactivated.Fprint.Manager` and `net.reactivated.Fprint.Device` interfaces.
- **Robust Hardware Recovery:** 3-second bounded timeouts for USB control commands, automatic fallback to electrical port reset on stalls, and graceful `SIGTERM`/`SIGINT` handling that disarms the sensor cleanly.
- **System Integration:** Fully compatible with standard Linux utilities (`fprintd-enroll`, `fprintd-verify`, `fprintd-list`), `pam_fprintd.so` for `sudo`, Polkit, SDDM, and Hyprland/GNOME/KDE lock screens.
- **100% Linux Native Pairing:** Pairs directly with the sensor over USB (`syna-tool pair`), generating the required 4096-byte certificate store with zero dependencies on Windows or Windows Hello.
- **Non-Destructive Dual-Boot:** Preserves existing pairing data, so Windows Hello continues to work without conflict in dual-boot setups.
- **Security-First Authorization:** Enforces strict caller UID validation over D-Bus; normal users can only access their own biometric templates while `root` retains system authorization for `sudo` and lock screens. Templates and pairing keys are stored with private `0600`/`0700` permissions.
- **Desktop & GUI Ready:** Full compatibility with GNOME Control Center and KDE System Settings, including modern `DeleteEnrolledFingers2()` support, clean non-intrusive cancellation without spurious error toasts, `scan-type: "press"` UI animations, and standard D-Bus introspection properties.

---

## 🚀 Installation

### Option A: Arch Linux (AUR / `makepkg`)
```bash
git clone https://github.com/ArsenShkryabin/synaptics-009b-fprintd.git
cd synaptics-009b-fprintd/aur
makepkg -si
```
*(Package installs standard systemd drop-in override for `fprintd.service`, preserving standard `pam_fprintd.so` and CLI tools).*

### Option B: Universal Installer (Ubuntu / Debian / Fedora / Arch)
```bash
git clone https://github.com/ArsenShkryabin/synaptics-009b-fprintd.git
cd synaptics-009b-fprintd
sudo ./install.sh
```

The installer will:
1. Automatically install all required system packages (`fprintd`, `python`, `python-dbus`, `python-gobject`, `python-pyqt6`, `libusb`, `rust`, `cargo`).
2. Download the official 1.2 MB driver CAB from Microsoft Update Catalog and extract neural model weights (`metviper_*.bin`) and all 75 firmware modules.
3. Pair directly with the sensor over USB (`syna-tool pair`) to generate `/etc/synaptics/certstore.bin` if not already present.
4. Compile `syna-tool` in release mode.
5. Install `syna-fprintd`, `syna-enroll-gui`, firmware assets to `/usr/share/synaptics/`, systemd service drop-in, udev rules, sleep hook, desktop launcher entry, and PAM configurations.
6. Enable and start the service.

---

## 🖐️ Enrolling & Verifying Fingerprints

### Method A: Graphical Setup (`syna-enroll-gui`)
Launch the Apple Touch ID-style guided enrollment tool directly from your application launcher or terminal:
```bash
syna-enroll-gui
```
Features 10 guided touch stages (center, micro-shift, flanks, tip, natural working angle), animated biometric ridge progress in Tokyo Night palette, and an instant post-enrollment test.

### Method B: Standard Linux CLI (`fprintd`)
Once installed, standard Linux fingerprint commands work out of the box:

#### 1. Enroll your finger (e.g. left index finger):
```bash
fprintd-enroll -f left-index-finger
```
Touch the touchpad sensor 8–10 times with slight shifts until it reports `enroll-completed`.

#### 2. Verify your fingerprint:
```bash
fprintd-verify
```
Touch the sensor. You will receive:
```text
Using device /net/reactivated/Fprint/Device/0
Listing enrolled fingers:
 - #0: left-index-finger
Verify started!
Verify result: verify-match (done)
```

#### 3. List registered fingers:
```bash
fprintd-list $USER
```

#### 4. Inspect stored biometric templates (offline diagnostic):
```bash
syna-tool inspect $(id -u)
```
Displays minutiae counts, quality ratings, and sub-views stored in your template files without opening the sensor.

---

## 🔒 PAM & Lock Screen Configuration

- **`sudo`:** Authenticate terminal commands with your fingerprint without typing your password.
- **Hyprland / Omarchy Lock Screen:** Handled automatically via `/etc/pam.d/omarchy-lock-fingerprint` or `hyprlock`. Touch the sensor while locked to instantly unlock.
- **SDDM / GDM:** Works out of the box with `pam_fprintd.so`.
- **Suspend & Resume:** `/usr/lib/systemd/system-sleep/synaptics-009b` automatically releases the sensor before suspend and safely re-enumerates upon wake.

---

## ❓ Troubleshooting & FAQ

<details>
<summary><b>1. Pairing or generating /etc/synaptics/certstore.bin manually</b></summary>

The installer automatically pairs with your sensor. If you ever need to generate or re-pair manually:
```bash
sudo syna-tool pair /etc/synaptics/certstore.bin
sudo systemctl restart fprintd
```
If you have an existing dual-boot Windows installation and wish to keep using your existing pairing material:
```bash
sudo syna-tool pair /etc/synaptics/certstore.bin --reuse-existing
sudo systemctl restart fprintd
```
</details>

<details>
<summary><b>2. Service status and real-time logs</b></summary>

To inspect driver logs:
```bash
journalctl -u fprintd -f
```
A successful verification cycle logs:
```text
syna-fprintd: syna-tool: STATUS:READY
syna-fprintd: VERIFY: diff=248 anchors=34 score=2517/1200 matched=true
syna-fprintd: syna-tool: MATCH:left-index-finger
syna-fprintd: Signal: VerifyFingerMatched(left-index-finger)
syna-fprintd: Signal: VerifyStatus(verify-match, True)
```
</details>

---

## 🛠 Project Architecture & Components

The repository is structured into focused modules:

- `synaptics-prometheus`: Core driver crate handling session establishment, stream arming, and frame capture.
- `synaptics-prometheus-qm`: Reverse-engineered QuantumMatcher host biometric engine for minutiae matching.
- `daemon/syna-fprintd`: Python D-Bus daemon bridging `net.reactivated.Fprint` to `syna-tool`.
- `daemon/syna-enroll-gui`: Standalone minimalist PyQt6 enrollment application with Touch ID-style animations.
- `tools/extract_qm_models.py`: Carves neural network weights (`metviper_weights.bin`, `metviper_mask.bin`, `metviper_lut.bin`) directly from `synaWudfBioUsb.dll`.
- `tools/extract_fw_modules.py`: Extracts sensor ROM configuration modules.

---

## 📜 License

GPL-3.0-or-later. Derived from reverse-engineering research by the open-source community (`heeen/rustics`). No proprietary binaries or captured biometric templates are stored in this repository.
