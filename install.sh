#!/bin/bash
set -e

# ==============================================================================
# synaptics-009b-fprintd installer
# Linux driver & fprintd drop-in service for Synaptics 06cb:009b (MSI SecurePad)
# ==============================================================================

if [ "$EUID" -ne 0 ]; then
  echo "Error: Please run as root (sudo ./install.sh)"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== 1. Checking dependencies ==="
MISSING_PKGS=""
command -v curl >/dev/null 2>&1 || MISSING_PKGS="$MISSING_PKGS curl"
command -v 7z >/dev/null 2>&1 || command -v 7za >/dev/null 2>&1 || command -v cabextract >/dev/null 2>&1 || MISSING_PKGS="$MISSING_PKGS 7zip"
command -v python3 >/dev/null 2>&1 || MISSING_PKGS="$MISSING_PKGS python"
command -v cargo >/dev/null 2>&1 || MISSING_PKGS="$MISSING_PKGS rust/cargo"

if [ -n "$MISSING_PKGS" ]; then
  echo "Missing required tools: $MISSING_PKGS"
  if command -v pacman >/dev/null 2>&1; then
    echo "Installing via pacman..."
    pacman -S --needed --noconfirm 7zip curl python rust
  elif command -v apt >/dev/null 2>&1; then
    echo "Installing via apt..."
    apt-get update && apt-get install -y p7zip-full curl python3 python3-pip cargo rustc libusb-1.0-0-dev
  elif command -v dnf >/dev/null 2>&1; then
    echo "Installing via dnf..."
    dnf install -y p7zip curl python3 cargo rust libusbx-devel
  else
    echo "Please install missing packages manually and re-run install.sh."
    exit 1
  fi
fi

mkdir -p windows-driver synaptics-prometheus-qm/data
install -d -m 700 /etc/synaptics
install -d -m 700 /var/lib/fprint/synaptics

echo "=== 2. Acquiring Synaptics driver DLL ==="
if [ ! -f "windows-driver/synaWudfBioUsb.dll" ]; then
  # Try to find from existing Windows partition first
  FOUND_WIN=""
  for part in /dev/nvme*p* /dev/sd*; do
    if blkid "$part" 2>/dev/null | grep -qi "ntfs"; then
      TMP_MNT=$(mktemp -d)
      if mount -o ro "$part" "$TMP_MNT" 2>/dev/null; then
        WIN_DLL=$(find "$TMP_MNT/Windows/System32" -iname "synaWudfBioUsb.dll" 2>/dev/null | head -n 1 || true)
        if [ -n "$WIN_DLL" ]; then
          echo "Found driver DLL on Windows partition ($part): $WIN_DLL"
          cp "$WIN_DLL" windows-driver/synaWudfBioUsb.dll
          FOUND_WIN="$part"
        fi
        umount "$TMP_MNT" 2>/dev/null || true
        rmdir "$TMP_MNT" 2>/dev/null || true
        [ -n "$FOUND_WIN" ] && break
      fi
    fi
  done

  # If not found on local disk, download official 1.2 MB CAB directly from Microsoft Update Catalog
  if [ ! -f "windows-driver/synaWudfBioUsb.dll" ]; then
    echo "Downloading official driver CAB from Microsoft Update Catalog..."
    MS_URL="https://catalog.s.download.windowsupdate.com/d/msdownload/update/driver/drvs/2022/02/5f113717-0077-472e-898b-776e2d10ba50_f1b188172ca2e951ff68896deaa7af9d3544168e.cab"
    CAB_SHA256="35866f5ef98d1cf14a621aee91895dd2be4fb534cb9722243e5b8254373c87c7"
    TMP_CAB="$(mktemp)"
    curl -fsSL "$MS_URL" -o "$TMP_CAB"
    echo "${CAB_SHA256}  ${TMP_CAB}" | sha256sum -c - >/dev/null || {
      echo "Error: Downloaded CAB failed SHA-256 verification" >&2
      rm -f "$TMP_CAB"
      exit 1
    }
    if command -v 7z >/dev/null 2>&1; then
      7z e -y "$TMP_CAB" -o"windows-driver/" synaWudfBioUsb.dll >/dev/null
    elif command -v cabextract >/dev/null 2>&1; then
      cabextract -q -F synaWudfBioUsb.dll -d windows-driver/ "$TMP_CAB"
    fi
    rm -f "$TMP_CAB"
  fi
fi

if [ ! -f "windows-driver/synaWudfBioUsb.dll" ]; then
  echo "Error: Failed to acquire synaWudfBioUsb.dll"
  exit 1
fi

DLL_SHA256="ab56871c7bf83841719b3ae90e8bfdc646bf0f0fd01e49f1b83bdded17d3bf7b"
echo "${DLL_SHA256}  windows-driver/synaWudfBioUsb.dll" | sha256sum -c - >/dev/null || {
  echo "Error: windows-driver/synaWudfBioUsb.dll failed SHA-256 verification" >&2
  exit 1
}

echo "=== 3. Extracting neural model weights and firmware modules ==="
python3 tools/extract_qm_models.py windows-driver/synaWudfBioUsb.dll synaptics-prometheus-qm/data/
python3 tools/extract_fw_modules.py --dll windows-driver/synaWudfBioUsb.dll

echo "=== 4. Compiling syna-tool (release build) ==="
cargo build --release --bin syna-tool
install -m 755 target/release/syna-tool /usr/local/bin/syna-tool

echo "=== 5. Installing firmware modules and assets ==="
install -d -m 755 /usr/share/synaptics/fw_modules
install -m 644 synaptics-prometheus/data/fw_modules/*.bin /usr/share/synaptics/fw_modules/
install -m 644 windows-driver/synaWudfBioUsb.dll /usr/share/synaptics/synaWudfBioUsb.dll

echo "=== 6. Setting up pairing certificate ==="
if [ -f "/etc/synaptics/certstore.bin" ]; then
  chmod 600 /etc/synaptics/certstore.bin
  chmod 700 /etc/synaptics
  echo "Using existing pairing certstore at /etc/synaptics/certstore.bin"
elif [ -f "certstore.bin" ]; then
  cp certstore.bin /etc/synaptics/certstore.bin
  chmod 600 /etc/synaptics/certstore.bin
  chmod 700 /etc/synaptics
  echo "Copied local certstore.bin to /etc/synaptics/certstore.bin"
else
  echo "No existing certstore found. Pairing with 06cb:009b sensor directly over USB..."
  /usr/local/bin/syna-tool pair /etc/synaptics/certstore.bin
  chmod 600 /etc/synaptics/certstore.bin
  chmod 700 /etc/synaptics
fi

# Existing template stores may predate the private-permission rule.
find /var/lib/fprint/synaptics -type d -exec chmod 700 {} + 2>/dev/null || true
find /var/lib/fprint/synaptics -type f -exec chmod 600 {} + 2>/dev/null || true

echo "=== 7. Installing D-Bus service, udev rules and PAM configs ==="
install -m 755 daemon/syna-fprintd /usr/local/bin/syna-fprintd
install -m 644 daemon/fprintd.service /etc/systemd/system/fprintd.service
install -m 644 daemon/70-synaptics-fingerprint.rules /etc/udev/rules.d/70-synaptics-fingerprint.rules
install -m 755 daemon/synaptics-009b /usr/lib/systemd/system-sleep/synaptics-009b

if [ -f "daemon/omarchy-lock-fingerprint" ]; then
  install -m 644 daemon/omarchy-lock-fingerprint /etc/pam.d/omarchy-lock-fingerprint
fi

# PAM for sudo
if [ -f "/etc/pam.d/sudo" ] && ! grep -q "pam_fprintd.so" /etc/pam.d/sudo; then
  echo "Configuring PAM for sudo..."
  sed -i '1i auth sufficient pam_fprintd.so' /etc/pam.d/sudo
fi

# PAM for polkit
if [ -f "/etc/pam.d/polkit-1" ] && ! grep -q "pam_fprintd.so" /etc/pam.d/polkit-1; then
  echo "Configuring PAM for polkit-1..."
  sed -i '1i auth sufficient pam_fprintd.so' /etc/pam.d/polkit-1
fi

echo "=== 8. Reloading system services ==="
udevadm control --reload-rules && udevadm trigger
systemctl daemon-reload
systemctl enable --now fprintd.service

echo ""
echo "=========================================================="
echo "   Installation completed successfully!"
echo "   To enroll your finger, run:"
echo "     fprintd-enroll"
echo "   To test verification, run:"
echo "     fprintd-verify"
echo "=========================================================="
