# Known-good baseline — working `06cb:009b` setup

**Snapshot date:** 2026-11-06 (Asia/Novosibirsk, UTC+06)
**Git commit:** `6b07ddc972c57ec5c3186be595d7c341fbd71b42`
**Git tag:** `known-good-2026-11-06`
**Branch at snapshot:** `main`
**Working tree at snapshot:** clean

This is the exact commit + machine configuration on which fingerprint
enrollment, `fprintd-verify`, `sudo`, and the Omarchy lock screen were last
confirmed working. Do not lose this page, the tag, or the root-only backup
described below.

---

## 1. Host

| Item | Value |
|---|---|
| OS | Omarchy 4.0.4 (`ID=omarchy`, Arch-based) |
| Kernel | `7.2.5-3-omarchy` x86_64 |
| Rust | `rustc 1.99.1` / `cargo 1.99.1` |
| Sensor | `06cb:009b Synaptics, Inc.` (Bus 001) |
| fprintd package | `fprintd 1.94.5-2` |
| libfprint package | `libfprint-git 1:1.94.100.r10.g6f9479c-1` |

## 2. Installed binaries

| Path | SHA-256 |
|---|---|
| `/usr/local/bin/syna-tool` | `b9c5b8773b87503dd2c6e34c945542c92f781f270101375ef63bc21d87b3ce91` |
| `/usr/local/bin/syna-fprintd` | `e33d59b0fbab001106cf573cf905981157bd2651f45ccc2c3346e7150f7d77bb` |

The installed daemon is byte-identical to `daemon/syna-fprintd` in the repo.
The installed `syna-tool` is byte-identical to `target/release/syna-tool`
built from the tagged commit.

## 3. Pairing material (sensor-bound — back this up)

| Item | Value |
|---|---|
| Path | `/etc/synaptics/certstore.bin` |
| Size | 4096 bytes |
| SHA-256 | `93dfe0f1df7e008bffa232a3a2847c97b07747d673df202fd83e92f7d59dfa09` |
| Mode at snapshot | `644 root:root` (works, but **should be `600`**) |

The repo-root `certstore.bin` is the same 4096-byte blob (mode `600`,
git-ignored). It is sealed with the empty `hw_key` binding used by `009b`,
so it unseals on this machine; it is still bound to **this sensor's ECDH
key** and is not portable to another sensor.

## 4. Enrolled template (back this up)

| Item | Value |
|---|---|
| Path | `/var/lib/fprint/synaptics/1000/07.tmpl` |
| Size | 5053 bytes |
| SHA-256 | `d091675bf664aa5957cceb951c55d5b93a97830bd6b6790cb3d88f41b43caa62` |
| Finger | `left-index-finger` (subtype `07`) |
| Mode at snapshot | `644 root:root` (works, but **should be `600`**) |

Directory modes at snapshot: `/var/lib/fprint` `700 root`, 
`/var/lib/fprint/synaptics` `700 root`, `.../1000` `755 root`.

## 5. Vendor/model blobs used by the working build

| File | SHA-256 |
|---|---|
| `synaptics-prometheus-qm/data/metviper_lut.bin` | `4dd8d761f871c960c104dd30f2161928ee9031d2d02556405a559764c2c93724` |
| `synaptics-prometheus-qm/data/metviper_mask.bin` | `ea85eb7a0fb5e45281e48cc2e95a422cb4e32135306680d0688e7cdf6c017b27` |
| `synaptics-prometheus-qm/data/metviper_weights.bin` | `997e8ebf01d31b8e6f02b8274e4dca95140cd7add4dee8f563aa2f6220bd603e` |

## 6. Service + integration files

| Item | Path / value |
|---|---|
| systemd unit | `/etc/systemd/system/fprintd.service` |
| ExecStart | `/usr/local/bin/syna-fprintd` |
| User | `root` |
| Service state at snapshot | `active`, `disabled` (started manually) |
| udev rule | `/etc/udev/rules.d/70-synaptics-fingerprint.rules` |
| PAM | `/etc/pam.d/omarchy-lock-fingerprint` |
| Sleep hook | `/usr/lib/systemd/system-sleep/synaptics-009b` |

## 7. Last confirmed working verification

From `journalctl -u fprintd` at snapshot time:

```text
VERIFY: diff=177 anchors=3 score=0/1200 matched=false
VERIFY: diff=255 anchors=4 score=1607/1200 matched=true
Signal: VerifyFingerMatched(left-index-finger)
Signal: VerifyStatus(verify-match, True)
```

`fprintd-list dhh` returned:

```text
Fingerprints for user dhh on Synaptics Prometheus (06cb:009b) (press):
 - #0: left-index-finger
```

## 8. Root-only backup

A full root-only copy of the pairing, template, and integration files was
made at:

```text
/root/syna-known-good-2026-11-06/
├── 07.tmpl
├── 70-synaptics-fingerprint.rules
├── certstore.bin
├── fprintd.service
├── omarchy-lock-fingerprint
├── README.txt
├── SHA256SUMS
└── synaptics-009b
```

`certstore.bin` and `07.tmpl` are mode `600`; the directory is `700 root`.

## 9. Restore recipe

```bash
# 1. Code
git fetch --tags
git switch --detach known-good-2026-11-06

# 2. Build
cargo build --release --locked --bin syna-tool

# 3. Pairing (from the root-only backup)
sudo install -d -m 700 /etc/synaptics
sudo install -m 600 /root/syna-known-good-2026-11-06/certstore.bin \
  /etc/synaptics/certstore.bin

# 4. Enrolled fingerprint
sudo install -d -m 700 /var/lib/fprint/synaptics/1000
sudo install -m 600 /root/syna-known-good-2026-11-06/07.tmpl \
  /var/lib/fprint/synaptics/1000/07.tmpl

# 5. Service
sudo install -m 644 /root/syna-known-good-2026-11-06/fprintd.service \
  /etc/systemd/system/fprintd.service
sudo systemctl daemon-reload
sudo systemctl restart fprintd

# 6. Verify
fprintd-list dhh
fprintd-verify
```

## 10. Notes / known issues at this baseline

- `certstore.bin` and the template are `644`; this is the working state, but
  it is a security issue (local users can read the sealed host key and the
  biometric template). Tightening to `600` is safe and planned.
- The daemon currently has **no D-Bus caller authorization**: any local user
  can call `Claim("<other user>")` and enroll into another user's template
  store. Fixing this is the first item on the `fix/security-hardening`
  branch; it must not change the working verification path.
- The AUR package installs binaries to `/usr/bin`, while the daemon looks for
  `syna-tool` at `/usr/local/bin/syna-tool`. Works with `install.sh`, broken
  on a clean AUR install.
- `matcher.rs` has a score-only fallback (`score >= threshold`) that can match
  without geometric consensus; `0x0450` (“already armed”) is accepted as a
  successful capture. Both need audit/tests before calling the build
  production-ready.
