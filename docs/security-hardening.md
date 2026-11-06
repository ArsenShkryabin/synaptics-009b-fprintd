# Security hardening — 2026-11-06

Branch: `fix/security-hardening` (based on `known-good-2026-11-06`)

This page records what was hardened, what was verified on the live `06cb:009b`
sensor, and which compromises are still deliberate because they keep the
working setup alive.

## 1. Applied changes

| Commit | Change |
|---|---|
| `004d5bc` | Recorded the known-good baseline (`docs/known-good-baseline.md`). |
| `3cf67d4` | D-Bus caller authorization in `daemon/syna-fprintd`; added `daemon/test-auth-bypass.sh`. |
| `769f964` | Private template/certstore permissions in the Rust store, `syna-tool` umask, `install.sh`, and the AUR install hook. |
| `fd11e0c` | The optional 009a capture-oracle test now skips when its large fixtures are absent, so a clean checkout compiles. |

Details:

- Every user-facing Device method resolves the D-Bus `sender` to a UID.
  A normal caller may only act for its own account. Root may act for any
  account, which is required by `pam_fprintd` under `sudo`.
- `Claim`, `VerifyStart`, `EnrollStart`, `DeleteEnrolledFinger*`, and
  `ListEnrolledFingers` no longer fall back to a hardcoded user (`dhh`/UID
  1000). An empty username means "the caller".
- `Release`, `VerifyStop`, and `EnrollStop` are limited to the claimant (or
  root).
- `syna-tool` is resolved with `shutil.which`, so both `/usr/local/bin`
  (`install.sh`) and `/usr/bin` (AUR) work.
- Template store roots and per-user directories are `0700`; template files
  are `0600`. `syna-tool` also sets `umask 077`. Existing live files were
  tightened with `chmod` / `find` and are now `700`/`600`.
- `install.sh` fails loudly if no pairing certstore is available instead of
  installing a daemon that cannot verify anything.

## 2. Live verification (same sensor, same template)

After installing the patched daemon and `syna-tool`:

```text
$ ./daemon/test-auth-bypass.sh
== positive: claim self ==
== positive: list own prints ==
== negative: claim root ==
== negative: list root's prints ==
== positive: release ==
OK: caller authorization is enforced.

$ fprintd-list dhh
 - #0: left-index-finger

$ fprintd-verify -f left-index-finger
Verify result: verify-match (done)
```

The successful frame in the journal:

```text
VERIFY: diff=189 anchors=2 score=1733/1200 consensus=false strict=false matched=true
Signal: VerifyFingerSelected(left-index-finger)
Signal: VerifyFingerMatched(left-index-finger)
Signal: VerifyStatus(verify-match, True)
```

`strict` is the DLL-faithful gate (`consensus.found && score > threshold`).
It was **false** on a genuine match. The current working verification
therefore depends on the `score >= threshold` fallback in
`synaptics-prometheus-qm/src/matcher.rs`. Removing that fallback now would
break the sensor. The code has a comment at the decision site and this page
is the regression record.

## 3. Capture-fault (`0x0450`) and matcher anchor-ranking fixes

### `0x0450` (`CaptureAlreadyArmed`)

- Commit `89d943f` had added `0x0450` to `RawFrame::is_ok` and `FrameCapturer::capture_one`,
  causing `capture_one` to block on a bulk EP-`0x82` read on a rejected arm *before*
  `Session::capture_one_recovering` (`Status::requests_sensor_reboot_retry()`) could reboot
  (`0x05`) and re-arm. That also broke two unit tests
  (`capture_one_skips_read_on_bad_arm`, `capture_one_recovering_reboots_and_rearms_once_on_capture_fault`).
- Restored `0x0000 | 0x0412` as the armed-OK predicate so a `0x0450` fault immediately skips the
  bulk read and triggers the single soft-reboot + re-arm recovery path.

### Matcher empty-compare sentinels & anchor comparator (`0x1800078d0`, `0x1800088a0`)

Disassembly of `synaWudfBioUsb.dll` revealed two bugs in the QM matcher port:

1. **`CompareRecord::empty` (`0x1800078d0` / `0x180004480`):** when `descriptor_match_loop` finds
   `count == 0` gallery matches, the DLL skips the three feature kernels and leaves `workRec` slots
   `+0x68` (`hamming_mean`), `+0x6c` (`hamming_median`), `+0x70` (`coverage_scalar`), `+0x84`
   (`coverage_buckets[4]`), `+0x98` (`angle_avg_all`), and `+0x9c` (`angle_avg_class0`) at their
   `0x7fff` sentinel values. The port previously filled all of them with `0`, which `znorm_feature`
   mapped to `-1.6` ("zero Hamming distance / perfect match"), inflating scores on 0-matchloop anchors.
2. **`sort_anchor_order` (`0x1800088a0` in `syna_qm_score_features@0x1800088d0`):** the DLL's
   `qsort` comparator ranks anchors by **`work[+0x68]` (`compare.hamming_mean`) ascending** first and
   **`work[+0x60]` (`match_count`) descending** second. The port previously ranked by
   `match_count` descending then local RANSAC `avg_dist` (`+0x5c`) ascending, ignoring `+0x68`.
   On the real enrolled `07.tmpl`, fixing both raised shifted-view self-scores (`view[0]: 637 → 3000`,
   `view[1]: 0 → 1743`) and cross-view genuine scores (`view[1]→view[3]: 0 → 2328`,
   `view[3]→view[0]: 0 → 2694` with `consensus=true`).

Note: the `score >= threshold` fallback in `matcher.rs` is still retained until geometric-consensus
`pick_transform`/`finalize` (`0x18000c460`/`0x18000bd40`) are ported in full.

## 4. Test status

- `cargo test --release` (entire workspace: unit + integration + examples) — **434 passed, 0 failed**.
- `python3 -m py_compile daemon/syna-fprintd` and
  `bash -n daemon/test-auth-bypass.sh` pass.

## 5. Installed live state

| Item | SHA-256 |
|---|---|
| `/usr/local/bin/syna-fprintd` | `390e974f7424ec28c54cce8bd2dc05af41c678dcceb54e2405ea9fe2574da510` |
| `/usr/local/bin/syna-tool` | `bdcdfda19b388b499a802f31532c9b79b9ea294cc670b936697f58a35bdce2a5` |
| `/etc/synaptics/certstore.bin` | unchanged `93dfe0f1…` |
| `/var/lib/fprint/synaptics/1000/07.tmpl` | unchanged `d091675b…` |

The known-good binaries are also stored, root-only, in
`/root/syna-known-good-2026-11-06/bin/`.

## 6. Rollback

```bash
sudo install -m 755 /root/syna-known-good-2026-11-06/bin/syna-fprintd \
  /usr/local/bin/syna-fprintd
sudo install -m 755 /root/syna-known-good-2026-11-06/bin/syna-tool \
  /usr/local/bin/syna-tool
sudo systemctl restart fprintd
fprintd-list dhh
```

The pairing material and template do not need to be restored for this
rollback; their permissions may stay `600`/`700`.
