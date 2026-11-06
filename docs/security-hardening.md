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

## 3. Deliberately not changed yet

### `0x0450` ("capture already armed")

- `capture_one` / `RawFrame::is_ok` currently treat `0x0450` as a successful
  arm and read a frame.
- `capture_one_skips_read_on_bad_arm` and
  `capture_one_recovering_reboots_and_rearms_once_on_capture_fault` assert the
  opposite (no read; reboot and re-arm).
- The calibration path (`session_cal.rs`) separately accepts `0x0450`, and
  the 009a calendar loop is known to depend on that tolerance.

Changing this globally could break either calibration or verification on
hardware that is not available here. The safe fix is a stream-only strict
predicate plus live tests on both `009a` and `009b`.

### Matcher score-only fallback

See §2. The consensus picker is still a simplified port; score-only matching
is what makes `009b` work. Tightening it is a biometric-quality project, not
a permission fix.

## 4. Test status

- `cargo test --release -p synaptics-prometheus --lib template_store` — 3/3 pass.
- `cargo test --release -p synaptics-prometheus-qm --lib` — 111/111 pass.
- Full `synaptics-prometheus` lib tests — 266 pass, 2 fail, both the
  `0x0450` assertions above. These failures are present at the known-good
  commit too; they are not caused by the hardening branch.
- `python3 -m py_compile daemon/syna-fprintd` and
  `bash -n daemon/test-auth-bypass.sh` pass.

## 5. Installed live state

| Item | SHA-256 |
|---|---|
| `/usr/local/bin/syna-fprintd` | `390e974f7424ec28c54cce8bd2dc05af41c678dcceb54e2405ea9fe2574da510` |
| `/usr/local/bin/syna-tool` (with diagnostics) | `3d738a77d9adc30744f6ecfeb3f99dc5ee9282ddfeeecc97cbeca66c994302da` |
| `/etc/synaptics/certstore.bin` | unchanged `93dfe0f1…` |
| `/var/lib/fprint/synaptics/1000/07.tmpl` | unchanged `d091675b…` |

The live match above was captured with the diagnostic build of this same
source; the final rebuild differs only by a source comment (no code change).

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
