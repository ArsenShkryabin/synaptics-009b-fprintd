# QM golden vectors (`QMFX`)

Place binary fixture files here for integration tests against the pinned vendor DLL.

**Format spec:** [`docs/qm/qmfx-format.md`](../../../docs/qm/qmfx-format.md) (header layout, stage IDs, payload conventions).

**Generate:**

```bash
# Stub (hash check + placeholder stage 11 only):
cargo run -p qm-dll-oracle -- \
  --dll ../../windows-driver/synaWudfBioUsb.dll \
  --out .

# Live enroll (finger-gated) — produces WBF datastore record, not QMFX directly:
# see docs/qm/qm-enrollment.md § "Tudor: live enroll"
```

Until the full oracle harness exists, this directory may contain only stub fixtures (`stub_match_score.qmfx`).
