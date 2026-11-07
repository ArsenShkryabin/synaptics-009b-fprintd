# Fresh-pairing probe (read-only)

`synfp pair --probe` is the first, deliberately non-destructive step toward
pairing a `06cb:009b` without Windows.

It sends only the two pre-TLS reads already used by `synfp info`:

- `0x01` GetRomInfo — identity + status/provisioning bytes;
- `0x3e` GetFlashInfo — flash IC + partition table.

It does **not** open a TLS session, send a `0x06` init payload, or emit
`0x4f`. On an unprovisioned die `0x4f` is the destructive re-partition/wipe
path. Nothing is written.

## Live output (this sensor, 2026-11-06)

```text
# read-only provisioning probe: 0x01 status + 0x3e flash table
# no TLS session, no 0x06 init, no 0x4f partition write
device: 06cb:009b
status: valid=true device_id=0x33 flags17=0x21
  reported_provisioned=false has_flash_bit=false provision_state=0
  format_mode=true key_08=0x06 key_09=0x14 key_0f=0x00
  payload[36]=10b604549a0000000614013300010000594649006b7b0021000000000100000000000006
# WARNING: bit 0x40 is clear, so the vendor format/wipe gate is armed
# on this pre-TLS read. The DLL reads this byte after firmware init, so
# a cold ROM-mode value is not a licence to run vendor init. Nothing was
# written by this probe.
flash: jedec=00ff:00ff blocks=0x1000×0x0 partitions=0
# probe complete; no pairing material was read or changed
```

## Interpretation

- `flags17 = 0x21`: bit `0x40` (has flash/partitions) is clear, so the
  vendor's `format_mode = (flags17 & 0x40) == 0` gate is **armed** on a cold
  read. This is the known cold-ROM value, not the post-init value.
- `reported_provisioned = false`; `provision_state = 0`. The Rust `SensorStatus`
  documentation already notes that a cold `0x01` on `009b` reports unpaired
  even when host-certstore TLS works.
- `jedec = 00ff:00ff`, `partitions = 0`: this SKU has no external SPI flash
  partition table in cold ROM mode, matching the existing bring-up notes
  (transient/tag-7 path, not the `0x4f` partition path).

The working Windows-paired setup is not contradicted by this: the cert-store
supplies the host key and the sensor's ECDH material, so TLS succeeds while the
sensor's own pre-TLS provisioning nibble still reads 0.

## What is still missing

A Windows-free pairing tool must reproduce the **non-destructive** vendor init
path: the tag-7/WRKP ECDH handshake that installs/reuses a host certificate
without calling `0x4f`. That work lives in
`/home/dhh/Work/rustics/docs/bringup/handshake-reconstruction.md` and
`provisioning-state-machine.md`. Until it is ported and reviewed, the driver
must keep using the Windows-created `certstore.bin`.

**Safety rule for any next step:** never emit `0x4f` on this sensor unless the
owner has explicitly accepted that it is destructive and has a verified
recovery path. Prefer a construction that physically cannot emit it.
