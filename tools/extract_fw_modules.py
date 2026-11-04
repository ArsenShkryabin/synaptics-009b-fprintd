#!/usr/bin/env python3
"""
Extract all 75 firmware-module payloads from synaWudfBioUsb.dll into
synaptics-prometheus/data/fw_modules/fwmod_{src_addr:016x}.bin.

The registry metadata lives in synaptics-prometheus/src/fw_registry.rs (must stay in sync).
Writes MANIFEST.json (safe to commit) with sha256 per blob; the .bin files are gitignored.

Usage:
  python3 tools/extract_fw_modules.py [--dll PATH] [--out DIR]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

IMAGE_BASE = 0x180000000
WILDCARD = 0xFFFF

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DLL = ROOT / "windows-driver" / "synaWudfBioUsb.dll"
DEFAULT_OUT = ROOT / "synaptics-prometheus" / "data" / "fw_modules"
REGISTRY_RS = ROOT / "synaptics-prometheus" / "src" / "fw_registry.rs"


def parse_registry(path: Path) -> list[dict]:
    text = path.read_text()
    # rec(id9, id4, id0a, subkey, flags, len, src_addr)
    pat = re.compile(
        r"rec\(\s*"
        r"(0x[0-9a-fA-F]+|WILDCARD)\s*,\s*"
        r"(0x[0-9a-fA-F]+|WILDCARD)\s*,\s*"
        r"(\d+)\s*,\s*"
        r"(\d+)\s*,\s*"
        r"(0x[0-9a-fA-F]+)\s*,\s*"
        r"(0x[0-9a-fA-F]+)\s*,\s*"
        r"(0x[0-9a-fA-F]+)\s*\)"
    )
    rows = []
    for m in pat.finditer(text):
        def u32(s: str) -> int:
            if s == "WILDCARD":
                return WILDCARD
            return int(s, 16)

        rows.append(
            {
                "id9": u32(m.group(1)),
                "id4": u32(m.group(2)),
                "id0a": int(m.group(3)),
                "subkey": int(m.group(4)),
                "flags": int(m.group(5), 16),
                "len": int(m.group(6), 16),
                "src_addr": int(m.group(7), 16),
            }
        )
    return rows


def rva(src_addr: int) -> int:
    return src_addr - IMAGE_BASE


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dll", type=Path, default=DEFAULT_DLL)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--registry", type=Path, default=REGISTRY_RS)
    args = ap.parse_args()

    if not args.dll.is_file():
        print(f"error: DLL not found: {args.dll}", file=sys.stderr)
        return 1
    if not args.registry.is_file():
        print(f"error: registry not found: {args.registry}", file=sys.stderr)
        return 1

    rows = parse_registry(args.registry)
    if len(rows) != 75:
        print(f"error: expected 75 registry rows, got {len(rows)}", file=sys.stderr)
        return 1

    blob = args.dll.read_bytes()
    args.out.mkdir(parents=True, exist_ok=True)

    manifest = {
        "source_dll": str(args.dll.resolve().relative_to(ROOT.resolve())) if args.dll.resolve().is_relative_to(ROOT.resolve()) else str(args.dll),
        "image_base": f"0x{IMAGE_BASE:x}",
        "record_count": len(rows),
        "modules": [],
    }
    total_len = 0

    for i, row in enumerate(rows):
        off = rva(row["src_addr"])
        length = row["len"]
        end = off + length
        if off < 0 or end > len(blob):
            print(
                f"error: row {i} src={row['src_addr']:#x} len={length} "
                f"out of DLL bounds (size={len(blob)})",
                file=sys.stderr,
            )
            return 1
        data = blob[off:end]
        name = f"fwmod_{row['src_addr']:016x}.bin"
        out_path = args.out / name
        out_path.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        total_len += length
        manifest["modules"].append(
            {
                "index": i,
                "filename": name,
                "src_addr": f"0x{row['src_addr']:x}",
                "id9": row["id9"] if row["id9"] != WILDCARD else None,
                "id4": row["id4"] if row["id4"] != WILDCARD else None,
                "id0a": row["id0a"],
                "subkey": row["subkey"],
                "flags": f"0x{row['flags']:08x}",
                "len": length,
                "sha256": digest,
            }
        )

    manifest["total_payload_len"] = total_len
    manifest_path = args.out / "MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    print(f"# extracted {len(rows)} modules ({total_len} bytes) -> {args.out}")
    print(f"# manifest -> {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
