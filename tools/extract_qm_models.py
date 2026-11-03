#!/usr/bin/env python3
"""Extract MetViper QM model blobs from synaWudfBioUsb.dll.

Static default model ``7fbMetViper_QM`` (677→36→2):
  - weights @ RVA 0x1f3ce0  → metviper_weights.bin  (24482 × int32 LE)
  - input mask @ RVA 0x1f27a0 → metviper_mask.bin   (678 bytes)
  - scaling LUT @ RVA 0x1f27b0 → metviper_lut.bin   (677 × {f32 mean, f32 stddev})

Usage:
  python3 tools/extract_qm_models.py [path/to/synaWudfBioUsb.dll] [out_dir]

Default DLL: ../windows-driver/synaWudfBioUsb.dll
Default out:  ../synaptics-prometheus-qm/data/
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

IMAGE_BASE = 0x180000000

WEIGHTS_RVA = 0x1F3CE0
WEIGHTS_COUNT = (677 + 1) * 36 + (36 + 1) * 2  # 24482 int32

MASK_RVA = 0x1F27A0
MASK_LEN = 678  # inputPoolSize + 1 guard byte

LUT_RVA = 0x1F27B0
LUT_PAIRS = 677
LUT_LEN = LUT_PAIRS * 8  # f32 mean + f32 stddev per input


def rva_to_offset(pe: bytes, rva: int) -> int:
    """Minimal PE32+ section RVA→file offset (first matching section)."""
    if pe[:2] != b"MZ":
        raise ValueError("not a PE file")
    e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
    if pe[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise ValueError("bad PE signature")
    num_sections = struct.unpack_from("<H", pe, e_lfanew + 6)[0]
    opt_hdr_size = struct.unpack_from("<H", pe, e_lfanew + 20)[0]
    section_table = e_lfanew + 24 + opt_hdr_size
    for i in range(num_sections):
        off = section_table + i * 40
        virt_size, virt_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", pe, off + 8)
        if virt_addr <= rva < virt_addr + max(raw_size, virt_size):
            return raw_ptr + (rva - virt_addr)
    raise ValueError(f"RVA 0x{rva:x} not in any section")


def extract(dll_path: Path, out_dir: Path) -> None:
    pe = dll_path.read_bytes()
    out_dir.mkdir(parents=True, exist_ok=True)

    w_off = rva_to_offset(pe, WEIGHTS_RVA)
    weights = pe[w_off : w_off + WEIGHTS_COUNT * 4]
    assert len(weights) == WEIGHTS_COUNT * 4

    m_off = rva_to_offset(pe, MASK_RVA)
    mask = pe[m_off : m_off + MASK_LEN]
    assert len(mask) == MASK_LEN

    l_off = rva_to_offset(pe, LUT_RVA)
    lut = pe[l_off : l_off + LUT_LEN]
    assert len(lut) == LUT_LEN

    (out_dir / "metviper_weights.bin").write_bytes(weights)
    (out_dir / "metviper_mask.bin").write_bytes(mask)
    (out_dir / "metviper_lut.bin").write_bytes(lut)

    print(f"Extracted from {dll_path}:")
    print(f"  metviper_weights.bin  {len(weights)} bytes  @ {IMAGE_BASE + WEIGHTS_RVA:#x}")
    print(f"  metviper_mask.bin     {len(mask)} bytes  @ {IMAGE_BASE + MASK_RVA:#x}")
    print(f"  metviper_lut.bin      {len(lut)} bytes  @ {IMAGE_BASE + LUT_RVA:#x}")


def main() -> None:
    repo = Path(__file__).resolve().parents[1]
    dll = Path(sys.argv[1]) if len(sys.argv) > 1 else repo / "windows-driver" / "synaWudfBioUsb.dll"
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else repo / "synaptics-prometheus-qm" / "data"
    extract(dll, out)


if __name__ == "__main__":
    main()
