#!/usr/bin/env python3
"""Limit factory rootfs_data without consuming the X30E Pro bad-block reserve.

Runs on the generated factory image only. It never modifies a live overlay.
"""
from pathlib import Path
import struct
import sys
import zlib

PEB_SIZE = 128 * 1024
VID_OFFSET = 2048
DATA_OFFSET = 4096
PARTITION_PEBS = 0x6F80000 // PEB_SIZE
UBI_OVERHEAD_PEBS = 4  # two layout, one wear-leveling and one atomic-change PEB
BAD_BLOCK_RESERVE_PEBS = 19
VTBL_VOL_ID = 0x7FFFEFFF
RECORD_SIZE = 172
CRC_OFFSET = 168
ROOTFS_DATA_MAX_LEBS = 750


def fix_image(path: Path) -> None:
    image = bytearray(path.read_bytes())
    if len(image) % PEB_SIZE:
        raise ValueError("factory UBI image must be PEB-aligned")
    copies = []
    for peb in range(0, len(image), PEB_SIZE):
        vid = peb + VID_OFFSET
        if image[vid:vid + 4] != b"UBI!":
            continue
        if struct.unpack_from(">I", image, vid + 8)[0] != VTBL_VOL_ID:
            continue
        table = peb + DATA_OFFSET
        other_reserved = 0
        data_record = None
        for index in range(128):
            record = table + index * RECORD_SIZE
            reserved = struct.unpack_from(">I", image, record)[0]
            if not reserved:
                continue
            expected_crc = zlib.crc32(image[record:record + CRC_OFFSET]) ^ 0xFFFFFFFF
            if struct.unpack_from(">I", image, record + CRC_OFFSET)[0] != expected_crc:
                raise ValueError("invalid volume-table record CRC")
            name_len = struct.unpack_from(">H", image, record + 14)[0]
            name = bytes(image[record + 16:record + 16 + name_len])
            if name == b"rootfs_data":
                if data_record is not None:
                    raise ValueError("duplicate rootfs_data volume")
                data_record = record
            else:
                other_reserved += reserved
        if data_record is None:
            raise ValueError("factory image has no rootfs_data volume")
        target = min(ROOTFS_DATA_MAX_LEBS,
                     PARTITION_PEBS - UBI_OVERHEAD_PEBS - BAD_BLOCK_RESERVE_PEBS - other_reserved)
        if target < 9:
            raise ValueError("insufficient space for rootfs_data and UBI reserve")
        copies.append((data_record, target))
    if len(copies) != 2 or copies[0][1] != copies[1][1]:
        raise ValueError("expected two consistent UBI volume-table copies")
    for record, target in copies:
        struct.pack_into(">I", image, record, target)
        image[record + 144] = 0  # disable autoresize
        checksum = zlib.crc32(image[record:record + CRC_OFFSET]) ^ 0xFFFFFFFF
        struct.pack_into(">I", image, record + CRC_OFFSET, checksum)
    path.write_bytes(image)
    print(f"X30E Pro rootfs_data: {copies[0][1]} LEBs; preserve {BAD_BLOCK_RESERVE_PEBS} reserve PEBs")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} FACTORY_UBI_IMAGE")
    fix_image(Path(sys.argv[1]))
