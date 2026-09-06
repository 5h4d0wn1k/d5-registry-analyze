#!/usr/bin/env python3
"""Craft a structurally-faithful synthetic REGF (registry hive) fixture for D5.

This implements the on-disk REGF_NI structures byte-for-byte as interpreted by the
registry parser firmware: regf header, nk (key node), vk (value), lf (subkey list),
with the documented offsets used by the parser. It is a *synthesized* hive (not a
captured real OS hive) but is structurally faithful: a real parser reading these
bytes would see valid signatures and fields.

Layout (absolute file offsets, little-endian):
  0x0000  regf header (512-byte base block)
  0x1000  root nk cell
  0x1400  root value-list pointer block
  0x1500  (value "RootValue" vk)
  0x1800  root subkey lf list -> SOFTWARE
  0x1C00  SOFTWARE nk
  0x2000  SOFTWARE value-list ptr block
  0x2100  SOFTWARE "Disable" dword vk
  0x2400  SOFTWARE subkey lf list -> Run, RunOnce
  0x2800  Run nk
  0x2900  Run value-list ptr block
  0x2A00  Run value vk (REG_SZ autostart path)
  0x3000  RunOnce nk
  0x3100  RunOnce value-list ptr block
  0x3200  RunOnce value vk (REG_SZ autostart path)
"""
import os
import struct
from datetime import datetime, timezone

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")

REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4

EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime(dt):
    return int((dt - EPOCH).total_seconds() * 10_000_000)


def nk(sig=b"nk", flags=0x2C20, last=filetime(datetime(2024, 1, 15, 9, 0, 0, tzinfo=timezone.utc)),
       parent=0, subkey_count=0, subkey_off=0, value_count=0, value_off=0, name=b""):
    """Build an nk cell body (offsets match the parser). Returns bytes (no size prefix)."""
    name16 = name.encode("utf-16-le") if isinstance(name, str) else name
    buf = bytearray(76)
    buf[0:2] = sig                     # 0x00
    struct.pack_into("<H", buf, 0x02, flags)
    struct.pack_into("<Q", buf, 0x08, last)          # last written FILETIME
    struct.pack_into("<I", buf, 0x14, parent)        # parent
    struct.pack_into("<I", buf, 0x18, subkey_count)
    struct.pack_into("<I", buf, 0x1C, subkey_off)
    struct.pack_into("<I", buf, 0x24, value_count)
    struct.pack_into("<I", buf, 0x28, value_off)
    struct.pack_into("<H", buf, 0x48, len(name16))   # name length (bytes)
    struct.pack_into("<H", buf, 0x4A, 0)             # class length
    buf += name16
    return bytes(buf)


def vk(name=b"", vtype=REG_SZ, data=b"", data_off=0):
    """Build a vk cell body. If data is inline-capable (<=4 bytes) it is embedded
    by setting the high bit of data_len; otherwise data_off points to a data blob."""
    name16 = name.encode("utf-16-le") if isinstance(name, str) else name
    buf = bytearray(20)
    buf[0:2] = b"vk"
    struct.pack_into("<H", buf, 2, len(name16))        # name length (bytes)
    if data_off is None:
        # inline data
        data_len = len(data) | 0x80000000
    else:
        data_len = len(data)
    struct.pack_into("<I", buf, 4, data_len)
    struct.pack_into("<I", buf, 8, data_off if data_off is not None else 0)
    struct.pack_into("<I", buf, 12, vtype)
    buf += name16
    return bytes(buf)


def lf(cells):
    """Build an 'lf' subkey list body: sig + u16 count + (u32 offset, u32 hash) pairs."""
    buf = bytearray(4 + 8 * len(cells))
    buf[0:2] = b"lf"
    struct.pack_into("<H", buf, 2, len(cells))
    for i, off in enumerate(cells):
        struct.pack_into("<II", buf, 4 + i * 8, off, 0x00000000)
    return bytes(buf)


def main():
    last_written = filetime(datetime(2024, 1, 15, 9, 30, 0, tzinfo=timezone.utc))

    # ---- regf header (512 bytes) ----
    header = bytearray(512)
    header[0:4] = b"regf"
    struct.pack_into("<I", header, 0x04, 1)          # primary seq
    struct.pack_into("<I", header, 0x08, 1)          # secondary seq
    struct.pack_into("<Q", header, 0x0C, last_written)
    struct.pack_into("<I", header, 0x14, 1)          # major
    struct.pack_into("<I", header, 0x18, 5)          # minor
    struct.pack_into("<I", header, 0x24, 0x1000)     # root cell offset (root nk)

    # ---- allocate cells ----
    # We build into a dict keyed by offset, then assemble the file as zero-padded.
    blob = bytearray(0x10000)  # 64 KiB backing, will trim
    blob[0:len(header)] = header  # regf header at offset 0

    def place(off, data):
        blob[off:off + len(data)] = data
        return off

    # Root nk (0x1000)
    # Root value: "RootValue" REG_SZ with data blob
    root_value_data = "rootdata".encode("utf-16-le") + b"\x00\x00"
    root_vk_off = place(0x1500, vk("RootValue", REG_SZ, root_value_data, 0x15A0))
    place(0x15A0, root_value_data)
    root_vlist_off = place(0x1400, struct.pack("<I", root_vk_off))
    # Root subkey lf -> SOFTWARE
    software_nk_off = 0x1C00
    root_lf_off = place(0x1800, lf([software_nk_off]))
    place(0x1000, nk(flags=0x2C20, last=last_written, parent=0xFFFFFFFF,
                     subkey_count=1, subkey_off=root_lf_off,
                     value_count=1, value_off=root_vlist_off, name=""))

    # SOFTWARE nk (0x1C00)
    run_nk_off = 0x2800
    runonce_nk_off = 0x3000
    software_vk_off = place(0x2100, vk("Disable", REG_DWORD, struct.pack("<I", 0), None))
    software_vlist_off = place(0x2000, struct.pack("<I", software_vk_off))
    software_lf_off = place(0x2400, lf([run_nk_off, runonce_nk_off]))
    place(0x1C00, nk(flags=0x2C20, last=last_written, parent=0x1000,
                     subkey_count=2, subkey_off=software_lf_off,
                     value_count=1, value_off=software_vlist_off, name="Software"))

    # Run nk (0x2800)
    run_data1 = "C:\\Windows\\System32\\runhidden.exe".encode("utf-16-le") + b"\x00\x00"
    run_vk1_off = place(0x2A00, vk("AutoStart1", REG_SZ, run_data1, 0x2A80))
    place(0x2A80, run_data1)
    run_data2 = "C:\\Tools\\evil_launcher.exe".encode("utf-16-le") + b"\x00\x00"
    run_vk2_off = place(0x2B00, vk("AutoStart2", REG_SZ, run_data2, 0x2B80))
    place(0x2B80, run_data2)
    run_vlist_off = place(0x2900, struct.pack("<II", run_vk1_off, run_vk2_off))
    place(0x2800, nk(flags=0x2C20, last=last_written, parent=software_nk_off,
                     subkey_count=0, subkey_off=0,
                     value_count=2, value_off=run_vlist_off, name="Run"))

    # RunOnce nk (0x3000)
    runonce_data = "C:\\Temp\\init.bat".encode("utf-16-le") + b"\x00\x00"
    runonce_vk_off = place(0x3200, vk("Cleanup", REG_SZ, runonce_data, 0x3280))
    place(0x3280, runonce_data)
    runonce_vlist_off = place(0x3100, struct.pack("<I", runonce_vk_off))
    place(0x3000, nk(flags=0x2C20, last=last_written, parent=software_nk_off,
                     subkey_count=0, subkey_off=0,
                     value_count=1, value_off=runonce_vlist_off, name="RunOnce"))

    # Trim trailing zeros
    end = 0x3280 + len(runonce_data)
    final = bytes(blob[:end])

    os.makedirs(FIXTURE_DIR, exist_ok=True)
    path = os.path.join(FIXTURE_DIR, "test_hive.regf")
    with open(path, "wb") as f:
        f.write(final)
    print("Wrote %s (%d bytes)" % (path, len(final)))


if __name__ == "__main__":
    main()
