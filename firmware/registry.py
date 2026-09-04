#!/usr/bin/env python3
"""D5 - Registry Analyzer

Windows registry hive parsing, key enumeration, timeline.
Uses struct, os, datetime only.
"""

import struct
import os
import sys
import datetime

REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_DWORD_BIG_ENDIAN = 5
REG_LINK = 6
REG_MULTI_SZ = 7
REG_QWORD = 11

TYPE_NAMES = {
    REG_SZ: "REG_SZ", REG_EXPAND_SZ: "REG_EXPAND_SZ", REG_BINARY: "REG_BINARY",
    REG_DWORD: "REG_DWORD", REG_DWORD_BIG_ENDIAN: "REG_DWORD_BIG_ENDIAN",
    REG_LINK: "REG_LINK", REG_MULTI_SZ: "REG_MULTI_SZ", REG_QWORD: "REG_QWORD",
}

SIG_HBIN = b"hbin"
SIG_NK = b"nk"
SIG_VK = b"vk"
SIG_LF = b"lf"
SIG_LH = b"lh"
SIG_RI = b"ri"


def filetime_to_dt(ft):
    """Convert Windows FILETIME (100ns since 1601) to datetime."""
    if ft == 0:
        return None
    try:
        epoch = datetime.datetime(1601, 1, 1)
        return epoch + datetime.timedelta(microseconds=ft / 10.0)
    except Exception:
        return None


def to_windows_ticks(dt):
    epoch = datetime.datetime(1601, 1, 1)
    return int((dt - epoch).total_seconds() * 10_000_000)


class RegistryHive:
    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        self.size = len(self.data)
        self.root_key = None
        self.keys = []
        self.values = []

    def parse(self):
        self._parse_hive_header()
        root_off = self._read_root()
        self.root_key = self._parse_key_block(root_off)

    def _parse_hive_header(self):
        sig = self.data[:4]
        if sig != b"regf":
            raise ValueError("Not a valid registry hive (missing regf signature)")
        # 0x24: last written FILETIME
        ft = struct.unpack_from("<Q", self.data, 0x24)[0]
        self.last_written = filetime_to_dt(ft)
        # 0x28: major, 0x2a: minor
        major = struct.unpack_from("<H", self.data, 0x28)[0]
        minor = struct.unpack_from("<H", self.data, 0x2A)[0]
        self.version = (major, minor)
        # 0x1C: root cell offset (relative to first hbin)
        self.root_cell = struct.unpack_from("<I", self.data, 0x1C)[0]

    def _read_root(self):
        # Root key cell is at some offset; walk hbin cells to find it.
        # The root offset in header is relative to base block (0).
        off = self.root_cell
        if off + 4 > self.size:
            raise ValueError("Root cell offset out of range")
        return off

    def _cell_off(self, rel):
        return rel

    def _read_data(self, voff, dsize):
        """Decode a value's data pointer/size into bytes."""
        if dsize & 0x80000000:
            # inline data
            return self.data[voff:voff + (dsize & 0x7FFFFFFF)]
        return self.data[voff:voff + dsize]

    def _parse_key_block(self, off):
        """Parse an nk block at file offset (absolute). Recursively load subkeys."""
        if off + 76 > self.size:
            return None
        if self.data[off:off + 2] != SIG_NK:
            return None
        # nk structure (relative offsets): skip 8-byte header
        flags = struct.unpack_from("<H", self.data, off + 2)[0]
        last_written = struct.unpack_from("<Q", self.data, off + 8)[0]
        parent = struct.unpack_from("<I", self.data, off + 0x14)[0]
        subkey_count = struct.unpack_from("<I", self.data, off + 0x18)[0]
        subkey_off = struct.unpack_from("<I", self.data, off + 0x1C)[0]
        value_count = struct.unpack_from("<I", self.data, off + 0x24)[0]
        value_off = struct.unpack_from("<I", self.data, off + 0x28)[0]
        name_len = struct.unpack_from("<H", self.data, off + 0x48)[0]
        class_len = struct.unpack_from("<H", self.data, off + 0x4A)[0]
        name = self.data[off + 76:off + 76 + name_len]
        try:
            name_str = name.decode("utf-16-le", errors="replace").rstrip("\x00")
        except Exception:
            name_str = name.decode(errors="replace")
        key = {
            "name": name_str,
            "last_written": filetime_to_dt(last_written),
            "flags": flags,
            "offset": off,
            "values": [],
            "subkeys": [],
        }
        for (vname, vtype, vdata, voff) in self._parse_values(value_off, value_count):
            key["values"].append({"name": vname, "type": vtype, "data": vdata, "offset": voff})
        self.keys.append(key)
        for sub in self._parse_subkeys(subkey_off, subkey_count):
            sk = self._parse_key_block(sub)
            if sk:
                key["subkeys"].append(sk)
        return key

    def _parse_values(self, value_off, count):
        """Parse a list of vk cells given the list offset and count."""
        if not count:
            return []
        out = []
        off = value_off
        for _ in range(min(count, 5000)):
            if off + 4 > self.size:
                break
            if self.data[off:off + 2] != SIG_VK:
                # value list stores offsets to individual vk cells
                cell = struct.unpack_from("<I", self.data, off)[0]
                vk = self._parse_one_value(cell)
                if vk:
                    out.append(vk)
                off += 4
            else:
                vk = self._parse_one_value(off)
                if vk:
                    out.append(vk)
                off += 20
            if len(out) >= count:
                break
        return out

    def _parse_one_value(self, off):
        if off + 24 > self.size or self.data[off:off + 2] != SIG_VK:
            return None
        name_len = struct.unpack_from("<H", self.data, off + 2)[0]
        data_len = struct.unpack_from("<I", self.data, off + 4)[0]
        data_off = struct.unpack_from("<I", self.data, off + 8)[0]
        vtype = struct.unpack_from("<I", self.data, off + 12)[0]
        name = self.data[off + 20:off + 20 + name_len]
        try:
            name_str = name.decode("utf-16-le", errors="replace")
        except Exception:
            name_str = name.decode(errors="replace")
        raw = self._read_data(data_off, data_len)
        return (name_str, vtype, self._decode_value(vtype, raw), off)

    def _decode_value(self, vtype, raw):
        if vtype == REG_DWORD:
            if len(raw) >= 4:
                return struct.unpack("<I", raw[:4])[0]
            return raw.hex()
        elif vtype == REG_QWORD:
            if len(raw) >= 8:
                return struct.unpack("<Q", raw[:8])[0]
            return raw.hex()
        elif vtype in (REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ):
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        elif vtype == REG_BINARY:
            return raw.hex()
        else:
            return raw.hex()

    def _parse_subkeys(self, list_off, count):
        """Parse a subkey list (lf/lh). Returns list of absolute cell offsets."""
        result = []
        if not count or list_off == 0xFFFFFFFF or list_off + 4 > self.size:
            return result
        sig = self.data[list_off:list_off + 2]
        if sig == SIG_RI:
            # index into more lists
            num = struct.unpack_from("<H", self.data, list_off + 2)[0]
            entry = list_off + 4
            for _ in range(num):
                sub = struct.unpack_from("<I", self.data, entry)[0]
                result.extend(self._parse_subkeys(sub, count))
                entry += 4
            return result
        elif sig in (SIG_LF, SIG_LH):
            num = struct.unpack_from("<H", self.data, list_off + 2)[0]
            entry = list_off + 4
            for _ in range(min(num, count)):
                if entry + 4 > self.size:
                    break
                cell = struct.unpack_from("<I", self.data, entry)[0]
                result.append(cell)
                entry += 8
            return result
        return result

    def flatten(self, key, prefix=""):
        rows = []
        path = prefix
        if key["name"]:
            path = prefix + "\\" + key["name"] if prefix else key["name"]
        for v in key["values"]:
            rows.append((path, v["name"], v["type"], v["data"], key["last_written"], key["offset"]))
        for sk in key["subkeys"]:
            rows.extend(self.flatten(sk, path))
        return rows

    def timeline(self):
        events = []
        for k in self.keys:
            if k["last_written"]:
                events.append((k["last_written"], "key_write", k["name"]))
                for v in k["values"]:
                    if k["last_written"]:
                        pass
        events.sort(key=lambda x: (x[0] or datetime.datetime.min))
        return events


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 registry.py <hive_file>")
        return 1
    path = sys.argv[1]
    if not os.path.isfile(path):
        print("Error: %s not found" % path)
        return 1
    try:
        hive = RegistryHive(path)
        hive.parse()
    except Exception as e:
        print("Error: %s" % e)
        return 1

    print("=== D5 - Registry Analyzer ===")
    print("File: %s" % path)
    print("Hive size: %d bytes" % hive.size)
    print("Version: %d.%d" % hive.version)
    print("Last written: %s" % (hive.last_written or "unknown"))
    print("Root key: %s" % hive.root_key["name"] if hive.root_key else "unknown")

    print("\n-- Key List (%d keys) --" % len(hive.keys))
    for k in hive.keys[:40]:
        ts = k["last_written"].isoformat() if k["last_written"] else "?"
        print("  [%s] %s" % (ts, k["name"]))

    print("\n-- Timeline (last 40 write events) --")
    events = hive.timeline()
    for ts, etype, name in events[-40:]:
        print("  %s  %-10s %s" % (ts.isoformat() if ts else "?", etype, name))
    if not events:
        print("  (no events)")

    print("\n-- Root subkeys sample --")
    if hive.root_key:
        for sk in hive.root_key["subkeys"][:20]:
            print("  \\%s (%d values)" % (sk["name"], len(sk["values"])))

    return 0


if __name__ == "__main__":
    sys.exit(main())
