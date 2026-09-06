#!/usr/bin/env python3
"""D5 - Registry Analyzer

Windows registry hive (REGF_NI) parsing: header, hbins, keys, values, data blobs.
Lists keys/values and extracts autostart (Run/RunOnce) entries.
Uses struct, os, datetime only.
"""

import struct
import os
import sys
import json
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

SIG_NK = b"nk"
SIG_VK = b"vk"
SIG_LF = b"lf"
SIG_LH = b"lh"
SIG_RI = b"ri"

AUTOSTART_KEYS = {"Run", "RunOnce"}


def filetime_to_dt(ft):
    if ft == 0:
        return None
    try:
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft / 10.0)
    except Exception:
        return None


class RegistryHive:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        self.size = len(self.data)
        self.root_key = None
        self.keys = []
        self.values = []

    def parse(self):
        self._parse_hive_header()
        root_off = self.root_cell
        self.root_key = self._parse_key_block(root_off)
        return self.root_key

    def _parse_hive_header(self):
        sig = self.data[:4]
        if sig != b"regf":
            raise ValueError("Not a valid registry hive (missing regf signature)")
        ft = struct.unpack_from("<Q", self.data, 0x0C)[0]
        self.last_written = filetime_to_dt(ft)
        major = struct.unpack_from("<I", self.data, 0x14)[0]
        minor = struct.unpack_from("<I", self.data, 0x18)[0]
        self.version = (major, minor)
        self.root_cell = struct.unpack_from("<I", self.data, 0x24)[0]

    def _read_data(self, voff, dsize, inline_off=None):
        if dsize & 0x80000000:
            dsize = dsize & 0x7FFFFFFF
            if inline_off is not None:
                return self.data[inline_off:inline_off + dsize]
            return self.data[voff:voff + dsize]
        return self.data[voff:voff + dsize]

    def _parse_key_block(self, off):
        if off + 76 > self.size:
            return None
        if self.data[off:off + 2] != SIG_NK:
            return None
        flags = struct.unpack_from("<H", self.data, off + 2)[0]
        last_written = struct.unpack_from("<Q", self.data, off + 8)[0]
        parent = struct.unpack_from("<I", self.data, off + 0x14)[0]
        subkey_count = struct.unpack_from("<I", self.data, off + 0x18)[0]
        subkey_off = struct.unpack_from("<I", self.data, off + 0x1C)[0]
        value_count = struct.unpack_from("<I", self.data, off + 0x24)[0]
        value_off = struct.unpack_from("<I", self.data, off + 0x28)[0]
        name_len = struct.unpack_from("<H", self.data, off + 0x48)[0]
        class_len = struct.unpack_from("<H", self.data, off + 0x4A)[0]
        name_bytes = self.data[off + 76:off + 76 + name_len]
        try:
            name = name_bytes.decode("utf-16-le", errors="replace").rstrip("\x00")
        except Exception:
            name = name_bytes.decode(errors="replace")

        key = {
            "name": name,
            "last_written": filetime_to_dt(last_written),
            "flags": flags,
            "offset": off,
            "parent": parent,
            "values": [],
            "subkeys": [],
        }
        for (vname, vtype, vdata, voff) in self._parse_values(value_off, value_count):
            key["values"].append({"name": vname, "type": TYPE_NAMES.get(vtype, "0x%x" % vtype),
                                  "type_id": vtype, "data": vdata, "offset": voff})
            self.values.append(key["values"][-1])
        self.keys.append(key)
        for sub in self._parse_subkeys(subkey_off, subkey_count):
            sk = self._parse_key_block(sub)
            if sk:
                key["subkeys"].append(sk)
        return key

    def _parse_values(self, value_off, count):
        if not count:
            return []
        out = []
        off = value_off
        for _ in range(min(count, 5000)):
            if off + 4 > self.size:
                break
            if self.data[off:off + 2] != SIG_VK:
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
        if data_len & 0x80000000:
            raw = self._read_data(data_off, data_len, inline_off=off + 20 + name_len)
        else:
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
        if not count or list_off == 0xFFFFFFFF or list_off + 4 > self.size:
            return []
        sig = self.data[list_off:list_off + 2]
        if sig == SIG_RI:
            num = struct.unpack_from("<H", self.data, list_off + 2)[0]
            entry = list_off + 4
            result = []
            for _ in range(num):
                sub = struct.unpack_from("<I", self.data, entry)[0]
                result.extend(self._parse_subkeys(sub, count))
                entry += 4
            return result
        elif sig in (SIG_LF, SIG_LH):
            num = struct.unpack_from("<H", self.data, list_off + 2)[0]
            entry = list_off + 4
            result = []
            for _ in range(min(num, count)):
                if entry + 4 > self.size:
                    break
                cell = struct.unpack_from("<I", self.data, entry)[0]
                result.append(cell)
                entry += 8
            return result
        return []

    # ------- helpers -------
    def key_path_map(self, key, prefix=""):
        path = prefix
        if key["name"]:
            path = prefix + "\\" + key["name"] if prefix else key["name"]
        yield (path, key)
        for sk in key["subkeys"]:
            yield from self.key_path_map(sk, path)

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

    def autostart_entries(self):
        """Extract Run/RunOnce values (autostart or persistence indicators)."""
        out = []
        for path, key in self.key_path_map(self.root_key):
            leaf = key["name"]
            if leaf in AUTOSTART_KEYS:
                for v in key["values"]:
                    if isinstance(v["data"], str) and v["data"]:
                        out.append({
                            "key": path,
                            "name": v["name"],
                            "command": v["data"],
                            "type": v["type"],
                        })
        return out

    def timeline(self):
        events = []
        for k in self.keys:
            if k["last_written"]:
                events.append((k["last_written"], "key_write", k["name"]))
        events.sort(key=lambda x: (x[0] or datetime.datetime.min))
        return events


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="D5 - Registry Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--input", "-i", help="Path to registry hive (.regf) file")
    parser.add_argument("--output", "-o", help="JSON report output path")
    parser.add_argument("--demo", action="store_true", help="Parse built-in fixture")
    args = parser.parse_args()

    if args.demo:
        base = os.path.dirname(os.path.abspath(sys.argv[0]))
        if os.path.basename(base) == "firmware":
            base = os.path.dirname(base)
        fixture = os.path.join(base, "tests", "fixtures", "test_hive.regf")
        if not os.path.isfile(fixture):
            print("[ERROR] Fixture not found: %s" % fixture)
            sys.exit(1)
        hive = RegistryHive(fixture)
        hive.parse()
        out_dir = os.path.join(base, "reports")
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, "d5_report.json")
        report = {
            "file": fixture,
            "size": hive.size,
            "version": "%d.%d" % hive.version,
            "last_written": hive.last_written.isoformat() if hive.last_written else None,
            "key_count": len(hive.keys),
            "value_count": len(hive.values),
            "autostart": hive.autostart_entries(),
            "keys": [{"name": k["name"], "values": [v["name"] for v in k["values"]],
                      "subkeys": [s["name"] for s in k["subkeys"]]} for k in hive.keys],
        }
        with open(out_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        print("=== D5 - Registry Analyzer (Demo) ===")
        print("Hive: %s" % fixture)
        print("Size: %d bytes" % hive.size)
        print("Version: %d.%d" % hive.version)
        print("Last written: %s" % (hive.last_written or "unknown"))
        print("Keys parsed: %d" % len(hive.keys))
        print("Values parsed: %d" % len(hive.values))
        print("\n-- Key/Value Tree --")
        for path, key in hive.key_path_map(hive.root_key):
            vnames = ", ".join("%s=%r" % (v["name"], v["data"]) for v in key["values"]) or "(none)"
            print("  \\%s  -> %s" % (path.replace("\\", ""), vnames))
        autostart = hive.autostart_entries()
        print("\n-- Autostart (Run/RunOnce) entries: %d --" % len(autostart))
        for a in autostart:
            print("  [%s] %s = %s" % (a["key"], a["name"], a["command"]))
        print("\nReport written to %s" % out_path)
        sys.exit(0)

    if not args.input:
        parser.print_help()
        sys.exit(1)

    if not os.path.isfile(args.input):
        print("Error: file not found: %s" % args.input)
        sys.exit(1)

    hive = RegistryHive(args.input)
    hive.parse()
    report = {
        "file": args.input,
        "size": hive.size,
        "version": "%d.%d" % hive.version,
        "key_count": len(hive.keys),
        "value_count": len(hive.values),
        "autostart": hive.autostart_entries(),
    }
    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print("Report written to %s" % args.output)
    print("=== D5 - Registry Analyzer ===")
    print("Hive: %s" % args.input)
    print("Keys parsed: %d, Values parsed: %d" % (len(hive.keys), len(hive.values)))
    for a in hive.autostart_entries():
        print("  [%s] %s = %s" % (a["key"], a["name"], a["command"]))
    sys.exit(0)


if __name__ == "__main__":
    main()
