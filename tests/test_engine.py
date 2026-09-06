#!/usr/bin/env python3
import os
import sys
import shutil
import subprocess
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "firmware"))
from registry import RegistryHive

HERE = os.path.dirname(__file__)
FIXTURE = os.path.join(HERE, "fixtures", "test_hive.regf")


class TestRegistryHiveHeader(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hive = RegistryHive(FIXTURE)
        cls.hive.parse()

    def test_magic(self):
        self.assertEqual(self.hive.data[:4], b"regf")

    def test_root_cell(self):
        root = self.hive.root_key
        self.assertIsNotNone(root)
        self.assertEqual(root["offset"], 0x1000)

    def test_version(self):
        self.assertEqual(self.hive.version, (1, 5))

    def test_last_written_year(self):
        self.assertEqual(self.hive.last_written.year, 2024)

    def test_root_is_unnamed(self):
        self.assertEqual(self.hive.root_key["name"], "")


class TestRegistryKeyParsing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hive = RegistryHive(FIXTURE)
        cls.root = cls.hive.parse()

    def test_key_count(self):
        self.assertEqual(len(self.hive.keys), 4)

    def test_known_keys_present(self):
        names = {k["name"] for k in self.hive.keys}
        self.assertIn("Software", names)
        self.assertIn("Run", names)
        self.assertIn("RunOnce", names)

    def test_tree_nesting(self):
        software = self.hive.root_key["subkeys"][0]
        self.assertEqual(software["name"], "Software")
        subnames = {s["name"] for s in software["subkeys"]}
        self.assertEqual(subnames, {"Run", "RunOnce"})

    def test_value_types_decoded(self):
        software = self.hive.root_key["subkeys"][0]
        dval = [v for v in software["values"] if v["name"] == "Disable"][0]
        self.assertEqual(dval["type"], "REG_DWORD")
        self.assertEqual(dval["data"], 0)


class TestAutostart(unittest.TestCase):
    def setUp(self):
        self.hive = RegistryHive(FIXTURE)
        self.hive.parse()

    def test_three_autostart_entries(self):
        entries = self.hive.autostart_entries()
        self.assertEqual(len(entries), 3)

    def test_run_values_found(self):
        entries = self.hive.autostart_entries()
        commands = sorted(e["command"] for e in entries)
        self.assertIn("C:\\Windows\\System32\\runhidden.exe", commands)
        self.assertIn("C:\\Tools\\evil_launcher.exe", commands)
        self.assertIn("C:\\Temp\\init.bat", commands)

    def test_runonce_maplocation(self):
        entries = self.hive.autostart_entries()
        paths = {e["key"] for e in entries}
        self.assertIn("Software\\Run", paths)
        self.assertIn("Software\\RunOnce", paths)


class TestFlatten(unittest.TestCase):
    def setUp(self):
        self.hive = RegistryHive(FIXTURE)
        self.hive.parse()

    def test_flatten_total_rows(self):
        rows = self.hive.flatten(self.hive.root_key)
        self.assertEqual(len(rows), 5)

    def test_flatten_carries_path(self):
        rows = self.hive.flatten(self.hive.root_key)
        paths = {r[0] for r in rows}
        self.assertIn("Software", paths)
        self.assertIn("Software\\Run", paths)


class TestCLIDemo(unittest.TestCase):
    def test_demo_exit_zero_and_report(self):
        repo = os.path.dirname(HERE)
        env = dict(os.environ)
        proc = subprocess.run([sys.executable, "cli.py", "--demo"],
                              cwd=repo, capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("autostart", proc.stdout.lower())
        report = os.path.join(repo, "reports", "d5_report.json")
        self.assertTrue(os.path.isfile(report))
        with open(report) as f:
            import json
            data = json.load(f)
        self.assertGreaterEqual(len(data["autostart"]), 3)


if __name__ == "__main__":
    unittest.main()
