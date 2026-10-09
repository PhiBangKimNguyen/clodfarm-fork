"""Trusted inbox reads must never create or migrate supervisor state."""

import hashlib
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from clodfarm.authority import Authority
from clodfarm.f1c import manager_authority
from clodfarm.tier0 import Denied


class InboxTests(unittest.TestCase):
    def test_reader_preserves_schema_bytes_and_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "authority ?#.db"
            with sqlite3.connect(path) as db:
                # A read-only view must also work without unrelated writable tables.
                db.execute("CREATE TABLE escalations (id TEXT, created REAL)")
                db.execute("INSERT INTO escalations VALUES ('pending-one', 1)")
            path.chmod(0o400)
            before = (hashlib.sha256(path.read_bytes()).digest(), path.stat().st_mode)
            with patch.dict(os.environ, {"FARM_AUTHORITY_DB": str(path), "FARM_TIER0": "0"}), \
                    patch("clodfarm.authority.os.chmod", side_effect=AssertionError("chmod")):
                reader = manager_authority(read_only=True)
                self.assertEqual(reader.inbox()[0]["id"], "pending-one")
                with reader.connect() as db:
                    with self.assertRaisesRegex(sqlite3.OperationalError, "readonly"):
                        db.execute("DELETE FROM escalations")
            self.assertEqual(before, (hashlib.sha256(path.read_bytes()).digest(), path.stat().st_mode))
            path.chmod(0o600)

    def test_missing_reader_and_cli_do_not_create_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "missing" / "authority.db"
            with self.assertRaisesRegex(Denied, "database missing"):
                Authority(path, read_only=True)
            self.assertFalse(path.parent.exists())
            self.check_cli_denial(path)
            self.assertFalse(path.parent.exists())

    def test_invalid_database_is_a_clean_cli_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid.db"
            path.write_bytes(b"not a database")
            self.check_cli_denial(path)
            self.assertEqual(path.read_bytes(), b"not a database")

    @unittest.skipUnless(os.name == "posix", "POSIX permissions required")
    def test_inaccessible_database_is_a_clean_cli_error(self):
        if os.geteuid() == 0:
            self.skipTest("root bypasses file permissions")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "authority.db"
            Authority(path)
            path.chmod(0)
            try:
                self.check_cli_denial(path)
            finally:
                path.chmod(0o600)

    def check_cli_denial(self, path):
        result = subprocess.run(
            [sys.executable, "-m", "clodfarm.f1c", "inbox"],
            env=os.environ | {"FARM_AUTHORITY_DB": str(path), "FARM_TIER0": "0"},
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("F1c operation denied", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.stdout, "")
