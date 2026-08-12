import tempfile
import unittest
from pathlib import Path

from ipscan import scope as scope_mod


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, text: str) -> str:
        path = self.dir / "scope.txt"
        path.write_text(text, encoding="utf-8")
        return str(path)

    def test_missing_file_auto_mode_warns(self):
        scope = scope_mod.load_scope(None, "auto", base_dir=self.dir)
        self.assertFalse(scope.active)
        warnings = scope_mod.enforce(scope, ["8.8.8.8"])
        self.assertEqual(len(warnings), 1)

    def test_missing_file_strict_mode_fails(self):
        with self.assertRaises(scope_mod.ScopeError):
            scope_mod.load_scope(None, "strict", base_dir=self.dir)

    def test_in_scope_passes(self):
        path = self._write("192.168.1.0/24\n10.0.0.0/8  # ic ag\n")
        scope = scope_mod.load_scope(path, "auto")
        self.assertTrue(scope.active)
        self.assertEqual(scope_mod.enforce(scope, ["192.168.1.5", "10.1.2.3"]), [])

    def test_out_of_scope_blocked(self):
        path = self._write("192.168.1.0/24\n")
        scope = scope_mod.load_scope(path, "auto")
        with self.assertRaises(scope_mod.ScopeError):
            scope_mod.enforce(scope, ["192.168.1.5", "8.8.8.8"])

    def test_off_mode_skips_checks(self):
        path = self._write("192.168.1.0/24\n")
        scope = scope_mod.load_scope(path, "off")
        self.assertFalse(scope.active)
        self.assertEqual(scope_mod.enforce(scope, ["8.8.8.8"]), [])

    def test_autodiscovers_scope_file(self):
        self._write("172.16.0.0/12\n")
        scope = scope_mod.load_scope(None, "auto", base_dir=self.dir)
        self.assertTrue(scope.active)
        with self.assertRaises(scope_mod.ScopeError):
            scope_mod.enforce(scope, ["1.1.1.1"])

    def test_invalid_line_rejected(self):
        path = self._write("192.168.1.0/24\nnot-an-ip\n")
        with self.assertRaises(scope_mod.ScopeError):
            scope_mod.load_scope(path, "auto")

    def test_public_targets(self):
        found = scope_mod.public_targets(["10.0.0.1", "8.8.8.8", "127.0.0.1"])
        self.assertEqual(found, ["8.8.8.8"])


if __name__ == "__main__":
    unittest.main()
