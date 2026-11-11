"""The GUI's model layer: same results as the command line, and read-only."""

import ast
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from corrobora_mobile.evidence import EvidencePackage
from corrobora_mobile.gui import model
from corrobora_mobile.platforms.android import detection
from corrobora_mobile.platforms.android.adb import Adb
from tests.unit.test_adb_root_provider import SERIAL, FakeEmulator

GUI_DIR = Path(model.__file__).parent


def factory(fake):
    return lambda path: Adb(path, runner=fake)


def assert_read_only(test, fake):
    for args in fake.calls:
        cmd = args[2:] if args[:1] == ["-s"] else args
        test.assertTrue(cmd in (["version"], ["devices"]) or cmd[:2] == ["shell", "getprop"],
                        f"not a read-only adb call: {args}")


class DevicesTests(unittest.TestCase):
    def test_rows_and_read_only(self):
        fake = FakeEmulator()
        rows = model.devices("adb", adb_factory=factory(fake))
        self.assertEqual([(r.serial, r.state, r.build_type) for r in rows],
                         [(SERIAL, "device", "userdebug")])
        assert_read_only(self, fake)


class DetectTests(unittest.TestCase):
    def test_same_text_as_the_detect_command(self):
        fake = FakeEmulator()
        view = model.detect("adb", None, adb_factory=factory(fake))
        out = io.StringIO()
        original = detection.Adb
        detection.Adb = lambda path: Adb(path, runner=FakeEmulator())
        try:
            with contextlib.redirect_stdout(out):
                self.assertEqual(detection.main(["--adb", "adb"]), 0)
        finally:
            detection.Adb = original
        self.assertEqual("\n".join(view.lines()), out.getvalue().rstrip("\n"))
        assert_read_only(self, fake)

    def test_gate_decisions_present(self):
        view = model.detect("adb", SERIAL, adb_factory=factory(FakeEmulator()))
        text = "\n".join(view.lines())
        self.assertIn("gate (normal mode): REFUSED", text)
        self.assertIn("gate (research mode requested): ALLOWED", text)
        self.assertNotIn("raw_responses", text)


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        pkg = EvidencePackage.create(Path(self.tmp), "acq-1", chunk_size=1024 * 1024)
        pkg.write_artifact("plan/plan.json", b"{}", description="plan")
        self.fin = pkg.finalize({"purpose": "gui test"})

    def tearDown(self):
        for p in Path(self.tmp).rglob("*"):
            p.chmod(0o700 if p.is_dir() else 0o600)

    def test_pass(self):
        view = model.verify(self.fin.root, self.fin.chain_head)
        self.assertEqual(view.exit_code, 2 | 4)
        self.assertEqual(view.integrity, "PASS")
        self.assertEqual(view.flags, ("completeness", "validation"))
        self.assertIsNone(view.error)
        self.assertIn("INTEGRITY:     PASS", view.text)

    def test_wrong_chain_head_fails_integrity(self):
        view = model.verify(self.fin.root, "0" * 64)
        self.assertEqual(view.integrity, "FAIL")
        self.assertIn("integrity", view.flags)

    def test_not_a_package(self):
        view = model.verify(Path(self.tmp) / "absent")
        self.assertEqual(view.exit_code, 8)
        self.assertEqual(view.integrity, "NOT RUN")
        self.assertIn("not a directory", view.error)

    def test_missing_verifier(self):
        view = model.verify(self.fin.root, tool=Path(self.tmp) / "nope.py")
        self.assertEqual(view.exit_code, 8)
        self.assertIn("not found", view.error)


class AssetTests(unittest.TestCase):
    def test_logo_files_are_pngs_of_the_stated_size(self):
        import struct
        import tomllib
        for size in (96, 64, 32, 16):
            data = (GUI_DIR / "assets" / f"logo-{size}.png").read_bytes()
            with self.subTest(size=size):
                self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
                self.assertEqual(struct.unpack(">II", data[16:24]), (size, size))
        repo = GUI_DIR.parents[2]
        data = tomllib.loads((repo / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(data["tool"]["setuptools"]["package-data"]["corrobora_mobile.gui"],
                         ["assets/*.png"])


class ReadOnlyGuardTests(unittest.TestCase):
    """Nothing in the GUI package may reach code that changes a device."""

    FORBIDDEN_MODULES = ("providers", "acquirer", "commands")
    FORBIDDEN_NAMES = {"root", "unroot", "shell_command", "exec_out", "exec_out_stream",
                       "root_access", "AdbRootProvider", "TarAcquirer"}

    def test_sources(self):
        files = sorted(GUI_DIR.glob("*.py"))
        self.assertGreaterEqual(len(files), 3)
        for path in files:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = [a.name for a in node.names]
                    if isinstance(node, ast.ImportFrom):
                        names.append(node.module or "")
                    for name in names:
                        with self.subTest(file=path.name, name=name):
                            self.assertFalse(any(part in self.FORBIDDEN_MODULES
                                                 for part in name.split(".")))
                if isinstance(node, ast.Attribute):
                    with self.subTest(file=path.name, attr=node.attr):
                        self.assertNotIn(node.attr, self.FORBIDDEN_NAMES)


if __name__ == "__main__":
    unittest.main()
