import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HARNESS = Path(__file__).resolve().parents[2] / "tools" / "validate_evidence_component.py"
HAS_EXTERNAL_HASHER = os.name == "nt" or bool(shutil.which("sha256sum") or shutil.which("shasum"))


@unittest.skipUnless(HAS_EXTERNAL_HASHER, "no external SHA-256 tool available")
class ValidationHarnessTests(unittest.TestCase):
    """Runs the harness end to end on synthetic data.

    This tests the harness itself. It is not a validation record.
    """

    def run_harness(self, data: bytes, *extra: str):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.addCleanup(_make_writable, tmp)  # finalized packages are read-only
        source = tmp / "input.bin"
        source.write_bytes(data)
        proc = subprocess.run(
            [sys.executable, str(HARNESS), "--input", str(source), "--workdir", str(tmp / "out"), *extra],
            capture_output=True, text=True, timeout=300,
        )
        runs = list((tmp / "out").glob("run-*"))
        self.assertEqual(len(runs), 1, proc.stdout + proc.stderr)
        results = json.loads((runs[0] / "results.json").read_text(encoding="utf-8"))
        return proc, {r["check"]: r for r in results["results"]}, results["environment"], runs[0]

    def test_all_checks_pass_on_correct_component(self):
        data = os.urandom(20_000)
        proc, by_check, env, run_dir = self.run_harness(
            data, "--chunk-size", "4096", "--interrupt-chunk-size", "4096"
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        for check in ("V0", "V1", "V2", "V3", "V4", "V6"):
            self.assertEqual(by_check[check]["status"], "PASS", by_check[check])
        self.assertIn(by_check["V5"]["status"], {"PASS", "INCONCLUSIVE"})
        self.assertEqual(env["input_size"], len(data))
        self.assertTrue(env["external_tools"])
        record = (run_dir / "record.md").read_text(encoding="utf-8")
        self.assertIn("does not validate any", record)

    def test_v3_skipped_when_input_too_small(self):
        proc, by_check, _, _ = self.run_harness(b"short", "--chunk-size", "4096")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(by_check["V3"]["status"], "SKIPPED")

    def test_input_is_not_modified(self):
        data = os.urandom(10_000)
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.addCleanup(_make_writable, tmp)
        source = tmp / "input.bin"
        source.write_bytes(data)
        subprocess.run(
            [sys.executable, str(HARNESS), "--input", str(source), "--workdir", str(tmp / "out"),
             "--chunk-size", "4096"],
            capture_output=True, timeout=300, check=True,
        )
        self.assertEqual(source.read_bytes(), data)

    def test_missing_input_is_a_usage_error(self):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        proc = subprocess.run(
            [sys.executable, str(HARNESS), "--input", str(tmp / "absent"), "--workdir", str(tmp / "out")],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertFalse((tmp / "out").exists())


def _make_writable(root: Path) -> None:
    for p in root.rglob("*"):
        try:
            p.chmod(0o700 if p.is_dir() else 0o600)
        except OSError:
            pass


if __name__ == "__main__":
    unittest.main()
