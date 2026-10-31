import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HARNESS = Path(__file__).resolve().parents[2] / "tools" / "validate_evidence_component.py"
HAS_EXTERNAL_HASHER = os.name == "nt" or bool(shutil.which("sha256sum") or shutil.which("shasum"))


def _load_harness():
    spec = importlib.util.spec_from_file_location("validate_evidence_component", HARNESS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


harness = _load_harness()

# Output format observed on Windows from certutil and from Get-FileHash in Windows
# PowerShell 5.1 for the same synthetic file (2026-10-31); the path is replaced
# with an example. Used to check parsing on every platform.
REAL_SHA = "d52e075826d65bd40edaf60afba64760c43fd221c098119679ff4972edb651fc"
CERTUTIL_OUTPUT = (
    "SHA256 hash of C:\\example\\input.bin:\r\n"
    f"{REAL_SHA}\r\n"
    "CertUtil: -hashfile command completed successfully.\r\n"
)
GET_FILEHASH_OUTPUT = REAL_SHA.upper() + "\r\n"


class ExternalToolHandlingTests(unittest.TestCase):
    """Parsing and error handling for the external tools, on every platform."""

    def test_certutil_output_parsed(self):
        with mock.patch.object(harness, "_check_output", return_value=CERTUTIL_OUTPUT):
            self.assertEqual(harness.ExternalHasher._run("certutil -hashfile", Path("x")), REAL_SHA)

    def test_certutil_spaced_output_parsed(self):
        spaced = " ".join(REAL_SHA[i:i + 2] for i in range(0, 64, 2))
        output = f"SHA256 hash of x:\r\n{spaced}\r\nCertUtil: done\r\n"
        with mock.patch.object(harness, "_check_output", return_value=output):
            self.assertEqual(harness.ExternalHasher._run("certutil -hashfile", Path("x")), REAL_SHA)

    def test_get_filehash_output_parsed(self):
        with mock.patch.object(harness, "_check_output", return_value=GET_FILEHASH_OUTPUT) as run:
            self.assertEqual(harness.ExternalHasher._run("PowerShell Get-FileHash", Path("x")), REAL_SHA)
        cmd = run.call_args.args[0]
        self.assertTrue(cmd[0].lower().endswith(r"system32\windowspowershell\v1.0\powershell.exe"))
        self.assertIn("-NonInteractive", cmd)
        self.assertEqual(run.call_args.kwargs["env"]["PSModulePath"],
                         harness.windows_powershell_env()["PSModulePath"])

    def test_unexpected_output_is_an_error_not_a_hash(self):
        for tool, output in (("sha256sum", ""), ("sha256sum", "abc  file\n"),
                             ("certutil -hashfile", "CertUtil: error\r\n"),
                             ("PowerShell Get-FileHash", "\r\n")):
            with self.subTest(tool=tool, output=output):
                with mock.patch.object(harness, "_check_output", return_value=output):
                    with self.assertRaisesRegex(RuntimeError, "unexpected output"):
                        harness.ExternalHasher._run(tool, Path("x"))

    def test_powershell_env_uses_only_windows_powershell_modules(self):
        base = {
            "SystemRoot": r"C:\WINDOWS",
            "ProgramFiles": r"C:\Program Files",
            "PSModulePath": r"C:\Program Files\PowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules",
            "OTHER": "kept",
        }
        env = harness.windows_powershell_env(base)
        self.assertEqual(
            env["PSModulePath"],
            r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\Modules;C:\Program Files\WindowsPowerShell\Modules",
        )
        self.assertEqual(env["OTHER"], "kept")
        self.assertIn("PowerShell\\Modules;", base["PSModulePath"])  # caller's mapping unchanged

    def test_failed_command_reports_status_and_stderr(self):
        cmd = [sys.executable, "-c", "import sys; sys.stderr.write('tool said no'); sys.exit(3)"]
        with self.assertRaisesRegex(RuntimeError, r"status 3: tool said no"):
            harness._check_output(cmd)

    def test_missing_program_is_reported(self):
        with self.assertRaisesRegex(RuntimeError, "cannot run"):
            harness._check_output([str(HARNESS.parent / "no-such-program")])


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
        self.assertTrue((runs[0] / "results.json").is_file(), proc.stdout + proc.stderr)
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
        proc = subprocess.run(
            [sys.executable, str(HARNESS), "--input", str(source), "--workdir", str(tmp / "out"),
             "--chunk-size", "4096"],
            capture_output=True, text=True, timeout=300,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
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
