import contextlib
import io
import os
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from corrobora_mobile import __version__, cli
from corrobora_mobile.evidence import EvidencePackage
from corrobora_mobile.platforms.android import adb as adb_module

REPO = Path(__file__).resolve().parents[2]


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class FakeAdb:
    def __init__(self, devices):
        self.devices = devices  # serial -> (state, build, model)
        self.calls = []

    def __call__(self, argv, timeout):
        args = argv[1:]
        self.calls.append(args)
        if args == ["devices"]:
            body = "".join(f"{s}\t{v[0]}\r\n" for s, v in self.devices.items())
            return 0, f"List of devices attached\r\n{body}\r\n".encode(), b""
        if args[2:4] == ["shell", "getprop"]:
            state, build, model = self.devices[args[1]]
            return 0, ((build if args[4] == "ro.build.type" else model) + "\r\n").encode(), b""
        raise AssertionError(argv)


class TopLevelTests(unittest.TestCase):
    def test_version_and_help(self):
        self.assertEqual(run("--version"), (0, f"corrobora-mobile {__version__}\n", ""))
        code, out, _ = run("--help")
        self.assertEqual(code, 0)
        for command in cli.COMMANDS:
            self.assertIn(command, out)
        self.assertIn("CHANGES DEVICE STATE", out)

    def test_unknown_command_or_option(self):
        self.assertEqual(run()[0], 2)
        self.assertEqual(run("bogus")[0], 2)
        self.assertEqual(run("--bogus", "devices")[0], 2)
        self.assertEqual(run("--adb")[0], 2)

    def test_acquire_without_required_options_is_a_usage_error(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            cli.main(["--adb", "adb", "acquire"])
        self.assertEqual(caught.exception.code, 2)

    def test_pyproject_declares_the_command(self):
        data = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(data["project"]["scripts"]["corrobora-mobile"], "corrobora_mobile.cli:main")


class AdbResolutionTests(unittest.TestCase):
    def test_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "corrobora.toml"
            cfg.write_text('output_dir = "out"\nadb_path = "C:/from/config/adb.exe"\n', encoding="utf-8")
            self.assertEqual(cli.resolve_adb("explicit", str(cfg)), "explicit")
            self.assertEqual(cli.resolve_adb(None, str(cfg)), "C:/from/config/adb.exe")
            sdk = Path(tmp, "Android", "Sdk", "platform-tools")
            sdk.mkdir(parents=True)
            (sdk / "adb.exe").write_bytes(b"")
            with mock.patch.dict(os.environ, {"LOCALAPPDATA": tmp}), \
                    mock.patch.object(cli.shutil, "which", return_value=None):
                self.assertEqual(cli.resolve_adb(None, None), str(sdk / "adb.exe"))
            with mock.patch.dict(os.environ, {"LOCALAPPDATA": str(Path(tmp, "none"))}), \
                    mock.patch.object(cli.shutil, "which", return_value=None):
                self.assertEqual(cli.resolve_adb(None, None), "adb")

    def test_bad_config_is_reported(self):
        code, _, err = run("--config", "does-not-exist.toml", "devices")
        self.assertEqual(code, 2)
        self.assertIn("configuration file not found", err)


class DevicesTests(unittest.TestCase):
    def devices(self, table):
        fake = FakeAdb(table)
        original = adb_module.Adb
        with mock.patch.object(adb_module, "Adb", lambda path: original(path, runner=fake)):
            code, out, _ = run("--adb", "adb", "devices")
        return code, out, fake

    def test_lists_build_type_and_model_read_only(self):
        code, out, fake = self.devices({
            "emulator-5554": ("device", "userdebug", "sdk_gphone64_x86_64"),
            "emulator-5556": ("device", "user", "sdk_gphone64_x86_64"),
            "R5CT": ("unauthorized", "", ""),
        })
        self.assertEqual(code, 0)
        self.assertRegex(out, r"emulator-5554\s+device\s+userdebug\s+sdk_gphone64_x86_64")
        self.assertRegex(out, r"R5CT\s+unauthorized\s+-")
        for args in fake.calls:
            self.assertTrue(args == ["devices"] or args[2:4] == ["shell", "getprop"], args)

    def test_no_devices(self):
        code, out, _ = self.devices({})
        self.assertEqual(code, 0)
        self.assertIn("No devices", out)


class DelegationTests(unittest.TestCase):
    def test_detect_and_provider_check_get_the_resolved_adb(self):
        from corrobora_mobile.platforms.android import detection
        from corrobora_mobile.platforms.android.providers import adb_root
        for command, module in (("detect", detection), ("provider-check", adb_root)):
            with self.subTest(command=command):
                with mock.patch.object(module, "main", return_value=7) as target:
                    code, _, _ = run("--adb", "C:/sdk/adb.exe", command, "--serial", "emulator-5554")
                self.assertEqual(code, 7)
                target.assert_called_once_with(["--adb", "C:/sdk/adb.exe", "--serial", "emulator-5554"])

    def test_explicit_adb_after_the_command_is_kept(self):
        from corrobora_mobile.platforms.android import detection
        with mock.patch.object(detection, "main", return_value=0) as target:
            run("--adb", "first", "detect", "--adb", "second")
        target.assert_called_once_with(["--adb", "second"])

    def test_verify_runs_the_standalone_verifier(self):
        with tempfile.TemporaryDirectory() as tmp:
            pkg = EvidencePackage.create(Path(tmp), "acq-1", chunk_size=1024 * 1024)
            pkg.write_artifact("plan/plan.json", b"{}", description="plan")
            fin = pkg.finalize({"purpose": "cli test"})
            code, _, _ = run("verify", str(fin.root), "--chain-head", fin.chain_head)
            for p in Path(tmp).rglob("*"):
                p.chmod(0o700 if p.is_dir() else 0o600)
        self.assertEqual(code, 2 | 4)  # integrity PASS; completeness and validation bits set
        self.assertEqual(run("verify", str(Path(tmp) / "absent"))[0], 8)


if __name__ == "__main__":
    unittest.main()
