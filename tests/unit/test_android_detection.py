"""Android detection against recorded adb outputs.

The property values below were observed on 2026-11-01 from two Android 17
(SDK 37) x86_64 emulators (Google APIs and Google Play images). They are
values of test emulators, not evidence about any person.
"""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from corrobora_mobile.compatibility import gate, load_registry
from corrobora_mobile.core.enums import Platform, Tristate
from corrobora_mobile.core.errors import AccessError, ModelValidationError, PreconditionError
from corrobora_mobile.evidence import EvidencePackage
from corrobora_mobile.platforms.android import detection
from corrobora_mobile.platforms.android.adb import Adb, parse_devices
from corrobora_mobile.platforms.android.detection import PROPERTIES, detect, save_to_package

VERSION = (b"Android Debug Bridge version 1.0.41\r\nVersion 37.0.1-15733141\r\n"
           b"Installed as C:\\Android\\platform-tools\\adb.exe\r\nRunning on Windows 10.0.26300\r\n")
GOOGLE_APIS = {"ro.build.type": "userdebug", "ro.build.tags": "dev-keys",
               "ro.build.version.release": "17", "ro.build.version.sdk": "37",
               "ro.product.manufacturer": "Google", "ro.product.model": "sdk_gphone64_x86_64",
               "ro.kernel.qemu": "1", "ro.boot.qemu": "1", "ro.hardware": "ranchu"}
GOOGLE_PLAY = {**GOOGLE_APIS, "ro.build.type": "user", "ro.build.tags": "release-keys"}


class FakeAdb:
    """Plays the role of the adb executable; records every argv it receives."""

    def __init__(self, devices: dict[str, dict[str, str]], states: dict[str, str] | None = None,
                 fail: set[str] = frozenset()):
        self.devices = devices
        self.states = states or {s: "device" for s in devices}
        self.fail = fail
        self.calls: list[list[str]] = []

    def __call__(self, argv, timeout):
        self.calls.append(argv)
        args = argv[1:]
        if args == ["version"]:
            return 0, VERSION, b""
        if args == ["devices"]:
            body = "".join(f"{s}\t{st}\r\n" for s, st in self.states.items())
            return 0, ("List of devices attached\r\n" + body + "\r\n").encode(), b""
        if args[:1] == ["-s"] and args[2:4] == ["shell", "getprop"]:
            serial, name = args[1], args[4]
            if name in self.fail:  # stdout present but exit status non-zero: must not be used
                return 1, b"userdebug\r\n", b"error: closed\r\n"
            return 0, (self.devices[serial].get(name, "") + "\r\n").encode(), b""
        raise AssertionError(f"unexpected adb command: {argv}")


def run(devices, serial=None, **kw):
    fake = FakeAdb(devices, **kw)
    return detect(Adb("adb", runner=fake), serial), fake


class DetectionTests(unittest.TestCase):
    def test_google_apis_emulator(self):
        r, _ = run({"emulator-5554": GOOGLE_APIS})
        i = r.identity
        self.assertEqual((i.platform, i.build_type, i.os_version, i.is_emulator),
                         (Platform.ANDROID, "userdebug", "17", Tristate.YES))
        self.assertEqual((i.manufacturer, i.model), ("Google", "sdk_gphone64_x86_64"))
        self.assertEqual(r.properties["ro.build.version.security_patch"], None)  # unset -> unknown

    def test_only_read_only_commands_are_issued(self):
        _, fake = run({"emulator-5554": GOOGLE_APIS})
        for argv in fake.calls:
            args = argv[1:]
            self.assertTrue(args in (["version"], ["devices"]) or args[2:4] == ["shell", "getprop"], argv)
            self.assertNotIn("root", args)
        getprops = [a[5] for a in fake.calls if "getprop" in a]
        self.assertEqual(getprops, list(PROPERTIES))
        self.assertNotIn("ro.serialno", getprops)

    def test_raw_outputs_are_kept_byte_for_byte(self):
        r, _ = run({"emulator-5554": GOOGLE_APIS})
        names = dict(r.records)
        self.assertEqual(names["00-adb-version"].stdout, VERSION)
        self.assertEqual(names["02-getprop-ro.build.type"].stdout, b"userdebug\r\n")
        self.assertEqual(len(r.identity.raw_responses), 2 + len(PROPERTIES))

    def test_missing_emulator_properties_give_unknown_not_physical(self):
        props = {k: v for k, v in GOOGLE_APIS.items() if "qemu" not in k}
        r, _ = run({"phone": props})
        self.assertEqual(r.identity.is_emulator, Tristate.UNKNOWN)
        self.assertTrue(any("not assumed physical" in n for n in r.notes))

    def test_failed_getprop_is_recorded_not_guessed(self):
        r, _ = run({"emulator-5554": GOOGLE_APIS}, fail={"ro.build.type"})
        self.assertIsNone(r.identity.build_type)
        self.assertTrue(any("ro.build.type failed" in n for n in r.notes))
        self.assertEqual(dict(r.records)["02-getprop-ro.build.type"].stderr, b"error: closed\r\n")


class DeviceSelectionTests(unittest.TestCase):
    def test_two_devices_need_an_explicit_serial(self):
        both = {"emulator-5554": GOOGLE_APIS, "emulator-5556": GOOGLE_PLAY}
        with self.assertRaisesRegex(PreconditionError, "choose one with --serial"):
            run(both)
        r, _ = run(both, serial="emulator-5556")
        self.assertEqual(r.identity.build_type, "user")

    def test_identity_follows_properties_not_serial(self):
        # The Play image was emulator-5554 in one run and emulator-5556 in another.
        r, _ = run({"emulator-5554": GOOGLE_PLAY})
        self.assertEqual(r.identity.build_type, "user")

    def test_unready_or_missing_devices(self):
        with self.assertRaisesRegex(PreconditionError, "no device ready"):
            run({"emulator-5554": GOOGLE_APIS}, states={"emulator-5554": "unauthorized"})
        with self.assertRaisesRegex(PreconditionError, "state 'unauthorized'"):
            run({"emulator-5554": GOOGLE_APIS}, serial="emulator-5554",
                states={"emulator-5554": "unauthorized"})
        with self.assertRaisesRegex(PreconditionError, "no device ready"):
            run({}, states={})
        with self.assertRaisesRegex(PreconditionError, "not connected"):
            run({"emulator-5554": GOOGLE_APIS}, serial="emulator-9999")

    def test_shell_injection_rejected(self):
        adb = Adb("adb", runner=FakeAdb({}))
        for bad in ("ro.x; reboot", "$(id)", "a b", ""):
            with self.assertRaises(ModelValidationError):
                adb.getprop("emulator-5554", bad)
        for bad in ("emu 1", "x;y", ""):
            with self.assertRaises(ModelValidationError):
                adb.getprop(bad, "ro.build.type")

    def test_adb_missing_is_access_error(self):
        def missing(argv, timeout):
            raise FileNotFoundError(argv[0])
        with self.assertRaisesRegex(AccessError, "adb not found"):
            detect(Adb("nope", runner=missing))

    def test_parse_devices(self):
        out = (b"* daemon not running; starting now\r\nList of devices attached\r\n"
               b"* daemon started successfully\r\nemulator-5554\tdevice\r\n\r\n")
        self.assertEqual(parse_devices(out), [("emulator-5554", "device")])
        with self.assertRaises(AccessError):
            parse_devices(b"garbage")


class GateIntegrationTests(unittest.TestCase):
    """Detection feeds the M1.7 gate; the refusal case is an M1 acceptance criterion."""

    def gates(self, props):
        r, _ = run({"emulator-5554": props})
        (a,) = load_registry().assess(r.identity)
        return a, gate(a, research_mode=False), gate(a, research_mode=True)

    def test_google_apis_matches_and_needs_research_mode(self):
        a, normal, research = self.gates(GOOGLE_APIS)
        self.assertEqual(a.matches, Tristate.YES)
        self.assertFalse(normal.allowed)
        self.assertTrue(research.allowed)

    def test_google_play_user_build_is_refused(self):
        a, normal, research = self.gates(GOOGLE_PLAY)
        self.assertEqual(a.matches, Tristate.NO)
        self.assertFalse(normal.allowed or research.allowed)


class SaveTests(unittest.TestCase):
    def test_raw_outputs_saved_and_package_verifies(self):
        r, _ = run({"emulator-5554": GOOGLE_APIS})
        with tempfile.TemporaryDirectory() as tmp:
            pkg = EvidencePackage.create(Path(tmp), "detect-test", chunk_size=1024 * 1024)
            save_to_package(pkg, r)
            fin = pkg.finalize({"purpose": "test"})
            root = fin.root
            self.assertEqual((root / "identity" / "02-getprop-ro.build.type.stdout").read_bytes(),
                             b"userdebug\r\n")
            commands = json.loads((root / "identity" / "commands.json").read_text(encoding="utf-8"))
            self.assertEqual(commands[2]["argv"], ["adb", "-s", "emulator-5554", "shell", "getprop",
                                                   "ro.build.type"])
            summary = json.loads((root / "identity" / "identity.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["identity"]["build_type"], "userdebug")
            for p in root.rglob("*"):
                if p.is_file():
                    p.chmod(0o600)


class CommandLineTests(unittest.TestCase):
    def test_main_prints_identity_and_gate(self):
        fake = FakeAdb({"emulator-5554": GOOGLE_PLAY})
        original = detection.Adb
        detection.Adb = lambda path: original(path, runner=fake)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = detection.main([])
        finally:
            detection.Adb = original
        out = buf.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("build_type: user", out)
        self.assertIn("REFUSED", out)
        self.assertNotIn("ALLOWED", out)


if __name__ == "__main__":
    unittest.main()
