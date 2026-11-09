"""The adb-root provider against a simulated emulator.

The simulation follows what two Android 17 emulators did on 2026-11-09:
``adb root`` on userdebug printed "restarting adbd as root" and gave uid 0;
on the user (Google Play) build it printed "adbd cannot run as root in
production builds" AND EXITED 0; ``adb unroot`` printed "restarting adbd as
non root" and left ``service.adb.root`` at "0" where it had been unset.
"""

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from corrobora_mobile.compatibility import load_registry
from corrobora_mobile.core.errors import (
    AccessError,
    ModelValidationError,
    PreconditionError,
    ResearchModeRequiredError,
    UnsupportedDeviceError,
)
from corrobora_mobile.evidence import EvidencePackage
from corrobora_mobile.platforms.android.adb import Adb
from corrobora_mobile.platforms.android.detection import detect
from corrobora_mobile.platforms.android.providers import adb_root
from corrobora_mobile.platforms.android.providers.adb_root import AdbRootProvider, root_access
from corrobora_mobile.research import ResearchAuthorization

SERIAL = "emulator-5554"
SHELL_ID = (b"uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input) "
            b"context=u:r:shell:s0\r\n")
ROOT_ID = b"uid=0(root) gid=0(root) groups=0(root),1004(input) context=u:r:su:s0\r\n"
BASE_PROPS = {"ro.build.type": "userdebug", "ro.build.tags": "dev-keys",
              "ro.build.version.release": "17", "ro.build.version.sdk": "37",
              "ro.product.manufacturer": "Google", "ro.product.model": "sdk_gphone64_x86_64",
              "ro.kernel.qemu": "1", "ro.boot.qemu": "1", "ro.hardware": "ranchu",
              "sys.user.0.ce_available": "true"}


class FakeEmulator:
    def __init__(self, build_type="userdebug", *, root=False, ce="true", root_noop=False,
                 unroot_noop=False, timeout_on=None):
        self.props = {**BASE_PROPS, "ro.build.type": build_type, "sys.user.0.ce_available": ce}
        self.root = root
        self.adb_root_prop = "1" if root else None
        self.root_noop, self.unroot_noop, self.timeout_on = root_noop, unroot_noop, timeout_on
        self.calls: list[list[str]] = []

    def __call__(self, argv, timeout):
        args = argv[1:]
        self.calls.append(args)
        if self.timeout_on and len(self.calls) == self.timeout_on:
            raise subprocess.TimeoutExpired(argv, timeout)
        if args == ["version"]:
            return 0, b"Android Debug Bridge version 1.0.41\r\n", b""
        if args == ["devices"]:
            return 0, f"List of devices attached\r\n{SERIAL}\tdevice\r\n\r\n".encode(), b""
        cmd = args[2:]
        if cmd == ["shell", "id"]:
            return 0, ROOT_ID if self.root else SHELL_ID, b""
        if cmd[:2] == ["shell", "getprop"]:
            value = self.adb_root_prop if cmd[2] == "service.adb.root" else self.props.get(cmd[2])
            return 0, ((value or "") + "\r\n").encode(), b""
        if cmd == ["wait-for-device"]:
            return 0, b"", b""
        if cmd == ["root"]:
            if self.props["ro.build.type"] == "user":
                return 0, b"adbd cannot run as root in production builds\r\n", b""
            if not self.root_noop:
                self.root, self.adb_root_prop = True, "1"
            return 0, b"restarting adbd as root\r\n", b""
        if cmd == ["unroot"]:
            if not self.unroot_noop:
                self.root, self.adb_root_prop = False, "0"
            return 0, b"restarting adbd as non root\r\n", b""
        raise AssertionError(f"unexpected adb command {argv}")

    def device_changes(self):
        return [a[2] for a in self.calls if a[2:] in (["root"], ["unroot"])]


def authorization(mods=None):
    record = load_registry()[adb_root.METHOD_ID]
    return ResearchAuthorization("OWNED-EMULATOR-001", tuple(mods or record.device_modifications))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.pkg = EvidencePackage.create(self.tmp, "provider-test", chunk_size=1024 * 1024)
        self.addCleanup(self._close)

    def _close(self):
        with contextlib.suppress(Exception):
            self.pkg.close()
        for p in self.tmp.rglob("*"):
            with contextlib.suppress(OSError):
                p.chmod(0o700 if p.is_dir() else 0o600)

    def setup_device(self, **kw):
        fake = FakeEmulator(**kw)
        adb = Adb("adb", runner=fake)
        identity = detect(adb, SERIAL).identity
        (assessment,) = load_registry().assess(identity)
        fake.calls.clear()
        return fake, adb, assessment

    def audit(self):
        self.pkg.audit._fh.flush()
        return [json.loads(line) for line in (self.pkg.root / "audit.jsonl").read_bytes().splitlines()]


class EstablishAndReleaseTests(Base):
    def test_root_established_confirmed_by_id_and_released(self):
        fake, adb, assessment = self.setup_device()
        provider = AdbRootProvider(adb, self.pkg.audit)
        with root_access(provider, SERIAL, assessment, research=authorization(),
                         operator_confirmed_unlocked=True) as session:
            self.assertEqual(session.after_root.uid, 0)
            self.assertTrue(fake.root)
        self.assertFalse(fake.root)
        self.assertEqual(fake.device_changes(), ["root", "unroot"])
        report = session.teardown_report
        self.assertEqual(report.residual_changes,
                         ("service.adb.root: unset before, '0' after teardown",))

    def test_every_device_change_is_inside_an_intent_result_pair(self):
        _, adb, assessment = self.setup_device()
        provider = AdbRootProvider(adb, self.pkg.audit)
        with root_access(provider, SERIAL, assessment, research=authorization(),
                         operator_confirmed_unlocked=True):
            pass
        entries = self.audit()
        intents = {e["seq"]: e["data"]["action"] for e in entries if e["type"] == "INTENT"}
        results = {e["data"]["intent_seq"]: e for e in entries if e["type"] == "RESULT"}
        actions = [intents[s] for s in sorted(intents) if intents[s].startswith("adb")]
        self.assertEqual(actions, ["adb root", "adb unroot"])
        for seq, action in intents.items():
            if action.startswith("adb"):
                self.assertTrue(results[seq]["data"]["succeeded"], action)
                self.assertGreater(results[seq]["seq"], seq)
        notes = [e["data"]["message"] for e in entries if e["type"] == "NOTE"]
        self.assertIn("unlock precondition", notes)

    def test_already_root_is_left_alone(self):
        fake, adb, assessment = self.setup_device(root=True)
        provider = AdbRootProvider(adb, self.pkg.audit)
        with root_access(provider, SERIAL, assessment, research=authorization(),
                         operator_confirmed_unlocked=True) as session:
            self.assertFalse(session.rooted_by_us)
        self.assertEqual(fake.device_changes(), [])
        self.assertTrue(fake.root)

    def test_teardown_runs_when_the_body_fails(self):
        fake, adb, assessment = self.setup_device()
        provider = AdbRootProvider(adb, self.pkg.audit)
        with self.assertRaises(RuntimeError):
            with root_access(provider, SERIAL, assessment, research=authorization(),
                             operator_confirmed_unlocked=True):
                raise RuntimeError("acquirer failed")
        self.assertFalse(fake.root)
        self.assertEqual(fake.device_changes(), ["root", "unroot"])


class RefusalTests(Base):
    """Refusals happen before any command that changes the device."""

    def refused(self, error, **kw):
        research = kw.pop("research", authorization())
        unlocked = kw.pop("unlocked", True)
        fake, adb, assessment = self.setup_device(**kw)
        provider = AdbRootProvider(adb, self.pkg.audit)
        with self.assertRaises(error):
            provider.establish(SERIAL, assessment, research=research,
                               operator_confirmed_unlocked=unlocked)
        self.assertEqual(fake.device_changes(), [])
        return fake

    def test_user_build_refused_even_in_research_mode(self):
        self.refused(UnsupportedDeviceError, build_type="user")

    def test_unverified_method_refused_without_research_mode(self):
        self.refused(ResearchModeRequiredError, research=None)

    def test_acknowledgement_must_match_declared_modifications(self):
        self.refused(PreconditionError, research=authorization(["adbd restarted as root"]))

    def test_unlock_property_and_operator_confirmation_both_required(self):
        self.refused(PreconditionError, ce="false")
        self.refused(PreconditionError, ce="")
        self.refused(PreconditionError, unlocked=False)


class FailureTests(Base):
    def test_exit_status_zero_is_not_trusted(self):
        # adb root "succeeds" (exit 0, says restarting) but uid stays 2000.
        fake, adb, assessment = self.setup_device(root_noop=True)
        provider = AdbRootProvider(adb, self.pkg.audit)
        with self.assertRaisesRegex(AccessError, "did not give root"):
            provider.establish(SERIAL, assessment, research=authorization(),
                               operator_confirmed_unlocked=True)
        root_result = [e for e in self.audit() if e["type"] == "RESULT"][-1]
        self.assertFalse(root_result["data"]["succeeded"])
        self.assertEqual(root_result["data"]["exit_status"], 0)

    def test_timeout_after_root_records_failure_and_recovers(self):
        fake, adb, assessment = self.setup_device()
        # calls: getprop ce, id, getprop root, root, wait-for-device (times out)
        fake.timeout_on = 5
        provider = AdbRootProvider(adb, self.pkg.audit)
        with self.assertRaisesRegex(AccessError, "timed out"):
            provider.establish(SERIAL, assessment, research=authorization(),
                               operator_confirmed_unlocked=True)
        self.assertEqual(fake.device_changes(), ["root", "unroot"])
        self.assertFalse(fake.root)
        actions = [e["data"]["action"] for e in self.audit() if e["type"] == "INTENT"]
        self.assertEqual(actions[-2:], ["adb root", "adb unroot (recovery)"])
        self.assertEqual(self.pkg.audit.open_intents, {})

    def test_unroot_that_leaves_root_is_reported(self):
        fake, adb, assessment = self.setup_device(unroot_noop=True)
        provider = AdbRootProvider(adb, self.pkg.audit)
        session = provider.establish(SERIAL, assessment, research=authorization(),
                                     operator_confirmed_unlocked=True)
        with self.assertRaisesRegex(AccessError, "did not restore"):
            provider.teardown(session)
        with self.assertRaisesRegex(AccessError, "already released"):
            provider.teardown(session)


class ResearchAuthorizationTests(unittest.TestCase):
    def test_reference_rules(self):
        for bad in ("", "ab", "x" * 200, "line\nbreak", " leading-space", "name@example.com"):
            with self.subTest(bad=bad):
                with self.assertRaises(ModelValidationError):
                    ResearchAuthorization(bad, ("m",))
        with self.assertRaises(ModelValidationError):
            ResearchAuthorization("OWNED-1", ())

    def test_manifest_fields_label_and_cap(self):
        fields = authorization().manifest_fields()
        self.assertEqual((fields["label"], fields["max_claimable_status"]), ("RESEARCH", "EXPERIMENTAL"))
        self.assertEqual(fields["authorization_reference"], "OWNED-EMULATOR-001")

    def test_record_declares_the_observed_residual_change(self):
        mods = load_registry()[adb_root.METHOD_ID].device_modifications
        self.assertTrue(any("service.adb.root left at 0" in m for m in mods))


class CommandLineTests(unittest.TestCase):
    def run_main(self, fake, *extra):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        original = adb_root.Adb
        adb_root.Adb = lambda path: original(path, runner=fake)
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                code = adb_root.main(["--output", str(tmp), *extra])
        finally:
            adb_root.Adb = original
        (pkg,) = tmp.iterdir()
        manifest = json.loads((pkg / "manifest.json").read_text(encoding="utf-8"))
        for p in tmp.rglob("*"):
            p.chmod(0o700 if p.is_dir() else 0o600)
        return code, buf.getvalue(), manifest["content"]

    FULL = ("--research", "--authorization-reference", "OWNED-EMULATOR-001",
            "--acknowledge-modifications", "--confirm-unlocked")

    def test_userdebug_research_run(self):
        fake = FakeEmulator()
        code, out, content = self.run_main(fake, *self.FULL)
        self.assertEqual(code, 0, out)
        self.assertEqual(content["outcome"], "ROOT_ESTABLISHED_AND_RELEASED")
        self.assertEqual(content["research"]["label"], "RESEARCH")
        self.assertEqual(content["residual_changes"], ["service.adb.root: unset before, '0' after teardown"])
        self.assertFalse(fake.root)

    def test_refusal_test_leaves_evidence(self):
        fake = FakeEmulator(build_type="user")
        code, out, content = self.run_main(fake, *self.FULL)
        self.assertEqual(code, 3)
        self.assertEqual(content["outcome"], "REFUSED")
        self.assertEqual(fake.device_changes(), [])

    def test_no_research_flag_is_refused(self):
        fake = FakeEmulator()
        code, _, content = self.run_main(fake)
        self.assertEqual((code, content["outcome"]), (3, "REFUSED"))
        self.assertIn("research mode", content["reason"])


if __name__ == "__main__":
    unittest.main()
