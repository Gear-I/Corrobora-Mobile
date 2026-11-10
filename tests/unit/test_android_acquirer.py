"""The M1.11 acquirer end to end, against the simulated emulator in fake_android."""

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from corrobora_mobile.core.enums import EntryType
from corrobora_mobile.core.errors import PreconditionError
from corrobora_mobile.platforms.android import acquirer
from corrobora_mobile.platforms.android.acquirer import (
    check_scope,
    classify_tar_stderr,
    parse_mounts,
)
from corrobora_mobile.platforms.android.adb import Adb
from tests.unit.fake_android import FakeAndroid, Node, node

REPO = Path(__file__).resolve().parents[2]
VERIFIER = REPO / "tools" / "verify_package.py"
ROOT = "/data/system/users"
DEVICE_CHANGES = ("root", "unroot")


def acquire(fake, *extra, path=ROOT, research=True):
    tmp = tempfile.mkdtemp()
    argv = ["--path", path, "--output", tmp, "--confirm-unlocked", *extra]
    if research:
        argv += ["--research", "--authorization-reference", "OWNED-EMULATOR-001",
                 "--acknowledge-modifications"]
    out = io.StringIO()
    with mock.patch.object(acquirer, "Adb",
                           lambda p: Adb(p, runner=fake, stream_runner=fake.stream)), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = acquirer.main(argv)
    packages = list(Path(tmp).iterdir())
    pkg = packages[0] if packages else None
    return code, out.getvalue(), pkg


def manifest(pkg):
    return json.loads((pkg / "manifest.json").read_text())["content"]


def reconciliation(pkg):
    return json.loads((pkg / "reconciliation.json").read_text())


def outcomes(pkg):
    import base64
    return {base64.b64decode(e["path"]["b64"]): (e["outcome"], e["content_reliability"])
            for e in reconciliation(pkg)["entries"]}


def device_changes(fake):
    root_cmds = [a[2] for a in fake.calls if a[2:] in (["root"], ["unroot"])]
    side = [t.split(" ")[0] for t in fake.texts if t.startswith(("mkdir", "rm -r"))]
    return root_cmds, side


class CleanAcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeAndroid()
        self.code, self.out, self.pkg = acquire(self.fake)

    def test_complete_with_every_entry_type(self):
        self.assertEqual(self.code, 0, self.out)
        content = manifest(self.pkg)
        self.assertEqual(content["outcome"], "ACQUIRED")
        self.assertEqual(content["completeness_status"], "COMPLETE")
        self.assertTrue(content["completeness_provisional"])
        self.assertEqual(content["acquisition_class"]["final"], "PRIVILEGED_SELECTED_DIRECTORY")
        self.assertEqual(content["research"]["label"], "RESEARCH")
        got = outcomes(self.pkg)
        self.assertEqual(len(got), len(self.fake.nodes))
        for path in (b"/data/system/users/0/new\nline", b"/data/system/users/0/bad\xffname",
                     b"/data/system/users/0/hard", b"/data/system/users/0/fifo",
                     b"/data/system/users/0/link"):
            self.assertEqual(got[path], ("ACQUIRED", "NO_CHANGE_DETECTED"), path)

    def test_device_changes_are_exactly_the_declared_ones_and_undone(self):
        root_cmds, side = device_changes(self.fake)
        self.assertEqual(root_cmds, ["root", "unroot"])
        self.assertEqual(side, ["mkdir", "rm"])
        self.assertEqual(self.fake.dirs, set())
        self.assertTrue(manifest(self.pkg)["sidecar_folder_removed"])
        self.assertIn("service.adb.root: unset before, '0' after teardown",
                      manifest(self.pkg)["observed_device_modifications"])

    def test_only_commands_from_the_builders_reach_the_device(self):
        allowed_prefixes = ("cat /proc/mounts", "toybox --version", "stat -c '%Y|%y|%Z|%z' ",
                            "mkdir /data/local/tmp/acq-", "rm -r /data/local/tmp/acq-",
                            "cat /data/local/tmp/acq-", f"find '{ROOT}' -printf ",
                            f"find '{ROOT}' -exec stat ", "tar -c --selinux --numeric-owner")
        for text in self.fake.texts:
            self.assertTrue(text.startswith(allowed_prefixes), text)

    def test_plan_precedes_the_first_data_read(self):
        lines = [json.loads(x) for x in (self.pkg / "audit.jsonl").read_text().splitlines()]
        def first(pred):
            return next(i for i, e in enumerate(lines) if pred(json.dumps(e)))
        plan = first(lambda s: "plan recorded before the first data read" in s)
        self.assertLess(plan, first(lambda s: "pre-enumeration pass 1" in s))
        self.assertLess(plan, first(lambda s: "data/archive.tar" in s))

    def test_package_passes_the_standalone_verifier(self):
        proc = subprocess.run([sys.executable, str(VERIFIER), str(self.pkg)],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2 | 4, proc.stdout + proc.stderr)  # integrity PASS

    def test_enumeration_keeps_nanoseconds_and_raw_names(self):
        lines = (self.pkg / "enumeration" / "pre.jsonl").read_text().splitlines()
        header = json.loads(lines[0])
        self.assertTrue(header["mechanism"]["pass_2_used"])
        rows = [json.loads(x) for x in lines[1:]]
        self.assertEqual(rows[0]["mtime_ns"], 1794271831_952000766)
        self.assertIn("new\nline", [r["path"]["display"].rsplit("/", 1)[-1] for r in rows])

    def tearDown(self):
        for p in Path(self.pkg).rglob("*"):
            p.chmod(0o700 if p.is_dir() else 0o600)


class OutcomeTests(unittest.TestCase):
    def test_sockets_are_unsupported_type_and_explain_exit_1(self):
        fake = FakeAndroid()
        fake.nodes.append(Node(b"/data/system/users/0/sock", "s", inode=200))
        code, out, pkg = acquire(fake)
        self.assertEqual(code, 0, out)
        self.assertEqual(manifest(pkg)["completeness_status"], "COMPLETE")
        self.assertEqual(outcomes(pkg)[b"/data/system/users/0/sock"][0], "UNSUPPORTED_TYPE")
        c2 = next(c for c in manifest(pkg)["completeness_checks"] if c["check"] == "C2")
        self.assertEqual(c2["state"], "PASS")
        self.assertIn("explained", c2["details"][0])

    def test_unknown_tar_message_gives_partial(self):
        fake = FakeAndroid()
        fake.extra_tar_stderr = ["tar: can't open 'users/0/secret': Permission denied"]
        code, out, pkg = acquire(fake)
        self.assertEqual(code, 0)
        self.assertEqual(manifest(pkg)["completeness_status"], "PARTIAL")
        failed = {c["check"] for c in manifest(pkg)["completeness_checks"] if c["state"] == "FAIL"}
        self.assertEqual(failed, {"C2", "C3"})

    def test_file_deleted_before_the_archive_is_an_error(self):
        fake = FakeAndroid()
        fake.before_tar = lambda f: f.nodes.remove(node(f, b"/userlist.xml"))
        code, out, pkg = acquire(fake)
        self.assertEqual(manifest(pkg)["completeness_status"], "PARTIAL")
        self.assertEqual(outcomes(pkg)[b"/data/system/users/userlist.xml"][0], "ERROR")

    def test_file_changed_during_acquisition(self):
        fake = FakeAndroid()
        def change(f):
            n = node(f, b"/settings.xml")
            n.mtime_ns += 5_000_000_000
        fake.after_tar = change
        code, out, pkg = acquire(fake)
        self.assertEqual(manifest(pkg)["completeness_status"], "COMPLETE_WITH_CHANGES")
        self.assertEqual(outcomes(pkg)[b"/data/system/users/0/settings.xml"],
                         ("ACQUIRED", "CHANGED_DURING_ACQUISITION"))

    def test_file_created_during_acquisition_is_an_unenumerated_change(self):
        fake = FakeAndroid()
        fake.before_tar = lambda f: f.nodes.append(
            Node(b"/data/system/users/0/new.xml", "f", content=b"x", inode=300))
        code, out, pkg = acquire(fake)
        self.assertEqual(manifest(pkg)["completeness_status"], "COMPLETE_WITH_CHANGES")
        self.assertEqual(reconciliation(pkg)["summary"]["unenumerated_members"], 1)

    def test_stat_pass_that_does_not_line_up_is_not_used(self):
        fake = FakeAndroid()
        fake.stat_drop_last = True
        code, out, pkg = acquire(fake)
        header = json.loads((pkg / "enumeration" / "pre.jsonl").read_text().splitlines()[0])
        self.assertFalse(header["mechanism"]["pass_2_used"])
        self.assertIn("lines for", header["notes"][0])
        row = json.loads((pkg / "enumeration" / "pre.jsonl").read_text().splitlines()[1])
        self.assertIsNone(row["mtime_ns"])
        # size and inode still compared, so the result can still be COMPLETE
        self.assertEqual(manifest(pkg)["completeness_status"], "COMPLETE")

    def test_stream_cut_off_by_adb_is_partial(self):
        fake = FakeAndroid(nodes=[Node(b"/data/system/users", "d", inode=1),
                                  Node(b"/data/system/users/big", "f", content=b"x" * 20000,
                                       inode=2)])
        fake.stream_cut_at = 6000
        code, out, pkg = acquire(fake)
        self.assertEqual(code, 0, out)
        self.assertEqual(manifest(pkg)["completeness_status"], "PARTIAL")
        c4 = next(c for c in manifest(pkg)["completeness_checks"] if c["check"] == "C4")
        self.assertEqual(c4["state"], "FAIL")
        self.assertIn("stream did not end cleanly", c4["details"])
        self.assertEqual(outcomes(pkg)[b"/data/system/users/big"][0], "ERROR")

    def test_host_error_mid_stream_leaves_package_unsealed_and_cleans_up(self):
        fake = FakeAndroid(nodes=[Node(b"/data/system/users", "d", inode=1),
                                  Node(b"/data/system/users/big", "f", content=b"x" * 20000,
                                       inode=2)])
        fake.stream_raises = OSError("disk full")
        tmp = tempfile.mkdtemp()
        with mock.patch.object(acquirer, "Adb",
                               lambda p: Adb(p, runner=fake, stream_runner=fake.stream)), \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaises(OSError):
            acquirer.main(["--path", ROOT, "--output", tmp, "--confirm-unlocked", "--research",
                           "--authorization-reference", "OWNED-EMULATOR-001",
                           "--acknowledge-modifications"])
        (pkg,) = Path(tmp).iterdir()
        self.assertFalse((pkg / "SEAL").exists())          # verifier: INTERRUPTED
        self.assertTrue((pkg / "data" / "archive.tar").exists())  # partial stream kept
        root_cmds, side = device_changes(fake)
        self.assertEqual(root_cmds, ["root", "unroot"])
        self.assertEqual(side, ["mkdir", "rm"])


class RefusalTests(unittest.TestCase):
    def assert_refused_without_device_change(self, fake, code, out):
        self.assertEqual(code, 3, out)
        root_cmds, side = device_changes(fake)
        self.assertEqual((root_cmds, side), ([], []))

    def test_scope_with_a_nested_mount_is_refused(self):
        fake = FakeAndroid(nodes=[Node(b"/data/user", "d", inode=1)])
        code, out, pkg = acquire(fake, path="/data/user")
        self.assert_refused_without_device_change(fake, code, out)
        self.assertIn("other mount points", manifest(pkg)["reason"])

    def test_sidecar_area_is_refused(self):
        for path in ("/data/local", "/data/local/tmp/x"):
            with self.subTest(path=path):
                fake = FakeAndroid()
                code, out, pkg = acquire(fake, path=path)
                self.assert_refused_without_device_change(fake, code, out)

    def test_bad_scope_strings_are_refused(self):
        for path in ("/data", "/system", "/data/../system", "/data/a b", "/data/x;rm"):
            with self.subTest(path=path):
                fake = FakeAndroid()
                code, out, pkg = acquire(fake, path=path)
                self.assert_refused_without_device_change(fake, code, out)

    def test_user_build_is_refused(self):
        fake = FakeAndroid(build_type="user")
        code, out, pkg = acquire(fake)
        self.assert_refused_without_device_change(fake, code, out)

    def test_without_research_mode_is_refused(self):
        fake = FakeAndroid()
        code, out, pkg = acquire(fake, research=False)
        self.assert_refused_without_device_change(fake, code, out)

    def test_existing_sidecar_folder_fails_and_still_releases_root(self):
        fake = FakeAndroid()
        fake.mkdir_fails = True
        code, out, pkg = acquire(fake)
        self.assertEqual(code, 4, out)
        root_cmds, side = device_changes(fake)
        self.assertEqual(root_cmds, ["root", "unroot"])
        self.assertEqual(side, ["mkdir"])  # nothing it did not create is removed
        self.assertEqual(manifest(pkg)["outcome"], "FAILED")


class HelperTests(unittest.TestCase):
    def test_classify_tar_stderr(self):
        sock = b"tar: unknown file type '140000'\ntar: had errors\n"
        self.assertEqual(classify_tar_stderr(sock, 1, 1)[:2], ([], []))
        self.assertIn("socket", classify_tar_stderr(sock, 1, 1)[2])
        errors, unclassified, why = classify_tar_stderr(sock, 2, 1)  # count mismatch
        self.assertEqual(len(unclassified), 1)
        self.assertIsNone(why)
        errors, unclassified, why = classify_tar_stderr(sock, None, 1)  # no enumeration
        self.assertEqual(len(unclassified), 1)
        errors, unclassified, why = classify_tar_stderr(b"tar: x: weird\ntar: had errors\n", 0, 1)
        self.assertEqual((errors, unclassified, why), (["tar: had errors"], ["tar: x: weird"], None))
        self.assertEqual(classify_tar_stderr(b"", 0, 0), ([], [], None))

    def test_parse_mounts_unescapes_octal(self):
        mounts = parse_mounts(b"/dev/a /data/my\\040dir ext4 rw,noatime 0 0\nbad line\n")
        self.assertEqual(mounts[0].mount_point, b"/data/my dir")
        self.assertEqual(mounts[0].options, ("rw", "noatime"))
        self.assertEqual(len(mounts), 1)

    def test_check_scope(self):
        mounts = parse_mounts(b"/dev/a /data ext4 rw 0 0\n/dev/a /data/user/0 ext4 rw 0 0\n")
        check_scope(b"/data/system/users", mounts)
        check_scope(b"/data/user/0", mounts)  # the mount point itself, nothing nested
        with self.assertRaises(PreconditionError):
            check_scope(b"/data/user", mounts)

    def test_socket_entry_type_from_find(self):
        fake = FakeAndroid()
        fake.nodes.append(Node(b"/data/system/users/s", "s", inode=9))
        from corrobora_mobile.platforms.android.enumeration import parse_find
        types = {r.path: r.entry_type for r in parse_find(fake._find(b"/data/system/users"))}
        self.assertIs(types[b"/data/system/users/s"], EntryType.SOCKET)


if __name__ == "__main__":
    unittest.main()
