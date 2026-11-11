import unittest

from corrobora_mobile.core.errors import ModelValidationError
from corrobora_mobile.platforms.android import commands
from corrobora_mobile.platforms.android.adb import Adb

ID = "acq-20261109T120000Z"


class ScopeRootTests(unittest.TestCase):
    def test_accepts_folders_under_data(self):
        for root in (b"/data/system/users", b"/data/data", b"/data/a.b_c-d/e"):
            self.assertEqual(commands.validate_scope_root(root), root)

    def test_rejects_everything_else(self):
        for root in (b"/data", b"/system/bin", b"/data/", b"/data//x", b"/data/./x",
                     b"/data/../x", b"/data/..", b"/data/a b", b"/data/x'y", b"/data/x;rm",
                     b"/data/$(id)", b"/data/x\nid", b"/data/\xff", "/data/x", b"data/x",
                     b"/database"):
            with self.subTest(root=root), self.assertRaises(ModelValidationError):
                commands.validate_scope_root(root)


class BuilderTests(unittest.TestCase):
    def test_exact_texts(self):
        side = f"/data/local/tmp/{ID}"
        self.assertEqual(
            commands.find_pass(b"/data/system/users", ID, "pre-find").text,
            "find '/data/system/users' -printf '%M\\0%m\\0%U\\0%G\\0%s\\0%i\\0%Z\\0%l\\0%p\\0' "
            f"2>{side}/pre-find.err; echo $? >{side}/pre-find.exit")
        self.assertEqual(
            commands.stat_pass(b"/data/system/users", ID, "post-stat").text,
            "find '/data/system/users' -exec stat -c '%i|%h|%Y|%y|%Z|%z|%X|%x' {} + "
            f"2>{side}/post-stat.err; echo $? >{side}/post-stat.exit")
        self.assertEqual(
            commands.tar_stream(b"/data/system/users", ID).text,
            "tar -c --selinux --numeric-owner -f - -C '/data/system' 'users' "
            f"2>{side}/tar.err; echo $? >{side}/tar.exit")
        self.assertEqual(commands.make_sidecar_dir(ID).text, f"mkdir {side}")
        self.assertEqual(commands.remove_sidecar_dir(ID).text, f"rm -r {side} && test ! -e {side}")
        self.assertEqual(commands.read_sidecar(ID, "tar", "exit").text, f"cat {side}/tar.exit")

    def test_no_sparse_option(self):
        # --sparse produced byte-identical output on 2026-11-09 (A-07); not used until understood
        self.assertNotIn("--sparse", commands.tar_stream(b"/data/x", ID).text)

    def test_rejects_unchecked_values(self):
        with self.assertRaises(ModelValidationError):
            commands.sidecar_dir("acq;rm -rf /")
        with self.assertRaises(ModelValidationError):
            commands.find_pass(b"/data/x", ID, "../../x")
        with self.assertRaises(ModelValidationError):
            commands.read_sidecar(ID, "tar", "out")
        with self.assertRaises(ModelValidationError):
            commands.tar_stream(b"/data/x y", ID)
        with self.assertRaises(ModelValidationError):
            commands.DeviceCommand("id\nrm -rf /", "two lines")


class AdbAcceptsOnlyDeviceCommandsTests(unittest.TestCase):
    def test_plain_strings_are_refused(self):
        calls = []
        adb = Adb("adb", runner=lambda argv, t: calls.append(argv) or (0, b"", b""),
                  stream_runner=lambda argv, sink: calls.append(argv) or (0, b""))
        for method in (adb.shell_command, adb.exec_out):
            with self.assertRaises(ModelValidationError):
                method("emulator-5554", "rm -rf /data")
        with self.assertRaises(ModelValidationError):
            adb.exec_out_stream("emulator-5554", "cat /dev/zero", lambda b: None)
        self.assertEqual(calls, [])

    def test_argv_shapes(self):
        calls = []

        def stream(argv, sink):
            calls.append((argv, None))
            sink(b"ab")
            return 0, b""

        adb = Adb("adb", runner=lambda argv, t: calls.append((argv, t)) or (0, b"x", b""),
                  stream_runner=stream)
        adb.shell_command("emulator-5554", commands.toybox_version())
        adb.exec_out("emulator-5554", commands.read_mounts(), timeout=99)
        got = []
        adb.exec_out_stream("emulator-5554", commands.tar_stream(b"/data/x", ID), got.append)
        self.assertEqual(calls[0], (["adb", "-s", "emulator-5554", "shell", "toybox --version"], 30))
        self.assertEqual(calls[1], (["adb", "-s", "emulator-5554", "exec-out", "cat /proc/mounts"], 99))
        self.assertEqual(calls[2][0][:4], ["adb", "-s", "emulator-5554", "exec-out"])
        self.assertEqual(got, [b"ab"])


if __name__ == "__main__":
    unittest.main()
