"""The window itself. Skipped where tkinter or a display is not available
(for example on CI runners without a display)."""

import time
import unittest
from pathlib import Path

from corrobora_mobile.platforms.android.adb import Adb
from tests.unit.test_adb_root_provider import SERIAL, FakeEmulator

try:
    import tkinter as tk
    _root = tk.Tk()
    _root.destroy()
    HAVE_DISPLAY = True
except Exception:  # ImportError, or TclError when there is no display
    HAVE_DISPLAY = False


@unittest.skipUnless(HAVE_DISPLAY, "tkinter with a display is not available")
class AppTests(unittest.TestCase):
    def setUp(self):
        from corrobora_mobile.gui import app, model
        self.model = model
        self.fake = FakeEmulator()
        self.verify_calls = []

        def fake_verify(package, head):
            self.verify_calls.append((package, head))
            return model.VerifyView(exit_code=6, text="INTEGRITY:     PASS", report={"integrity": {"result": "PASS"}},
                                    flags=("completeness", "validation"))

        self.root = tk.Tk()
        self.root.withdraw()
        self.app = app.App(self.root, adb_factory=lambda p: Adb(p, runner=self.fake),
                           verify_fn=fake_verify)

    def tearDown(self):
        self.root.destroy()

    def wait(self, timeout=10):
        deadline = time.monotonic() + timeout
        self.root.update()
        while self.app.busy and time.monotonic() < deadline:
            self.root.update()
            time.sleep(0.02)
        self.root.update()
        self.assertFalse(self.app.busy, "background task did not finish")

    def text(self, widget):
        return widget.get("1.0", "end")

    def test_devices_then_double_click_detects(self):
        self.app.refresh_devices()
        self.wait()
        rows = [self.app.device_table.item(i, "values") for i in self.app.device_table.get_children()]
        self.assertEqual([r[:3] for r in rows], [(SERIAL, "device", "userdebug")])
        self.assertEqual(self.app.serial.get(), SERIAL)
        self.app.device_table.selection_set(self.app.device_table.get_children()[0])
        self.app._detect_selected()
        self.wait()
        text = self.text(self.app.detect_text)
        self.assertIn("gate (normal mode): REFUSED", text)
        self.assertIn("Detection is read-only", text)
        for args in self.fake.calls:
            cmd = args[2:] if args[:1] == ["-s"] else args
            self.assertTrue(cmd in (["version"], ["devices"]) or cmd[:2] == ["shell", "getprop"],
                            args)

    def test_buttons_disabled_while_busy(self):
        self.app.refresh_devices()
        self.assertTrue(all(b.instate(["disabled"]) for b in self.app._buttons))
        self.wait()
        self.assertTrue(all(not b.instate(["disabled"]) for b in self.app._buttons))

    def test_only_one_task_at_a_time(self):
        self.app.refresh_devices()
        self.app.refresh_devices()  # ignored while the first runs
        self.app.run_detect()       # also ignored
        self.wait()
        self.assertEqual(sum(1 for args in self.fake.calls if args == ["devices"]), 1)
        self.assertNotIn("Device (adb serial", self.text(self.app.detect_text))

    def test_errors_are_shown_not_raised(self):
        self.app.adb_path.set("adb")
        self.app._adb_factory = lambda p: Adb("definitely-not-adb-xyz")
        self.app.refresh_devices()
        self.wait()
        self.assertIn("Error: adb not found", self.app.status.get())

    def test_verify(self):
        self.app.run_verify()
        self.assertIn("Choose a package folder", self.app.status.get())
        self.app.package.set("C:/cases/acq-1")
        self.app.chain_head.set("  ab" * 1)
        self.app.run_verify()
        self.wait()
        self.assertEqual(self.verify_calls, [(Path("C:/cases/acq-1"), "ab")])
        self.assertTrue(self.app.verdict.get().startswith("INTEGRITY PASS"))
        self.assertEqual(self.app.verdict.get(), "INTEGRITY PASS")
        self.assertIn("not recomputed", self.app.caveat.get())
        self.assertIn("not mean the acquisition method is validated", self.app.caveat.get())

    def test_verify_failure_is_marked(self):
        self.app._verify_fn = lambda p, h: self.model.VerifyView(
            exit_code=1, text="INTEGRITY:     FAIL", report={"integrity": {"result": "FAIL"}}, flags=("integrity",))
        self.app.package.set("x")
        self.app.run_verify()
        self.wait()
        self.assertIn("do not rely on this package", self.app.verdict.get())

    def test_logo_and_icon_loaded(self):
        self.assertIsNotNone(self.app.logo)
        self.assertEqual((self.app.logo.width(), self.app.logo.height()), (96, 96))
        self.assertEqual([i.width() for i in self.app.icons], [64, 32, 16])

    def test_missing_images_do_not_stop_the_window(self):
        from corrobora_mobile.gui import app
        self.assertIsNone(app.load_image("no-such-file.png"))

    def test_title_and_notice(self):
        self.assertIn("pre-alpha", self.root.title())
        self.assertIn("never changes a device", self.model.READ_ONLY_NOTICE)


if __name__ == "__main__":
    unittest.main()
