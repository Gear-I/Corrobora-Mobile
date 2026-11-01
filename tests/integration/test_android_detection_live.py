"""Opt-in detection test against a real, running emulator.

Skipped unless CORROBORA_TEST_ADB_SERIAL is set. Read-only: issues only
``adb version``, ``adb devices`` and ``adb -s <serial> shell getprop``.

    $env:CORROBORA_TEST_ADB = "C:\\Users\\<you>\\AppData\\Local\\Android\\Sdk\\platform-tools\\adb.exe"
    $env:CORROBORA_TEST_ADB_SERIAL = "emulator-5554"
    $env:CORROBORA_TEST_EXPECT_BUILD_TYPE = "userdebug"   # optional
    $env:PYTHONPATH = "src"; python -m unittest tests.integration.test_android_detection_live -v
"""

import os
import unittest

from corrobora_mobile.core.enums import Tristate
from corrobora_mobile.platforms.android.adb import Adb
from corrobora_mobile.platforms.android.detection import detect

SERIAL = os.environ.get("CORROBORA_TEST_ADB_SERIAL")


@unittest.skipUnless(SERIAL, "set CORROBORA_TEST_ADB_SERIAL to run against a real emulator")
class LiveDetectionTests(unittest.TestCase):
    def test_detects_a_running_emulator(self):
        result = detect(Adb(os.environ.get("CORROBORA_TEST_ADB", "adb")), SERIAL)
        identity = result.identity
        self.assertEqual(identity.is_emulator, Tristate.YES, result.notes)
        self.assertIn(identity.build_type, ("user", "userdebug", "eng"))
        expected = os.environ.get("CORROBORA_TEST_EXPECT_BUILD_TYPE")
        if expected:
            self.assertEqual(identity.build_type, expected)
        for name, record in result.records:
            self.assertEqual(record.exit_status, 0, f"{name}: {record.stderr!r}")


if __name__ == "__main__":
    unittest.main()
