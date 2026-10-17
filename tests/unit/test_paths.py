import unittest

from corrobora_mobile.core.errors import ModelValidationError
from corrobora_mobile.core.paths import is_within, validate_device_path


class ValidateDevicePathTests(unittest.TestCase):
    def test_accepts_canonical_paths(self):
        for good in (b"/", b"/data", b"/data/app/x.apk", b"/data/\xff\xfe", b"/data/..hidden", b"/a/...", b"/data/ space "):
            with self.subTest(good=good):
                self.assertIs(validate_device_path(good), good)

    def test_never_normalizes(self):
        # Rejected rather than silently rewritten.
        with self.assertRaises(ModelValidationError):
            validate_device_path(b"/data/./app")

    def test_rejects_non_canonical(self):
        for bad in (
            b"",
            b"data",
            b"./data",
            b"/data/",
            b"//data",
            b"/data//app",
            b"/.",
            b"/..",
            b"/data/.",
            b"/data/..",
            b"/data/../etc",
            b"/da\x00ta",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ModelValidationError):
                    validate_device_path(bad)

    def test_rejects_str(self):
        with self.assertRaises(ModelValidationError):
            validate_device_path("/data")  # type: ignore[arg-type]

    def test_no_length_limit_on_observed_paths(self):
        deep = b"/" + b"/".join([b"d"] * 3000)
        self.assertIs(validate_device_path(deep), deep)


class IsWithinTests(unittest.TestCase):
    def test_component_wise(self):
        self.assertTrue(is_within(b"/data", b"/data"))
        self.assertTrue(is_within(b"/data/app", b"/data"))
        self.assertFalse(is_within(b"/database", b"/data"))
        self.assertFalse(is_within(b"/data", b"/data/app"))

    def test_root_contains_everything(self):
        self.assertTrue(is_within(b"/proc", b"/"))
        self.assertTrue(is_within(b"/", b"/"))


if __name__ == "__main__":
    unittest.main()
