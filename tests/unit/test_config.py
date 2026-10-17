import tempfile
import unittest
from pathlib import Path

from corrobora_mobile.config import (
    DEFAULT_CHUNK_SIZE_BYTES,
    config_from_mapping,
    load_config,
)
from corrobora_mobile.core.errors import ConfigError


class ConfigFromMappingTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.gettempdir()).resolve()

    def test_minimal(self):
        cfg = config_from_mapping({"output_dir": "evidence"}, base_dir=self.base)
        self.assertEqual(cfg.output_dir, (self.base / "evidence").resolve())
        self.assertEqual(cfg.chunk_size_bytes, DEFAULT_CHUNK_SIZE_BYTES)
        self.assertEqual(cfg.adb_path, "adb")

    def test_absolute_output_dir_kept(self):
        absolute = str(self.base / "abs-evidence")
        cfg = config_from_mapping({"output_dir": absolute}, base_dir=Path("/elsewhere"))
        self.assertEqual(cfg.output_dir, Path(absolute))

    def test_output_dir_required(self):
        with self.assertRaises(ConfigError):
            config_from_mapping({}, base_dir=self.base)

    def test_unknown_key_rejected(self):
        with self.assertRaisesRegex(ConfigError, "unknown configuration keys: output_dri"):
            config_from_mapping({"output_dir": "e", "output_dri": "typo"}, base_dir=self.base)

    def test_research_mode_cannot_be_set_in_file(self):
        for value in (True, False):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ConfigError, "research mode"):
                    config_from_mapping(
                        {"output_dir": "e", "research_mode": value}, base_dir=self.base
                    )

    def test_chunk_size_bounds(self):
        for bad in (0, 1024, 2 * 1024**3):
            with self.subTest(bad=bad):
                with self.assertRaises(ConfigError):
                    config_from_mapping({"output_dir": "e", "chunk_size_bytes": bad}, base_dir=self.base)

    def test_chunk_size_rejects_bool_and_float(self):
        for bad in (True, 1.5e7):
            with self.subTest(bad=bad):
                with self.assertRaises(ConfigError):
                    config_from_mapping({"output_dir": "e", "chunk_size_bytes": bad}, base_dir=self.base)

    def test_empty_adb_path_rejected(self):
        with self.assertRaises(ConfigError):
            config_from_mapping({"output_dir": "e", "adb_path": ""}, base_dir=self.base)


class LoadConfigTests(unittest.TestCase):
    def test_load_resolves_relative_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corrobora.toml"
            path.write_text('output_dir = "out"\nchunk_size_bytes = 1048576\n', encoding="utf-8")
            cfg = load_config(path)
            self.assertEqual(cfg.output_dir, (Path(tmp) / "out").resolve())
            self.assertEqual(cfg.chunk_size_bytes, 1048576)

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigError):
                load_config(Path(tmp) / "absent.toml")

    def test_invalid_toml(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.toml"
            path.write_text("output_dir = \n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
