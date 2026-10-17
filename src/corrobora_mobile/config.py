"""Operator configuration, loaded from a TOML file.

Rules:

* Unknown keys are rejected, so a typo cannot silently fall back to a
  default.
* Research mode can never be enabled from a configuration file. It
  requires an explicit per-run flag (docs/ARCHITECTURE.md, Section 7.3).
* Relative paths are resolved against the configuration file's directory.

Example ``corrobora.toml``::

    output_dir = "D:/evidence"
    chunk_size_bytes = 67108864
    adb_path = "C:/Android/platform-tools/adb.exe"
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from corrobora_mobile.core.errors import ConfigError

DEFAULT_CHUNK_SIZE_BYTES = 64 * 1024 * 1024  # 64 MiB (Section 5.5)
MIN_CHUNK_SIZE_BYTES = 1024 * 1024  # 1 MiB
MAX_CHUNK_SIZE_BYTES = 1024 * 1024 * 1024  # 1 GiB

_ALLOWED_KEYS = frozenset({"output_dir", "chunk_size_bytes", "adb_path"})
_FORBIDDEN_KEYS = {
    "research_mode": (
        "research mode cannot be enabled from a configuration file; "
        "use the explicit per-run command-line flag (ARCHITECTURE.md Section 7.3)"
    ),
}


@dataclass(frozen=True, kw_only=True, slots=True)
class Config:
    output_dir: Path
    chunk_size_bytes: int = DEFAULT_CHUNK_SIZE_BYTES
    adb_path: str = "adb"


def config_from_mapping(data: Mapping[str, Any], *, base_dir: Path) -> Config:
    """Build a validated Config from parsed TOML data."""
    if not isinstance(data, Mapping):
        raise ConfigError("configuration must be a table")

    for key, message in _FORBIDDEN_KEYS.items():
        if key in data:
            raise ConfigError(message)

    unknown = sorted(set(data) - _ALLOWED_KEYS)
    if unknown:
        raise ConfigError(f"unknown configuration keys: {', '.join(unknown)}")

    if "output_dir" not in data:
        raise ConfigError("output_dir is required")
    output_dir_raw = data["output_dir"]
    if not isinstance(output_dir_raw, str) or not output_dir_raw.strip():
        raise ConfigError("output_dir must be a non-empty string")
    output_dir = Path(output_dir_raw)
    if not output_dir.is_absolute():
        output_dir = (base_dir / output_dir).resolve()

    chunk = data.get("chunk_size_bytes", DEFAULT_CHUNK_SIZE_BYTES)
    if isinstance(chunk, bool) or not isinstance(chunk, int):
        raise ConfigError("chunk_size_bytes must be an integer")
    if not MIN_CHUNK_SIZE_BYTES <= chunk <= MAX_CHUNK_SIZE_BYTES:
        raise ConfigError(
            f"chunk_size_bytes must be between {MIN_CHUNK_SIZE_BYTES} "
            f"and {MAX_CHUNK_SIZE_BYTES}"
        )

    adb_path = data.get("adb_path", "adb")
    if not isinstance(adb_path, str) or not adb_path.strip():
        raise ConfigError("adb_path must be a non-empty string")

    return Config(output_dir=output_dir, chunk_size_bytes=chunk, adb_path=adb_path)


def load_config(path: Path) -> Config:
    """Load and validate a TOML configuration file."""
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError as exc:
        raise ConfigError(f"configuration file not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
    return config_from_mapping(data, base_dir=path.parent.resolve())
