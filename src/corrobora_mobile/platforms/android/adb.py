"""A deliberately narrow adb wrapper for read-only detection.

Only three commands can be issued through this module:

* ``adb version``                         -- host side only;
* ``adb devices``                         -- host side only;
* ``adb -s <serial> shell getprop <name>`` -- reads one system property.

Nothing here can run ``adb root``, push or pull files, or run an arbitrary
shell command. Inputs that reach the device shell are validated against
strict patterns first, because ``adb shell`` passes its arguments to the
device's shell as a command line.

Every command is returned as a ``CommandRecord`` holding the exact argv,
exit status, and raw stdout and stderr bytes, so the caller can store them
as evidence unmodified.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from corrobora_mobile.core.errors import AccessError, ModelValidationError

PROPERTY_NAME = re.compile(r"^[A-Za-z0-9._-]{1,128}$", re.ASCII)
SERIAL = re.compile(r"^[A-Za-z0-9._:-]{1,128}$", re.ASCII)
DEFAULT_TIMEOUT_S = 30

#: (argv, timeout) -> (exit status, stdout, stderr); injectable for tests.
Runner = Callable[[list[str], float], tuple[int, bytes, bytes]]


def subprocess_runner(argv: list[str], timeout: float) -> tuple[int, bytes, bytes]:
    proc = subprocess.run(argv, capture_output=True, stdin=subprocess.DEVNULL, timeout=timeout,
                          check=False)
    return proc.returncode, proc.stdout, proc.stderr


@dataclass(frozen=True, slots=True)
class CommandRecord:
    argv: tuple[str, ...]
    exit_status: int
    stdout: bytes
    stderr: bytes

    @property
    def stdout_sha256(self) -> str:
        return hashlib.sha256(self.stdout).hexdigest()

    @property
    def stderr_sha256(self) -> str:
        return hashlib.sha256(self.stderr).hexdigest()


def validate_serial(serial: str) -> str:
    if not isinstance(serial, str) or not SERIAL.match(serial):
        raise ModelValidationError(f"invalid adb serial: {serial!r}")
    return serial


def validate_property_name(name: str) -> str:
    if not isinstance(name, str) or not PROPERTY_NAME.match(name):
        raise ModelValidationError(f"invalid property name: {name!r}")
    return name


class Adb:
    """Issues only the read-only commands listed in the module docstring."""

    def __init__(self, adb_path: str = "adb", *, runner: Runner = subprocess_runner,
                 timeout: float = DEFAULT_TIMEOUT_S) -> None:
        if not isinstance(adb_path, str) or not adb_path.strip():
            raise ModelValidationError("adb_path must be a non-empty string")
        self._adb = adb_path
        self._runner = runner
        self._timeout = timeout

    def _run(self, args: list[str]) -> CommandRecord:
        argv = [self._adb, *args]
        try:
            code, out, err = self._runner(argv, self._timeout)
        except FileNotFoundError as exc:
            raise AccessError(f"adb not found: {self._adb}") from exc
        except subprocess.TimeoutExpired as exc:
            raise AccessError(f"adb timed out after {self._timeout}s: {' '.join(argv)}") from exc
        except OSError as exc:
            raise AccessError(f"cannot run adb: {exc}") from exc
        return CommandRecord(argv=tuple(argv), exit_status=code, stdout=out, stderr=err)

    def version(self) -> CommandRecord:
        return self._run(["version"])

    def devices(self) -> CommandRecord:
        return self._run(["devices"])

    def getprop(self, serial: str, name: str) -> CommandRecord:
        return self._run(["-s", validate_serial(serial), "shell", "getprop",
                          validate_property_name(name)])


def parse_devices(stdout: bytes) -> list[tuple[str, str]]:
    """Parse ``adb devices`` output into (serial, state) pairs.

    Lines before the "List of devices attached" header, blank lines, and
    lines starting with ``*`` (adb server messages) are ignored.
    """
    text = stdout.decode("utf-8", errors="replace")
    devices: list[tuple[str, str]] = []
    seen_header = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("*"):
            continue
        if stripped.startswith("List of devices attached"):
            seen_header = True
            continue
        if not seen_header:
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            devices.append((parts[0], parts[1]))
    if not seen_header:
        raise AccessError("unexpected `adb devices` output (no device list header)")
    return devices
