"""A deliberately narrow adb wrapper.

Only these commands can be issued through this module:

* ``adb version``                         -- host side only;
* ``adb devices``                         -- host side only;
* ``adb -s <serial> shell getprop <name>`` -- reads one system property;
* ``adb -s <serial> shell id``            -- reads the shell's identity;
* ``adb -s <serial> wait-for-device``     -- waits for the connection;
* ``adb -s <serial> root`` / ``unroot``   -- restart adbd as root / non-root;
* ``adb -s <serial> shell <DeviceCommand>`` and
  ``adb -s <serial> exec-out <DeviceCommand>`` -- only commands built by
  ``platforms/android/commands.py`` (M1.11), which interpolates nothing
  but checked values. ``exec-out`` is used where the output must be
  byte-exact; it returns no exit status and mixes the device's stderr into
  the output (observed 2026-11-09), so those commands send their stderr and
  exit status to sidecar files instead.

``root`` and ``unroot`` change device state. They are called only by the
adb-root provider (``providers/adb_root.py``), after the compatibility gate,
and always inside audit-log INTENT/RESULT pairs. Their exit status must not
be trusted: on a production build ``adb root`` printed "adbd cannot run as
root in production builds" and still exited with 0 (observed 2026-11-09).

Nothing here can push or pull files or run an arbitrary shell command: a
``DeviceCommand`` is required, and only ``commands.py`` builds one. Inputs
that reach the device shell are validated against strict patterns first,
because ``adb shell`` passes its arguments to the device's shell as a
command line.

Every command is returned as a ``CommandRecord`` holding the exact argv,
exit status, and raw stdout and stderr bytes, so the caller can store them
as evidence unmodified.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass

from corrobora_mobile.core.errors import AccessError, ModelValidationError
from corrobora_mobile.platforms.android.commands import DeviceCommand

PROPERTY_NAME = re.compile(r"^[A-Za-z0-9._-]{1,128}$", re.ASCII)
SERIAL = re.compile(r"^[A-Za-z0-9._:-]{1,128}$", re.ASCII)
DEFAULT_TIMEOUT_S = 30

#: (argv, timeout) -> (exit status, stdout, stderr); injectable for tests.
Runner = Callable[[list[str], float], tuple[int, bytes, bytes]]


#: (argv, sink) -> (exit status, stderr); stdout is passed to ``sink`` in pieces.
StreamRunner = Callable[[list[str], Callable[[bytes], None]], tuple[int, bytes]]
STREAM_READ_SIZE = 1024 * 1024


def subprocess_runner(argv: list[str], timeout: float) -> tuple[int, bytes, bytes]:
    proc = subprocess.run(argv, capture_output=True, stdin=subprocess.DEVNULL, timeout=timeout,
                          check=False)
    return proc.returncode, proc.stdout, proc.stderr


def subprocess_stream_runner(argv: list[str], sink: Callable[[bytes], None]) -> tuple[int, bytes]:
    """Run ``argv``, passing stdout to ``sink`` as it arrives. No overall timeout.

    adb's own stderr is drained on a thread so a full pipe cannot stall it.
    If ``sink`` raises, the process is killed and the error re-raised.
    """
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    err_parts: list[bytes] = []
    drain = threading.Thread(target=lambda: err_parts.append(proc.stderr.read()), daemon=True)
    drain.start()
    try:
        while True:
            piece = proc.stdout.read(STREAM_READ_SIZE)
            if not piece:
                break
            sink(piece)
    except BaseException:
        proc.kill()
        proc.wait()
        raise
    finally:
        proc.stdout.close()
    code = proc.wait()
    drain.join()
    return code, b"".join(err_parts)


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
    """Issues only the commands listed in the module docstring."""

    def __init__(self, adb_path: str = "adb", *, runner: Runner = subprocess_runner,
                 stream_runner: StreamRunner = subprocess_stream_runner,
                 timeout: float = DEFAULT_TIMEOUT_S) -> None:
        if not isinstance(adb_path, str) or not adb_path.strip():
            raise ModelValidationError("adb_path must be a non-empty string")
        self._adb = adb_path
        self._runner = runner
        self._stream_runner = stream_runner
        self._timeout = timeout

    def _run(self, args: list[str], timeout: float | None = None) -> CommandRecord:
        argv = [self._adb, *args]
        limit = self._timeout if timeout is None else timeout
        try:
            code, out, err = self._runner(argv, limit)
        except FileNotFoundError as exc:
            raise AccessError(f"adb not found: {self._adb}") from exc
        except subprocess.TimeoutExpired as exc:
            raise AccessError(f"adb timed out after {limit}s: {' '.join(argv)}") from exc
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

    def shell_id(self, serial: str) -> CommandRecord:
        return self._run(["-s", validate_serial(serial), "shell", "id"])

    def wait_for_device(self, serial: str) -> CommandRecord:
        return self._run(["-s", validate_serial(serial), "wait-for-device"])

    def root(self, serial: str) -> CommandRecord:
        """Changes device state. Use only through the adb-root provider."""
        return self._run(["-s", validate_serial(serial), "root"])

    def unroot(self, serial: str) -> CommandRecord:
        """Changes device state. Use only through the adb-root provider."""
        return self._run(["-s", validate_serial(serial), "unroot"])

    def shell_command(self, serial: str, command: DeviceCommand, *,
                      timeout: float | None = None) -> CommandRecord:
        """``adb shell``: exit status and stderr are reliable; output may be altered."""
        return self._run(["-s", validate_serial(serial), "shell", _command(command)], timeout)

    def exec_out(self, serial: str, command: DeviceCommand, *,
                 timeout: float | None = None) -> CommandRecord:
        """``adb exec-out``: output is byte-exact; exit status and stderr are NOT
        those of the device command (see the module docstring)."""
        return self._run(["-s", validate_serial(serial), "exec-out", _command(command)], timeout)

    def exec_out_stream(self, serial: str, command: DeviceCommand,
                        sink: Callable[[bytes], None]) -> tuple[tuple[str, ...], int, bytes]:
        """Like ``exec_out`` but streams stdout to ``sink``; returns (argv, adb exit, adb stderr).

        No timeout: a large archive can take a long time. Errors from adb
        itself (not found, cannot start) raise ``AccessError``; an error
        raised by ``sink`` is re-raised unchanged.
        """
        argv = [self._adb, "-s", validate_serial(serial), "exec-out", _command(command)]
        try:
            code, err = self._stream_runner(argv, sink)
        except FileNotFoundError as exc:
            raise AccessError(f"adb not found: {self._adb}") from exc
        return tuple(argv), code, err


def _command(command: DeviceCommand) -> str:
    if not isinstance(command, DeviceCommand):
        raise ModelValidationError("device shell commands must be DeviceCommand values "
                                   "(built by platforms/android/commands.py)")
    return command.text


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
