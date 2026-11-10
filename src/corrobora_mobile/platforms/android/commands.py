"""The fixed set of device shell commands the acquirer may run (M1.11).

``Adb`` runs a shell command on the device only when it is given a
``DeviceCommand``, and the only place ``DeviceCommand`` values are built is
this module. Every builder interpolates only values that have passed a
strict check, so no device path found during acquisition, and no operator
text other than a checked scope path, ever reaches the device shell.

Checked values:

* a scope root: ``/data/<component>[/<component>...]``, each component
  ASCII letters, digits, ``.``, ``_`` or ``-``, not ``.`` or ``..``;
* an acquisition ID: as accepted by ``evidence.package.validate_acquisition_id``;
* a sidecar file name: one of the names in ``SIDECAR_NAMES``.

Sidecar folder (decision 2026-11-09, docs/ARCHITECTURE.md Section 8.3):
``adb exec-out`` keeps binary output intact but returns no exit status and
mixes stderr into the data (observed 2026-11-09). Every command whose
output is evidence therefore runs as::

    <command> 2>SIDE/<name>.err; echo $? >SIDE/<name>.exit

with ``SIDE = /data/local/tmp/<acquisition_id>``. The folder is created
with ``mkdir`` (which fails if it already exists, so nothing is reused) and
removed at the end. Creating and removing it is a declared device
modification.

Enumeration (observed 2026-11-09 on toybox 0.8.13-android):

* ``find -printf`` writes ``\\0`` as a NUL byte, so pass 1 is NUL-separated
  and safe for any file name. Its ``%T@`` was observed to drop leading
  zeros from the fractional part, so it is not used.
* ``stat -c`` cannot write NUL; pass 2 therefore prints no names, one line
  per entry, in the same ``find`` order, and is matched to pass 1 by inode.
  ``stat`` ``%Z`` is the change time (observed: it moved after ``chmod``,
  ``%Y`` did not), whatever its help text says.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from corrobora_mobile.core.errors import ModelValidationError
from corrobora_mobile.core.paths import validate_device_path
from corrobora_mobile.evidence.package import validate_acquisition_id

SIDECAR_PARENT = "/data/local/tmp"
SCOPE_ROOT = re.compile(r"^/data(/[A-Za-z0-9._-]+)+$", re.ASCII)
SIDECAR_NAMES = frozenset({
    "pre-find", "pre-stat", "tar", "post-find", "post-stat",
})

#: pass 1: type+mode string, octal mode, uid, gid, size, inode, SELinux label,
#: symlink target, path -- each field NUL-terminated (9 fields per entry).
FIND_FORMAT = r"%M\0%m\0%U\0%G\0%s\0%i\0%Z\0%l\0%p\0"
FIND_FIELDS = 9
#: pass 2: inode, link count, then each time as unix seconds and full form.
STAT_FORMAT = "%i|%h|%Y|%y|%Z|%z|%X|%x"
#: tar options. --sparse is left out: on 2026-11-09 it produced output
#: byte-identical to a run without it (A-07); holes are stored as zeros.
TAR_OPTIONS = "-c --selinux --numeric-owner -f -"


@dataclass(frozen=True, slots=True)
class DeviceCommand:
    """A command line for the device shell, built only by this module."""

    text: str
    purpose: str

    def __post_init__(self) -> None:
        if not isinstance(self.text, str) or not self.text or "\n" in self.text:
            raise ModelValidationError("device command must be one non-empty line")
        if not isinstance(self.purpose, str) or not self.purpose.strip():
            raise ModelValidationError("device command needs a purpose")


def validate_scope_root(path: bytes) -> bytes:
    """Return ``path`` if it is an acceptable scope root; otherwise raise."""
    validate_device_path(path, "scope root")
    try:
        text = path.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ModelValidationError(f"scope root must be ASCII: {path!r}") from exc
    if not SCOPE_ROOT.match(text) or any(c in (".", "..") for c in text.split("/")):
        raise ModelValidationError(
            "scope root must be a folder under /data made of letters, digits, '.', '_' "
            f"and '-': {path!r}")
    return path


def sidecar_dir(acquisition_id: str) -> str:
    validate_acquisition_id(acquisition_id)
    return f"{SIDECAR_PARENT}/{acquisition_id}"


def _side(acquisition_id: str, name: str) -> str:
    if name not in SIDECAR_NAMES:
        raise ModelValidationError(f"unknown sidecar name: {name!r}")
    return f"{sidecar_dir(acquisition_id)}/{name}"


def _with_sidecars(command: str, acquisition_id: str, name: str) -> str:
    side = _side(acquisition_id, name)
    return f"{command} 2>{side}.err; echo $? >{side}.exit"


def _root(root: bytes) -> str:
    return validate_scope_root(root).decode("ascii")


# -- read-only commands -----------------------------------------------------------------


def toybox_version() -> DeviceCommand:
    return DeviceCommand("toybox --version", "record the on-device tool version")


def read_mounts() -> DeviceCommand:
    return DeviceCommand("cat /proc/mounts", "capture the mount table")


def stat_sidecar_parent() -> DeviceCommand:
    return DeviceCommand(f"stat -c '%Y|%y|%Z|%z' {SIDECAR_PARENT}",
                         "record the sidecar parent folder's times (it is modified)")


def read_sidecar(acquisition_id: str, name: str, kind: str) -> DeviceCommand:
    if kind not in ("err", "exit"):
        raise ModelValidationError(f"sidecar kind must be 'err' or 'exit': {kind!r}")
    return DeviceCommand(f"cat {_side(acquisition_id, name)}.{kind}", f"read sidecar {name}.{kind}")


def find_pass(root: bytes, acquisition_id: str, name: str) -> DeviceCommand:
    """Pass 1: NUL-separated listing; stderr and exit status to sidecars."""
    cmd = f"find '{_root(root)}' -printf '{FIND_FORMAT}'"
    return DeviceCommand(_with_sidecars(cmd, acquisition_id, name), f"enumeration {name} (names)")


def stat_pass(root: bytes, acquisition_id: str, name: str) -> DeviceCommand:
    """Pass 2: one name-free line per entry, in find order."""
    cmd = f"find '{_root(root)}' -exec stat -c '{STAT_FORMAT}' {{}} +"
    return DeviceCommand(_with_sidecars(cmd, acquisition_id, name), f"enumeration {name} (times)")


def tar_stream(root: bytes, acquisition_id: str) -> DeviceCommand:
    """The archive of one scope root, written to stdout; names relative to its parent."""
    text = _root(root)
    parent, base = text.rsplit("/", 1)
    cmd = f"tar {TAR_OPTIONS} -C '{parent}' '{base}'"
    return DeviceCommand(_with_sidecars(cmd, acquisition_id, "tar"), "archive stream")


# -- commands that change the device (declared modifications) ---------------------------


def make_sidecar_dir(acquisition_id: str) -> DeviceCommand:
    """mkdir without -p: fails if the folder exists, so nothing is reused."""
    return DeviceCommand(f"mkdir {sidecar_dir(acquisition_id)}",
                         "DEVICE CHANGE: create the sidecar folder")


def remove_sidecar_dir(acquisition_id: str) -> DeviceCommand:
    side = sidecar_dir(acquisition_id)
    return DeviceCommand(f"rm -r {side} && test ! -e {side}",
                         "DEVICE CHANGE: remove the sidecar folder and confirm it is gone")
