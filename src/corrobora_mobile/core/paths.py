"""Validation of device filesystem paths.

Paths are raw ``bytes`` and are **never normalized**: a path is either
already in canonical form or it is rejected. Normalizing could silently
turn one recorded path into another.

Canonical form (for paths on the source device):

* absolute: starts with ``/``;
* no NUL bytes;
* no empty components (``//``);
* no ``.`` or ``..`` components;
* no trailing ``/``, except for the root path ``/`` itself.

Any other byte, including bytes that are not valid UTF-8, is allowed,
because device filenames may contain them.

No length limit is enforced. Observed paths are evidence, and a deep path
on the device must be recorded rather than rejected.
"""

from __future__ import annotations

from corrobora_mobile.core.errors import ModelValidationError

ROOT = b"/"


def validate_device_path(raw: bytes, name: str = "path") -> bytes:
    """Return ``raw`` unchanged if canonical; otherwise raise."""
    if not isinstance(raw, bytes):
        raise ModelValidationError(f"{name} must be bytes")
    if not raw.startswith(b"/"):
        raise ModelValidationError(f"{name} must be absolute: {raw!r}")
    if b"\x00" in raw:
        raise ModelValidationError(f"{name} must not contain NUL bytes")
    if raw == ROOT:
        return raw
    if raw.endswith(b"/"):
        raise ModelValidationError(f"{name} must not end with '/': {raw!r}")
    for component in raw[1:].split(b"/"):
        if component == b"":
            raise ModelValidationError(f"{name} must not contain empty components: {raw!r}")
        if component in (b".", b".."):
            raise ModelValidationError(f"{name} must not contain '.' or '..': {raw!r}")
    return raw


def is_within(path: bytes, ancestor: bytes) -> bool:
    """True if ``path`` equals ``ancestor`` or lies beneath it.

    Compares whole components, so ``/database`` is not within ``/data``.
    Both arguments must already be canonical.
    """
    if ancestor == ROOT:
        return True
    return path == ancestor or path.startswith(ancestor + b"/")
