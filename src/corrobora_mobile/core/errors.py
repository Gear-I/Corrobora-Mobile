"""Typed errors (docs/ARCHITECTURE.md, Section 6).

All project errors derive from ``CorroboraError`` so callers can tell
project failures apart from unexpected exceptions. No code may catch these
broadly and continue without recording them.
"""

from __future__ import annotations


class CorroboraError(Exception):
    """Base class for all Corrobora Mobile errors."""


class ConfigError(CorroboraError):
    """Invalid or unsafe configuration."""


class ModelValidationError(CorroboraError, ValueError):
    """A data model was constructed with values that violate its rules."""


class ClassificationError(CorroboraError):
    """An attempt to raise an acquisition class, or another class-rule violation."""


class UnsupportedDeviceError(CorroboraError):
    """No usable method exists for the detected device configuration."""


class PreconditionError(CorroboraError):
    """A method's preconditions are not met; nothing was changed on the device."""


class AccessError(CorroboraError):
    """Privileged access could not be established or was lost."""


class AcquisitionError(CorroboraError):
    """Data acquisition failed."""


class IntegrityError(CorroboraError):
    """A hash, chain, or seal check failed. Always fails the acquisition."""


class AuditLogError(CorroboraError):
    """The audit log was used incorrectly (e.g. appending after sealing).

    Distinct from ``IntegrityError``, which reports evidence that fails
    verification.
    """


class EvidencePackageError(CorroboraError):
    """The evidence package was used incorrectly (e.g. writing a file twice).

    Distinct from ``IntegrityError``, which reports evidence that fails
    verification.
    """


class ResearchModeRequiredError(CorroboraError):
    """A research-only method was requested without research mode (Section 7.3)."""
