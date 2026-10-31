"""Enumerations shared across Corrobora Mobile.

Every value here is part of the evidence-package vocabulary and is written
into manifests verbatim. Changing a value is a format change.

References are to docs/ARCHITECTURE.md (Revision 3).
"""

from __future__ import annotations

from enum import StrEnum


class Platform(StrEnum):
    ANDROID = "android"
    IOS = "ios"


class Tristate(StrEnum):
    """A yes/no fact that may not be observable. Unknown is never guessed."""

    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"


class LockState(StrEnum):
    LOCKED = "locked"
    UNLOCKED = "unlocked"
    UNKNOWN = "unknown"


class BootState(StrEnum):
    """BFU = before first unlock; AFU = after first unlock."""

    BFU = "bfu"
    AFU = "afu"
    UNKNOWN = "unknown"


class AcquisitionClass(StrEnum):
    """Technical scope of a file-level acquisition (Section 0.2).

    The order of definition is the order of claim strength, lowest first.
    A class is never a statement about completeness, integrity, or
    validation.
    """

    SELECTED_DIRECTORY = "SELECTED_DIRECTORY"
    PRIVILEGED_SELECTED_DIRECTORY = "PRIVILEGED_SELECTED_DIRECTORY"
    PRIVILEGED_FILESYSTEM = "PRIVILEGED_FILESYSTEM"
    FFS = "FFS"

    @property
    def rank(self) -> int:
        """Position in claim-strength order (0 = lowest)."""
        return list(AcquisitionClass).index(self)


class ValidationStatus(StrEnum):
    """Status of a method on an exact device configuration (Sections 0.3, 5.8).

    These are the compatibility statuses required by the project
    instructions. Recorded independently of the acquisition class.
    """

    VERIFIED = "VERIFIED"
    EXPERIMENTAL = "EXPERIMENTAL"
    UNVERIFIED = "UNVERIFIED"
    UNSUPPORTED = "UNSUPPORTED"


class CompletenessStatus(StrEnum):
    """Completeness of an acquisition against its declared scope (Section 5.2)."""

    COMPLETE = "COMPLETE"
    COMPLETE_WITH_CHANGES = "COMPLETE_WITH_CHANGES"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    INTERRUPTED = "INTERRUPTED"
    COMPLETENESS_UNVERIFIED = "COMPLETENESS_UNVERIFIED"


class IntegrityStatus(StrEnum):
    """Verifier integrity finding (Section 5.7). PASS implies nothing about
    completeness or validation."""

    PASS = "PASS"
    FAIL = "FAIL"
    INCOMPLETE = "INCOMPLETE"


class EntryType(StrEnum):
    REGULAR = "regular"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    HARDLINK = "hardlink"
    CHAR_DEVICE = "char_device"
    BLOCK_DEVICE = "block_device"
    FIFO = "fifo"
    SOCKET = "socket"
    UNKNOWN = "unknown"


class EntryOutcome(StrEnum):
    """Reconciliation outcome for one in-scope entry (Section 5.2, check C6)."""

    ACQUIRED = "ACQUIRED"
    EXCLUDED_BY_RULE = "EXCLUDED_BY_RULE"
    UNSUPPORTED_TYPE = "UNSUPPORTED_TYPE"
    ERROR = "ERROR"


class ContentReliability(StrEnum):
    """Change observation for an acquired entry (Section 5.2.1).

    The name follows the architecture document's ``content_reliability``
    field. The values describe only what the before-and-after enumeration
    observed. No value certifies that content is reliable: in particular,
    NO_CHANGE_DETECTED is not a guarantee of correctness or consistency.
    """

    NO_CHANGE_DETECTED = "NO_CHANGE_DETECTED"
    CHANGED_DURING_ACQUISITION = "CHANGED_DURING_ACQUISITION"
    UNKNOWN = "UNKNOWN"


class RiskClass(StrEnum):
    """Risk class of a device modification (Section 7.2), lowest first."""

    NONE = "NONE"
    STATE_CHANGE = "STATE_CHANGE"
    PERSISTENT_CHANGE = "PERSISTENT_CHANGE"
    POSSIBLE_DATA_LOSS = "POSSIBLE_DATA_LOSS"
    POSSIBLE_DEVICE_DAMAGE = "POSSIBLE_DEVICE_DAMAGE"


class AuditEntryType(StrEnum):
    """Audit-log entry types (Section 5.6)."""

    SESSION_START = "SESSION_START"
    INTENT = "INTENT"
    RESULT = "RESULT"
    CHUNK = "CHUNK"
    NOTE = "NOTE"
    SEAL = "SEAL"


class AuditLogState(StrEnum):
    """Verifier classification of an audit log (Section 5.6).

    SEALED and UNSEALED describe only the log's own consistency. Neither
    proves the log was not regenerated in full; that needs the chain head
    anchored outside the package.
    """

    SEALED = "SEALED"
    UNSEALED = "UNSEALED"
    BROKEN = "BROKEN"
