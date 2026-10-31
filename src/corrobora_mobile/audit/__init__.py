"""Hash-chained, write-ahead audit log (docs/ARCHITECTURE.md, Section 5.6).

``log`` writes the log; ``verify`` classifies an existing log as SEALED,
UNSEALED, or BROKEN. The line format is specified in ``log``'s module
docstring so that it can be checked without this package.
"""

from corrobora_mobile.audit.log import GENESIS_PREV, AuditLog, LogEntry
from corrobora_mobile.audit.verify import AuditVerification, OpenIntent, verify_audit_log

__all__ = [
    "GENESIS_PREV",
    "AuditLog",
    "AuditVerification",
    "LogEntry",
    "OpenIntent",
    "verify_audit_log",
]
