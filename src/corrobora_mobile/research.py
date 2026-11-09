"""Research-mode controls (docs/ARCHITECTURE.md, Section 7.3).

A method whose status is UNVERIFIED may run only in research mode. Research
mode needs, for each run:

* an explicit request (the ``--research`` command-line flag; it can never be
  enabled from a configuration file, see ``config.py``);
* an authorization reference: the ID of the device-ownership or consent
  record, stored in the manifest. It is a reference, not the record itself,
  and must not contain personal data;
* an acknowledgement of exactly the device modifications the method's
  compatibility record declares.

A research-mode result is labeled RESEARCH and can never claim a method
status above EXPERIMENTAL.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from corrobora_mobile.core.errors import ModelValidationError, PreconditionError

RESEARCH_LABEL = "RESEARCH"
MAX_RESEARCH_CLAIM = "EXPERIMENTAL"
AUTHORIZATION_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/#-]{2,127}$", re.ASCII)


@dataclass(frozen=True, slots=True)
class ResearchAuthorization:
    authorization_reference: str
    acknowledged_modifications: tuple[str, ...]

    def __post_init__(self) -> None:
        ref = self.authorization_reference
        if not isinstance(ref, str) or not AUTHORIZATION_REFERENCE.match(ref):
            raise ModelValidationError(
                "authorization reference must be 3-128 characters: letters, digits, "
                "space and . _ : / # - (a record ID, not personal data)")
        mods = self.acknowledged_modifications
        if not isinstance(mods, tuple) or not mods or \
                not all(isinstance(m, str) and m.strip() for m in mods):
            raise ModelValidationError("acknowledged_modifications must be a non-empty tuple of strings")

    def check_covers(self, declared: Sequence[str]) -> None:
        """The acknowledgement must cover exactly the declared modifications."""
        if set(self.acknowledged_modifications) != set(declared):
            raise PreconditionError(
                "research-mode acknowledgement does not match the method's declared device "
                f"modifications: acknowledged {sorted(self.acknowledged_modifications)}, "
                f"declared {sorted(declared)}")

    def manifest_fields(self) -> dict[str, Any]:
        return {
            "label": RESEARCH_LABEL,
            "research_mode": True,
            "authorization_reference": self.authorization_reference,
            "acknowledged_device_modifications": list(self.acknowledged_modifications),
            "max_claimable_status": MAX_RESEARCH_CLAIM,
        }
