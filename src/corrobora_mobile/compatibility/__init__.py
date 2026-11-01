"""Method compatibility registry and gate (docs/ARCHITECTURE.md, Sections 3.1 and 3.3)."""

from corrobora_mobile.compatibility.registry import (
    Assessment,
    GateDecision,
    MethodRecord,
    Registry,
    assess,
    default_methods_dir,
    gate,
    load_registry,
)

__all__ = [
    "Assessment",
    "GateDecision",
    "MethodRecord",
    "Registry",
    "assess",
    "default_methods_dir",
    "gate",
    "load_registry",
]
