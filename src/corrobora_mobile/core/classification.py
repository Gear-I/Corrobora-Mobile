"""Acquisition-class rules (docs/ARCHITECTURE.md, Sections 0.2 and 0.3).

The class is determined from the acquisition's own recorded evidence. It
never depends on whether the method has been validated, and it never
changes a method's validation status.

Every criterion is a ``CriterionResult`` rather than a bare boolean:

* a criterion counts as met only when its result is ``YES`` **and** it
  cites at least one evidence file in the package;
* ``NO`` and ``UNKNOWN`` must explain why;
* ``UNKNOWN`` is treated exactly like ``NO``. A criterion that could not
  be established is never assumed to hold.

Where a criterion can be computed directly from recorded data, a helper
here computes it (``assess_mount_coverage``), so callers do not assert it.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from corrobora_mobile.core.enums import AcquisitionClass, Tristate
from corrobora_mobile.core.errors import ClassificationError, ModelValidationError
from corrobora_mobile.core.models import AcquisitionPlan, MountEntry
from corrobora_mobile.core.paths import is_within


@dataclass(frozen=True, kw_only=True, slots=True)
class CriterionResult:
    """The outcome of one classification criterion, with its evidence.

    Attributes:
        result: ``YES``, ``NO`` or ``UNKNOWN``.
        evidence_refs: package-relative paths of the evidence files the
            result was derived from (e.g. ``plan/mounts.txt``). Required
            when ``result`` is ``YES``.
        detail: explanation. Required when ``result`` is ``NO`` or
            ``UNKNOWN``.
    """

    result: Tristate
    evidence_refs: tuple[str, ...] = ()
    detail: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.result, Tristate):
            raise ModelValidationError("result must be a Tristate")
        if not isinstance(self.evidence_refs, tuple):
            raise ModelValidationError("evidence_refs must be a tuple")
        for ref in self.evidence_refs:
            if not isinstance(ref, str) or not ref.strip():
                raise ModelValidationError("evidence_refs entries must be non-empty strings")
            if ref.startswith(("/", "\\")) or ".." in ref.replace("\\", "/").split("/"):
                raise ModelValidationError(f"evidence ref must be package-relative: {ref!r}")
        if self.detail is not None and (not isinstance(self.detail, str) or not self.detail.strip()):
            raise ModelValidationError("detail must be a non-empty string or None")
        if self.result is Tristate.YES and not self.evidence_refs:
            raise ModelValidationError("a YES result must cite at least one evidence file")
        if self.result is not Tristate.YES and self.detail is None:
            raise ModelValidationError(f"a {self.result.value} result requires detail")

    @property
    def met(self) -> bool:
        """True only for a YES result. UNKNOWN is never met."""
        return self.result is Tristate.YES

    def to_dict(self) -> dict[str, object]:
        return {
            "result": self.result.value,
            "evidence_refs": list(self.evidence_refs),
            "detail": self.detail,
        }


# Criterion names, in the order they are evaluated and reported.
CRITERIA: tuple[str, ...] = (
    "privileged_session",
    "full_mount_table_scope",
    "f1_persistent_mounts_in_scope",
    "f2_app_private_in_scope",
    "f3_content_for_readable_files",
    "f4_required_attributes_captured",
)

_FFS_CRITERIA = CRITERIA[2:]


@dataclass(frozen=True, kw_only=True, slots=True)
class ClassificationEvidence:
    """All criteria that determine an acquisition's class.

    Every field is required. There are no defaults, so a criterion cannot
    be left out by omission.
    """

    privileged_session: CriterionResult
    full_mount_table_scope: CriterionResult
    f1_persistent_mounts_in_scope: CriterionResult
    f2_app_private_in_scope: CriterionResult
    f3_content_for_readable_files: CriterionResult
    f4_required_attributes_captured: CriterionResult

    def __post_init__(self) -> None:
        for name in CRITERIA:
            if not isinstance(getattr(self, name), CriterionResult):
                raise ModelValidationError(f"{name} must be a CriterionResult")

    def to_dict(self) -> dict[str, object]:
        return {name: getattr(self, name).to_dict() for name in CRITERIA}


@dataclass(frozen=True, kw_only=True, slots=True)
class ClassDetermination:
    """The result of classifying an acquisition, with its reasons.

    ``limiting_criteria`` lists the criteria that were not met and that
    prevented a higher class, in evaluation order.
    """

    planned: AcquisitionClass
    highest_supported: AcquisitionClass
    final: AcquisitionClass
    limiting_criteria: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "planned": self.planned.value,
            "highest_supported": self.highest_supported.value,
            "final": self.final.value,
            "limiting_criteria": list(self.limiting_criteria),
        }


def assess_mount_coverage(
    plan: AcquisitionPlan,
    mounts: Iterable[MountEntry],
    *,
    mount_table_ref: str,
    plan_ref: str,
) -> CriterionResult:
    """Compute ``full_mount_table_scope`` from the plan and the mount table.

    Met only if every mount point in the captured table is either an
    included path or covered by an exclusion in the plan. ``UNKNOWN`` if the
    mount table is empty, because an empty capture cannot show coverage.
    """
    mount_points = sorted({m.mount_point for m in mounts})
    if not mount_points:
        return CriterionResult(
            result=Tristate.UNKNOWN,
            detail="mount table capture is empty; coverage cannot be established",
        )
    excluded = [ex.path for ex in plan.exclusions]
    missing = [
        mp
        for mp in mount_points
        if mp not in plan.included_paths and not any(is_within(mp, ex) for ex in excluded)
    ]
    if missing:
        shown = ", ".join(repr(mp) for mp in missing[:10])
        more = f" (+{len(missing) - 10} more)" if len(missing) > 10 else ""
        return CriterionResult(
            result=Tristate.NO,
            evidence_refs=(mount_table_ref, plan_ref),
            detail=f"{len(missing)} mount point(s) neither included nor excluded: {shown}{more}",
        )
    return CriterionResult(result=Tristate.YES, evidence_refs=(mount_table_ref, plan_ref))


def determine_class(
    planned: AcquisitionClass, evidence: ClassificationEvidence
) -> ClassDetermination:
    """Classify an acquisition from its evidence.

    The final class is the lower of the planned class and the highest class
    the evidence supports. It never exceeds the plan.
    """
    if not isinstance(planned, AcquisitionClass):
        raise ModelValidationError("planned must be an AcquisitionClass")
    if not isinstance(evidence, ClassificationEvidence):
        raise ModelValidationError("evidence must be ClassificationEvidence")

    if not evidence.privileged_session.met:
        supported, limiting = AcquisitionClass.SELECTED_DIRECTORY, ("privileged_session",)
    elif not evidence.full_mount_table_scope.met:
        supported, limiting = (
            AcquisitionClass.PRIVILEGED_SELECTED_DIRECTORY,
            ("full_mount_table_scope",),
        )
    else:
        unmet = tuple(n for n in _FFS_CRITERIA if not getattr(evidence, n).met)
        supported = AcquisitionClass.PRIVILEGED_FILESYSTEM if unmet else AcquisitionClass.FFS
        limiting = unmet

    final = planned if planned.rank <= supported.rank else supported
    return ClassDetermination(
        planned=planned, highest_supported=supported, final=final, limiting_criteria=limiting
    )


def relabel(current: AcquisitionClass, new: AcquisitionClass) -> AcquisitionClass:
    """Change a recorded class after the fact. Only lowering is allowed."""
    if new.rank > current.rank:
        raise ClassificationError(
            f"acquisition class cannot be raised ({current.value} -> {new.value})"
        )
    return new


def class_covered_by_validation(
    acquisition_class: AcquisitionClass,
    validated_classes: frozenset[AcquisitionClass],
) -> bool:
    """Whether a method's validation record covers this acquisition's class.

    Returns False when the record does not list the class, including when
    the method has no validation record (empty set). The caller reports
    False as "class not validated for this method" (Section 0.3).
    """
    return acquisition_class in validated_classes
