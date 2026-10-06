"""Compare two LabModels: what was added, removed or changed between snapshots."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from labwarden.model.lab import LabModel

# Collections that are streams, not state. Diffing them is noise.
_SKIP_KINDS = {"log_events"}
# Fields that don't represent a real change to the lab.
_IGNORED_FIELDS = {"source"}


class FieldChange(BaseModel):
    field: str
    before: Any
    after: Any


class EntityChange(BaseModel):
    kind: str
    key: tuple[str, ...]
    status: str  # "added" | "removed" | "changed"
    changes: list[FieldChange] = Field(default_factory=list)

    def label(self) -> str:
        return f"{self.kind}[{' / '.join(self.key)}]"


class LabDiff(BaseModel):
    changes: list[EntityChange] = Field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not self.changes

    def by_status(self, status: str) -> list[EntityChange]:
        return [c for c in self.changes if c.status == status]


def diff_models(before: LabModel, after: LabModel) -> LabDiff:
    result = LabDiff()
    for kind in LabModel.kinds():
        if kind in _SKIP_KINDS:
            continue
        old = {e.key(): e for e in getattr(before, kind)}
        new = {e.key(): e for e in getattr(after, kind)}

        for key in sorted(new.keys() - old.keys()):
            result.changes.append(EntityChange(kind=kind, key=key, status="added"))
        for key in sorted(old.keys() - new.keys()):
            result.changes.append(EntityChange(kind=kind, key=key, status="removed"))
        for key in sorted(old.keys() & new.keys()):
            a = old[key].model_dump(mode="json", exclude=_IGNORED_FIELDS)
            b = new[key].model_dump(mode="json", exclude=_IGNORED_FIELDS)
            field_changes = [
                FieldChange(field=f, before=a.get(f), after=b.get(f))
                for f in sorted(a.keys() | b.keys())
                if a.get(f) != b.get(f)
            ]
            if field_changes:
                result.changes.append(
                    EntityChange(kind=kind, key=key, status="changed", changes=field_changes)
                )
    return result
