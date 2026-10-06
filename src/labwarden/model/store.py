"""SQLite-backed history of LabModel snapshots."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

from labwarden.model.lab import LabModel

_SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    taken_at   TEXT NOT NULL,
    label      TEXT,
    errors     TEXT NOT NULL DEFAULT '{}',
    model_json TEXT NOT NULL
);
"""


class SnapshotInfo(BaseModel):
    id: int
    taken_at: datetime
    label: str | None = None
    # Collector target name -> error message, for targets that failed this run.
    errors: dict[str, str] = Field(default_factory=dict)


class Snapshot(SnapshotInfo):
    model: LabModel


class SnapshotStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn, conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def save(
        self,
        model: LabModel,
        *,
        label: str | None = None,
        errors: dict[str, str] | None = None,
        taken_at: datetime | None = None,
    ) -> int:
        taken_at = taken_at or datetime.now(UTC)
        with closing(self._connect()) as conn, conn:
            cur = conn.execute(
                "INSERT INTO snapshots (taken_at, label, errors, model_json) VALUES (?, ?, ?, ?)",
                (taken_at.isoformat(), label, json.dumps(errors or {}), model.model_dump_json()),
            )
            return int(cur.lastrowid)

    def history(self, limit: int = 50) -> list[SnapshotInfo]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT id, taken_at, label, errors FROM snapshots ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._info(r) for r in rows]

    def get(self, snapshot_id: int) -> Snapshot | None:
        with closing(self._connect()) as conn:
            row = conn.execute("SELECT * FROM snapshots WHERE id = ?", (snapshot_id,)).fetchone()
        return self._snapshot(row) if row else None

    def latest(self, offset: int = 0) -> Snapshot | None:
        """The newest snapshot, or with ``offset=1`` the one before it, and so on."""
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM snapshots ORDER BY id DESC LIMIT 1 OFFSET ?", (offset,)
            ).fetchone()
        return self._snapshot(row) if row else None

    @staticmethod
    def _info(row: sqlite3.Row) -> SnapshotInfo:
        return SnapshotInfo(
            id=row["id"],
            taken_at=datetime.fromisoformat(row["taken_at"]),
            label=row["label"],
            errors=json.loads(row["errors"]),
        )

    @classmethod
    def _snapshot(cls, row: sqlite3.Row) -> Snapshot:
        info = cls._info(row)
        return Snapshot(**info.model_dump(), model=LabModel.model_validate_json(row["model_json"]))
