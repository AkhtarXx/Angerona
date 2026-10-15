"""Reversible checkpoint database for mutating analysis agents.

Inspired by the IDA Pro Book's emphasis: "There is no undo in IDA!" The only
revert path is to discard the database or restore a checkpoint. In angerona,
every mutating agent records its changes as a diff against a checkpoint. A
later stage can query the audit log, inspect a checkpoint, or roll back to it.

Schema per workspace:
  checkpoints(id, parent_id, agent, rationale, created_at)
  mutations(id, checkpoint_id, table, row_key, field, old_value, new_value)
  tags(id, checkpoint_id, key, value)

Values are stored JSON-serialized. `old_value` may be NULL for inserts; a rollback
replays mutations in reverse order with parent context so the previous state is
restored.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from ..observability import content_descriptor, ledger_for_workspace, sanitize_attributes


@dataclass
class Mutation:
    id: int | None
    checkpoint_id: int
    table: str
    row_key: str
    field: str
    old_value: Any | None
    new_value: Any | None

    def old(self) -> Any:
        return json.loads(self.old_value) if self.old_value is not None else None

    def new(self) -> Any:
        return json.loads(self.new_value) if self.new_value is not None else None


@dataclass
class Checkpoint:
    id: int
    parent_id: int | None
    agent: str
    rationale: str
    created_at: str
    tags: dict[str, str] = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.tags is None:
            self.tags = {}


class CheckpointDB:
    """Per-workspace reversible analysis database."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        root = self.db_path.expanduser().absolute().parent
        self.observability = (
            ledger_for_workspace(root)
            if (root / "run.json").is_file()
            and all((root / name).is_dir() for name in ("code", "docs", "raw"))
            else None
        )
        self._ensure_tables()

    def _observe(self, action: str, attributes: dict[str, object]) -> None:
        if self.observability is not None:
            self.observability.emit(
                component="checkpoint_db",
                category="database",
                action=action,
                attributes=attributes,
            )

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()

    def _ensure_tables(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS checkpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    parent_id INTEGER REFERENCES checkpoints(id) ON DELETE CASCADE,
                    agent TEXT NOT NULL,
                    rationale TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );
                CREATE INDEX IF NOT EXISTS idx_ckpt_parent ON checkpoints(parent_id);

                CREATE TABLE IF NOT EXISTS mutations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    checkpoint_id INTEGER NOT NULL REFERENCES checkpoints(id) ON DELETE CASCADE,
                    table_name TEXT NOT NULL,
                    row_key TEXT NOT NULL,
                    field TEXT NOT NULL,
                    old_value TEXT,
                    new_value TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_mut_ckpt ON mutations(checkpoint_id);

                CREATE TABLE IF NOT EXISTS tags (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    checkpoint_id INTEGER NOT NULL REFERENCES checkpoints(id) ON DELETE CASCADE,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_tags_ckpt ON tags(checkpoint_id);

                CREATE TABLE IF NOT EXISTS state_kv (
                    row_key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            conn.commit()
        self._observe("schema_ready", {"database": self.db_path.name})

    # -------------------------------------------------------------- checkpoint CRUD

    def create_checkpoint(self, agent: str, rationale: str,
                          parent_id: int | None = None,
                          tags: dict[str, str] | None = None) -> Checkpoint:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO checkpoints (parent_id, agent, rationale) VALUES (?, ?, ?)",
                (parent_id, agent, rationale),
            )
            ckpt_id = cur.lastrowid
            assert ckpt_id is not None
            for k, v in (tags or {}).items():
                conn.execute("INSERT INTO tags (checkpoint_id, key, value) VALUES (?, ?, ?)",
                             (ckpt_id, k, v))
            conn.commit()
            checkpoint = self.get_checkpoint(ckpt_id)
        self._observe(
            "checkpoint_created",
            {
                "checkpoint_id": ckpt_id,
                "parent_id": parent_id,
                "agent": agent,
                "rationale": content_descriptor(rationale),
                "tags": sanitize_attributes(tags or {}),
            },
        )
        assert checkpoint is not None
        return checkpoint

    def get_checkpoint(self, checkpoint_id: int) -> Checkpoint | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM checkpoints WHERE id = ?", (checkpoint_id,)).fetchone()
            if row is None:
                return None
            tags = {r["key"]: r["value"] for r in
                    conn.execute("SELECT key, value FROM tags WHERE checkpoint_id = ?", (checkpoint_id,))}
            return Checkpoint(
                id=row["id"],
                parent_id=row["parent_id"],
                agent=row["agent"],
                rationale=row["rationale"],
                created_at=row["created_at"],
                tags=tags,
            )

    def list_checkpoints(self) -> list[Checkpoint]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM checkpoints ORDER BY id ASC").fetchall()
            result = []
            for row in rows:
                tags = {r["key"]: r["value"] for r in
                        conn.execute("SELECT key, value FROM tags WHERE checkpoint_id = ?", (row["id"],))}
                result.append(Checkpoint(
                    id=row["id"],
                    parent_id=row["parent_id"],
                    agent=row["agent"],
                    rationale=row["rationale"],
                    created_at=row["created_at"],
                    tags=tags,
                ))
            return result

    def checkpoint_chain(self, checkpoint_id: int) -> list[Checkpoint]:
        """Return this checkpoint plus all ancestors back to root."""
        chain: list[Checkpoint] = []
        current_id = checkpoint_id
        while current_id is not None:
            ck = self.get_checkpoint(current_id)
            if ck is None:
                break
            chain.append(ck)
            current_id = ck.parent_id
        return list(reversed(chain))

    # ---------------------------------------------------------------- mutations

    def record_mutation(self, checkpoint_id: int, table: str, row_key: str, field: str,
                        old_value: Any, new_value: Any) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO mutations (checkpoint_id, table_name, row_key, field, old_value, new_value) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (checkpoint_id, table, row_key, field,
                 json.dumps(old_value, default=str) if old_value is not None else None,
                 json.dumps(new_value, default=str) if new_value is not None else None),
            )
            conn.commit()
        self._observe(
            "mutation_recorded",
            {
                "checkpoint_id": checkpoint_id,
                "table": table,
                "row_key": content_descriptor(row_key),
                "field": field,
                "old_value": content_descriptor(json.dumps(old_value, default=str)),
                "new_value": content_descriptor(json.dumps(new_value, default=str)),
            },
        )

    def record_mutations(self, checkpoint_id: int,
                         mutations: Iterable[tuple[str, str, str, Any, Any]]) -> None:
        """Batch record: (table, row_key, field, old_value, new_value)."""
        with self._conn() as conn:
            rows = []
            for table, row_key, field, old_value, new_value in mutations:
                rows.append((
                    checkpoint_id, table, row_key, field,
                    json.dumps(old_value, default=str) if old_value is not None else None,
                    json.dumps(new_value, default=str) if new_value is not None else None,
                ))
            conn.executemany(
                "INSERT INTO mutations (checkpoint_id, table_name, row_key, field, old_value, new_value) "
                "VALUES (?, ?, ?, ?, ?, ?)", rows,
            )
            conn.commit()
        for _checkpoint_id, table, row_key, field, old_json, new_json in rows:
            self._observe(
                "mutation_recorded",
                {
                    "checkpoint_id": checkpoint_id,
                    "table": table,
                    "row_key": content_descriptor(row_key),
                    "field": field,
                    "old_value": content_descriptor(old_json),
                    "new_value": content_descriptor(new_json),
                },
            )

    def mutations_for(self, checkpoint_id: int) -> list[Mutation]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM mutations WHERE checkpoint_id = ? ORDER BY id ASC", (checkpoint_id,)
            ).fetchall()
            return [Mutation(
                id=r["id"], checkpoint_id=r["checkpoint_id"], table=r["table_name"],
                row_key=r["row_key"], field=r["field"],
                old_value=r["old_value"], new_value=r["new_value"],
            ) for r in rows]

    def audit_log(self) -> list[dict[str, Any]]:
        """Flat log of checkpoints with mutation counts."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT c.id, c.parent_id, c.agent, c.rationale, c.created_at,
                       COUNT(m.id) as mutation_count
                FROM checkpoints c
                LEFT JOIN mutations m ON m.checkpoint_id = c.id
                GROUP BY c.id
                ORDER BY c.id ASC
                """
            ).fetchall()
            return [dict(r) for r in rows]

    # ---------------------------------------------------------------- state store

    def set_state(self, row_key: str, value: Any) -> None:
        """Store a generic JSON serializable value by row_key."""
        serialized = json.dumps(value, default=str)
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO state_kv (row_key, value) VALUES (?, ?) "
                "ON CONFLICT(row_key) DO UPDATE SET value=excluded.value",
                (row_key, serialized),
            )
            conn.commit()
        self._observe(
            "state_set",
            {"row_key": content_descriptor(row_key), "value": content_descriptor(serialized)},
        )

    def get_state(self, row_key: str) -> Any | None:
        with self._conn() as conn:
            row = conn.execute("SELECT value FROM state_kv WHERE row_key = ?", (row_key,)).fetchone()
        if row is None:
            return None
        return json.loads(row["value"])

    # ---------------------------------------------------------------- rollback

    def rollback(self, checkpoint_id: int, *, apply: bool = False) -> list[Mutation]:
        """Return the mutations of this checkpoint in reverse order (diff for undo).

        If ``apply=True`` and the mutation targets the generic ``state_kv`` table
        (row_key prefixed with `kv:`), the old value is written back automatically.
        Other tables require the caller to apply the diff to external artifacts.
        """
        mutations = list(reversed(self.mutations_for(checkpoint_id)))
        if apply:
            for m in mutations:
                if m.table == "state_kv":
                    rk = m.row_key if not m.row_key.startswith("kv:") else m.row_key[3:]
                    self.set_state(rk, m.old())
        return mutations

    def revert_to(self, checkpoint_id: int, *, apply: bool = False) -> list[tuple[int, list[Mutation]]]:
        """Roll back every descendant checkpoint of checkpoint_id (children first).

        Returns a list of (checkpoint_id, reversed_mutations) tuples in rollback order.
        With ``apply=True``, generic ``state_kv`` mutations are applied automatically.
        """
        descendants = self._descendants_of(checkpoint_id)
        result = []
        for ck_id in reversed(descendants):
            if ck_id == checkpoint_id:
                continue
            result.append((ck_id, self.rollback(ck_id, apply=apply)))
        return result

    def _descendants_of(self, checkpoint_id: int) -> list[int]:
        """Return all checkpoint ids in subtree rooted at checkpoint_id, pre-order."""
        visited: list[int] = []
        stack = [checkpoint_id]
        with self._conn() as conn:
            while stack:
                current = stack.pop()
                visited.append(current)
                rows = conn.execute("SELECT id FROM checkpoints WHERE parent_id = ? ORDER BY id DESC",
                                   (current,)).fetchall()
                stack.extend(r["id"] for r in rows)
        return visited

    # ---------------------------------------------------------------- helpers for agents

    @contextmanager
    def checkpoint_scope(self, agent: str, rationale: str,
                           parent_id: int | None = None,
                           tags: dict[str, str] | None = None):
        """Context manager: creates a checkpoint, yields it, and records no-op if empty."""
        ckpt = self.create_checkpoint(agent, rationale, parent_id=parent_id, tags=tags)
        try:
            yield ckpt
        except Exception:
            # Optional: auto-rollback on failure could be enabled here.
            raise

    def diff_json(self, checkpoint_id: int) -> dict[str, Any]:
        """Return a JSON-friendly diff for the checkpoint."""
        mutations = self.mutations_for(checkpoint_id)
        return {
            "checkpoint": checkpoint_id,
            "mutations": [
                {
                    "table": m.table,
                    "row_key": m.row_key,
                    "field": m.field,
                    "old": m.old(),
                    "new": m.new(),
                }
                for m in mutations
            ],
        }
