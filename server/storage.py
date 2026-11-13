"""SQLite storage for user feedback only.

Submitted URLs and messages are NOT stored by the analysis endpoint. A row is
written only when a user explicitly sends feedback, and the submitted content
is included only if they tick the consent box. Rows older than the retention
period are deleted automatically.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,
    analysis_id TEXT NOT NULL,
    input_type TEXT NOT NULL,
    classification TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    verdict TEXT NOT NULL,
    comment TEXT NOT NULL DEFAULT '',
    content TEXT
);
CREATE INDEX IF NOT EXISTS feedback_created ON feedback(created_at);
"""


class FeedbackStore:
    def __init__(self, data_dir: Path, retention_days: int) -> None:
        data_dir.mkdir(parents=True, exist_ok=True)
        self.path = data_dir / "feedback.sqlite3"
        self.retention = retention_days * 86400
        self._lock = threading.Lock()
        self._last_purge = 0.0
        with self._connect() as db:
            db.executescript(SCHEMA)
        self.purge()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5)

    def purge(self) -> int:
        with self._lock, self._connect() as db:
            cur = db.execute("DELETE FROM feedback WHERE created_at < ?", (int(time.time()) - self.retention,))
            self._last_purge = time.time()
            return cur.rowcount

    def add(self, *, analysis_id: str, input_type: str, classification: str, risk_score: int, verdict: str,
            comment: str, content: str | None) -> None:
        if time.time() - self._last_purge > 86400:
            self.purge()
        with self._lock, self._connect() as db:
            db.execute(   # parameterised: user text is never interpolated into SQL
                "INSERT INTO feedback (created_at, analysis_id, input_type, classification, risk_score, verdict, comment, content)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (int(time.time()), analysis_id, input_type, classification, risk_score, verdict, comment, content),
            )

    def count(self) -> int:
        with self._connect() as db:
            return db.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
