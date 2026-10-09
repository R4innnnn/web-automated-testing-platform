from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.environ.get("WEBTEST_DATA_DIR", BASE_DIR / "data"))
DB_PATH = DATA_DIR / "jobs.sqlite3"
RUN_DIR = DATA_DIR / "runs"
_LOCK = threading.Lock()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute(
        """CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            target TEXT NOT NULL,
            config_json TEXT NOT NULL,
            progress_json TEXT NOT NULL,
            result_json TEXT NOT NULL,
            error TEXT
        )"""
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS suppressions (
            finding_id TEXT PRIMARY KEY,
            module TEXT NOT NULL,
            title TEXT NOT NULL,
            url TEXT NOT NULL,
            created_at TEXT NOT NULL
        )"""
    )
    connection.commit()
    return connection


def new_job(target: str, public_config: dict) -> str:
    job_id = uuid4().hex
    with _LOCK, _connect() as db:
        db.execute(
            "INSERT INTO jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (job_id, "queued", now(), now(), target,
             json.dumps(public_config, ensure_ascii=False), "{}",
             json.dumps({"findings": [], "events": []}, ensure_ascii=False), None),
        )
        db.commit()
    (RUN_DIR / job_id).mkdir(parents=True, exist_ok=True)
    return job_id


def update_job(job_id: str, *, status: str | None = None,
               progress: dict | None = None, result: dict | None = None,
               error: str | None = None) -> None:
    with _LOCK, _connect() as db:
        row = db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if row is None:
            return
        db.execute(
            """UPDATE jobs SET status=?, updated_at=?, progress_json=?,
               result_json=?, error=? WHERE id=?""",
            (status or row["status"], now(),
             json.dumps(progress, ensure_ascii=False) if progress is not None else row["progress_json"],
             json.dumps(result, ensure_ascii=False) if result is not None else row["result_json"],
             error if error is not None else row["error"], job_id),
        )
        db.commit()


def get_job(job_id: str) -> dict | None:
    with _connect() as db:
        row = db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    if row is None:
        return None
    item = dict(row)
    item["config"] = json.loads(item.pop("config_json"))
    item["progress"] = json.loads(item.pop("progress_json"))
    item["result"] = json.loads(item.pop("result_json"))
    return item


def list_jobs(limit: int = 50) -> list[dict]:
    with _connect() as db:
        rows = db.execute(
            "SELECT id, status, created_at, updated_at, target, error FROM jobs "
            "ORDER BY created_at DESC LIMIT ?", (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def run_path(job_id: str) -> Path:
    path = RUN_DIR / job_id
    path.mkdir(parents=True, exist_ok=True)
    return path


def add_suppression(finding: dict) -> None:
    with _LOCK, _connect() as db:
        db.execute(
            "INSERT OR REPLACE INTO suppressions VALUES (?, ?, ?, ?, ?)",
            (finding["id"], finding["module"], finding["title"],
             finding.get("url", ""), now()),
        )
        db.commit()


def is_suppressed(finding_id: str) -> bool:
    with _connect() as db:
        row = db.execute(
            "SELECT 1 FROM suppressions WHERE finding_id = ?", (finding_id,)
        ).fetchone()
    return row is not None


def list_suppressions() -> list[dict]:
    with _connect() as db:
        rows = db.execute(
            "SELECT * FROM suppressions ORDER BY created_at DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def remove_suppression(finding_id: str) -> None:
    with _LOCK, _connect() as db:
        db.execute(
            "DELETE FROM suppressions WHERE finding_id = ?", (finding_id,)
        )
        db.commit()
