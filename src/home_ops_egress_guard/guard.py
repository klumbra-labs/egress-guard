from __future__ import annotations

import json
import logging
import os
import sqlite3
import subprocess
import time
import urllib.parse
import urllib.request
import uuid
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Self

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1
DEFAULT_DB_PATH = "/state/egress-ledger.sqlite3"
TRUE_VALUES = {"1", "true", "yes", "on"}
BLOCKED_STATUSES = {"blocked", "skipped"}
ATTEMPT_STATUSES = {"attempted", "success", "failed"}


class EgressBlocked(RuntimeError):
    """Raised before an external request when egress policy blocks it."""


@dataclass(frozen=True)
class GuardLimits:
    max_per_run: int | None = None
    max_per_hour: int | None = None
    max_per_day: int | None = None
    max_concurrency: int | None = None
    max_retries_per_item: int | None = None
    max_candidates_per_run: int | None = None


@dataclass(frozen=True)
class RequestRecord:
    id: int
    provider: str
    operation: str
    item_key: str


@dataclass(frozen=True)
class RunSummary:
    service: str
    operation: str
    candidate_count: int = 0
    attempted_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    skipped_count: int = 0
    blocked_count: int = 0
    abort_reason: str = ""


def _normalize_key(value: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in value.upper()).strip("_")


def _bool_env(env: Mapping[str, str], key: str) -> bool:
    return env.get(key, "").strip().lower() in TRUE_VALUES


def _int_env(env: Mapping[str, str], key: str) -> int | None:
    raw_value = env.get(key, "").strip()
    if not raw_value:
        return None
    value = int(raw_value)
    if value < 0:
        raise ValueError(f"{key} must be non-negative")
    return value


def _now() -> float:
    return time.time()


def _sanitize_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _request_url(request_or_url: urllib.request.Request | str) -> str:
    if isinstance(request_or_url, urllib.request.Request):
        return request_or_url.full_url
    return request_or_url


class EgressGuard:
    def __init__(
        self,
        *,
        service: str,
        db_path: Path | str | None = None,
        run_id: str | None = None,
        default_limits: Mapping[tuple[str, str], GuardLimits] | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        source_env = env if env is not None else os.environ
        configured_db_path = db_path or source_env.get("EGRESS_GUARD_DB_PATH") or DEFAULT_DB_PATH
        self.service = service
        self.db_path = Path(configured_db_path)
        self.run_id = run_id or uuid.uuid4().hex
        self.env = source_env
        self.default_limits = dict(default_limits or {})
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS egress_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    item_key TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL,
                    started_at REAL NOT NULL,
                    finished_at REAL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    error TEXT NOT NULL DEFAULT ''
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_egress_requests_limits
                ON egress_requests(provider, operation, started_at, status)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_egress_requests_run
                ON egress_requests(run_id, provider, operation, status)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_egress_requests_item
                ON egress_requests(provider, operation, item_key, status)
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS egress_run_summaries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    candidate_count INTEGER NOT NULL,
                    attempted_count INTEGER NOT NULL,
                    success_count INTEGER NOT NULL,
                    failure_count INTEGER NOT NULL,
                    skipped_count INTEGER NOT NULL,
                    blocked_count INTEGER NOT NULL,
                    abort_reason TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (SCHEMA_VERSION, _now()),
            )

    def limits_for(self, provider: str, operation: str) -> GuardLimits:
        provider_key = _normalize_key(provider)
        operation_key = _normalize_key(operation)
        defaults = self.default_limits.get((provider, operation), GuardLimits())
        return GuardLimits(
            max_per_run=_int_env(
                self.env, f"EGRESS_LIMIT_{provider_key}_{operation_key}_MAX_PER_RUN"
            )
            if f"EGRESS_LIMIT_{provider_key}_{operation_key}_MAX_PER_RUN" in self.env
            else defaults.max_per_run,
            max_per_hour=_int_env(
                self.env, f"EGRESS_LIMIT_{provider_key}_{operation_key}_MAX_PER_HOUR"
            )
            if f"EGRESS_LIMIT_{provider_key}_{operation_key}_MAX_PER_HOUR" in self.env
            else defaults.max_per_hour,
            max_per_day=_int_env(
                self.env, f"EGRESS_LIMIT_{provider_key}_{operation_key}_MAX_PER_DAY"
            )
            if f"EGRESS_LIMIT_{provider_key}_{operation_key}_MAX_PER_DAY" in self.env
            else defaults.max_per_day,
            max_concurrency=_int_env(
                self.env, f"EGRESS_LIMIT_{provider_key}_{operation_key}_MAX_CONCURRENCY"
            )
            if f"EGRESS_LIMIT_{provider_key}_{operation_key}_MAX_CONCURRENCY" in self.env
            else defaults.max_concurrency,
            max_retries_per_item=_int_env(
                self.env, f"EGRESS_LIMIT_{provider_key}_{operation_key}_MAX_RETRIES_PER_ITEM"
            )
            if f"EGRESS_LIMIT_{provider_key}_{operation_key}_MAX_RETRIES_PER_ITEM" in self.env
            else defaults.max_retries_per_item,
            max_candidates_per_run=_int_env(
                self.env, f"EGRESS_LIMIT_{provider_key}_{operation_key}_MAX_CANDIDATES_PER_RUN"
            )
            if f"EGRESS_LIMIT_{provider_key}_{operation_key}_MAX_CANDIDATES_PER_RUN" in self.env
            else defaults.max_candidates_per_run,
        )

    def check_candidates(self, provider: str, operation: str, count: int) -> None:
        limit = self.limits_for(provider, operation).max_candidates_per_run
        if limit is None or count <= limit:
            return
        reason = (
            f"egress candidate batch blocked for {provider}/{operation}: "
            f"{count} candidates exceeds limit {limit}"
        )
        self.record_skipped(provider, operation, status="blocked", error=reason)
        log.warning("egress_guard_blocked %s", json.dumps({"reason": reason}, sort_keys=True))
        raise EgressBlocked(reason)

    def _disabled_reason(self, provider: str, operation: str) -> str:
        if _bool_env(self.env, "EGRESS_DISABLED"):
            return f"egress globally disabled before {provider}/{operation}"

        provider_key = _normalize_key(provider)
        if _bool_env(self.env, f"EGRESS_PROVIDER_{provider_key}_DISABLED"):
            return f"egress provider {provider} disabled before {provider}/{operation}"
        return ""

    def _count(
        self,
        conn: sqlite3.Connection,
        provider: str,
        operation: str,
        *,
        since: float | None = None,
        run_id: str | None = None,
        item_key: str | None = None,
        statuses: set[str] | None = None,
    ) -> int:
        clauses = ["provider = ?", "operation = ?"]
        params: list[str | float] = [provider, operation]
        if since is not None:
            clauses.append("started_at >= ?")
            params.append(since)
        if run_id is not None:
            clauses.append("run_id = ?")
            params.append(run_id)
        if item_key is not None:
            clauses.append("item_key = ?")
            params.append(item_key)
        if statuses:
            placeholders = ",".join("?" for _ in statuses)
            clauses.append(f"status IN ({placeholders})")
            params.extend(sorted(statuses))
        row = conn.execute(
            f"SELECT COUNT(*) AS total FROM egress_requests WHERE {' AND '.join(clauses)}",
            params,
        ).fetchone()
        return int(row["total"])

    def _limit_reason(
        self,
        conn: sqlite3.Connection,
        provider: str,
        operation: str,
        item_key: str,
    ) -> str:
        limits = self.limits_for(provider, operation)
        current_time = _now()
        checks = [
            (
                limits.max_per_run,
                self._count(
                    conn,
                    provider,
                    operation,
                    run_id=self.run_id,
                    statuses=ATTEMPT_STATUSES,
                ),
                "per-run",
            ),
            (
                limits.max_per_hour,
                self._count(
                    conn,
                    provider,
                    operation,
                    since=current_time - 3600,
                    statuses=ATTEMPT_STATUSES,
                ),
                "hourly",
            ),
            (
                limits.max_per_day,
                self._count(
                    conn,
                    provider,
                    operation,
                    since=current_time - 86400,
                    statuses=ATTEMPT_STATUSES,
                ),
                "daily",
            ),
            (
                limits.max_concurrency,
                self._count(conn, provider, operation, statuses={"attempted"}),
                "concurrency",
            ),
        ]
        for limit, count, label in checks:
            if limit is not None and count >= limit:
                return f"egress {label} limit reached for {provider}/{operation}: {count}/{limit}"

        retry_limit = limits.max_retries_per_item
        if retry_limit is None or not item_key:
            return ""
        attempts = self._count(
            conn,
            provider,
            operation,
            item_key=item_key,
            statuses=ATTEMPT_STATUSES,
        )
        if attempts >= retry_limit:
            return (
                f"egress retry limit reached for {provider}/{operation} item "
                f"{item_key}: {attempts}/{retry_limit}"
            )
        return ""

    def _insert_request(
        self,
        conn: sqlite3.Connection,
        provider: str,
        operation: str,
        item_key: str,
        status: str,
        metadata: Mapping[str, str | int | float | bool | None] | None = None,
        error: str = "",
    ) -> RequestRecord:
        cursor = conn.execute(
            """
            INSERT INTO egress_requests(
                service, run_id, provider, operation, item_key, status,
                started_at, finished_at, metadata_json, error
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self.service,
                self.run_id,
                provider,
                operation,
                item_key,
                status,
                _now(),
                _now() if status in BLOCKED_STATUSES else None,
                json.dumps(dict(metadata or {}), sort_keys=True),
                error,
            ),
        )
        return RequestRecord(
            id=int(cursor.lastrowid),
            provider=provider,
            operation=operation,
            item_key=item_key,
        )

    def start_request(
        self,
        provider: str,
        operation: str,
        *,
        item_key: str = "",
        metadata: Mapping[str, str | int | float | bool | None] | None = None,
    ) -> RequestRecord:
        disabled_reason = self._disabled_reason(provider, operation)
        with self._connect() as conn:
            reason = disabled_reason or self._limit_reason(conn, provider, operation, item_key)
            if reason:
                self._insert_request(
                    conn,
                    provider,
                    operation,
                    item_key,
                    "blocked",
                    metadata=metadata,
                    error=reason,
                )
                conn.commit()
                log.warning(
                    "egress_guard_blocked %s",
                    json.dumps(
                        {"provider": provider, "operation": operation, "reason": reason},
                        sort_keys=True,
                    ),
                )
                raise EgressBlocked(reason)
            return self._insert_request(conn, provider, operation, item_key, "attempted", metadata)

    def finish_request(self, record: RequestRecord, status: str, error: str = "") -> None:
        if status not in {"success", "failed", "skipped"}:
            raise ValueError(f"invalid egress request status: {status}")
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE egress_requests
                SET status = ?, finished_at = ?, error = ?
                WHERE id = ?
                """,
                (status, _now(), error, record.id),
            )

    def record_skipped(
        self,
        provider: str,
        operation: str,
        *,
        item_key: str = "",
        status: str = "skipped",
        error: str = "",
    ) -> None:
        if status not in BLOCKED_STATUSES:
            raise ValueError("skipped records must use skipped or blocked status")
        with self._connect() as conn:
            self._insert_request(conn, provider, operation, item_key, status, error=error)

    @contextmanager
    def request(
        self,
        provider: str,
        operation: str,
        *,
        item_key: str = "",
        metadata: Mapping[str, str | int | float | bool | None] | None = None,
    ):
        record = self.start_request(provider, operation, item_key=item_key, metadata=metadata)
        try:
            yield record
        except Exception as exc:
            self.finish_request(record, "failed", str(exc))
            raise
        else:
            self.finish_request(record, "success")

    def write_run_summary(self, summary: RunSummary) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO egress_run_summaries(
                    service, run_id, operation, candidate_count, attempted_count,
                    success_count, failure_count, skipped_count, blocked_count,
                    abort_reason, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    summary.service,
                    self.run_id,
                    summary.operation,
                    summary.candidate_count,
                    summary.attempted_count,
                    summary.success_count,
                    summary.failure_count,
                    summary.skipped_count,
                    summary.blocked_count,
                    summary.abort_reason,
                    _now(),
                ),
            )

    def summarize_requests(
        self,
        operation: str,
        *,
        candidate_count: int,
        abort_reason: str = "",
    ) -> None:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT status, COUNT(*) AS total
                FROM egress_requests
                WHERE run_id = ?
                GROUP BY status
                """,
                (self.run_id,),
            ).fetchall()
        counts = {str(row["status"]): int(row["total"]) for row in rows}
        self.write_run_summary(
            RunSummary(
                service=self.service,
                operation=operation,
                candidate_count=candidate_count,
                attempted_count=sum(counts.get(status, 0) for status in ATTEMPT_STATUSES),
                success_count=counts.get("success", 0),
                failure_count=counts.get("failed", 0),
                skipped_count=counts.get("skipped", 0),
                blocked_count=counts.get("blocked", 0),
                abort_reason=abort_reason,
            )
        )


def guarded_urlopen(
    guard: EgressGuard,
    provider: str,
    operation: str,
    request_or_url: urllib.request.Request | str,
    *,
    item_key: str = "",
    timeout: float | None = None,
    opener: urllib.request.OpenerDirector | None = None,
):
    metadata = {"url": _sanitize_url(_request_url(request_or_url))}
    record = guard.start_request(provider, operation, item_key=item_key, metadata=metadata)
    try:
        if opener is not None:
            response = opener.open(request_or_url, timeout=timeout)
        else:
            response = urllib.request.urlopen(request_or_url, timeout=timeout)
    except Exception as exc:
        guard.finish_request(record, "failed", str(exc))
        raise
    return _GuardedResponse(response, guard, record)


class _GuardedResponse:
    def __init__(
        self,
        response,
        guard: EgressGuard,
        record: RequestRecord,
    ) -> None:
        self._response = response
        self._guard = guard
        self._record = record
        self._finished = False

    def __enter__(self) -> Self:
        self._response.__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        try:
            return self._response.__exit__(exc_type, exc, traceback)
        finally:
            if exc is None:
                self._finish("success")
            else:
                self._finish("failed", str(exc))

    def _finish(self, status: str, error: str = "") -> None:
        if self._finished:
            return
        self._guard.finish_request(self._record, status, error)
        self._finished = True

    def __getattr__(self, name: str):
        return getattr(self._response, name)


def guarded_subprocess_run(
    guard: EgressGuard,
    provider: str,
    operation: str,
    command: Sequence[str],
    *,
    item_key: str = "",
    capture_output: bool = False,
    text: bool = False,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    metadata = {"command": command[0] if command else ""}
    record = guard.start_request(provider, operation, item_key=item_key, metadata=metadata)
    try:
        result = subprocess.run(
            command,
            capture_output=capture_output,
            text=text,
            check=check,
        )
    except Exception as exc:
        guard.finish_request(record, "failed", str(exc))
        raise

    status = "success" if result.returncode == 0 else "failed"
    error = "" if result.returncode == 0 else f"exit {result.returncode}"
    guard.finish_request(record, status, error)
    return result
