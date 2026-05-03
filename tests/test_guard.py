from __future__ import annotations

import sqlite3
import subprocess
import urllib.request
from pathlib import Path

import pytest

from home_ops_egress_guard import (
    EgressBlocked,
    EgressGuard,
    GuardLimits,
    RunSummary,
    guarded_subprocess_run,
)
from home_ops_egress_guard.guard import guarded_urlopen


def make_guard(
    tmp_path: Path,
    *,
    env: dict[str, str] | None = None,
    limits: dict[tuple[str, str], GuardLimits] | None = None,
) -> EgressGuard:
    return EgressGuard(
        service="test",
        db_path=tmp_path / "ledger.sqlite3",
        default_limits=limits or {},
        env=env or {},
    )


def request_statuses(db_path: Path) -> list[str]:
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute("SELECT status FROM egress_requests ORDER BY id").fetchall()
    return [str(row[0]) for row in rows]


def test_schema_creation_is_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "ledger.sqlite3"
    EgressGuard(service="test", db_path=db_path, env={})
    EgressGuard(service="test", db_path=db_path, env={})

    with sqlite3.connect(db_path) as conn:
        version = conn.execute("SELECT version FROM schema_migrations").fetchone()[0]

    assert version == 1


def test_kill_switch_blocks_before_external_call(tmp_path: Path) -> None:
    guard = make_guard(tmp_path, env={"EGRESS_DISABLED": "1"})

    with pytest.raises(EgressBlocked):
        guard.start_request("provider", "op")

    assert request_statuses(tmp_path / "ledger.sqlite3") == ["blocked"]


def test_per_run_limit_blocks_second_attempt(tmp_path: Path) -> None:
    guard = make_guard(
        tmp_path,
        limits={("provider", "op"): GuardLimits(max_per_run=1)},
    )

    record = guard.start_request("provider", "op")
    guard.finish_request(record, "success")

    with pytest.raises(EgressBlocked):
        guard.start_request("provider", "op")

    assert request_statuses(tmp_path / "ledger.sqlite3") == ["success", "blocked"]


def test_hourly_and_daily_limits_block(tmp_path: Path) -> None:
    guard = make_guard(
        tmp_path,
        limits={("provider", "op"): GuardLimits(max_per_hour=1, max_per_day=1)},
    )

    record = guard.start_request("provider", "op")
    guard.finish_request(record, "success")

    with pytest.raises(EgressBlocked):
        guard.start_request("provider", "op")


def test_concurrency_limit_blocks_open_attempt(tmp_path: Path) -> None:
    guard = make_guard(
        tmp_path,
        limits={("provider", "op"): GuardLimits(max_concurrency=1)},
    )

    guard.start_request("provider", "op")

    with pytest.raises(EgressBlocked):
        guard.start_request("provider", "op")


def test_retry_limit_blocks_by_item_key(tmp_path: Path) -> None:
    guard = make_guard(
        tmp_path,
        limits={("youtube", "fetch"): GuardLimits(max_retries_per_item=2)},
    )

    for _ in range(2):
        record = guard.start_request("youtube", "fetch", item_key="video-1")
        guard.finish_request(record, "failed", "boom")

    with pytest.raises(EgressBlocked):
        guard.start_request("youtube", "fetch", item_key="video-1")


def test_candidate_batch_limit_blocks(tmp_path: Path) -> None:
    guard = make_guard(
        tmp_path,
        limits={("feed", "fetch"): GuardLimits(max_candidates_per_run=2)},
    )

    with pytest.raises(EgressBlocked):
        guard.check_candidates("feed", "fetch", 3)


def test_run_summary_is_written(tmp_path: Path) -> None:
    guard = make_guard(tmp_path)
    record = guard.start_request("provider", "op")
    guard.finish_request(record, "success")
    guard.write_run_summary(
        RunSummary(
            service="test",
            operation="run",
            candidate_count=4,
            attempted_count=1,
            success_count=1,
        )
    )

    with sqlite3.connect(tmp_path / "ledger.sqlite3") as conn:
        row = conn.execute(
            "SELECT candidate_count, attempted_count, success_count FROM egress_run_summaries"
        ).fetchone()

    assert row == (4, 1, 1)


def test_metadata_sanitizes_query_strings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard = make_guard(tmp_path)

    class Response:
        status = 200

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return b"ok"

    monkeypatch.setattr(urllib.request, "urlopen", lambda *args, **kwargs: Response())

    with guarded_urlopen(
        guard,
        "provider",
        "op",
        "https://example.test/path?token=secret",
    ) as response:
        assert response.read() == b"ok"

    with sqlite3.connect(tmp_path / "ledger.sqlite3") as conn:
        metadata = conn.execute("SELECT metadata_json FROM egress_requests").fetchone()[0]

    assert "token" not in metadata
    assert "https://example.test/path" in metadata


def test_guarded_subprocess_records_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = make_guard(tmp_path)

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(["cmd"], 7, "", "failed")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = guarded_subprocess_run(guard, "youtube", "fetch", ["yt-dlp"], text=True)

    assert result.returncode == 7
    assert request_statuses(tmp_path / "ledger.sqlite3") == ["failed"]
