# egress-guard

`egress-guard` is a small standard-library Python package for guarding outbound calls from home automation jobs.

It owns:

- SQLite schema creation and request/run ledgers.
- Global and per-provider kill switches.
- Per-run, hourly, daily, concurrency, retry, and candidate-batch limits.
- Guarded `urllib` and subprocess helpers.

Common env vars:

- `EGRESS_GUARD_DB_PATH=/state/egress-ledger.sqlite3`
- `EGRESS_DISABLED=1`
- `EGRESS_PROVIDER_<PROVIDER>_DISABLED=1`
- `EGRESS_LIMIT_<PROVIDER>_<OP>_MAX_PER_RUN=10`
- `EGRESS_LIMIT_<PROVIDER>_<OP>_MAX_PER_HOUR=50`
- `EGRESS_LIMIT_<PROVIDER>_<OP>_MAX_PER_DAY=100`
- `EGRESS_LIMIT_<PROVIDER>_<OP>_MAX_CONCURRENCY=1`
- `EGRESS_LIMIT_<PROVIDER>_<OP>_MAX_RETRIES_PER_ITEM=3`
- `EGRESS_LIMIT_<PROVIDER>_<OP>_MAX_CANDIDATES_PER_RUN=25`
- `EGRESS_LIMIT_<PROVIDER>_<OP>_STALE_ATTEMPT_SECS=300`

Stale-attempt recovery is opt-in per operation. When configured, an `attempted`
ledger entry older than the threshold is marked failed before concurrency is
checked. This prevents an interrupted process or host reboot from permanently
consuming a concurrency slot without imposing a global timeout on long-running
operations.
