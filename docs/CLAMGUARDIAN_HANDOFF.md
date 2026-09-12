# CLAMGUARDIAN — DEVELOPMENT HANDOFF

## 1. Date

2026-08-30

## 2. Repository State

```text
branch:   feature (jules worktree)
HEAD:     a33d6a6b1f1d689f2bd8e273b34b4c7e4ff31d5a
working tree: updated with headless controller fix and project docs
```

## 3. Current M4 Position

```text
M4-A     DONE

M4-B1    DONE
M4-B2    DONE
M4-B3    DONE
M4-B4    DONE
M4-B5    DONE
M4-B6    DONE
M4-B7    DONE

M4-B8    NEXT / TO BE DEFINED
...
M4-FINAL PENDING
```

M4 is **not** complete. The full M4 audit remains deferred until all M4-B implementation milestones are complete.

## 4. Today's Completed Work — M4-B7

### Objective

Add history lifecycle management: a `purge` operation on the `HistoryStore` and a corresponding `history purge` CLI command, so records can be deleted by retention criteria (age and/or status) without ever silently clearing the entire history.

### Implementation

**Commit:** `06221c5` — `feat(history): add history purge and retention management`

Single commit, no intermediate checkpoint commits for B7.

**Files changed (6 files, +447 / -3):**

| File | Change |
|------|--------|
| `clamguardian/cli/main.py` | +85 — `history purge` subcommand, `_cmd_history_purge`, `_history_purge` async helper, timestamp parsing, JSON output |
| `clamguardian/cli/output.py` | +6 — `format_purge_result(deleted: int)` human-readable formatter |
| `clamguardian/history/backend.py` | +33 — `SqliteHistoryStore.purge()` implementation |
| `clamguardian/history/interface.py` | +14 — `purge()` protocol method with documented error semantics |
| `tests/test_cli.py` | +148 — CLI-level purge tests (validation, JSON output, store failures, close behavior, isolation from list/show) |
| `tests/test_history.py` | +164 — backend-level purge tests (criteria, idempotency, cascade, naive datetime, failure modes) |

### APIs Added/Modified

- `HistoryStore.purge(*, before: datetime | None = None, status: str | None = None) -> int` — new protocol method on the `HistoryStore` contract (`interface.py`). Requires at least one criterion; `purge()` with neither raises `ValueError`. Invalid status raises `ValueError`. Backend failure raises `HistoryError`.
- `SqliteHistoryStore.purge()` — builds a parameterized `DELETE FROM scan_history WHERE ...` with `started_at < ?` (exclusive boundary) and/or `status = ?`. Cascades to `scan_threats` via foreign key. Returns the deleted row count.

### CLI Changes

New subcommand: `clamguardian history purge`

```text
usage: clamguardian history purge [--before TIMESTAMP] [--status STATUS] [--json]

  --before TIMESTAMP   delete records started before this ISO-8601 timestamp (exclusive)
  --status STATUS      only delete records with this status (clean, infected, error, timeout, cancelled)
  --json               emit {"deleted": N} instead of human text
```

- Requires at least one of `--before` / `--status` (exit 2 otherwise).
- Unparseable timestamp → usage error (exit 2).
- Store open failure → runtime error (exit 3).
- Store read/purge failure → runtime error (exit 3).
- Success → exit 0; store connection released before return.
- Human output: `"Purged N record(s) from history."`
- JSON output: `{"deleted": N}`

### Database / Schema

No schema change. `purge` operates on the existing `scan_history` / `scan_threats` tables (schema v1, `PRAGMA user_version = 1`). Deletion cascades threats via `ON DELETE CASCADE`.

### Tests Added

- **Backend** (`tests/test_history.py`): purge with `before` only, `status` only, both criteria, no-match returns zero, all-match empties store, idempotency (second purge returns 0), cascade deletes threats (verified no orphan `scan_threats` rows), naive datetime accepted (normalized to UTC), backend failure raises `HistoryError`.
- **CLI** (`tests/test_cli.py`): no-criteria rejected (exit 2), invalid timestamp (exit 2), JSON output contract, store open failure (exit 3), store purge failure (exit 3), store closed after command, purge does not affect read-only `list`/`show`.

### Commit SHA

`06221c521d4bbf278fa3ea56b43efec47c0d7ced`

### Validation

```text
pytest:           194 passed in 3.25s
ruff:             All checks passed!
mypy:             Success: no issues found in 29 source files
git diff --check: (no issues)
working tree:     clean
```

## 5. M4-B1 → M4-B7 Summary

| Milestone | Commit | Message |
|-----------|--------|---------|
| M4-B1 History persistence foundation (data model) | `7b7c7d6` | feat(history): add SQLite-backed scan history persistence layer |
| M4-B2 History API / model (store contract) | `7b7c7d6` | feat(history): add SQLite-backed scan history persistence layer |
| M4-B3 SQLite backend | `7b7c7d6` | feat(history): add SQLite-backed scan history persistence layer |
| M4-B4 P1 fixes | `a917045` | fix(history): harden P1 fixes for recorder backend |
| M4-B5 Recorder / Controller Wiring | `49ae3e5` | feat: wire history recorder into scan completion |
| M4-B6 History Reporting / Query Integration | `724cbb5` | feat(history): add history query/reporting CLI command |
| M4-B7 History Lifecycle / Management | `06221c5` | feat(history): add history purge and retention management |

**Note on B1/B2/B3:** All three milestones were delivered together in commit `7b7c7d6`, which introduced the entire `clamguardian.history` package. The module docstrings label `models.py` as B1 (data model), `interface.py` as B2 (store contract), and `backend.py` as B3 (SQLite backend). The commit created 5 files with 1301 insertions.

## 6. Current Architecture Snapshot

```text
Core / Engine          (clamguardian/core, clamguardian/engines)
      │
      ▼
ScanResult             (immutable frozen dataclass, core/base.py)
      │
      ▼
Controller             (clamguardian/cli/main.py — orchestration + best-effort recording)
      │
      ▼
HistoryStore           (Protocol abstraction, clamguardian/history/interface.py)
      │
      ▼
SQLite backend         (clamguardian/history/backend.py — only module importing sqlite3)
      ▲
      │
History CLI / Reporting / Management   (cli/main.py + cli/output.py)
```

### Layer Responsibilities

- **Core / Engine** (`clamguardian/core/`, `clamguardian/engines/clamav.py`): Scan orchestration via `ScanTaskRunner` → `BaseAVEngine.scan()` → `ScanResult`. Defines `ScanStatus`, `ScanResult`, `ScanProfile`, `BaseAVEngine`. **Does not import `sqlite3` or any history module.** Produces results; never persists them.

- **ScanResult** (`core/base.py`): Immutable frozen dataclass — the authoritative, normalized outcome of a scan. Status, threats, timestamps, metadata. The `clean` boolean is derived from `status`, never independent.

- **Controller** (`cli/main.py`): Parses arguments, resolves profiles, drives the event loop, presents output. At scan completion, calls `recorder.record_scan(result)` **best-effort**: a persistence failure is warned but never alters the `ScanResult` or its exit code. The recorder is opened via `_default_history_store()` and closed in a `finally` block.

- **HistoryStore** (`history/interface.py`): `Protocol` defining the async contract — `record_scan`, `get_scan`, `list_scans`, `delete_scan`, `clear_history`, `purge`, `count_scans`, `close`. Documented error semantics (e.g., `purge()` with no criteria → `ValueError`). No SQLite types leak through the abstraction.

- **SQLite backend** (`history/backend.py`): Sole module that imports `sqlite3`. Schema v1 with `scan_history` / `scan_threats` tables, WAL mode, `busy_timeout`, foreign keys, `0o700` directory / `0o600` file permissions. Thread-safe via a single connection + `threading.Lock`. Defensive row parsing (malformed rows skipped, never crash).

- **History CLI / Reporting / Management** (`cli/main.py` + `cli/output.py`): `history list`, `history show`, `history purge` subcommands. Pure presentation functions in `output.py` (human text + deterministic JSON). **Never executes SQL** — all access is through the `HistoryStore` protocol.

### Verified Architectural Boundaries

- Core does not know History: **verified** — no history imports in `core/`.
- Core does not know SQLite: **verified** — no `sqlite3` imports in `core/`.
- Engine does not directly access SQLite: **verified** — no `sqlite3` imports in `engines/`.
- CLI does not execute SQL: **verified** — CLI uses only `HistoryStore` protocol methods.
- History persistence remains behind `HistoryStore`: **verified** — backend is injected via `_default_history_store()`.
- Recorder does not alter scan-result semantics: **verified** — `record_scan` failure is caught and warned, never changes the `ScanResult` or exit code.

## 7. Validation State

```text
pytest:           179 passed, 2 skipped in 2.01s (uv run --extra test pytest)
ruff:             All checks passed!
mypy:             Success: no issues found in 29 source files
git diff --check: (no issues — no conflict markers or whitespace errors)
working tree:     clean / documented
```

All commands were actually executed on 2026-08-30.

## 8. Known / Deferred Items

### Item 1 — Metadata / profile snapshot size budgets

- **issue:** Each JSON column (`metadata_json`, `profile_snapshot`) is capped at 8 KB (`METADATA_MAX_BYTES`, `PROFILE_SNAPSHOT_MAX_BYTES`). Oversized payloads are deterministically truncated (largest values dropped first) and tagged with `__cg_history_truncated__`. Never raises.
- **current behavior:** Silent deterministic truncation; consumers can detect via the marker key.
- **reason deferred:** Intentional design per M4-A budgets (~8 KB per column, ~32 KB combined). Changing the budget is a design decision, not a bug.
- **planned review:** M4 FINAL AUDIT

### Item 2 — Test FakeRecorder return-type divergence

- **issue:** `tests/test_cli.py` `FakeRecorder.record_scan` is annotated `-> None`, while the `HistoryStore` protocol requires `-> HistoryRecord`.
- **current behavior:** Functionally harmless — the CLI ignores the return value of `record_scan`. The fake stores the record internally for `list_scans`/`get_scan`.
- **reason deferred:** Test-only artifact; does not affect production code or real backend.
- **planned review:** M4 FINAL AUDIT

### Item 3 — No aggregate statistics API

- **issue:** `HistoryStore` deliberately exposes no `get_statistics` method. The only aggregate is `count_scans(status=...)`.
- **current behavior:** Documented design boundary in the `HistoryStore` interface docstring. Full reporting requires listing records.
- **reason deferred:** Deliberate design choice to keep the store contract minimal and append-oriented.
- **planned review:** M4 FINAL AUDIT

## 9. Important Tomorrow TODO — Create Local Project Documentation

**This section is mandatory.**

Tomorrow, before continuing implementation, create two local project documents:

### A. Complete Implementation Roadmap

Create a persistent local Markdown roadmap containing the complete development map agreed in the project discussion.

It should include:

```text
M0
M0.5
F0
M1
M2
M3
M4-A
M4-B1
M4-B2
M4-B3
M4-B4
M4-B5
M4-B6
M4-B7
remaining M4-B milestones
M4 FINAL
M5
M6
M7
1.0
post-1.0 roadmap
```

For every completed milestone, record:

- objective;
- implementation status;
- important architectural decisions;
- relevant commit(s);
- validation status.

For pending milestones, record:

- objective;
- scope;
- dependencies;
- current status.

The roadmap must distinguish:

```text
COMPLETED
NEXT
PENDING
DEFERRED
```

### B. Complete Local Project Plan

Create a second Markdown document containing the broader **ClamGuardian project plan**.

This document should describe the project at a higher level than the implementation roadmap, including:

- project objectives;
- architectural direction;
- major components;
- milestone structure;
- development phases;
- security strategy;
- testing strategy;
- CI strategy;
- packaging/release strategy;
- post-1.0 evolution;
- boundaries deliberately deferred to later phases.

The purpose is to have a local **project map**, not merely a list of commits.

### Important

These two documents must be created **tomorrow together**, after reviewing the current repository and the development decisions established in the project discussion.

Do **not** create incomplete versions today merely to satisfy the handoff.

## 10. Tomorrow's Starting Procedure

Tomorrow:

```bash
git checkout feature
git status
git pull --ff-only
git rev-parse HEAD
```

Then read:

```text
docs/CLAMGUARD_HANDOFF.md
```

Before implementing the next M4-B milestone:

1. create the complete local implementation roadmap;
2. create the complete local project-plan document;
3. reconcile both documents with the actual repository state;
4. identify the next M4-B milestone;
5. continue implementation-first.

## 11. M4 Workflow Remains Unchanged

Do **not** perform the full M4 audit tomorrow merely because the handoff is being created.

The agreed sequence remains:

```text
M4-B7 DONE
    ↓
create local project documentation
    ↓
remaining M4-B implementation
    ↓
LAST M4-B
    ↓
M4 FINAL AUDIT
    ↓
P0 / P1 / P2 / P3 classification
    ↓
M4 FINAL FIX PASS if required
    ↓
full validation
    ↓
M4 FINAL REPORT
```

## 12. Rules for the Next Session

The next session must:

- start from the current `feature` HEAD;
- verify clean working tree;
- read this handoff;
- create the local roadmap and project-plan documents first;
- reconcile them with the actual repository;
- not redo M4-B1 → B7;
- continue with the next M4-B implementation milestone;
- not perform the M4 Final Audit prematurely;
- preserve the HistoryStore abstraction;
- preserve Core/Engine isolation from SQLite;
- run full validation;
- commit only when green;
- update the roadmap and handoff after the next milestone.

## 13. Do NOT Do

Do NOT:

- modify `testing`;
- rewrite/squash existing M4 history unnecessarily;
- redo completed M4 milestones;
- invent B8 functionality without establishing its scope;
- perform the M4 Final Audit prematurely;
- introduce unrelated refactoring;
- fix deferred P2/P3 issues opportunistically;
- introduce SQLite dependencies into Core/Engine;
- put SQL into CLI/presentation;
- create duplicate History abstractions;
- create the complete project roadmap today.
