# UI/UX Independent Audit — GTK Database Pages & CLI (1.0 branch)

**Date:** 2026-10-18
**Scope:** static analysis of the UI/UX layer — `clamguardian/ui/` (633 lines)
and `clamguardian/cli/` (800 lines) — plus the directly wired backend surface
(`databases/manager.py` update flow, `history` store contract, `core/base.py`
`ScanResult`) and the CLI design doc (`docs/design/cli.md`).
**Method:** independent read-only review; no execution, no GTK runtime
(headless environment). Dynamic rendering/resizing issues are out of scope and
belong to `docs/validation/DESKTOP-TEST-1.0.md`.
**Baseline:** `feature` @ `db8f379`.

## Verdict

**No P1.** The layer is well structured (contracts honored, best-effort
history, clean cancellation). Found **2 × P2** (both in the GTK database
layer) and **4 × P3** (U-04 and U-06 touch the observable CLI contract and
were fixed right after this report). See `docs/ROADMAP.md`, Working Rules:
fixes are tracked below with file:line evidence.

| ID | Severity | Location | Finding | Status |
|---|---|---|---|---|
| U-01 | P2 | `ui/database_pages.py:278-286` | Toggle switches ignore the real manager state: `set_enabled`/`set_auto_update` run unguarded and the `state-set` handler always returns `False` (GTK applies the visual state). If the manager raises (e.g. `_persist()` → `OSError` on full disk), the switch stays visually on while the model is unchanged, and `schedule_refresh()` masks the error with a rebuild. Fix: `try/except`, show the error, return `True` (block the visual state) or restore the previous `set_active()`. | FIXED |
| U-02 | P2 | `ui/database_pages.py:265-268` + `408-413` | Duplicate error dialog on one failed update: the manager `status_callback` path (`_on_status` → `idle_add(_on_status_changed)` → `row.set_status(ERROR)` → `page.show_error`) and `on_update_finished` (which shows `AlertDialog("Update error")` when `error` is set) both fire for the same failure → two identical stacked modal dialogs. Fix: show the dialog in one place only (`on_update_finished`); `set_status` updates the label. | FIXED |
| U-03 | P3 | `ui/database_pages.py:361-387`, `397-406` | `rebuild_list()` destroys and recreates every row on each toggle/refresh: loses focus, and a row replaced mid-update is born with its update button **re-enabled** while the background task still runs (the asyncio lock in the manager keeps correctness; the UX shows inconsistent state). Fix: incremental refresh (update existing `set_active`/labels) or keep row controls disabled for the update duration. | OPEN — UX rework, deferred |
| U-04 | P3 | `cli/main.py:511-513` | Missing target maps to exit 3 instead of exit 2: `_cmd_scan` returns `EXIT_ENGINE_ERROR` when `_validate_target` fails, but a nonexistent path is a usage error (`docs/design/cli.md`: "2 = usage / CLI argument error"). Scripts distinguishing "wrong path" (2) from "engine failed" (3) misclassify. Fix: return `EXIT_USAGE` on validation failure. | FIXED |
| U-05 | P3 | `cli/output.py:115` | History table truncates targets to 30 chars (`…` + last 29) with no human-mode way to see the full path (only `--json` escapes). Deep similar paths render ambiguously. Fix: document `--json` for full paths or size to terminal width. | OPEN — minor, documented here |
| U-06 | P3 | `cli/main.py:269-275`, `292-298`, `332-338` | `history list/show/purge` catch only `HistoryError`, but the backend raises `ValueError` for invalid `--status` (`unknown status`, backend `list_scans`/`purge`/`count_scans`) and non-positive `--limit`: raw traceback on stderr + exit 1 instead of a clean message with exit 2. Fix: validate `--status` against `valid_statuses()` and `--limit > 0` up front, mapping failures to `EXIT_USAGE`. | FIXED |

## Verified healthy (no bug)

- `run_async`/`_invoke_idle` thread marshalling (`database_pages.py:47-93`).
- `ShieldTaskController` signal semantics (`controller.py:52-109`).
- Ctrl+C path: exit 5, coherent JSON payload, recorder closed in `finally`
  (`main.py:484-504`).
- `update()`/`update_enabled()` staging, backup and atomic rollback (M5).
- `_validate_target` strict resolution; TOCTOU accepted by M5-R4.
- Headless import safety (`ui/__init__.py`, `_GtkNotAvailable`).
- JSON contracts (`result_to_payload`, `cancelled_payload`,
  `history_record_to_payload`).

## Non-bug UX note (confirm at runtime)

`_on_update_all_clicked` (`database_pages.py:397-406`) toasts "All databases
updated" even when some sources failed (`update_enabled` swallows per-source
`DatabaseUpdateError` and returns no aggregate error). Suggest "N of M updated"
or "completed with N errors". If reproduced on desktop, file as P3.

## Fixes applied

U-01, U-02, U-04, U-06 fixed on `feature` in the commit following this report;
U-03 and U-05 left open as documented follow-ups. Verified after the fixes:
`ruff check .` clean, `mypy clamguardian` clean (29 files), full suite
**254 passed** (was 251: +3 new U-06 regression tests; the pre-existing
`test_missing_target_file` updated from exit 3 to exit 2 per U-04).
