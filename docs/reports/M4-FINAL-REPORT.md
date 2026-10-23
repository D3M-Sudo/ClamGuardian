# M4 Final Report — History, profiles, content hash, boundaries

**Date:** 2026-10-13
**Branch:** `fix/pr5-audit-remediation` (remediation of PR #5, base `feature`)
**Baseline under audit:** `3bf087316f683bac012ffcd370a8b3ffd149c951` (PR #5 head)
**Fixes for this gate:** `81ea321` (profile propagation + clamd digest), `88a57a6` (best-effort observability)
**Independent audit that produced the findings:** read-only audit of PR #5 (report archived under the annotated tag `audit/pr5-2026-10-12`)

---

## 1. Gate criteria and verdict

M4 Final is the sequence of Phases 1-4 of `../ROADMAP.md`: profile-aware history
propagation, the content-hash model, the security test gap closure, and boundary
isolation + quality gates + report.

| Criterion | Verdict | Evidence |
|---|---|---|
| Phase 1 — deterministic `profile_id` + `profile_snapshot` propagation | **MET** | `core/profiles.py` `resolve_profile()`; `history/models.py:191-199`; engine annotates both backends (`engines/clamav.py` `_annotate_profile`/`_finalize`). Tests: `tests/test_history.py::test_record_from_scan_resolves_engine_default_profile`, `::test_unregistered_profile_id_is_not_persisted_raw`, `::test_record_scan_persists_profile_and_snapshot` |
| Phase 2 — SHA-256 for single-file scans, `None` for directories | **MET** | `engines/clamav.py::_finalize` is now on the clamd path too (it was only on the `clamscan` fallback). Tests: `tests/test_engine.py::test_clamd_branch_records_single_file_sha256`, `::test_clamd_branch_has_no_sha256_for_directories`, `::test_engine_single_file_sha256_metadata` |
| Phase 3 — security test gap closure (quarantine, databases, engine, filesystem) | **MET** | Quarantine: `tests/test_quarantine.py` (wrong key, corrupted ciphertext, corrupted AAD/metadata, `item_id` traversal, missing item, TOCTOU, non-AES256 key). Databases: `tests/test_databases.py::test_verify_sha256_checksum_mismatch` plus new provider-level enforcement tests. Engine/filesystem: `tests/test_engine.py::test_special_filesystem_objects_handling`, `::test_engine_flatpak_host_command_construction` |
| Phase 4 — boundary isolation, quality gates, report | **MET** | See sections 2 and 3; this document is the report |

**Verdict: M4 Final is closed on the branch above.** Residual items that belong to
later milestones are listed in section 5 and are explicitly *not* part of this gate.

---

## 2. Boundary isolation (Architecture Freeze v1)

| Invariant | Check | Result |
|---|---|---|
| SQLite confined to the History backend | `grep -rn "import sqlite3" clamguardian` | only `history/backend.py:13` |
| Profile → ClamAV argument translation only in the engine | `grep -rn "_clamscan_args\|--scan-archive" clamguardian` | only `engines/clamav.py` |
| Core must not import History at runtime | `grep -rn "history" clamguardian/core/` | no match: Core has no dependency on the History layer at all |
| No circular imports | import of every package in isolation | clean |
| Front-ends never build engine arguments | `cli/main.py`, `ui/*` | no ClamAV flags outside the engine |

---

## 3. Quality gates on the audited commit

Environment: Python 3.11.2, pytest 9.1.1, ruff/mypy from the same virtualenv.

```text
pytest -q        203 passed, 2 skipped in 2.01s
ruff check .     All checks passed!
mypy clamguardian  Success: no issues found in 26 source files
```

The 2 skips are environmental and expected: PyGObject/GTK is not installed in
the headless test environment (`tests/test_core_models.py:187`,
`tests/test_ui_databases.py:190`).

Baseline for comparison: at PR #5 head the suite was `213 passed, 2 skipped` over
36 source files. This branch adds 11 tests and removes the 23 tests that belonged
to the modules deferred out of 1.0 (section 7), hence 203 passed over 26 source files.

---

## 4. Defects fixed by this work package

| ID (audit) | Defect | Fix |
|---|---|---|
| `P1-ENG-01` | SHA-256 computed only on the `clamscan` fallback: on a host with a running clamd no single-file scan carried `metadata["sha256"]`, so the threat-intelligence seam had no digest | both backends go through `ClamAVEngine._finalize()`; a timed-out scan records the applied profile but no digest |
| `P2-HIST-02` | `DEFAULT_PROFILE` (id `"default"`) was not resolvable, so a scan run with the engine default stored `profile_id` without any `profile_snapshot` | `resolve_profile()` knows the engine default as well as the registry presets |
| `P2-HIST-01` | an unvalidated `profile_id` taken from `result.metadata` was persisted verbatim (and was filterable through `list_scans`) | an id matching no known profile now degrades to `None` |
| `P3-HIST-03` | `contextlib.suppress(Exception)` around `record_scan` and the completion callback made persistence failures completely invisible | the two call sites were fixed in `88a57a6`; they live in the deferred modules, so the fix travels with them (section 7) and is not part of the 1.0 artifact |

Each fix has a test that was written first and observed to fail against the
pre-fix code (for WP-1.3 the two production files were temporarily stashed to
record the red run).

---

## 5. Residual items — explicitly outside M4 Final

These were found by the same independent audit and are tracked by their own work
package; none of them blocks this gate.

| ID (audit) | Item | Owner |
|---|---|---|
| `P1-DB-01` | `DatabaseArtifact.sha256` is optional, so an artifact without a digest is installed with no integrity check | WP-2 (M5) |
| `P2-TGT-01` | no explicit rejection of special targets (FIFO/socket/device) before scanning | WP-2 (M5) |
| `P2-QRN-01` | quarantine reads the whole file into memory (no streaming/chunked encryption) | WP-2 (M5) |
| `P2-DBG-02` | UI calls `DatabaseManager.update_all()`, which does not exist | WP-2 (M5) |
| `P3-DBG-03` | rollback is not atomic per artifact in `DatabaseManager.update` | WP-2 (M5) |
| `P3-ENG-02` | the `FOUND` detection parser can flag a clean path containing `" FOUND"` | WP-2 (M5) |
| `P3-SHA-TOCTOU` | the digest is computed after the scan by re-resolving the path | WP-2 (M5) |
| `P1-RT-*`, `P2-RT-*` | realtime orchestrator/inotify defects (duplicate dispatch, queue bound, shutdown, stale watches, silent overflow) | not applicable to this branch: `clamguardian/realtime/` was removed (section 7); owner WP-5 (2.x-A) |
| `P2-USB-01` | USB scan does not validate a removable mount and has no call site | not applicable to this branch: `core/usb.py` was removed (section 7); owner WP-6 (1.1) |

---

## 6. How to reproduce

```bash
# full gate on this branch
python -m pytest -q
ruff check .
mypy clamguardian

# the fixes of this work package
git log --oneline 3bf0873..HEAD
```

---

## 7. Scope split applied to this branch (decision D5 / option B)

The 1.0 branch deliberately does not contain the phases that are out of its
perimeter. The following were removed in the same series of changes, together
with their tests:

| Removed | Reason | Where it lives now |
|---|---|---|
| `clamguardian/realtime/` (+ `tests/test_realtime.py`) | unwired, and still carries open P1 defects that need their own gate | git history — reachable from the annotated tag `audit/pr5-2026-10-12`; returns as WP-5 (2.x-A) |
| `clamguardian/core/usb.py` (+ `tests/test_usb.py`) | unwired: no CLI/UI call site | git history — reachable from the annotated tag `audit/pr5-2026-10-12`; returns as WP-6 (1.1) |
| `tests/test_intelligence.py` | tests for the unwired threat-intelligence providers | git history — reachable from the annotated tag `audit/pr5-2026-10-12`; returns with Phase 11 |
| `docs/design/2.x-A-realtime-remediation-design.md` | documents the removed subsystem and describes already-fixed defects as open | travels with the realtime module |
| `inotify-simple` runtime dependency (`pyproject.toml`, `uv.lock`) | used only by the removed realtime package | returns with WP-5 |

The Core extension seam `BaseThreatProvider` (`core/base.py`) is intentionally
kept: it is an abstract contract, not an implementation, and it is part of the
Architecture Freeze v1 provider boundary.

The `clamguardian/intelligence/` **package** itself is *not* removed: it predates
PR #5 (it is present on `feature` since the initial commit) and is kept on the 1.0
branch **unwired** — nothing in the CLI or UI imports it, and no distribution
declares the `clamguardian.threat_providers` entry-point group it looks for. Only
its tests were deferred. Deleting the package would have removed pre-existing code
from the base branch, which is outside the scope of this remediation.
