# ClamGuardian Implementation Roadmap

*Last updated: 2026-11-12 — PR #18 and subsequent remediation/integration PRs are merged into `feature`. USB, VirusTotal, realtime monitoring, scheduled scans, autostart and scan-linked VirusTotal evidence are implemented on this branch. This is implementation status, not a claim of release promotion or real-host validation. VirusTotal Public API requests remain administratively blocked pending written eligibility authorization. PR #30 (final feature hardening) was merged into this branch on 2026-11-12. Future versions are planning targets, not promised releases or dates.*

This document outlines the authoritative development roadmap for ClamGuardian, tracking completed milestones, in-progress targets, and future architectural phases.

---

## Roadmap Overview

![ClamGuardian production roadmap](ROADMAP-PRODUCTION.svg)

```
M0 → M0.5 → F0 → M1 → M2 → M3 → M4-A → M4-B (B1..B7) [COMPLETED]
    ↓
Phase 1: M4 Profile Propagation [COMPLETED]
Phase 2: M4 Content Hashing [COMPLETED]
Phase 3: M4 Security Test Gap Closure [COMPLETED]
Phase 4: M4 Finalization & Report [COMPLETED]
    ↓
Phase 5: M5 Security Hardening [COMPLETED]
Phase 6: M5 P2 Evaluation [COMPLETED]
Phase 7: M6 CI & Quality Gates [COMPLETED]
Phase 8: M7 Packaging [COMPLETED]
Phase 9: 1.0 Release Gate [COMPLETED 2026-10-16 — tag v1.0.0 @ 8ee8a56, installable Flatpak bundle]
    ↓
1.0.x: Stabilization [v1.0.1 PUBLISHED 2026-10-24; manual D4 evidence not retained in repository]
    ↓
Desktop Application (GTK4/Libadwaita) [D1..D4 IMPLEMENTED 2026-10-19 on `feature` — manual desktop validation pending]
    ↓
Phase 10: 1.1 USB Auto-Scan [IMPLEMENTED ON feature — host validation / release promotion remain separate]
Phase 11: Threat Intelligence Integration [IMPLEMENTED — Public API use administratively gated; Premium entitlement required]
Phase 12: 2.x-A Event-Driven Monitoring [IMPLEMENTED ON feature — host validation / release promotion remain separate]
Phase 13: Shared scan enrichment + scan-linked VT evidence [IMPLEMENTED — PRs #25, #28, #29]
    ↓
2.x-B / 2.x-C [DEFERRED]
```

---

## Release Status Summary

Future versions are planning targets, not implemented releases or promised dates.

| Status | Milestone | Exit criterion |
|---|---|---|
| **Completed** | `v1.0.0` | Green release gate, bundle produced, promotions documented |
| **Published** | `v1.0.1` | GitHub Release published 2026-10-24 from tag `v1.0.1` (`32c9ca6`); Flatpak asset attached. The checked-in D4 session record remains PENDING, so the repository does not retain the manual-validation evidence cited by the release description (`reports/RELEASE-1.0.1.md`, `validation/DESKTOP-TEST-D4-2026-10-19.md`). |
| **Implemented** | Desktop App — Phases D1 + D2 + D3 + D4 | Foundations + diagnostics, Scan page, History, Quarantine, Databases, Diagnostics and Settings; window chrome, About, opt-in notifications, accent stylesheet, default-profile settings, quarantine ingest from scan results — committed on `feature`, CI smoke covers every page |
| **Evidence follow-up** | D4 desktop / Flatpak restore record | The published release description says D4 validation preceded the tag, but the checked-in D4 record remains PENDING and the Flatpak restore checklist has no recorded result. Recover and archive original host evidence if available; otherwise retain these as undocumented/unverified host checks. |
| **Implemented / validation pending** | `v1.1.0` | USB mount identity checks, lifecycle cancellation and CLI/GTK integration are present on `feature`; record real-host validation before promotion. |
| **Implemented / policy-gated** | `v1.2.0` | Public/Premium profiles, Secret Service, hash lookup, consent-gated file upload and persisted scan-linked evidence are implemented. Public API calls remain blocked pending written eligibility authorization; Premium requires entitlement. |
| **Implemented / host validation pending** | `v2.0.0` | Realtime inotify monitoring, bounded orchestration, descriptor-based scanning, lifecycle integration and final feature hardening (PR #30) are integrated on `feature`; real-host validation remains a separate evidence gate. |
| **2.x extension** | `v2.1.x` | `fanotify`/`clamonacc` access-prevention evaluation, privileges and threat model |
| **2.x extension** | `v2.2.x` | Privileged service/IPC/Polkit only if justified by a use case |

---

## Completed Milestones

### M0: Repository Initialization
- **Objective:** Establish Python project structure, packaging layout, license, and initial CI setup.
- **Status:** COMPLETED

### M0.5: ClamAV Engine Abstraction
- **Objective:** Implement `BaseAVEngine` interface and `ClamAVEngine` supporting hybrid clamd UNIX socket execution with `clamscan` fallback.
- **Status:** COMPLETED

### F0: Architecture Freeze v1
- **Objective:** Freeze foundational architecture: Core owns scan models, Engine owns ClamAV execution, History owns persistence, UI owns GTK presentation.
- **Status:** COMPLETED

### M1: Asynchronous ScanTaskRunner & Cancellation
- **Objective:** Implement bounded concurrency, queueing, process-group SIGTERM/SIGKILL termination, and cancellation.
- **Status:** COMPLETED

### M2: Profile Infrastructure & Preset Models
- **Objective:** Implement `ScanProfile` model, preset registry (`quick`, `home`, `full`, `custom`), validation, and engine translation.
- **Status:** COMPLETED

### M3: Subprocess Security & Flatpak Host Execution
- **Objective:** Implement safe subprocess execution, arguments translation, process-group isolation, and `flatpak-spawn --host` support.
- **Status:** COMPLETED

### M4-A: History Schema Design & Budgets
- **Objective:** Define history persistence schema v1, budget caps (~8 KiB JSON columns), and data models.
- **Status:** COMPLETED

### M4-B1 → M4-B7: SQLite History Persistence & Subcommands
- **Objective:** Implement `HistoryStore` protocol, `SqliteHistoryStore` backend (WAL, foreign keys, `0o700` dir permissions), CLI subcommands (`history list`, `history show`, `history purge`), and background recording.
- **Status:** COMPLETED

---

## Active & Pending Roadmap Phases

### Phase 1: M4 Profile-Aware History Propagation
- **Status:** COMPLETED
- **Scope:** Ensure scan profile information (`profile_id`, `profile_snapshot`) flows deterministically from Scan Request → ScanProfile → ScanTaskRunner → Engine → ScanResult → History.
- **Dependencies:** M4-B history layer.
- **Evidence:** `docs/reports/M4-FINAL-REPORT.md` (fixes `81ea321`, `88a57a6`).

### Phase 2: M4 Content Hash Model
- **Status:** COMPLETED
- **Scope:** Compute SHA-256 for single-file scan artifacts (`sha256=<digest>`); set `sha256=None` for directory scans.
- **Dependencies:** Phase 1.
- **Evidence:** `docs/reports/M4-FINAL-REPORT.md`; digest now recorded on both engine backends.

### Phase 3: M4 Security Test Gap Closure
- **Status:** COMPLETED
- **Scope:** Audit and add comprehensive tests for Quarantine (ciphertext, corrupted auth, path traversal, TOCTOU), Database updates (checksum mismatch, rollback), Engine (Flatpak host execution), and Filesystem (special files, symlinks, FIFOs, sockets, devices).
- **Dependencies:** Phase 2.
- **Evidence:** `docs/reports/M4-FINAL-REPORT.md`; provider-level digest enforcement tests added. Database digest optionality is an M5 item (see report, section 5).

### Phase 4: M4 Finalization & Report
- **Status:** COMPLETED
- **Scope:** Verify Core/Engine/History boundary isolation, run full quality gates, produce M4 Report.
- **Dependencies:** Phase 3.
- **Evidence:** `docs/reports/M4-FINAL-REPORT.md`; boundaries verified, quality gates green (203 passed / 2 skipped, ruff, mypy on 26 source files).

### Phase 5 & 6: M5 Security Hardening & P2 Evaluation
- **Status:** COMPLETED
- **Scope:** Quarantine streaming/chunked AES-256-GCM encryption, database download integrity, explicit scan target validation (handling special files/symlinks), host execution hardening, intelligence trust boundaries, P2 evaluation.
- **Dependencies:** Phase 4.
- **Evidence:** `docs/reports/M5-HARDENING-REPORT.md`; fixes `3394f86`, `192695c`, `d1a5cb3`, `b21e320`.

### Phase 7: M6 CI & Quality Gates
- **Status:** COMPLETED
- **Scope:** Integrate `mypy` and `pip-audit` into GitHub Actions CI pipeline.
- **Dependencies:** Phase 5 & 6.
- **Evidence:** `docs/reports/M6-CI-GATE-REPORT.md`; dedicated `audit` job on the pinned lockfile (`uv lock --check` + `pip-audit --strict -r`), `test` job on Python 3.11/3.12/3.13. **Closed by execution:** CI run `38493461942` on `9832b4d` — `audit` job green (`pip-audit --strict`: "No known vulnerabilities found"), `test` green on 3.11/3.12/3.13 (247 tests each).

### Phase 8 & 9: M7 Packaging & 1.0 Release Gate
- **Status:** COMPLETED (both) — 2026-10-16
- **Scope:** Desktop metadata, icon, Flatpak manifest, 1.0 release readiness audit & gate.
- **Dependencies:** Phase 7.
- **Evidence:** `docs/reports/M7-PACKAGING-REPORT.md`; `tests/test_packaging.py` (16 tests); wheel built, installed and run end to end; Release Gate CI (`.github/workflows/release-gate.yml`) — 7 jobs on the final tag run `38977065253` (`v1.0.0` @ `8ee8a56`; an earlier green tag run `38975655153` validated `745e1e7`): preflight, GNOME 51 offline Flatpak build (local manifest), AppStream validation, real ClamAV (clamscan + clamd, clean + EICAR), GTK smoke, release-manifest build pinned to the tag, and gate summary — all green. Deliverable: `ClamGuardian-v1.0.0-linux-x86_64.flatpak` (installable bundle, ~4.7 MB). The first tag run failed on a `cffi` cp312 wheel left in the release manifest only (404 on first-ever download of those sources); the fix (`cffi` cp314 in both manifests) shipped in `745e1e7` with two guard tests (manifest parity + runtime platform tags), then the tag was re-pointed to the fixed commit and finally to the release docs commit `8ee8a56`, each position re-validated by a green tag run.
- The checklist, the per-gate evidence and the procedure for each gate live in **`docs/reports/RELEASE-GATE-1.0.md`**.

### 1.0.x: Post-Release Evidence & Maintenance
- **Release status:** `v1.0.1` was published on 2026-10-24. Release engineering and publication are complete; the checks below are post-release evidence follow-ups, not prerequisites for publishing that tag.
- **M1 — Documentation realignment:** **COMPLETED.** The production roadmap, release-gate records and packaging references were reconciled through the repository's documented branch workflow. The historical comparison with `origin/main` and tag `v1.0.0` is retained in the earlier project record; it is not an active task.
- **M2 — Real-desktop validation evidence:** **PENDING — maintainer host required.** The CI GTK smoke test runs under Xvfb and does not establish real-desktop behaviour. Execute `docs/validation/DESKTOP-TEST-D4-2026-10-19.md` (14 steps) where applicable, verify Flatpak launch, GTK pages, host ClamAV access, controlled clean/EICAR scans, results/history and database update, then archive explicit PASS/FAIL outcomes. The D4 session record currently remains PENDING; do not infer successful host validation from CI or from the published release description.
- **M2 goal:** retain reproducible host evidence with the tested environment and outcomes. Test template: `docs/validation/DESKTOP-TEST-1.0.md`.
- **M3 — Quarantine restore verification in Flatpak:** **PENDING — maintainer host required.** Verify restore destinations from the installed sandboxed application; `--filesystem=host:ro` may restrict writes. Define the supported destinations from observed behaviour and, only if necessary, evaluate a file portal or narrowly scoped writable permissions. Do not broaden Flatpak permissions indiscriminately.
- **M3 goal:** document verified restore behaviour without weakening the sandbox unnecessarily. The Flatpak restore checklist currently has no recorded result.
- **M4 — Dependency and manifest maintenance:** ongoing maintenance of CI, lockfile and offline manifests; handle concrete drift or failures through the normal reviewed workflow.
- **Future promotion testing:** for a future `feature → testing` promotion, the Release Gate workflow's `flatpak-local` job uploads an installable test bundle (`ClamGuardian-testing-linux-x86_64.flatpak`, 14-day retention). Install and exercise it on the host per `docs/validation/DESKTOP-TEST-1.0.md` before merging the promotion PR, so `testing` is validated before further promotion or a new tag.
- **Gate:** no critical regressions; tests, audit and packaging green. Ship a patch only if actual fixes are needed.
- **Dependencies:** 1.0 Release Gate.

### Desktop Application (GTK4/Libadwaita)

- **Status:** IMPLEMENTED on `feature`: Phases D1–D4 delivered the GTK4/Libadwaita application and all six primary pages (Scan, History, Quarantine, Databases, Diagnostics, Settings), with About, notifications, theme and quarantine ingest. The 2026-10-19 D4 session record remains a pending manual-validation artifact; automated GTK smoke is not a substitute for real-host testing. The original design/implementation handoff is historical: `project/HANDOFF-2026-10-18-DESKTOP-UI.md`.
- **Historical context:** this phase originally began when the repository lacked the GTK application shell. That statement described the 2026-10-18 baseline and is no longer a description of the current branch.
- **Phase D1 — Foundations + Diagnostics:** **IMPLEMENTED 2026-10-18 (`4a37241`)** — headless `core/diagnostics.py` (`run_dependency_checks()` with per-distro remedies, Flatpak-aware binary lookup), CLI `clamguardian doctor [--json]` (exit 6 on critical gaps) + `clamguardian ui`, `Adw.Application` shell with `NavigationSplitView` sidebar (Scan/History/Quarantine placeholders until D2/D3, Databases embedded, Diagnostics real), Diagnostics page (status banner + per-component expanders with per-distro install guides + Recheck), startup auto-dialog when critical dependencies are missing, `.desktop` fixed to `Exec=clamguardian ui`, release-gate GTK smoke extended to app shell + diagnostics page. Local evidence: ruff + mypy green, 279 passed / 2 skipped, live validation on the desktop (healthy path + missing-dependency dialog path). Remaining for closure: CI smoke on the next gate run + maintainer click-through.
- **Phase D2 — Scan page:** **IMPLEMENTED 2026-10-18 (`26abf34`)** — target chooser (folder/file/home), profile dropdown, Scan/Cancel buttons, in-flight state (timer + threat counter), cancel, result cards (clean / infected with per-threat `ActionRow` list / error / cancelled), history recording via `record_scan`; integrated into `MainWindow` shell and the GTK smoke job in `.github/workflows/release-gate.yml`. Gate green (ruff/mypy/pytest).
- **Phase D3 — History + Quarantine pages:** **IMPLEMENTED 2026-10-18 (`5dbd74c`)** — `ui/history_page.py` with status-filter list and limit, detail dialog, purge with `AlertDialog` confirmation; `ui/quarantine_page.py` with entry list, restore (destination dialog) and delete with confirmation; key management via Secret Service with `0600` file fallback in app-data. Tests `tests/test_history_page.py` + `tests/test_quarantine_page.py`. Gate green (ruff/mypy/pytest).
- **Phase D4 — Polish:** implemented accent stylesheet, About dialog, optional content-free desktop notifications, persisted default-profile/theme settings, window chrome, quarantine ingest and expanded GTK smoke coverage. See the historical implementation handoff for original details.
- **Gate per phase:** ruff + mypy + pytest green, CI smoke green, commit to `feature`; commits/pushes per the standing authorization rule.
- **Exit criterion:** installable Flatpak presenting all five pages, diagnostics dialog blocking-on-missing-dependencies at first run, desktop validation recorded.

### Phase 10: 1.1 USB Auto-Scan
- **Status:** IMPLEMENTED on `feature`; real-host behaviour remains a separate validation item.
- **Scope:** Require an actual mount point beneath configured roots; track/cancel auto-scan tasks on unmount and shutdown; validate service lifecycle.
- **Integration:** GTK background service runtime starts the USB monitor when enabled and shares the application runner/history store; CLI configuration remains available.
- **Evidence:** `clamguardian/core/usb.py`, `tests/test_usb.py`, CLI `usb` command group and GTK Settings integration. PR #18 was merged; later fixes are reflected in the current branch.

### Phase 11: Threat Intelligence Integration
- **Status:** IMPLEMENTED on `feature`; Public API network access remains administratively blocked pending written eligibility authorization. Premium requires a valid entitlement.
- **Scope:** Keep hash-only VirusTotal v3 integration opt-in; enforce a 15.1-second minimum interval; cache one provider per service lifetime; require Secret Service D-Bus availability; keep outbound lookups disabled behind `VIRUSTOTAL_TERMS_ELIGIBILITY_CONFIRMED=False` until the terms review is completed.
- **Integration:** Scan-result enrichment uses `ThreatIntelligenceService`; CLI enforces `intelligence_enabled` and provides hidden-input `intel set-key`. Remote intelligence remains supplemental metadata and never changes the local ClamAV verdict.
- **Evidence:** `clamguardian/intelligence/`, `docs/design/threat-intelligence.md`, `docs/security/virustotal-evidence-storage.md`, `tests/test_intelligence.py`, `tests/test_enrichment_flows.py` and `tests/test_history.py`; merged implementation includes shared enrichment and persisted scan-linked evidence. No claim of legal/terms compliance is made.

### Phase 12: 2.x-A Event-Driven Monitoring
- **Status:** IMPLEMENTED and final feature hardening integrated on `feature` (PR #30); real-host validation remains pending.
- **Scope:** Preserve queue invariants and debounce/coalescing behavior; recreate the orchestrator on restart; fail startup on missing/inaccessible watches; expose watch-registration failures and retain overflow/drop counters.
- **Integration:** GTK background runtime starts/stops the monitor and applies path changes; runtime shares the app runner/history store.
- **Evidence:** `clamguardian/realtime/`, `clamguardian/core/runner.py`, descriptor-based engine transport, `docs/security/realtime-filesystem-boundary.md`, `tests/test_realtime.py` and `tests/test_enrichment_flows.py`. PRs #18, #23, #25, #27 and #29 provide the implementation/remediation history.

---

## Deferred Phases (Out of Scope for 2.x-A)

### 2.x-B: Access Prevention (fanotify / clamonacc)
- **Status:** DEFERRED
- **Reason:** Requires architectural review of root privileges / on-access blocking.
- **Milestones:** privilege threat model and architecture; `fanotify`/`clamonacc` evaluation, fail-open/fail-closed and recovery; compatibility, blocking and degradation tests.
- **Exit criterion:** on-access feature only with security boundaries and a dedicated gate; subordinate to 2.0 stability.
- **Dependencies:** v2.0.0.

### 2.x-C: Privileged IPC Service / Daemon / Polkit
- **Status:** DEFERRED
- **Reason:** Requires separate system security architecture decision.
- **Milestones:** separate architectural decision; minimal IPC API, authentication/authorization, input validation and abuse testing; verify whether the existing one-shot execution is insufficient.
- **Exit criterion:** introduce daemon/Polkit only if the use case justifies the added cost and risk.
- **Dependencies:** v2.0.0 stability; v2.1.x where applicable.

---

## Recommended Work Order

1. **Host validation on `feature`:** complete and record the real-desktop checks for the GTK application, Flatpak quarantine restore, USB mount/unmount lifecycle and realtime watch/event behaviour. CI smoke tests do not replace these host-side checks. Use `docs/validation/DESKTOP-TEST-1.0.md` and the relevant subsystem checklists; preserve explicit PASS/FAIL evidence.
2. **VirusTotal policy gate:** keep Public API requests disabled until written eligibility authorization is recorded. Enable no Public network path merely because the implementation is present. Premium use remains conditional on valid entitlement.
3. **Release promotion:** when host validation and the applicable release criteria are satisfied, promote the intended `feature` snapshot through `testing` → `development` → `main` using separate reviewed PRs and the release gate. Do not treat implementation on `feature` as a published release.
4. **2.x-B evaluation:** assess `fanotify` / `clamonacc` access prevention only after 2.x-A stability evidence and a dedicated privilege/threat-model review.
5. **2.x-C decision:** consider privileged IPC / Polkit only if a concrete use case justifies the added attack surface; otherwise keep it deferred.

`v1.0.1` is already published (2026-10-24). USB Auto-Scan, Threat Intelligence integration, realtime monitoring and scan-linked VirusTotal evidence are implemented on `feature`; their implementation status does not imply release promotion, host validation, or permission to use policy-gated external APIs. This order keeps the project sustainable for a single maintainer and avoids prematurely turning ClamGuardian into an overly broad EDR.

## Working Rules

- Verify branch, SHAs, working tree, remotes and CI before every task.
- No automatic commit, push, merge, tag or PR without explicit authorization.
- Never rewrite the `v1.0.0` tag; no destructive resets or operations overwriting local changes.
- Stop if the baseline is unexpected or a command fails.
- Every milestone needs a measurable goal, reproducible tests, evidence, known limits and an exit criterion.
- Code not wired to a real call site and not covered by the gate is not a completed feature.
- No fictitious dates for future releases: ship when the gate is green.
- Branch policy (rulesets, 2026-10-19): `main` is governed only by the `main-protection`
  ruleset (id `25427935`, enforcement `active`, target `refs/heads/main`); classic branch
  protection on `main` was removed to avoid double enforcement. Rules: PR required before
  merging with `required_approving_review_count: 0` (solo-maintainer: no self-approval
  deadlock), `required_review_thread_resolution: true`, `deletion` + `non_fast_forward`
  blocked, `bypass_actors: []` (nobody bypasses). No `required_status_checks` pinned yet —
  add CI checks to the ruleset only after validating exact check names + integration_id.
  Promotion flow: `feature` (unprotected) → PR → `testing`/`development` (count 0) → PR →
  `main` (ruleset).
