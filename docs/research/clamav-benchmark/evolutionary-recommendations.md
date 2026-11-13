# Evolutionary Recommendations

## Principles

- Keep Python shared Core as the single scan orchestration layer.
- Keep GTK presentation separate from engine/persistence.
- Preserve unprivileged operation by default.
- Reuse ScanTaskRunner, profiles, history and result semantics.
- Make incomplete coverage visible; no detection is not proof all data was scanned.
- Keep host-owned ClamAV configuration and official database lifecycle external unless separately approved.

## CG-E01 — Realtime coverage-loss recovery (P1)

**Finding:** inotify overflow and dropped events are counted, but complete reconciliation of affected roots is not established.

**Historical proposal — SUPERSEDED:** the original research proposed a bounded recovery state machine with affected-root tracking and controlled traversal/rescan. This is retained as research history, not the accepted 2.x-A closure requirement.

**Current maintainer decision — CONSERVATIVE:** retain and expose kernel overflow and internal queue-saturation evidence; mark affected monitoring coverage degraded/uncertain; identify affected roots or intervals where possible; require an explicit user-initiated scan when automatic recovery cannot be proven safe and complete. Do not make automatic root reconciliation or rescanning a requirement for current 2.x-A closure. See `docs/ROADMAP.md`, workstream WS-RT-REC.

**Exit evidence:** deterministic tests proving event loss cannot be represented as full coverage; degraded-state persistence across relevant lifecycle transitions; repeated overflow, shutdown and restart behavior; actionable UI/diagnostics guidance for manual recovery. Record real-host evidence separately from CI. Automatic bounded traversal/rescan is not an acceptance criterion.

## CG-E02 — Quarantine key custody/recoverability (P1)

**Finding:** Secret Service preferred, 0600 local-key fallback; key and ciphertext may share user-data trust boundary.

**Proposal:** document attacker model, reinstall/recovery, keyring-unavailable/headless behavior, encrypted backup policy and data-loss warnings. Do not remove fallback before migration/recovery design.

**Exit evidence:** threat model, failure matrix, missing/corrupt key, keyring unavailable, backup/restore and reinstall tests.

## CG-E03 / CG-E04 — Existing validation gates (P1)

Realtime host validation and Flatpak restore/desktop validation are already in roadmap. Do not duplicate. Close only with recorded host evidence.

## CG-E05 — Scan completeness (P2)

ClamUI provides structured skipped-file and nonfatal-warning semantics. ClamGuardian has status/count/error/metadata, but frontends should communicate backend/profile limits and skipped coverage consistently.

**Proposal:** structured skipped count/reasons, warnings, effective backend, unsupported profile options and coverage state (complete/partial/unknown). Keep detection verdict separate. CLEAN with skipped items should say “no threats detected in scanned content; coverage incomplete”.

**Exit evidence:** clamscan/clamd parser fixtures; all-skipped, partial skipped, warnings without threats, threats plus skipped, output truncation and unknown counts.

## CG-E06 — Persistent unprivileged scheduling (P2)

Investigate per-user systemd timer/service invoking existing CLI/Core. No root daemon, setuid, Polkit or duplicate scan logic. Cron only if systemd unavailable and complexity justified.

Exit evidence: missed runs, duplicate prevention, logout/login, environment/PATH, Flatpak host execution and logs.

## CG-E07 — Packaging/dependency governance (P2 maintenance)

Keep manifest parity, offline wheelhouse validation, architecture coverage, permissions review, license inventory and SBOM. Add packaging check for desktop adapters; do not broaden Flatpak host write permissions.

## CG-E08 — Quarantine UX (P3)

Optional refinements only after key custody and restore semantics clear; preserve AES-GCM.

## CG-E09 — Additional engines/YARA (RESEARCH)

Research only. No dependency/model/engine without product requirement, licensing, false-positive and performance review.

## CG-E10 — fanotify/clamonacc (RESEARCH / DEFERRED)

Separate from inotify. Prevention requires privilege architecture, failure-mode analysis, performance tests, safe exclusions and explicit opt-in.

## CG-E11 — Privileged helper/Polkit (EXCLUDE)

No evidence justifies a root helper or privileged daemon for ordinary scans. Exclude absent a concrete need that existing user permissions/host ClamAV cannot meet.
