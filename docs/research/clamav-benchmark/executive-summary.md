# ClamGuardian — Comparative Benchmark and Integration Evolution

## Executive conclusion

At the pinned baselines, ClamGuardian is a Python/GTK4 application with shared core, direct ClamD protocol integration, encrypted quarantine, third-party database management and user-space inotify monitoring. ClamUI is a Rust headless core with Tauri/React shell, command-based ClamAV integration, Nautilus script, structured scan-completeness reporting and optional privileged On-Access integration.

There is no defensible overall winner. ClamGuardian's encrypted quarantine and descriptor-preserving realtime scans are meaningful strengths. ClamUI provides useful patterns for skipped-file reporting, file-manager entry points and persistent scheduling. Its privileged On-Access design is not directly transferable to ClamGuardian's unprivileged model.

## Highest-value findings

1. **File-manager integration is a product gap.** The pinned ClamGuardian desktop entry launches the app but declares no scan action; no Nemo/Nautilus/Dolphin/Caja/Thunar integration artifact was found. ClamUI includes a Nautilus script, but it is an adapter, not a shared integration framework.
2. **ClamGuardian's engine is more capable than the old benchmark wording implied.** It speaks the ClamD UNIX-socket protocol directly, supports FILDES with INSTREAM fallback for descriptor scans, bounds output/timeouts and does not silently fall back after an established daemon connection fails.
3. **Profile parity differs by backend.** Some semantic options are server-side clamd.conf settings and are surfaced as unsupported metadata; clamscan translates them to command-line options. UI should expose backend-dependent limitations.
4. **Scan completeness should be first-class.** ClamUI records skipped paths/counts and nonfatal warnings. ClamGuardian should ensure CLEAN is not mistaken for proof that every selected file was scanned.
5. **Do not replace ClamGuardian quarantine with ClamUI's model.** AES-256-GCM provides confidentiality and authenticated integrity; filesystem-hardening tests are useful inspiration but not an equivalent design.
6. **Do not adopt fanotify prevention in the current architecture.** clamonacc requires elevated permissions; prevention can affect performance and system availability.

## Priority recommendations

| Priority | Recommendation | Class |
|---|---|---|
| P1 | Conservative realtime coverage-loss handling; explicit manual scan when safe automatic recovery is uncertain | ACCEPTED DECISION — no automatic reconciliation requirement |
| P1 | Preserve descriptor-pinned realtime scanning; validate on real hosts | RETAIN / VALIDATION |
| P1 | Clarify quarantine key custody and recovery | INVESTIGATE |
| P2 | Structured scan completeness: skipped files, warnings, coverage | ADOPT SEMANTICS |
| P2 | Shared multi-path invocation contract and coordinated Nemo, Nautilus and Dolphin first delivery wave | ACCEPTED ROADMAP DIRECTION — adapter mechanisms remain desktop-specific |
| P2 | Unprivileged per-user systemd timer | INVESTIGATE |
| RESEARCH | fanotify/clamonacc as separately gated architecture | DEFER |
| EXCLUDE | Root helper, setuid, Polkit or privileged daemon for ordinary scans | EXCLUDE |

## Recommended file-manager direction

Use thin native adapters calling one ClamGuardian-owned entry point. Keep scanning, profiles, history, cancellation and result interpretation in existing Core/Engine/UI layers. Deliver Nemo, Nautilus and Dolphin together in the same first wave after the shared multi-path contract is ready; their adapter mechanisms and desktop-specific validation remain distinct. Nemo may be the first adapter exercised during development on Cinnamon, but that test order does not create a Nemo-only release phase. Caja and Thunar can follow as later candidates.

Preferred UX: one ClamGuardian window accepts multiple selected local paths, displays progress, supports cancellation and links detections to existing quarantine workflow. Adapter must not implement scanning or invoke ClamAV directly.

## No direct cherry-pick

No direct cherry-pick from ClamUI is justified or was performed. Rust/Tauri code is not a drop-in dependency for Python/GTK. Transfer concepts/tests only after design review. MIT/GPLv3 compatibility does not make unrelated code architecturally suitable.

## Limitations

No controlled throughput/CPU/RAM benchmark, no real-host end-to-end file-manager validation, no real-host fanotify/inotify validation, and no approval of new code, dependencies, permissions, packages or roadmap phases.

## Review finding and current disposition

The pathname ClamD parser defect is a **VERIFIED defect in the historical pinned baseline** `b42c01612d34ef20b980518aa9b3845f48ea4210`, not a finding about current `feature`. PR #45 fixed it with fail-closed response validation and regression tests (merge commit `c1da5c8974c8148ac60b23f507a5deec2816b52c`); PR #46 documented the remediation in the changelog (merge commit `a90463bd77a1f47f7c512fc6e4f5a0f92b9fb96b`). The detailed finding and immutable source anchors are retained as historical evidence in [ClamAV Integration Study](clamav-integration-study.md#8-p1-finding--pathname-clamd-response-can-be-classified-clean-without-a-valid-reply).
