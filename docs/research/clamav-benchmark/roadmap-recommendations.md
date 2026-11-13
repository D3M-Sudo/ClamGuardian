# Roadmap Recommendation Summary

## Purpose

Planning input for a later roadmap review. This report does not edit `docs/ROADMAP.md` or approve future milestones.

## Existing roadmap items — do not duplicate

The current roadmap already tracks:
- 2.x-A inotify event-driven monitoring, implemented on `feature`, with real-host validation pending.
- 2.x-B fanotify/clamonacc access-prevention evaluation, deferred.
- 2.x-C privileged service/IPC/Polkit, deferred and gated by concrete need.
- Desktop D4 and Flatpak restore validation, pending host evidence.
- Packaging/dependency maintenance.

Update these only when evidence or decisions change; do not create duplicates.

## Proposed additions or refinements

| Candidate | Priority | Suggested treatment |
|---|---|---|
| File-manager integration (Nemo-first) | P2 | New scoped feature milestone after API/design approval |
| Structured scan completeness | P2 | Core result contract + UI/CLI reporting |
| ClamD profile limitation visibility | P2 | Include in scan completeness work |
| FreshClam service/update conflict diagnostics | P2 | Operational reliability follow-up |
| ClamD explicit command framing review | P2 | Focused engine-hardening investigation |
| Persistent user-level scheduler | P2 | Evaluate before replacing/augmenting app-lifecycle scheduler |
| Realtime overflow reconciliation | P1 | Refine existing 2.x-A work; no duplicate milestone |
| Quarantine key custody/recovery | P1 | Threat-model and recoverability design gate |

## Suggested sequence

1. Complete existing host validation gates for desktop, Flatpak and realtime where maintainer environment is available.
2. Design structured scan completeness and backend limitation reporting.
3. Define file-manager request contract and Nemo MVP.
4. Validate Nemo MVP on a real Cinnamon session before generalizing adapters.
5. Evaluate FreshClam diagnostics and user-level systemd scheduling.
6. Keep fanotify prevention and privileged IPC as separate research/approval decisions.

## Acceptance criteria for future milestones

File-manager integration:
- One multi-selection request creates one scan session.
- All scan logic remains in Core/Engine.
- Path input is bounded and shell-safe.
- Progress, cancellation, result, history and quarantine match the existing GTK scan flow.
- Installer/uninstaller is idempotent and user-scoped.
- Flatpak gains no broad writable host permissions.
- Nemo is validated on real Cinnamon; other adapters are tested on their supported environments.

Scan completeness:
- Structured skipped-file and nonfatal-warning evidence.
- Complete/partial/unknown coverage semantics.
- Backend-specific unsupported profile options visible to users.
- Parser tests for clean, infected, skipped, warnings, all-skipped, timeout and truncated output.
- History retains coverage state.

No candidate above is approved by this report. The maintainer decides what to add, release target and dependencies in a later roadmap review.
