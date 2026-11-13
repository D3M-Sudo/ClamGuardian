# Roadmap Recommendation Summary

## Purpose and disposition

This document records the benchmark research recommendations and their disposition in the authoritative `docs/ROADMAP.md` revision dated 2026-11-13. It is no longer prospective input for a later roadmap review. The dispositions below distinguish accepted roadmap direction from modified or deferred research proposals; they do not authorize implementation, dependencies, permissions, packaging or release promotion.

## Existing roadmap items — do not duplicate

The roadmap tracks:
- 2.x-A inotify event-driven monitoring, implemented on `feature`, with real-host validation pending.
- Conservative realtime coverage-loss handling: expose degraded/uncertain coverage and require an explicit user-initiated scan when safe automatic recovery cannot be proven. The earlier bounded automatic reconciliation/rescan proposal is superseded and is not a 2.x-A closure requirement.
- 2.x-B fanotify/clamonacc access-prevention evaluation, deferred.
- 2.x-C privileged service/IPC/Polkit, deferred and gated by concrete need.
- Desktop D4 and Flatpak restore validation, pending host evidence.
- Packaging/dependency maintenance.

Update these only when evidence or maintainer decisions change; do not create duplicates.

## Recommendation disposition

| Candidate | Priority | Current disposition |
|---|---|---|
| Shared file-manager request contract and Nemo, Nautilus, Dolphin first wave | P2 | ACCEPTED ROADMAP DIRECTION; coordinated delivery phase, desktop-specific adapters and validation |
| Structured scan completeness | P2 | RETAINED PLANNED WORKSTREAM; complete/partial/unknown coverage semantics |
| ClamD profile limitation visibility | P2 | RETAINED within scan-completeness work |
| FreshClam service/update conflict diagnostics | P2 | RETAINED investigation; ClamGuardian must not take ownership of host service lifecycle |
| ClamD explicit command framing review | P2 | RETAINED focused engine investigation |
| Persistent user-level scheduler | P2 | RETAINED; evaluate after current scheduler reliability contract |
| Realtime overflow reconciliation | P1 | SUPERSEDED by conservative coverage-loss decision; automatic traversal/rescan not required |
| Quarantine key custody/recovery | P1 | RETAINED security design gate; no key-custody change approved |
| fanotify/clamonacc and privileged IPC | RESEARCH | DEFERRED; separate architecture and threat-model decisions |

## Current recommended sequence

1. Close existing host-validation gates for desktop, Flatpak and realtime when maintainer environment is available.
2. Define structured scan completeness and backend limitation reporting.
3. Complete the shared multi-path request contract.
4. Deliver Nemo, Nautilus and Dolphin together in the first file-manager wave; Nemo may be the first Cinnamon test target, not a separate earlier delivery.
5. Evaluate FreshClam diagnostics and persistent user-level scheduling after the scheduler reliability contract.
6. Keep fanotify prevention and privileged IPC as separate research/approval decisions.

## Acceptance criteria retained for planned work

File-manager integration:
- One multi-selection request creates one scan session.
- All scan logic remains in Core/Engine.
- Path input is bounded and shell-safe.
- Progress, cancellation, result, history and quarantine match the existing GTK scan flow.
- Installer/uninstaller is idempotent and user-scoped.
- Flatpak gains no broad writable host permissions.
- Nemo, Nautilus and Dolphin are each tested on their supported desktop environments; shared request semantics do not substitute for adapter-specific host validation.

Scan completeness:
- Structured skipped-file and nonfatal-warning evidence.
- Complete/partial/unknown coverage semantics.
- Backend-specific unsupported profile options visible to users.
- Parser tests for clean, infected, skipped, warnings, all-skipped, timeout and truncated output.
- History retains coverage state.

These dispositions describe planning and research status only. Implementation and release assignment remain subject to separate maintainer authorization and the roadmap's stated gates.
