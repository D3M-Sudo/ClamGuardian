# Decisions Register

Research recommendations only; this is not implementation approval.

| ID | Topic | Recommendation | Class | Priority / gate |
|---|---|---|---|---|
| D-01 | Nemo context action | Thin Nemo adapter over shared ClamGuardian request API | PROPOSE | P2; one UI request, no duplicate scan logic |
| D-02 | Nautilus | Script first; Python MenuProvider only if needed | INVESTIGATE | P2; extension lifecycle/API compatibility |
| D-03 | Dolphin | KIO service menu for file and directory MIME types | INVESTIGATE | P2; verify KDE Frameworks support |
| D-04 | Caja | Optional Caja-Actions integration | DEFER | P3; packaging/runtime validation |
| D-05 | Thunar | Optional custom action | DEFER | P3; config/uninstall behavior |
| D-06 | Multi-selection | Structured multi-path UI request; current CLI is single-path | PROPOSE | P2; bounded JSON request |
| D-07 | Scan completeness | Skipped-file, warning and coverage semantics | ADOPT SEMANTICS | P2; CLEAN must not imply full coverage |
| D-08 | ClamD framing | Evaluate explicit NUL/newline command framing | INVESTIGATE | P2; path command currently legacy-framed |
| D-09 | ClamD fallback | Keep narrow initial-unavailable/refused fallback | RETAIN | P1; do not rescan after timeout/protocol failure |
| D-10 | Descriptor scan | FILDES → INSTREAM; never pathname fallback | RETAIN | P1; TOCTOU invariant |
| D-11 | FreshClam | Diagnose host-managed updater conflicts | INVESTIGATE | P2; do not manage systemd service |
| D-12 | User systemd timer | Evaluate unprivileged user-level service/timer | INVESTIGATE | P2; reuse CLI/Core |
| D-13 | Realtime overflow | Bounded reconciliation after event loss | INVESTIGATE | P1; avoid rescan storms |
| D-14 | Quarantine key custody | Complete threat model and recovery design | INVESTIGATE | P1; do not remove fallback prematurely |
| D-15 | clamonacc/fanotify | Keep deferred; separate architecture review | DEFER | RESEARCH; elevated permissions/performance |
| D-16 | Privileged helper/Polkit | Do not adopt | EXCLUDE | No justified use case |
| D-17 | ClamUI quarantine model | Do not replace AES-GCM vault | EXCLUDE | Hash integrity is not encryption |
| D-18 | YARA/extra engines | Research only | DEFER | Licensing/dependency/performance/product need |
| D-19 | DEB/RPM parity | Demand-driven only | DEFER | No parity-driven package expansion |
| D-20 | Direct cherry-pick | None recommended or performed | EXCLUDE | Different language/architecture/trust boundaries |

All PROPOSE/INVESTIGATE/DEFER items require separate maintainer approval. This register does not authorize code, dependency, permission, package, service or roadmap changes.

| D-21 | Pathname ClamD response validation | Require non-empty, fully recognized responses; malformed/empty/error replies must never be CLEAN | FIX — separate implementation PR | P1; regression matrix required; no fallback after established connection |
