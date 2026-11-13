# Evidence and Test Results

## Pinned baselines

- ClamGuardian: `b42c01612d34ef20b980518aa9b3845f48ea4210`
- ClamUI: `106e403c7cfea14ab38a97ccfd41bd12a1172e4f`

## ClamGuardian source evidence

| Area | Evidence | Status |
|---|---|---|
| Main scan | Direct UNIX socket; SCAN/CONTSCAN; response read to EOF | VERIFIED |
| Fallback | Socket missing/refused during connection establishment only; timeout/protocol failure does not fallback | VERIFIED |
| Descriptor scan | FILDES capability probe; INSTREAM fallback; no pathname fallback; bounded workers | VERIFIED |
| Commands | argv subprocess, bounded output, inactivity/maximum timeouts, process-group teardown | VERIFIED |
| Profiles | clamscan options translated; unsupported per-connection clamd options in metadata | VERIFIED |
| Realtime | inotify, debounce, coalescing, bounded queue, pinned root FDs, descriptor scan | VERIFIED |
| File-manager action | Desktop entry launcher only; no native action in pinned tree | OBSERVED |
| Flatpak | Host ClamAV via flatpak-spawn; read-only host filesystem; portal/app-data access | VERIFIED |
| FreshClam | update_signatures invokes FreshClam; does not manage systemd lifecycle | VERIFIED |

## ClamGuardian CI evidence recorded in benchmark campaign

- CI run #562 SUCCESS: https://github.com/D3M-Sudo/ClamGuardian/actions/runs/43369793150
- Release Gate #505 SUCCESS: https://github.com/D3M-Sudo/ClamGuardian/actions/runs/43369793151
- Python 3.11/3.12/3.13: 641 passed, 9 skipped per version.
- Python 3.14 headless: 611 passed, 22 skipped.
- GTK smoke and packaging succeeded.
- Real ClamAV Release Gate exercised FreshClam and clean/EICAR through clamscan, clamdscan and descriptor FILDES.
- This does not prove real-host inotify event-to-clamd behavior or manual desktop integration.

## ClamUI CI evidence recorded in benchmark campaign

14 workflows on pinned commit succeeded; core Rust tests: 235 passed, 1 ignored, 0 failed. CI included Tauri build, Rust/frontend lint, CodeQL, dependency audit, Flatpak x86_64/aarch64, AppImage x86_64, Debian amd64/arm64 and helper RPM x86_64/aarch64.

Scanner tests use fixtures/mocks, not real ClamAV. FreshClam tests use mocks. Quarantine tests cover temporary filesystem operations, SHA-256, symlink rejection and restore/no-overwrite. No operational on-access VM test was evidenced.

## BLOCKED / not established

No controlled throughput/CPU/memory/concurrency benchmark; no end-to-end file-manager action tests; no real-host inotify reconciliation or fanotify prevention validation; no controlled FreshClam race comparison; no cross-desktop Flatpak validation; no host stress tests. These are BLOCKED/DEFERRED, not PASS.

## Future validation

File managers: record versions, package type, selection count, spaces/unicode/newline paths, directories, symlinks, cancellation, focus/notifications and uninstall.

ClamAV: daemon absent/running, permission denied, refusal, malformed/partial reply, timeout, output truncation, unsupported profile options, EICAR/clean/skipped files, FILDES absent, INSTREAM limit, FreshClam already running, stale/corrupt database. Record exact versions/configuration.

## Additional review evidence — PR #44 review

### P1 ClamD response-classification finding

**VERIFIED historical finding** at pinned commit `b42c01612d34ef20b980518aa9b3845f48ea4210`: pathname ClamD response handling could return code zero for empty or unrecognized output, allowing `_result()` to classify the scan as CLEAN. The immutable source anchors in [ClamAV Integration Study](clamav-integration-study.md#8-p1-finding--pathname-clamd-response-can-be-classified-clean-without-a-valid-reply) remain valid for that baseline.

**Current disposition: RESOLVED.** PR #45 (`c1da5c8974c8148ac60b23f507a5deec2816b52c`) added fail-closed pathname response and summary validation plus regression tests in `tests/test_engine.py`. PR #46 (`a90463bd77a1f47f7c512fc6e4f5a0f92b9fb96b`) documented the fix in `CHANGELOG.md`. The historical defect is not a statement about current `feature`.

The PR #45 regression suite covers malformed/empty protocol responses and summary consistency; the implementation also retains detections/errors and does not fall back to CLI after an established connection protocol failure.

### CI traceability

- Original PR #44 head validation: CI run https://github.com/D3M-Sudo/ClamGuardian/actions/runs/43383029161 and Release Gate run https://github.com/D3M-Sudo/ClamGuardian/actions/runs/43383029178 both completed successfully on the then-current PR head. These are **historical pre-rebase runs**, not validation of this reconstructed branch.
- PR #45 validation: CI run https://github.com/D3M-Sudo/ClamGuardian/actions/runs/43396650195 completed with all 9 jobs passing; Release Gate run https://github.com/D3M-Sudo/ClamGuardian/actions/runs/43396650487 completed with 6 passed and 1 expected skip. These runs support the ClamD remediation, not this documentation branch as a whole.
- The new rebased documentation branch must pass its own CI and Release Gate before it is considered validated. Add those final run links after they complete.
- CI jobs validate only the steps they execute. They do not exercise the proposed file-manager request API, real Nemo action parsing, host-side installation or on-access behavior.

### ClamUI workflow-count wording

The earlier phrase “14 workflows” is imprecise. The observation is **14 workflow runs**, not 14 distinct workflow definitions. Some runs are dependency automation; the count must not be presented as 14 independent code-CI workflows. The aggregate count is contextual only and is not a substitute for linking each run individually.

### Evidence traceability limits

The pinned source revisions are historical comparison points. Where this dossier does not provide a direct commit-pinned file/line anchor or an individual CI run URL, treat the statement as an observation from the recorded review rather than independently reproducible evidence. In particular, host file-manager behavior and host fanotify/inotify behavior remain **BLOCKED**, not PASS.
