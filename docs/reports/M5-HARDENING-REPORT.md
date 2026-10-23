# M5 Security Hardening Report (Phases 5 & 6)

**Date:** 2026-10-13
**Branch:** `fix/pr5-audit-remediation` (remediation of PR #5, base `feature`)
**Defects addressed:** `P1-DB-01`, `P2-TGT-01`, `P2-QRN-01`, `P2-DBG-02`,
`P3-DBG-03`, `P3-ENG-02` from the independent audit of PR #5.

---

## 1. Phase 5 — hardening delivered

| M5 scope item | Defect | Fix (commit) | Evidence |
|---|---|---|---|
| Database download integrity | `P1-DB-01`: an artifact with no declared digest was downloaded and installed with no verification at all | `3394f86`: the provider refuses the artifact before fetching a byte and verifies unconditionally; the add-source dialog requires a 64-hex digest | provider-level tests: refusal without download, nothing published; `DatabaseManager.update` surfaces `DatabaseUpdateError` with status `ERROR` and installs nothing |
| Explicit scan target validation | `P2-TGT-01`: FIFOs, sockets and device nodes were handed to ClamAV | `d1a5cb3`: `_reject_unsupported_target` returns an explicit `ERROR` result before any backend runs | tests with a real FIFO and a UNIX socket: refused, `_run_command` never invoked; symlink to a regular file still scanned |
| Quarantine streaming/chunked encryption | `P2-QRN-01`: the whole file was read into memory on both paths, with no size limit | `192695c`: chunked AES-GCM records (`CLAMGUARDIAN-Q2`), per-chunk nonce derived from the record nonce plus the chunk index, AAD bound to metadata + index + final-chunk flag; streaming atomic writer both ways; `chunk_size`/`max_bytes` limits | 8 new tests: multi-chunk and exact-multiple round trips, empty file, truncated record, reordered chunks, size limit (source preserved), memory bounded (`tracemalloc` peak < 2 MiB for an 8 MiB payload both ways), legacy `Q1` record still restorable |
| Host execution hardening | — | unchanged: `flatpak-spawn --host` path, no shell, process-group SIGTERM/SIGKILL escalation (M0.5) | `tests/test_engine.py::test_engine_flatpak_host_command_construction`; no new finding from the audit |
| Intelligence trust boundaries | — | not wired: `clamguardian/intelligence` is present on this branch but nothing imports it — no CLI or UI call site, and no distribution declares the `clamguardian.threat_providers` entry-point group it discovers. The audit judged the provider seam itself correct (digest validated, no upload, 429 rate-limit handled) | see the scope-split section of `docs/reports/M4-FINAL-REPORT.md` |
| Rollback / atomic install | `P3-DBG-03`: a failure during the install move lost the previous database | `b21e320`: the rollback entry is recorded before the install move | test red before the fix (`FileNotFoundError`, the database file really was gone) and green after |
| UI/database contract | `P2-DBG-02`: the "Update all" button called a method that does not exist | `b21e320`: the UI calls `update_enabled()`; a headless regression test asserts every `self._manager.<method>(...)` in the UI exists on `DatabaseManager` | the guard test fails against the pre-fix UI |
| Detection parsing | `P3-ENG-02`: a clean path containing `" FOUND"` was classified as infected | `d1a5cb3`: detections are extracted only from canonical `path: <signature> FOUND` lines | test with a clean file named `my FOUND report.txt` |

---

## 2. Phase 6 — P2 residual risk evaluation

Everything below is a **known, accepted** residual risk, not an unaddressed P1.

| # | Residual risk | Assessment |
|---|---|---|
| R1 | **Quarantine key custody.** The 32-byte key is owned by the caller and kept in memory; the vault never persists it. If the operator loses it, quarantined payloads are unrecoverable; if the operator stores it insecurely, the vault is only as strong as that storage. | Accepted for 1.0: documented in the README security model. A keyring integration is a 1.x candidate, not a 1.0 blocker. |
| R2 | **Digest provenance.** The database digest is now mandatory, but the vault does not verify *who* signed the artifact: the operator must supply a digest obtained from a trusted channel. | Accepted: it is strictly stronger than the previous behaviour (no verification). Trust-on-first-use and a signed manifest are follow-ups. |
| R3 | **Hash/scan TOCTOU.** `P3-SHA-TOCTOU`: the digest is computed after the scan, so a file replaced in between could yield a hash that does not describe the scanned bytes. | Accepted and documented; the scan result itself is not affected. Closing it needs a single-pass hashing scanner or a verified file handle, i.e. an engine redesign — out of 1.0 scope. |
| R4 | **Special-file rejection is at the engine boundary.** The CLI still resolves and passes a path; the refusal happens inside `ClamAVEngine.scan`. | Accepted: single choke point, covered by tests. Any new front-end inherits the protection. |
| R5 | **`max_bytes` default.** A 512 MiB default means a very large suspicious file cannot be quarantined without raising the limit. | Accepted and configurable per vault; the failure is explicit (`ValueError`) and never deletes the source. |
| R6 | **Not audited in CI: the `test`/`gtk` extras.** The M6 audit covers the runtime closure only. | Accepted by design (see `docs/reports/M6-CI-GATE-REPORT.md`, section 2). |
| R7 | **Realtime / USB defects are out of this branch.** The audit's `P1-RT-*`, `P2-RT-*`, `P2-USB-01` are real but belong to code that is no longer shipped in 1.0. Threat intelligence carries no open finding. | Accepted by decision D5/B: those modules were removed and return with their own gate. Reintroducing any of them without the corresponding fixes would reopen P1 findings. `clamguardian/intelligence` stays on the branch but unwired, so it is not reachable in the 1.0 release. |
| R8 | **No privileged surface.** ClamGuardian runs entirely in user space; no root daemon, no setuid, no Polkit. | Confirmed by inspection: no privilege-escalation mechanism exists in the 1.0 branch. Any 2.x-C privileged service requires a separate design and threat model before implementation. |

---

## 3. Gate verdict

- Phase 5: **MET** — every M5 hardening item has a fix with a test that was red
  before it, or a documented reason for not applying to this branch.
- Phase 6: **MET** — the residual risks above are the P2 evaluation; none of them
  is blocking for the 1.0 gate.
- No P1 remains open inside the 1.0 perimeter. The findings still open in the
  audit report all live in code that was removed from this branch (`P1-RT-*`,
  `P2-RT-*`, `P2-USB-01`) or in the documentation items tracked for the final
  documentation pass.

## 4. How to reproduce

```bash
pytest -q tests/test_databases.py tests/test_quarantine.py tests/test_engine.py
ruff check . && mypy clamguardian
git log --oneline 3bf0873..HEAD   # the fixes listed in section 1
```
