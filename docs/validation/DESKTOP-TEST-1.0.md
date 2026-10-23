# ClamGuardian 1.0 Manual Desktop Test Checklist

This document is the evidence template for **`docs/ROADMAP.md`, 1.0.x M2** (manual test on a
real desktop) and **M3** (quarantine-restore verification inside the Flatpak sandbox).

- **Status:** TEMPLATE — copy it per test session (e.g. `validation/DESKTOP-TEST-1.0-<YYYY-MM-DD>.md`)
  or fill the per-step tables below.
- **Scope:** `1.0.1` release evidence (the desktop application and the AUD-01
  security fix), on `feature` before the tag or on the tagged commit once
  `v1.0.1` is cut. Record the exact commit under test in §1.
- **Bundle under test:** before the tag, use the promotion artifact
  `ClamGuardian-testing-linux-x86_64.flatpak` built by the release gate on the
  `feature → testing` PR; after the tag, use
  `ClamGuardian-v1.0.1-linux-x86_64.flatpak`. Both are built offline from the
  same local manifest; the resolved commit and SHA-256 must be recorded.
- **Prerequisites:** the CI GTK smoke test passed under Xvfb; this checklist is
  the last gate before the `v1.0.1` tag.

---

## 1. Environment (fill before testing)

| Field | Recorded value |
|---|---|
| Test date | _YYYY-MM-DD_ |
| Tester | _name_ |
| Host distro / version | _e.g. Fedora 42_ |
| Desktop session | _e.g. GNOME 51 (Wayland / X11)_ |
| CPU / arch | _e.g. x86_64_ |
| `flatpak --version` | _x.y.z_ |
| Host `clamscan --version` | _e.g. ClamAV x.y.z_ |
| Host `clamd` running | _yes / no (systemctl status clamav-daemon)_ |
| Tag/commit under test | _record `git rev-parse HEAD` of the bundle source (`feature` pre-tag, `v1.0.1` after the tag)_ |
| Bundle file | `ClamGuardian-testing-linux-x86_64.flatpak` (pre-tag) or `ClamGuardian-v1.0.1-linux-x86_64.flatpak` |
| Bundle SHA-256 | _record the digest of the installed bundle_ |
| ClamAV definitions date | _e.g. freshclam log date_ |

Outcome markers used below: `PASS` · `FAIL` · `N/A` · `BLOCKED` (with blocker reference).

---

## 2. M2 — Installation and first launch

| # | Step | Expected | Outcome | Notes / evidence |
|---|---|---|---|---|
| 2.1 | Install: `flatpak install --user ClamGuardian-testing-linux-x86_64.flatpak` (or the `v1.0.1` bundle after the tag) | Install completes with no error | | |
| 2.2 | List: `flatpak list --app` and grep ClamGuardian | `io.github.clamguardian.ClamGuardian` present | | |
| 2.3 | Launch from the desktop launcher (or `flatpak run io.github.clamguardian.ClamGuardian`) | Main window opens, no crash, no GTK criticals on stderr | | |
| 2.4 | First-run state | Default profile selected, empty history, fresh database state visible | | |

---

## 3. M2 — GTK pages review

Open each page and confirm it renders and reacts (no traceback, no frozen UI).

| # | Page | Expected | Outcome | Notes / evidence |
|---|---|---|---|---|
| 3.1 | Scan page | Default profile matches Settings (`quick` on a fresh install); target picker opens; threat rows offer **Quarantine** | | |
| 3.2 | History page | Opens and refreshes after a scan; filters, limit and purge work; detail dialog shows profile and SHA-256 | | |
| 3.3 | Quarantine page | Lists entries with name, size, date and original path; detail view offers Restore/Delete; Refresh works | | |
| 3.4 | Databases page | Database version/age displayed; update action available; third-party management opens | | |
| 3.5 | Diagnostics page | Global banner state matches the environment; per-distro remedies expand | | |
| 3.6 | Settings page | Default profile, notifications and theme persist after restart | | |
| 3.7 | About dialog | Version, license, website and issue tracker correct; opens from the menu and Settings | | |
| 3.8 | Window chrome | Sidebar and content header bars, page title follows navigation, menu and `Ctrl+Q`/`F1` work | | |
| 3.9 | Theme | Follows system by default; Light/Dark apply immediately; accent stylesheet renders on GNOME 46 and 51 | | |
| 3.10 | Notifications | With the setting enabled, a background scan completion shows a notification without file names/paths; disabled setting sends none | | |

---

## 4. M2 — Host ClamAV access

| # | Step | Expected | Outcome | Notes / evidence |
|---|---|---|---|---|
| 4.1 | Start a scan and observe the backend used | `clamd` preferred when reachable, else `clamscan` fallback (`flatpak-spawn --host`) | | |
| 4.2 | Stop host `clamd` (if running) and rescan | Graceful fallback to `clamscan`, scan completes | | |
| 4.3 | Restart host `clamd` and rescan | Backend switches back to `clamd` without app issues | | |

---

## 5. M2 — Clean scan on a controlled folder

Prepare a fixture folder with a handful of known-clean files
(e.g. `~/cg-test/clean/` with text files and a wheel/tarball).

| # | Step | Expected | Outcome | Notes / evidence |
|---|---|---|---|---|
| 5.1 | Quick-profile scan of the fixture folder | Verdict CLEAN, sane duration | | _record: profile, target, duration_ |
| 5.2 | Home-profile scan of the same folder | Verdict CLEAN, no false positives | | |
| 5.3 | `--json` CLI run (same scan, headless) | Exit code 0, JSON output parses, matches the UI result | | |
| 5.4 | Cancel a scan of a larger folder mid-run | Prompt cancellation, child process reaped, UI returns to idle | | |

---

## 6. M2 — EICAR detection (controlled environment)

> The EICAR string is a **harmless industry-standard test file**, not malware. Create it in an
> isolated folder only (e.g. `~/cg-test/eicar/`), never in a shared or synced directory,
> and delete the folder after the test. One EICAR file is enough — download
> `eicar.com.txt` from <https://www.eicar.org/download-anti-malware-testfile/>
> (the literal test string is intentionally **not** embedded in this document,
> so that scanning this repository stays clean).

| # | Step | Expected | Outcome | Notes / evidence |
|---|---|---|---|---|
| 6.1 | Scan the isolated EICAR folder (both backends if possible) | DETECTED via `clamd` and via `clamscan` | | |
| 6.2 | Quarantine the EICAR file on detection | File encrypted into the vault (AES-256-GCM), original removed | | |
| 6.3 | Remove the isolated EICAR folder | Host left clean | | |

## 7. M2 — History and database

| # | Step | Expected | Outcome | Notes / evidence |
|---|---|---|---|---|
| 7.1 | Open History / run `clamguardian history list` | Clean and EICAR scans recorded | | |
| 7.2 | `clamguardian history show <scan-id>` (single-file scan) | Shows `profile_id`, `profile_snapshot`, `sha256=<digest>` | | |
| 7.3 | `clamguardian history show <scan-id>` (directory scan) | Shows `sha256=None` (by design) | | |
| 7.4 | Trigger a database update | Update completes, or failure is reported with recoverable state | | _record: previous → new DB version_ |

---

## 8. M3 — Quarantine restore in the Flatpak sandbox

Prerequisite: one quarantined file from §6.2 (or a harmless test file quarantined on
purpose). The app runs with `--filesystem=host:ro` plus the writable
`xdg-data/clamguardian` path — record what actually works.

| # | Step | Expected | Outcome | Notes / evidence |
|---|---|---|---|---|
| 8.1 | Restore to the writable app path | Success; file readable by the owner | | _record: exact destination_ |
| 8.2 | Restore to an arbitrary host path (e.g. `~/Desktop/`) | **Record the observed behaviour** (a block from the read-only permission is data, not a failure) | | |
| 8.3 | Integrity check of the restored file | SHA-256 matches the pre-quarantine digest | | |
| 8.4 | Repeat 8.1–8.3 with the UI action (not only CLI) | Same behaviour as the CLI path | | |

### 8.5 Supported-restore matrix (the M3 deliverable)

| Destination | Works | Notes |
|---|---|---|
| App writable path (`xdg-data/clamguardian`) | _yes / no_ | |
| `~/Desktop/` (or other arbitrary host path) | _yes / no + observed error_ | |
| _other path tried_ | | |

> Rule: document the model that **actually** works; only if a legitimate use case is blocked
> may a file portal or a narrowly scoped writable permission be evaluated — never widen
> Flatpak permissions indiscriminately.

---

## 9. Shutdown and session hygiene

| # | Step | Expected | Outcome | Notes / evidence |
|---|---|---|---|---|
| 9.1 | Close the app normally | Window closes, no lingering processes | | |
| 9.2 | Reopen and re-check History | Recorded scans persist (SQLite intact) | | |

---

## 10. Consolidated exit criteria

| ID | Criterion | Met | Reference |
|---|---|---|---|
| M2 | Repeatable checklist with environment and outcomes recorded here | _yes / no_ | this file, §§1–7, 9 |
| M3 | Restore tested and documented without weakening the sandbox | _yes / no_ | §8, incl. the 8.5 matrix |
| M3-alt | If supported paths already work, evidence recorded with no superfluous changes | _yes / no / N/A_ | |
| Gate | No critical regressions; tests, audit and packaging still green | _yes / no_ | CI run(s): _record_ |
| D4 | All six pages reachable; Settings/About/notifications/theme behave as in §3.6–3.10 | _yes / no_ | this file, §3 |

**Known limits / follow-ups:** _list anything deferred._

**Conclusions:** _one short paragraph: sign-off or blockers._

_Tester signature / date:_ ____________________
