# ClamGuardian D4 — Manual Desktop Test Session

Session record for the desktop phase **D4** (Settings, About, notifications,
theme, window chrome, quarantine ingest). The authoritative step-by-step
checklist is [`DESKTOP-TEST-1.0.md`](DESKTOP-TEST-1.0.md); this file only
records the D4 session.

- **Status:** TEMPLATE — to be executed on a real desktop session.
- **Scope:** `feature` @ D4 (record the exact commit in the table below).
- **Automated coverage:** `ruff`, `mypy`, `pytest` (including GTK widget tests
  under Xvfb) and the Release Gate must be green before this session starts.

## 1. Environment

| Field | Recorded value |
|---|---|
| Test date | _YYYY-MM-DD_ |
| Tester | _name_ |
| Host distro / version | _e.g. Ubuntu 24.04 / Fedora 42_ |
| Desktop session | _e.g. GNOME 46 (Wayland / X11)_ |
| Libadwaita version | _e.g. 1.5.0 / 1.9.x_ |
| CPU / arch | _e.g. x86_64_ |
| Install method | _Flatpak bundle / `pip install` from source_ |
| Commit under test | `feature` @ `44ca472` (D4 code; later docs-only commits do not change the UI) |
| `flatpak --version` | _x.y.z_ |
| Host `clamscan --version` | _e.g. ClamAV x.y.z_ |
| Host `clamd` running | _yes / no_ |

Outcome markers: `PASS` · `FAIL` · `N/A` · `BLOCKED` (with reference).

## 2. D4 outcomes

| # | Step | Expected | Outcome | Notes / evidence |
|---|---|---|---|---|
| D4.1 | Scan with the default profile | Preselected profile matches Settings (`Quick Scan` on a fresh install) | | |
| D4.2 | Detect the EICAR fixture and press **Quarantine** on the threat row | Confirmation appears; on accept the original is removed and the entry appears under Quarantine | | |
| D4.3 | Quarantine → entry → **Restore** | Folder chooser opens; the file is restored to the chosen folder; integrity check matches | | |
| D4.4 | Quarantine → entry → **Delete** | Confirmation appears; the entry disappears after accept | | |
| D4.5 | History after a scan | New scan is listed without restarting the app; filters/limit/purge work | | |
| D4.6 | Settings → change default profile, restart | New profile is preselected on the Scan page after restart | | |
| D4.7 | Settings → notifications off/on | No notification when disabled; background scan completion notifies when enabled | | |
| D4.8 | Notification text | Contains status/counts only — no file names or paths | | |
| D4.9 | Settings → Light / Dark / Follow system | Theme changes immediately and survives restart | | |
| D4.10 | Window chrome | Sidebar + content header bars, page title follows navigation | | |
| D4.11 | Menu / shortcuts | About opens from the menu and Settings; `F1` opens About; `Ctrl+Q` quits | | |
| D4.12 | About dialog | Version, license, website and issue tracker correct | | |
| D4.13 | Diagnostics page | Banner state and per-distro remedies match the host | | |
| D4.14 | All six pages | Scan, History, Quarantine, Databases, Diagnostics, Settings open without tracebacks or criticals on stderr | | |

## 3. Exit

| Criterion | Met | Reference |
|---|---|---|
| All D4 steps PASS or explicitly N/A/BLOCKED with a follow-up | _yes / no_ | §2 |
| No GTK criticals/warnings on stderr during the session | _yes / no_ | stderr log |
| Flatpak restore behaviour recorded without widening permissions | _yes / no_ | `DESKTOP-TEST-1.0.md` §8 |
| Gate still green (tests, audit, packaging) | _yes / no_ | CI run(s): _record_ |

**Known limits / follow-ups:** _list anything deferred._

**Conclusions:** _one short paragraph: sign-off or blockers._

_Tester signature / date:_ ____________________
