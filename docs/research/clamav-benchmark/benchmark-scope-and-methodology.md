# Benchmark Scope and Methodology

## Objective

Compare pinned ClamGuardian and ClamUI implementations, identify transferable engineering practices and propose a safe evolution path for file-manager and ClamAV integration. No performance ranking is made without controlled measurements.

## Pinned sources

| Project | Repository | Commit |
|---|---|---|
| ClamGuardian | https://github.com/D3M-Sudo/ClamGuardian | `b42c01612d34ef20b980518aa9b3845f48ea4210` |
| ClamUI | https://github.com/linx-systems/clamui | `106e403c7cfea14ab38a97ccfd41bd12a1172e4f` |

Later upstream changes are outside this historical comparison unless identified as external documentation.

## Evaluation dimensions

Desktop integration; architecture and lifecycle; clamd/clamscan/clamdscan/freshclam transports and scan completeness; inotify versus fanotify/clamonacc; quarantine confidentiality/integrity/recovery; scheduling/database ownership; privilege/security boundaries; packaging and licensing.

## Evidence sources

ClamGuardian: `clamguardian/engines/clamav.py`, `clamguardian/core/runner.py`, `clamguardian/realtime/`, profiles, diagnostics, scan UI, desktop entry, Flatpak manifest, tests, roadmap and existing benchmark report.

ClamUI: `scanner.rs`, `scan_parser.rs`, `scheduler.rs`, `quarantine.rs`, Nautilus integration scripts and workflows/tests associated with the pinned commit.

External primary references:
- ClamAV [Usage](https://docs.clamav.net/manual/Usage.html), [ClamD Protocol](https://docs.clamav.net/manual/Usage/ClamdProtocol.html), [Scanning](https://docs.clamav.net/manual/Usage/Scanning.html), [Signature Management](https://docs.clamav.net/manual/Usage/SignatureManagement.html), [Configuration](https://docs.clamav.net/manual/Usage/Configuration.html), [On-Access](https://docs.clamav.net/manual/OnAccess.html).
- [Nemo Actions](https://github.com/linuxmint/nemo/blob/master/files/usr/share/nemo/action-info.md), [nautilus-python](https://gnome.pages.gitlab.gnome.org/nautilus-python/nautilus-python-overview.html), [Dolphin service menus](https://develop.kde.org/docs/apps/dolphin/service-menus/), [Caja Actions](https://github.com/mate-desktop/caja-actions), [Thunar custom actions](https://docs.xfce.org/xfce/thunar/custom-actions), [Desktop Entry Specification](https://specifications.freedesktop.org/desktop-entry/latest-single/).

## Evidence labels

VERIFIED: source or authoritative documentation. OBSERVED: repository artifact/test, not necessarily independently repeated. INFERRED: derived conclusion. PROPOSED: future behavior. BLOCKED: required host/runtime unavailable. DEFERRED: intentionally outside current decision.

A green CI job proves only steps it executes. Mock tests are not real-engine validation; Xvfb smoke is not manual desktop validation; source-level fanotify config is not proof of runtime prevention.

## Limitations

No controlled performance benchmark; no provisioned host VM for cross-desktop testing; no real-host Nemo/Nautilus/Dolphin/Caja/Thunar test; no real-host on-access prevention experiment. Missing tests are not passes.
