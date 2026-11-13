# ClamUI Functional Benchmark Evaluation

This document evaluates the publicly observable capabilities of [linx-systems/clamui](https://github.com/linx-systems/clamui) against ClamGuardian's architecture and security model.

## Evaluation Criteria

1. **Product Fit**: Does it align with a native Linux antivirus desktop application?
2. **Security & Privilege Model**: Does it adhere to ClamGuardian's unprivileged model (no root execution, no setuid, no privileged background daemons)?
3. **Architecture Integrity**: Does it respect the core, engine, persistence, and GTK presentation boundaries?

---

## Benchmark Matrix

| Feature Area | ClamUI Capability | ClamGuardian Status | Evaluation Decision | Technical Reasoning |
|---|---|---|---|---|
| **Scan Workflows** | Manual file/directory scans, preset scan targets | Implemented | Already implemented & verified | ClamGuardian implements `quick`, `home`, `full`, and `custom` profiles driven by `ScanTaskRunner` and shared across UI/CLI. |
| **ClamAV Backend** | clamd / clamscan integration | Implemented | Already implemented & verified | ClamGuardian directly uses the configured clamd UNIX socket when available. It falls back to `clamscan` only if the socket is absent or the initial daemon connection is unavailable/refused; a timeout or protocol/transport failure after connection does not trigger a second scan. Descriptor scans prefer FILDES and use INSTREAM when FILDES is unavailable, without falling back to a pathname scan. |
| **Quarantine Vault** | File isolation and restore | Implemented | Already implemented & verified | ClamGuardian provides AES-256-GCM authenticated encryption with 96-bit fresh nonces and tamper-evident associated data metadata. |
| **Databases** | Freshclam official + extra signatures | Implemented | Already implemented & verified | ClamGuardian includes official detection diagnostics and third-party database management with HTTPS enforcement and mandatory SHA-256 integrity verification. |
| **Removable Media** | USB auto-detection and scanning | Implemented on `feature` | Implemented; real-host validation pending | PR #18 is merged. `USBDeviceScanner` / `USBMountMonitor` require removable-device mount identity beneath an allowed root, track scans and cancel on unmount/shutdown. CI coverage is present; real-host mount/unmount validation remains a separate evidence gate. |
| **Threat Intelligence** | Cloud threat lookups | Implemented on `feature` | Public policy-gated; Premium entitlement-gated | PRs #18, #25 and #29 integrate explicit Public/Premium profiles, Secret Service credentials, hash-first lookups, consent-gated upload and shared scan enrichment with scan-linked evidence persistence. Public network requests remain blocked pending written eligibility authorization; Premium requires valid entitlement. CI tests cover the current implementation. |
| **Realtime Monitoring** | Inotify event monitoring | Implemented on `feature` | Integrated; final hardening / host validation pending | PR #18 is merged. The subsystem uses native inotify, policy filtering, bounded orchestration and descriptor-based scans. PR #30 is merged into `feature` and adds quarantine race/restore hardening, third-party database lifecycle protections and shutdown cleanup; real-host event/watch coverage also remains to be recorded. |
| **Scheduled Scans** | Automated periodic scanning | Implemented (Phase 4) | Implemented & integrated | Unprivileged user-level scheduler (`ScheduledScanManager`) integrated with existing `ScanTaskRunner` and `HistoryStore`, configurable via GTK Settings and CLI (`clamguardian schedule`). Missed-scan detection on daily boundaries. |
| **Desktop Autostart** | Launch application on login | Implemented (Phase 4) | Implemented & integrated | Implemented via standard user-session `~/.config/autostart` XDG desktop entry (`AutostartManager`), disabled by default, managed via Settings and CLI (`clamguardian autostart`). |
| **Privileged IPC Daemon** | Root-dependent background daemon | Rejected | Rejected | Violates unprivileged security model. Excluded scope (2.x-C). |
| **On-Access Blocking** | fanotify/clamonacc blocking | Deferred | Deferred | Requires root privileges and system-level intervention. Excluded scope (2.x-B). |
| **System Tray Icon** | Background tray/AppIndicator | Deferred | Deferred | GNOME/Libadwaita desktop standard prefers background portal notifications over legacy StatusNotifier/XEmbed system tray icons. Desktop notifications are fully integrated. |

---

## Follow-up research

The detailed pinned-source comparison, ClamAV backend analysis, file-manager integration proposal, evidence matrix and roadmap recommendations are maintained in [the ClamAV benchmark research dossier](../research/clamav-benchmark/README.md).

## P1 ClamD response-validation finding

The pinned baseline finding below remains historically valid. Its correction was implemented and merged into `feature` by PR #45 (merge commit `c1da5c8974c8148ac60b23f507a5deec2816b52c`). The current branch therefore contains fail-closed pathname-response validation and regression tests; this historical finding is resolved in the current implementation. It remains separate from the ClamUI comparison and from this documentation dossier. See the [detailed research finding](../research/clamav-benchmark/clamav-integration-study.md#8-p1-finding--pathname-clamd-response-can-be-classified-clean-without-a-valid-reply).
