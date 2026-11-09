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
| **ClamAV Backend** | clamd / clamscan integration | Implemented | Already implemented & verified | ClamGuardian automatically prefers `clamd` UNIX sockets and seamlessly falls back to `clamscan`. |
| **Quarantine Vault** | File isolation and restore | Implemented | Already implemented & verified | ClamGuardian provides AES-256-GCM authenticated encryption with 96-bit fresh nonces and tamper-evident associated data metadata. |
| **Databases** | Freshclam official + extra signatures | Implemented | Already implemented & verified | ClamGuardian includes official detection diagnostics and third-party database management with HTTPS enforcement and mandatory SHA-256 integrity verification. |
| **Removable Media** | USB auto-detection and scanning | Implemented (Phase 1) | Implemented & integrated | Implemented in `clamguardian.core.usb` (`USBDeviceScanner`, `USBMountMonitor`), target validation strictly under standard mount roots, symlink protection, duplicate suppression, and GTK/CLI controls. |
| **Threat Intelligence** | Cloud threat lookups | Implemented (Phase 2) | Implemented & integrated | Implemented in `clamguardian.intelligence` with SHA-256 hash-only lookups (VirusTotal v3), zero file uploads, rate limiting, and OS Secret Service credential storage. Disabled by default with zero network requests when disabled. |
| **Realtime Monitoring** | Inotify event monitoring | Implemented (Phase 3) | Implemented & integrated | Implemented 2.x-A event-driven monitoring (`InotifyMonitor → Policy → Orchestrator → ScanTaskRunner`) using native libc syscalls, trailing-edge debounce, strict queue bounds (`pending + dispatched + active <= max_queue_depth`), dirty/retrigger handling, and deterministic shutdown. |
| **Scheduled Scans** | Automated periodic scanning | Implemented (Phase 4) | Implemented & integrated | Unprivileged user-level scheduler (`ScheduledScanManager`) integrated with existing `ScanTaskRunner` and `HistoryStore`, configurable via GTK Settings and CLI (`clamguardian schedule`). Missed-scan detection on daily boundaries. |
| **Desktop Autostart** | Launch application on login | Implemented (Phase 4) | Implemented & integrated | Implemented via standard user-session `~/.config/autostart` XDG desktop entry (`AutostartManager`), disabled by default, managed via Settings and CLI (`clamguardian autostart`). |
| **Privileged IPC Daemon** | Root-dependent background daemon | Rejected | Rejected | Violates unprivileged security model. Excluded scope (2.x-C). |
| **On-Access Blocking** | fanotify/clamonacc blocking | Deferred | Deferred | Requires root privileges and system-level intervention. Excluded scope (2.x-B). |
| **System Tray Icon** | Background tray/AppIndicator | Deferred | Deferred | GNOME/Libadwaita desktop standard prefers background portal notifications over legacy StatusNotifier/XEmbed system tray icons. Desktop notifications are fully integrated. |
