# Comparative Technical Analysis

## Architecture comparison

| Dimension | ClamGuardian | ClamUI | Assessment |
|---|---|---|---|
| Core/runtime | Python shared core; GTK4/Libadwaita UI and CLI | Rust headless core; Tauri 2 + React/TypeScript | Different stacks; no direct code interchange |
| Engine | Direct ClamD UNIX socket; clamscan fallback | clamdscan/clamscan command execution/parser | ClamGuardian lower-level protocol control; ClamUI richer CLI-output parser |
| Results | ScanResult status, threats, metadata, profile, history | Scanned files/dirs, skipped paths/counts, warnings, threats, backend | ClamUI completeness semantics useful |
| Realtime | inotify, debounce/coalescing, bounded queue, descriptor-pinned scan | clamonacc/fanotify optional system integration | Event-triggered scan is not access prevention |
| Quarantine | AES-256-GCM authenticated encryption | Hash/integrity and filesystem restore hardening | Keep ClamGuardian confidentiality model |
| Updates | Official FreshClam delegated to host; separate HTTPS/SHA-256 third-party manager | Host FreshClam config and scanner database discovery | Preserve ownership separation |
| Scheduler | asyncio tied to application lifecycle | user-level systemd/cron | Investigate user timer |
| Desktop | standard launcher; no context-menu adapter in pinned tree | Nautilus script | Concrete ClamGuardian opportunity |

## Scanner behavior

ClamGuardian checks its configured UNIX socket. If absent, it runs clamscan. If present, it sends ClamD path commands: CONTSCAN for recursive directories and SCAN otherwise; it reads through EOF to retain all directory result lines.

Fallback is narrow: initial FileNotFoundError or ConnectionRefusedError permits clamscan retry. Timeout, cancellation or protocol/transport failure after connecting returns an error rather than launching a second potentially expensive scan.

Descriptor scans probe VERSIONCOMMANDS, prefer FILDES and otherwise stream from the same opened descriptor with INSTREAM. There is no pathname fallback. Worker capacity is bounded and cancellation interrupts the socket worker.

ClamUI uses standard command-line clients and records skipped files, warning categories, scan counts and threat details. Its Nautilus script passes selected paths to the app; the wrapper is not a reusable scanning architecture.

## Realtime distinction

ClamGuardian inotify reacts to filesystem events and schedules scans after events; it is event-driven detection, not kernel prevention. It uses policy filtering, debounce, coalescing, bounded work, root directory descriptors and descriptor-pinned scans.

ClamAV clamonacc is a separate On-Access client using fanotify on Linux. Prevention can block access to malicious files and requires elevated permissions; ClamAV warns of performance impact in frequently accessed directories. Notify-only is distinct from prevention.

## Quarantine

ClamGuardian AES-256-GCM provides confidentiality and authenticated integrity. ClamUI's symlink rejection, restore-collision, no-overwrite and integrity tests are useful patterns, but a hash is not confidentiality.

## Scheduler and database ownership

ClamGuardian asyncio scheduler is tied to app lifecycle. ClamUI user-level systemd/cron patterns can persist beyond the desktop process. A user-level systemd timer could invoke existing CLI/Core without root or duplicated scan logic.

FreshClam manages official signature databases. ClamGuardian's third-party manager separately handles HTTPS, staging, SHA-256 and rollback. Keep ownership domains separate; avoid races with host FreshClam.

## Conclusion

Selectively adopt ClamUI result semantics, selected-file integration concept and scheduler lifecycle patterns. Retain Python/GTK, encrypted quarantine, descriptor-based realtime scans and unprivileged default. Evidence supports no performance ranking.
