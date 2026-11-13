# Security and Privilege Analysis

## Security baseline

At the pinned baseline ClamGuardian is a user-space application. Ordinary scans do not require a privileged ClamGuardian daemon, setuid helper or Polkit action. Host ClamAV owns daemon identity, socket permissions, official database ownership and system service lifecycle.

## ClamD socket trust boundary

- Prefer a local UNIX socket. ClamAV documents TCP ClamD as unauthenticated and unencrypted; do not expose it to untrusted networks.
- Socket existence does not prove daemon health or user connect permission.
- Socket ownership/group/mode are host configuration. Report permission failures; do not silently change them.
- Path commands are resolved by clamd, so the daemon must be able to read the target.
- Flatpak host path visibility and socket visibility are separate requirements.

## Subprocess and file-manager boundary

ClamGuardian invokes host binaries with argument arrays, not a shell, and applies output bounds, timeouts, cancellation and process-group teardown. Preserve these invariants in all adapters.

Treat a file-manager adapter as an untrusted input boundary. Bound request size/count, validate paths in Core, re-check identity/access at scan time, and never concatenate selected paths into shell source. MIME filters are UX filters, not security controls.

## Descriptor and race safety

Realtime scans open files beneath pinned authorized root descriptors and pass the opened descriptor to the engine. FILDES/INSTREAM preserves the scanned object; pathname fallback weakens this guarantee. Preserve the no-path-fallback rule for descriptor scans.

A context-menu path is a request, not a stable file identity. Define regular-file/directory, symlink and mount-boundary policy; targets can be replaced between selection and scan.

## Flatpak

The pinned manifest grants host read-only filesystem access and uses `flatpak-spawn --host` for host ClamAV commands, alongside required portal and Secret Service access. Do not expand writable host filesystem permissions to install file-manager actions. Prefer host-side user-scoped integration files and an explicit installer/uninstaller.

## Privileged On-Access boundary

clamonacc/fanotify prevention differs materially from user-space event monitoring. It requires elevated permissions and can block process access. Broad paths, incorrect exclusions, clamd outage or stalled prevention can affect system availability. Do not hide it inside the existing realtime toggle.

A future evaluation requires explicit opt-in; distinct notify/prevention modes; root ownership/install/update/uninstall design; strict path allowlist and system exclusions; kernel capability detection; defined clamd outage behavior; performance/deadlock tests; audit logs, rollback and separate threat model.

## Quarantine key custody

Secret Service preference with a 0600 file fallback supports headless environments but leaves a key-custody question: same-user compromise may expose both ciphertext and key. Do not remove fallback without a recovery design. Document keyring loss, reinstall, backup/restore and irrecoverable vault scenarios.

## Decision

Retain the unprivileged model. Do not introduce privileged helper, setuid, Polkit or root daemon as a convenience layer for file-manager integration. Adapters should submit requests to the existing user-session application.
