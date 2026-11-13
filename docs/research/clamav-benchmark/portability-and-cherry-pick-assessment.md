# Portability and Cherry-Pick Assessment

## Licensing baseline

ClamGuardian is GPL-3.0-or-later. The pinned ClamUI repository is MIT-licensed; MIT is generally GPLv3-compatible when copyright and license notices are preserved. Compatibility does not imply architectural suitability.

The inspected Maldet codebase is GPL-2-only, not GPL-2-or-later. Do not combine its code with this GPLv3-or-later project absent additional permission. Wazuh contains multiple licensing components; review the exact component before any reuse. This is an engineering screen, not legal advice.

## Direct cherry-pick verdict

**No direct cherry-pick is recommended or was performed.** ClamUI is a Rust core/Tauri/React application; its scanner, scheduler, UI and helper commits are not drop-in commits for ClamGuardian's Python/GTK architecture. Porting concepts is not cherry-picking commits.

## Transferability

| ClamUI concept | ClamGuardian decision | Rationale |
|---|---|---|
| Nautilus selected-file script | Reimplement concept | Thin adapter idea is useful; script is app-specific |
| Structured skipped-file/warning model | Adopt semantics | Improves scan completeness without importing Rust |
| User-level systemd scheduler | Investigate | Could outlive desktop process without root |
| Quarantine filesystem-hardening tests | Reuse test ideas | Add equivalent tests only where coverage is missing |
| Unencrypted quarantine payload | Exclude | Not equivalent to AES-256-GCM confidentiality |
| Privileged helper / Polkit | Exclude | Not justified by current architecture |
| clamonacc/fanotify prevention | Defer/research | Elevated permissions and kernel support required |
| YARA/other engines | Research | Product and dependency decision not established |
| RPM parity | No action | No concrete requirement identified |
| DEB packaging | Demand-based research | Only if distribution demand justifies maintenance |

## Reuse checklist

1. Pin exact source commit and paths.
2. Verify file-level license and notices.
3. Identify generated, vendored or derived code.
4. Review direct and transitive dependencies/licenses.
5. Port behind ClamGuardian's existing Core/Engine boundary.
6. Preserve local tests, threat model and error semantics.
7. Record provenance.

ClamGuardian's pinned branch supports Flatpak x86_64/aarch64 and AppImage x86_64/aarch64. ClamUI CI included Flatpak x86_64/aarch64, AppImage x86_64, Debian amd64/arm64 and helper RPM builds; helper RPM is not a full application RPM.

For file-manager integration, prefer native package installation or an explicit, user-scoped host installer with uninstall support. Do not assume Flatpak can write host extension directories.
