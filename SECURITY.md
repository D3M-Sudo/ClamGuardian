# Security policy

## Supported versions

| Version | Supported | Notes |
|---|---|---|
| `1.0.1` (published 2026-10-24) | ✅ latest published release | Contains the security fixes and GTK desktop application documented in the `[1.0.1]` changelog section; later USB, realtime and VirusTotal integration work on `feature` is not part of this release. |
| `1.0.0` | ⚠️ upgrade strongly recommended | **Affected by AUD-01**: a `clamd` directory scan could report `clean` for a directory that contains an infected file; use published `1.0.1` or later. |
| `< 1.0.0` | ❌ | Pre-release development builds, no support |

The full finding history and remediation state live in
[`docs/reports/INDEPENDENT-AUDIT-2026-10-19.md`](docs/reports/INDEPENDENT-AUDIT-2026-10-19.md).

## Reporting a vulnerability

Please report privately, **not** in a public issue:

1. Open a private advisory through GitHub: **Security → Advisories → Report a
   vulnerability** on this repository.
2. Include the affected version (`clamguardian --version`), the command or UI
   path, the expected and observed behaviour, and a minimal reproduction.
3. Do not attach live malware. Use the EICAR test string or a sanitised sample;
   the project never asks for real samples.

You can expect an acknowledgement within 7 days and a remediation plan (fix,
mitigation or accepted risk with rationale) within 30 days. Fixes ship through
the normal promotion flow (`feature → testing → development → main`) and are
documented in [`CHANGELOG.md`](CHANGELOG.md).

## Scope

In scope: the `clamguardian` package, the CLI, the GTK4 desktop application, the
quarantine vault, the history store, packaging metadata and the CI workflows.

Out of scope:

- ClamAV, `clamd`, `clamscan`, `freshclam` and the signature databases (report to
  the ClamAV project).
- Third-party databases configured by the user.
- A compromised host, root-level attackers or a malicious Flatpak runtime.
- The `0.0.0.0` listeners of the session/CI container documented as accepted
  risk AUD-06 in [`docs/project/RUNTIME-EXPOSURE.md`](docs/project/RUNTIME-EXPOSURE.md):
  ClamGuardian opens no network listener.

## Security design

- Fully unprivileged: no root, no setuid, no Polkit, no system daemon.
- AES-256-GCM quarantine with a per-record nonce and AAD-sealed metadata;
  `0700` vault directories, `0600` records.
- No shell execution; process groups isolated with `start_new_session=True`.
- Optional VirusTotal intelligence is implemented on the current development branch, not in the published `v1.0.1` release. It is opt-in and uses OS Secret Service credentials. Public API requests remain blocked until written eligibility authorization is recorded; Premium requires the user's valid entitlement. Hash lookup sends a SHA-256 digest only. Full-file upload is a separate operation requiring fresh per-file consent, an absent-hash lookup and post-consent digest revalidation. Remote assessments are supplemental and never replace the local ClamAV verdict.
