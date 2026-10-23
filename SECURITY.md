# Security policy

## Supported versions

| Version | Supported | Notes |
|---|---|---|
| `1.0.1` (release candidate) | ✅ after the tag is cut | Fixes AUD-01, AUD-02, AUD-03, AUD-04 and the P3 findings closed by PR #13 |
| `1.0.0` | ⚠️ upgrade recommended | **Affected by AUD-01**: a `clamd` directory scan could report `clean` for a directory that contains an infected file |
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
- Threat intelligence is frozen and unwired in 1.x: no file or hash leaves the
  machine.
