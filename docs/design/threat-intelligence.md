# Threat intelligence — opt-in, eligibility-gated VirusTotal integration

## Status

`clamguardian.intelligence` is integrated with scan-result enrichment and CLI
configuration. Public API requests remain administratively blocked by default;
Premium requests require a valid subscription entitlement:

- CLI commands provide profile selection, credential setup, status, enable,
  disable, hash lookup and explicit file submission; GTK settings provide
  profile selection, Secret Service credential setup and consent-gated upload;
- `pyproject.toml` declares no `clamguardian.threat_providers` entry point;
- the `intelligence` extra is reserved and intentionally empty;
- importing the package performs no network I/O and reads no secrets.

VirusTotal remains opt-in. The maintainer eligibility constant blocks the
Public profile until applicable Public API terms and product/use-case eligibility
have been clarified in writing. Premium is an independently selected, licensed
profile and is not inferred from key format. A user preference cannot bypass
either profile's authorization requirements.

## Why network lookups remain gated

| Reason | Detail |
|---|---|
| Privacy | a SHA-256 digest would leave the machine for a third party; it requires explicit opt-in and a clear explanation of what is sent |
| Trust boundary | a remote verdict must never overwrite the local ClamAV result; it is additional context, not a replacement |
| Resilience | rate limits (HTTP 429), timeouts, offline behaviour and partial failures need a dedicated gate |
| Product eligibility | Public API terms and product/use-case eligibility require maintainer review before external requests are enabled |

## Security and operational invariants

The active regression suite covers explicit opt-in, the independent maintainer
gate, Secret Service reachability and fail-closed storage, hash-only requests,
shared rate limiting, and preservation of the local ClamAV verdict.

The provider is reachable through the service, CLI and GTK settings workflow. Credentials
are stored only in Secret Service; no plaintext fallback exists. Availability
checks exercise a D-Bus operation rather than merely importing the binding.
Hash-only lookup is the default. Full-file submission is a separate optional
operation, available only after a fresh hash lookup reports no existing report
and the user explicitly consents to that exact file. The UI displays its name,
size, SHA-256 and privacy warning before consent. A private upload snapshot is
created only after consent and revalidated against the approved digest. Remote
verdicts remain supplemental metadata and never replace the local ClamAV result.

## Operational gates

- explicit opt-in is required before lookup;
- CLI checks opt-in before accessing Secret Service;
- Public provider eligibility is a separate maintainer-controlled hard gate;
- Premium access requires the user's valid Premium entitlement;
- API keys require reachable Secret Service; plaintext fallback is prohibited;
- rate limiting is shared across provider instances and processes;
- hash-only lookup is the default; full-file upload requires a fresh absent-hash
  result, explicit per-file consent and a post-consent SHA-256 revalidation;
- upload polling and remote verdicts remain separate from ClamAV results;
- GTK credentials are stored only in OS Secret Service; settings JSON never
  contains API keys.

## Verification

```bash
pytest -q tests/test_intelligence_frozen.py
rg -n "intelligence" clamguardian --glob "!clamguardian/intelligence/**"
git grep -n "clamguardian.threat_providers" -- pyproject.toml
```


## Dual API profiles (v2)

ClamGuardian supports explicit `public` and `premium` VirusTotal profiles.
Select the profile with `clamguardian intel profile public|premium`, and store
its credential independently with `clamguardian intel set-key --profile public|premium`.
Credentials are stored only in the operating system Secret Service; there is no
plaintext fallback. The selected profile is persisted in the owner-only settings
file. A key's appearance or format is never used to infer subscription level.

Hash lookup remains the default operation. Public API lookups remain blocked until
written VirusTotal clarification/authorization is recorded by the maintainer.
Premium use requires the user's actual Premium entitlement and credential. There
is no automatic fallback between profiles.

File submission is a separate, explicit operation. The UI/service must present
the file name, size, SHA-256 and privacy warning, then obtain a fresh per-file
affirmative consent immediately before upload. Sensitive, confidential, personal,
or regulated files must not be submitted. The upload path rechecks the file digest
to detect changes after preview. Uploads are limited to 650 MiB; files above 32 MiB
use VirusTotal's one-time upload URL. Analysis is polled and reported separately
from the local ClamAV verdict.

Public request pacing is 4 requests/minute and 500 requests/day, tracked in an
owner-only cross-process state file. Premium throughput and quotas remain subject
to the subscription; HTTP 429 and `Retry-After` are surfaced without falling back
to Public. Upstream response bodies and credentials are not copied into logs.


## Desktop workflow

Open **Settings → Automation & Protection** to enable Threat Intelligence and
select the Public or Premium API profile. Under **VirusTotal Integration**, enter
the corresponding credential and save it to OS Secret Service. Credentials are
never written to the settings file. Public network requests remain blocked until
written VirusTotal eligibility authorization is recorded; do not select Public
as a workaround for missing Premium entitlement.

The **Choose file…** action is separate from scan-result enrichment. It first
computes the local SHA-256 and queries the selected profile. If a report exists,
the report is displayed and no upload is attempted. If the hash is absent, the
application displays the file name, size, digest and disclosure warning. Only
the explicit **Upload file** response authorizes transmission. Closing the
dialog or choosing Cancel sends no file contents. The upload is then polled and
its status shown separately from the ClamAV verdict.

CLI equivalents:

```bash
clamguardian intel profile premium
clamguardian intel set-key --profile premium
clamguardian intel status --json
clamguardian intel upload /path/to/file
```

The CLI requires typing `UPLOAD` at the per-file confirmation prompt. Never
submit confidential, personal, proprietary, regulated or otherwise sensitive
files. VirusTotal may retain, analyze and share submitted samples under its
policies.
