# Threat intelligence — opt-in, eligibility-gated VirusTotal integration

## Status

`clamguardian.intelligence` is integrated with scan-result enrichment and CLI
configuration, but external VirusTotal requests remain administratively
blocked by default:

- CLI commands provide key setup, status, enable, disable and lookup; GTK scan
  completion adds supplemental hash-only metadata when permitted;
- `pyproject.toml` declares no `clamguardian.threat_providers` entry point;
- the `intelligence` extra is reserved and intentionally empty;
- importing the package performs no network I/O and reads no secrets.

VirusTotal remains opt-in. The maintainer eligibility constant remains false
until applicable Public API terms and product/use-case eligibility have been
reviewed. A user preference cannot bypass that administrative hard gate.

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

The provider is reachable only through the gated service and CLI. Credentials
are stored only in Secret Service; no plaintext fallback exists. Availability
checks exercise a D-Bus operation rather than merely importing the binding.
Only SHA-256 hashes are sent; file contents are never uploaded. Remote verdicts
remain supplemental metadata and never replace the local ClamAV result.

## Operational gates

- explicit opt-in is required before lookup;
- CLI checks opt-in before accessing Secret Service;
- provider eligibility is a separate maintainer-controlled hard gate;
- API keys require reachable Secret Service; plaintext fallback is prohibited;
- rate limiting is shared across provider instances and processes;
- only hashes are sent and remote verdicts remain separate from ClamAV results.

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
