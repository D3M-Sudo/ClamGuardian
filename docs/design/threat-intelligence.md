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
