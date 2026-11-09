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

## Why it is frozen

| Reason | Detail |
|---|---|
| Privacy | a SHA-256 digest would leave the machine for a third party; it requires explicit opt-in and a clear explanation of what is sent |
| Trust boundary | a remote verdict must never overwrite the local ClamAV result; it is additional context, not a replacement |
| Resilience | rate limits (HTTP 429), timeouts, offline behaviour and partial failures need a dedicated gate |
| Product scope | Phase 11 is scheduled for `v1.2.0`, after the 1.0 release gate |

## Current invariants (guarded by tests)

`tests/test_intelligence_frozen.py` enforces:

1. no production module imports the package (AST analysis, including relative
   imports and dynamic `importlib` string constants);
2. no `clamguardian.threat_providers` entry point is declared in
   `pyproject.toml`;
3. `ThreatProviderManager()` has no providers unless one is registered
   explicitly;
4. the `intelligence` extra exists but installs nothing new;
5. `VirusTotalProvider` rejects an empty API key and a malformed digest before
   any network call, and an upstream error never echoes the key.

## Accepted risk

Shipping unreachable code has a maintenance cost and could be wired by mistake.
The guard tests fail if any production module imports it, so an accidental
activation is caught in CI. The package has no side effects on import and no
credential storage: the API key is passed to the constructor, kept in memory
and sent only in the `x-apikey` header of an explicit `lookup_hash` call.

## Operational gates

- **M1 Privacy**: explicit opt-in, statement of which hashes are sent.
- **M2 Provider**: wire the call site; keep the lookup asynchronous and
  cancellable.
- **M3 Resilience**: rate limiting, timeouts, offline and partial-failure
  behaviour.
- **M4 Trust boundary**: keep the remote verdict separate from the local
  ClamAV result in storage and UI.
- **M5 Test/gate**: mocked provider, opt-in, no network access when disabled.

## Verification

```bash
pytest -q tests/test_intelligence_frozen.py
rg -n "intelligence" clamguardian --glob "!clamguardian/intelligence/**"
git grep -n "clamguardian.threat_providers" -- pyproject.toml
```
