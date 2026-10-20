# Runtime network exposure — accepted risk (AUD-06)

## Finding

The session container exposes three listeners on all interfaces:

| Port | Owner | Evidence |
|---:|---|---|
| 8080 | session infrastructure (agent runtime) | `/proc/net/tcp` local address `00000000:1F90`, state `0A` |
| 8081 | session infrastructure (agent runtime) | `/proc/net/tcp` local address `00000000:1F91`, state `0A` |
| 15001 | session infrastructure (agent runtime) | `/proc/net/tcp` local address `00000000:3A99`, state `0A` |

None of these ports belongs to ClamGuardian: the application opens no TCP
listener (it only reaches host ClamAV through `flatpak-spawn` and downloads
third-party databases on explicit user action). `ss` and `lsof` are not
installed in the image, so a PID-to-port mapping could not be produced locally.

## Why it is not fixed in this repository

The listeners are created by the execution environment, not by project code.
Changing them requires an infrastructure/network change (bind to loopback,
firewall rule or platform network policy), which is outside the repository and
outside the release artefact.

## Accepted risk and mitigations

- **Accepted by:** ClamGuardian maintainers, 2026-10-19.
- **Scope:** session/CI container only; the Flatpak app does not expose ports.
- **Mitigation:** the host must not publish these ports beyond loopback; the
  platform network policy is the enforcement point.
- **If the ports must be reachable:** require authentication and TLS at the
  platform layer; never expose the agent runtime directly to an untrusted
  network.

## Verification

On a host that provides the tooling:

```bash
ss -ltnp | grep -E ':(8080|8081|15001)\b'
# expected before remediation: 0.0.0.0:8080, 0.0.0.0:8081, 0.0.0.0:15001
```

Without `ss`, inspect `/proc/net/tcp` and decode the little-endian port:

```bash
awk 'NR>1 && $4=="0A" {print $2}' /proc/net/tcp
```

## Review trigger

Re-open this decision if the session tooling changes, if the host publishes
the ports, or before shipping any environment that runs the agent runtime on a
shared network.
