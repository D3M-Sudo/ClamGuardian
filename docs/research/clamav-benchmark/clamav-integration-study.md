# ClamAV Integration Study

## 1. Component responsibilities

| Component | Responsibility | ClamGuardian relationship |
|---|---|---|
| `libclamav` | Scanning engine library | Indirectly used by host programs/daemon |
| `clamd` | Long-running multi-threaded daemon | Direct UNIX-socket protocol client |
| `clamscan` | Standalone scanner | Narrow fallback |
| `clamdscan` | Standard CLI client for clamd | Diagnostics/validation, not normal backend |
| `freshclam` | Official signature database updater | Invoked for official updates |
| `clamonacc` | Linux on-access client for clamd | Not integrated; privileged capability deferred |
| `sigtool` | Signature/database inspection | Not in normal scan flow |

References: [ClamAV Usage](https://docs.clamav.net/manual/Usage.html), [Terminology](https://docs.clamav.net/appendix/Terminology.html), [ClamD Protocol](https://docs.clamav.net/manual/Usage/ClamdProtocol.html), [Scanning](https://docs.clamav.net/manual/Usage/Scanning.html), [Signature Management](https://docs.clamav.net/manual/Usage/SignatureManagement.html), [On-Access](https://docs.clamav.net/manual/OnAccess.html).

## 2. clamd protocol and transports

ClamGuardian opens a UNIX stream socket and sends `SCAN` or `CONTSCAN` with a path. It reads until EOF because directory scans may emit multiple result lines. Control characters in paths are rejected.

ClamAV's protocol documentation recommends explicit command framing for new clients (`zCOMMAND\\0` or `nCOMMAND\\n`). The current ClamGuardian path command uses legacy unprefixed newline framing; descriptor FILDES/INSTREAM requests use newline-prefixed framing. Evaluate explicit framing as a focused hardening change.

- UNIX sockets support path commands, INSTREAM and FILDES when descriptor passing is available.
- TCP supports path commands when the path exists on the daemon host, and INSTREAM; it does not support FILDES. ClamD TCP is unauthenticated and unencrypted. Do not make remote TCP the default.
- FILDES preserves the opened descriptor and is preferred when available.
- INSTREAM transmits the already-open content in length-prefixed chunks.

The descriptor path probes `VERSIONCOMMANDS`, uses FILDES when advertised and otherwise INSTREAM. It never falls back to a pathname scan. Preserve this TOCTOU invariant.

## 3. clamscan fallback

ClamGuardian uses clamscan only when no socket exists or the initial daemon connection is unavailable/refused. It does not rerun a scan after daemon timeout or protocol failure.

The command uses argv rather than a shell, bounded output, inactivity/maximum timeouts and process-group termination. Profile translation maps recursion, archive/mail scanning, PUA, file/scan size, recursion depth, file count and symlink behavior to clamscan flags.

ClamAV limits may cause large files or archive members to be skipped/truncated. Represent such cases as partial coverage, not unconditional clean. Validate option semantics against the installed ClamAV version.

## 4. clamdscan versus direct protocol

`clamdscan` is the standard command-line client. Local path mode asks the daemon to open paths; `--fdpass` uses FILDES over UNIX socket; `--stream` uses INSTREAM. Remote TCP uses INSTREAM. `--multiscan` behavior differs by local-path versus descriptor/stream mode.

ClamGuardian's direct client is justified by descriptor identity, cancellation and result handling. Replacing it wholesale requires proof that those invariants and error/partial-result semantics are preserved. Keep clamdscan as a diagnostic/compatibility reference.

## 5. FreshClam and database ownership

FreshClam manages official CVD/CLD databases from a valid `freshclam.conf`. ClamGuardian's `update_signatures()` invokes the configured executable and reports non-zero exit as an engine error; it does not own systemd service state or all distribution-specific lifecycle rules.

Distributions may run FreshClam as a service/timer. A manual update can conflict with an active updater or package-managed configuration. Before adding UI controls, detect and explain the active update mechanism; do not stop, disable or reconfigure host services automatically.

Third-party databases remain a separate application-managed domain: HTTPS, staging, SHA-256 verification and rollback. Keep ownership separate from official FreshClam files.

## 6. clamonacc and fanotify

ClamAV On-Access is Linux-only and uses fanotify. The documented setup runs clamd and clamonacc side by side. Elevated permissions are required for kernel event/intervention capabilities. Notify-only and prevention are distinct; prevention can materially affect performance. Some kernels lack `CONFIG_FANOTIFY_ACCESS_PERMISSIONS`, making blocking unavailable.

ClamGuardian inotify reacts to filesystem events and scans afterward; it does not block access. Keep 2.x-B deferred. Any future proposal needs privilege boundaries, performance impact, failure-open/closed policy, exclusions, deadlock prevention, kernel capability detection and recovery.

## 7. Proposed sequence

1. Surface clamd profile limitations in GTK and CLI, not metadata only.
2. Add structured skipped-file and warning semantics to ScanResult/history.
3. Evaluate explicit ClamD command framing and newline path support.
4. Test malformed/partial protocol replies, timeout, refusal, missing capabilities, FILDES failure, INSTREAM limits and partial detections.
5. Add FreshClam service/update conflict diagnostics without taking ownership of system services.
6. Keep fanotify/clamonacc a separate research gate.

## 8. P1 finding — pathname ClamD response can be classified CLEAN without a valid reply

**VERIFIED at pinned ClamGuardian baseline `b42c01612d34ef20b980518aa9b3845f48ea4210`:**

- `_scan_socket()` reads the response until EOF, then sets the returned code to failure only when a line matches its current broad `ERROR` substring/suffix check.
- An empty response, whitespace-only response or unrecognized response line therefore leaves the returned code at zero.
- `_result()` maps `exit_code == 0` with no recognized detection lines to `ScanStatus.CLEAN`.

This creates a fail-open classification path: a connected daemon socket that closes without a valid scan result, or returns unrecognized output, can be represented as CLEAN. This finding concerns the pathname SCAN/CONTSCAN response path; the descriptor-response parser has separate explicit response validation. It is not a claim that a healthy ClamD normally returns an empty response. It is a correctness defect in how the client interprets missing or invalid protocol evidence.

Immutable source anchors:
- [_scan_socket() and response-code construction](https://github.com/D3M-Sudo/ClamGuardian/blob/b42c01612d34ef20b980518aa9b3845f48ea4210/clamguardian/engines/clamav.py#L673-L721)
- [_result() status classification](https://github.com/D3M-Sudo/ClamGuardian/blob/b42c01612d34ef20b980518aa9b3845f48ea4210/clamguardian/engines/clamav.py#L989-L1015)
- [Existing engine tests](https://github.com/D3M-Sudo/ClamGuardian/blob/b42c01612d34ef20b980518aa9b3845f48ea4210/tests/test_engine.py)

**Required fix contract:** only a non-empty response in which every line is recognized as a valid ClamD result may produce CLEAN or INFECTED. Empty, whitespace-only, malformed, truncated, mixed valid/unknown, or explicit ERROR responses must produce ERROR (or another non-clean failure status), never CLEAN. Preserve any parsed detections as diagnostic evidence, but do not report a successful complete scan when the protocol response is invalid.

**Regression matrix:** empty response; whitespace-only response; unknown command/protocol text; truncated result line; valid clean line; valid FOUND line; valid multi-line directory result; ERROR-only response; valid result mixed with an unknown line; response-size overflow. Assert no CLI fallback after a connection has been established, and assert that every invalid/error case is non-CLEAN.

**Disposition:** P1 correctness fix is being handled on a separate implementation branch/PR. It is not folded into this research/documentation PR.
