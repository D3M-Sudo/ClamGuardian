# CLI / Headless design (M3)

## Positioning

The CLI is a **second front-end over the same Core** used by the GTK UI:

```text
              ┌──────────────┐
              │     GTK      │
              └──────┬───────┘
              ┌──────▼───────┐
              │     CLI      │   clamguardian.cli.*
              └──────┬───────┘
                     ▼
             ┌───────────────┐
             │     CORE      │
             │  Profiles · Runner · Results · Cancellation
             └───────┬───────┘
                     ▼
             ┌───────────────┐
             │ ClamAVEngine  │
             └───────┬───────┘
                 clamd  clamscan
```

The CLI package is intentionally small:

```text
clamguardian/cli/
├── __init__.py     # re-exports run/build_parser + exit codes
├── exit_codes.py   # centralized exit-code policy
├── output.py       # human formatting + deterministic JSON serializer
├── main.py         # argparse parser, command handlers, event loop
└── __main__.py     # python -m clamguardian.cli
```

**The CLI never**: spawns subprocesses, touches clamd sockets, builds ClamAV
flags, duplicates profiles, or converts `CancelledError` into a generic
error. Scan orchestration is `ScanProfileRegistry → ScanTaskRunner →
BaseAVEngine`, exactly as for the GTK controller.

## Commands

| Command     | Status | Notes                                                        |
| ----------- | ------ | ------------------------------------------------------------ |
| `scan`      | ✅ M3  | `clamguardian scan PATH [--profile ID] [--json]`             |
| `profiles`  | ✅ M3  | reads `DEFAULT_REGISTRY.list()`; `--json` supported          |
| `version`   | ✅ M3  | from `clamguardian.__version__` (single source of truth)     |
| `databases` | ❌ M3  | see "Why no `databases` command" below                       |

### Default profile

Without `--profile` the CLI uses the Core's `DEFAULT_PROFILE`
(id `default`, *Standard Scan*) — the same backward-compatible default the
engine applies pre-M2. It is **not** duplicated in the CLI; `--profile` ids
are resolved exclusively via `ScanProfileRegistry.get()` (`quick`, `home`,
`full`, `custom`), and unknown ids are a usage error (exit 2).

### Progress

`ScanProgress.percent` is optional and the ClamAV engine does not currently
stream progress, so the CLI prints only `Scanning...` and never fabricates a
percentage or file count.

## JSON contract (`scan --json`)

One JSON object on stdout; diagnostics go to stderr. Deterministic key set
and order:

| Key                | Type            | Semantics                                   |
| ------------------ | --------------- | ------------------------------------------- |
| `status`           | `str`           | `clean` / `infected` / `error` / `timeout` / `cancelled` |
| `profile`          | `str`           | profile id actually used                    |
| `target`           | `str`           | resolved target path                        |
| `engine`           | `str \| null`   | `clamd` / `clamscan`; `null` if cancelled   |
| `threats`          | `list[str]`     | engine detection lines                      |
| `files_scanned`    | `int`           | 0 when the engine does not expose it        |
| `duration_seconds` | `float \| null` | `null` for cancellations                    |
| `error`            | `str \| null`   | engine error text, if any                   |
| `metadata`         | `object`        | engine metadata (e.g. `profile_id`)         |

On Ctrl+C with `--json`, a payload with `"status": "cancelled"` is still
emitted on stdout, with the human message on stderr.

## Exit codes

Centralized in `clamguardian/cli/exit_codes.py`:

| Code | Meaning                                |
| ---- | -------------------------------------- |
| 0    | scan completed successfully / clean    |
| 1    | scan completed and threats detected    |
| 2    | usage / CLI argument error             |
| 3    | engine or runtime error                |
| 4    | scan timeout                           |
| 5    | scan cancelled by the user (Ctrl+C)    |

## Ctrl+C / cancellation

```text
Ctrl+C (SIGINT)
  └─▶ asyncio.run(): main task cancelled
        └─▶ ScanTaskRunner.submit() → CancelledError
              └─▶ ClamAVEngine._run_command()
                    ├─ SIGTERM to the process group (start_new_session=True)
                    ├─ TERMINATE_GRACE_SECONDS grace
                    ├─ SIGKILL if needed
                    └─ await process.wait()   (no zombie/orphan)
                          └─ re-raise CancelledError
                                └─▶ CLI: message on stderr, exit code 5
```

`CancelledError` is never swallowed or converted into a generic error: exit
code 5 preserves the M0.5 distinction between *caller-requested
cancellation* and *engine failure*.

## Why no `databases` command in M3

`DatabaseManager` requires explicit `database_dir` / `state_file` paths and
is designed around UI-driven flows (providers, status callbacks, confirmed
removals). Inventing CLI-default paths now would be an arbitrary policy
choice outside the Core; the command is deferred until a Headless-approved
configuration surface exists.

## Future hooks (M4+, not implemented here)

The `ScanResult` produced by `scan` is the natural input for a history
database and reporting layer; the JSON contract above is designed to stay
stable so M4 can consume it without CLI changes.
