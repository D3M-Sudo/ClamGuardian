# Architecture Freeze v1 (post M0.5 — Core Hardening)

> **M2 addendum (Scan Profiles):** `BaseAVEngine.scan`, `ScanTaskRunner.submit/create_task`
> e `ShieldTaskController.scan` accettano ora un parametro opzionale
> `profile: ScanProfile | None`. Il default `None` preserva esattamente il
> comportamento pre-M2 (backward compatible). Il profilo vive in
> `clamguardian/core/profiles.py`, è immutabile e validato
> (`ProfileError`), e la sua traduzione verso clamd/clamscan avviene
> esclusivamente nel layer engine. Dettagli: `docs/design/scan-profiles.md`.

Questo documento descrive le API del core **così come esistono dopo M0.5**.
È il contratto di riferimento per tutti i front-end futuri (GTK, CLI, headless).
Le interfacce qui definite sono congelate: modifiche breaking richiedono una
nuova versione di questo documento.

---

## 1. Core interfaces

Tutte le primitive vivono in `clamguardian/core` e sono riesportate da
`clamguardian.core`.

### `BaseAVEngine` (`core/base.py`)

```python
class BaseAVEngine(ABC):
    name: str
    async def scan(self, target: Path, *, recursive: bool = True) -> ScanResult: ...
    async def update_signatures(self) -> str: ...
```

### `ScanStatus` (`core/base.py`)

Enum dei stati terminali di uno scan, mutuamente esclusivi:

```text
CLEAN · INFECTED · ERROR · TIMEOUT · CANCELLED
```

`CANCELLED` è semanticamente distinto da `ERROR` e `TIMEOUT`: la cancellation
è richiesta dal chiamante, non è un fallimento del motore.

### `ScanResult` (`core/base.py`)

Dataclass immutabile (`frozen=True, slots=True`):

| Campo            | Tipo                | Note                                            |
|------------------|---------------------|-------------------------------------------------|
| `target`         | `str`               | percorso scansionato                            |
| `clean`          | `bool`              | legacy, sempre consistente con `status`         |
| `status`         | `ScanStatus`        | **stato autorevole**                            |
| `threats`        | `tuple[str, ...]`   | righe detections dell'engine                    |
| `files_scanned`  | `int`               | 0 se l'engine non lo espone                     |
| `engine`         | `str`               | `clamd` / `clamscan` / …                        |
| `error`          | `str \| None`       | solo per `ERROR`                                |
| `metadata`       | `dict[str, str]`    | dati extra opzionali dell'engine                |
| `started_at` / `finished_at` | `datetime` (UTC) |                                    |

Proprietà: `duration_seconds`.
Costruttori helper: `ScanResult.cancelled(target)`, `ScanResult.timed_out(target)`.
`__post_init__` normalizza `status` e `clean` affinché non esistano combinazioni
ambigue di booleani.

### `ScanProgress` (`core/base.py`)

Snapshot immutabile del progresso in-flight:

```python
@dataclass(frozen=True, slots=True)
class ScanProgress:
    phase: str = "scanning"          # label libera scelta dall'engine
    files_scanned: int = 0
    bytes_scanned: int = 0
    current_path: str | None = None
    threats_found: int = 0
    elapsed_seconds: float = 0.0
    percent: float | None = None     # opzionale: spesso NON disponibile
```

`percent` deve essere trattato come assente a meno che l'engine non possa
calcolarlo realmente (né clamd né `clamscan --no-summary` lo forniscono).

### `ScanTaskRunner` (`core/runner.py`)

```python
class ScanTaskRunner:
    def __init__(self, engine: BaseAVEngine, max_concurrency: int = 2): ...
    async def submit(self, target, *, recursive=True,
                     on_start: Callable[[], None] | None = None) -> ScanResult
    def create_task(self, target, *, recursive=True,
                    on_start: Callable[[], None] | None = None) -> asyncio.Task[ScanResult]
    async def cancel_all(self) -> None
    @property
    def active_count(self) -> int
```

Lifecycle garantito:

```text
create ──▶ running ──▶ completed / failed / cancelled ──▶ cleanup
```

* ogni task è registrato in `_tasks` e rimosso al completamento, fallimento o
  cancellation (`finally` + done callback, idempotenti) — nessun task resta
  registrato indefinitamente;
* la concurrency è limitata da `asyncio.Semaphore(max_concurrency)`;
* `on_start` è invocato esattamente una volta, dopo l'acquisizione dello slot
  (cioè quando lo scan gira davvero, non mentre è in coda);
* le eccezioni non vengono mai silenziosamente perse: propagano al chiamante
  (asyncio logga le eccezioni di task mai recuperate);
* `cancel_all()` cancella solo task non ancora terminati e attende il settle.

### Errori (`core/errors.py`)

```python
class ClamGuardianError(Exception): ...
class EngineError(ClamGuardianError): ...
```

---

## 2. Scan lifecycle

```text
created ──▶ running ──▶ completed (CLEAN / INFECTED)
                 ├──▶ failed     (ERROR, via EngineError)
                 ├──▶ timeout    (TIMEOUT, come ScanResult)
                 └──▶ cancelled  (CANCELLED, via asyncio.CancelledError)
```

Regole:

* `TIMEOUT` è rappresentato come `ScanResult` con `status=TIMEOUT`, non come
  eccezione verso il chiamante;
* `CANCELLED` **non** viene mai convertito in errore generico: il chiamante
  osserva sempre `asyncio.CancelledError`;
* i fallimenti del motore (binario mancante, freshclam non a zero) propagano
  come `EngineError`.

---

## 3. Events (`ShieldTaskController`)

| Signal            | Payload            | Semantica                                                                    |
|-------------------|--------------------|------------------------------------------------------------------------------|
| `scan-started`    | `(target: str)`    | emesso **una sola volta**, quando lo scan entra effettivamente in running (slot di concorrenza acquisito), mai mentre è in coda |
| `threat-detected` | `(target, threat)` | una emissione per minaccia trovata; **non** implica che lo scan sia terminato; emesso prima di `scan-finished` |
| `scan-finished`   | `(ScanResult,)`    | solo per scan conclusi con risultato (clean, infected, error, timeout)       |
| `scan-cancelled`  | `(target: str)`    | emesso **invece** di `scan-finished` quando il chiamante cancella; sempre seguito dal re-raise di `CancelledError` |

Le eccezioni del motore (`EngineError`) non generano segnali: propagano al
chiamante, che decide come mostrarle.

---

## 4. Cancellation semantics

Quando il chiamante cancella uno scan:

```text
ScanTask.cancel() / cancel_all()
  └─▶ asyncio.CancelledError nel task
        └─▶ ClamAVEngine._run_command()
              ├─ SIGTERM al process group (start_new_session=True)
              ├─ attesa limitata (TERMINATE_GRACE_SECONDS = 5 s)
              ├─ SIGKILL al process group se necessario
              ├─ await process.wait()   (no zombie)
              └─ re-raise CancelledError
                    └─▶ controller: emit "scan-cancelled" + re-raise
```

Garanzie:

* nessun `clamscan`/`freshclam` orfano: il segnale va all'intero process group;
* nessun doppio kill: `_terminate_process` è no-op su processo già terminato;
* cancellazione prima dell'avvio: l'engine non viene mai invocato;
* `CancelledError` resta distinguibile da error/timeout/threat/clean a ogni
  livello della catena (engine → runner → controller → UI).

---

## 5. Engine abstraction (`ClamAVEngine`)

* **clamd UNIX socket** — primo tentativo se `socket_path` esiste
  (`SCAN <path>` su connessione UNIX); timeout/errore di socket → fallback;
* **CLI fallback** — `clamscan --no-summary [--recursive] <target>`;
* **Flatpak host execution** — con `flatpak_host=True` ogni comando è
  prefissato con `flatpak-spawn --host` (vale anche per `freshclam`);
* `command_timeout` limita ogni comando; il timeout del CLI scan produce
  `ScanResult(status=TIMEOUT)`;
* subprocess avviati con `start_new_session=True` e connessi con
  `stdin=DEVNULL`, `stdout=PIPE`, `stderr=STDOUT`.

---

## 6. Boundary

```text
GTK4/Adw UI            (clamguardian.ui.*)
   │  consuma solo segnali GObject + ScanResult
Controller             (clamguardian.ui.controller.ShieldTaskController)
   │
Core                   (clamguardian.core.*, clamguardian.engines.*)
   │  nessuna dipendenza da GTK; nessuna stampa; nessuna UI
ClamAV                 (clamd / clamscan / freshclam)
```

* il **Core** non importa `gi`, non stampa, non gestisce la presentazione;
* la **GTK UI** non tocca subprocess né socket: passa solo dal controller/core;
* il **future CLI** e i front-end headless useranno direttamente
  `ScanTaskRunner` + `BaseAVEngine` con la stessa API, senza implementazioni
  parallele.

---

## 7. Privileges

> Per M0–M4 **non** viene introdotto un persistent privileged system service.

Le operazioni privilegiate rimangono one-shot dove necessario. La decisione su
eventuali `systemd service`, D-Bus, fanotify o privileged daemon è rimandata
alla progettazione concreta delle milestone real-time/on-access.

