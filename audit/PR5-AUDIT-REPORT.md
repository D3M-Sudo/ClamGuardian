# ClamGuardian — Audit indipendente READ-ONLY della PR #5

**Data:** 13 ottobre 2026
**Repository:** `D3M-Sudo/ClamGuardian`
**PR:** #5 — *Complete ClamGuardian roadmap M4 through 2.x-A* (`OPEN`, base `feature`)
**Commit esaminato:** `3bf087316f683bac012ffcd370a8b3ffd149c951` (HEAD della PR)
**Baseline PR:** `a33d6a6b1f1d689f2bd8e273b34b4c7e4ff31d5a` · parent di HEAD: `60bf0eb`
**Natura dell'audit:** sola lettura. Nessun file del progetto modificato, nessuna operazione Git di scrittura sul branch della PR.

> Questo documento e gli script di riproduzione vivono **solo** sul branch di servizio `cline/1afzx1w5`
> (cartella `audit/`), creato per non toccare né `feature-756467115717530540` né `feature`.

---

## 1. Metodo e ambiente

Evidenze raccolte:

| Cosa | Comando / strumento | Esito |
|---|---|---|
| Identità del commit | `git rev-parse HEAD` | `3bf0873…` = `headRefOid` della PR |
| CI del commit esaminato | `gh run view 34688533042` | `success` sui 3 job (3.11 / 3.12 / 3.13), step Lint, Type Check, Security Audit, Test tutti `success` |
| Suite locale | `python -m pytest` (pytest 9.1.1) | **213 passed, 2 skipped** (214 item raccolti; 211 funzioni `def test`; 2 skip = PyGObject/GTK assente) |
| Ruff | `ruff check --no-cache .` | `All checks passed!` |
| mypy | `mypy clamguardian` | `Success: no issues found in 36 source files` |
| pip-audit | `pip-audit` | **non riproducibile in sandbox** (intercettazione TLS del proxy); in CI lo step risulta `success` |
| Differenza PR | `git diff --stat a33d6a6 3bf0873` | 35 file, +2933 / −40 |
| Differenza remediation | `git diff --stat c2e7532 3bf0873` | `realtime/orchestrator.py` +145, `realtime/inotify.py` +91, `test_realtime.py` +84, design doc +346, `ci.yml` ±1 |
| Prova empirica realtime | `audit/repro/rt_probe.py`, `stress_probe.py`, `race_probe*.py` | 4 difetti riprodotti |
| Prova empirica inotify | `audit/repro/inot_probe.py`, `phantom_probe.py` | 3 difetti riprodotti + 1 limitazione |

Gli script in `audit/repro/` sono eseguibili con:

```bash
PYTHONPATH=/workspace python audit/repro/rt_probe.py
PYTHONPATH=/workspace python audit/repro/inot_probe.py
PYTHONPATH=/workspace python audit/repro/stress_probe.py
PYTHONPATH=/workspace python audit/repro/phantom_probe.py
```

---

## 2. Verdetto sintetico

1. **La CI verde non equivale ad approvazione.** Il commit esaminato passa lint, typing, audit dipendenze e test, e la suite è riproducibile in locale. I difetti trovati sono **tutti in rami non coperti dai test esistenti**, quindi nessun gate automatico li avrebbe intercettati.
2. **Dei tre P1 realtime storici, uno è chiuso, due sono solo parzialmente chiusi**, e la remediation ne ha introdotti di nuovi (dedup e shutdown).
3. **M4 Final non è chiudibile**: SHA-256 manca sul percorso primario (clamd) e la propagazione del profilo non è deterministica su tutti i percorsi.
4. **M5 non è chiudibile**: il digest dei database è opzionale (installazione senza verifica di integrità) e due obiettivi dichiarati (quarantine streaming, validazione dei target speciali) non sono implementati.
5. **M7 / 1.0 non è chiudibile**: manca l'icona referenziata dal desktop entry, il metainfo AppStream non è validabile, il manifest Flatpak non è pinnato e non installa l'integrazione desktop.
6. **1.1, Threat Intelligence e 2.x-A non sono cablati**: `core/usb.py`, `intelligence/` e `realtime/` non sono importati da nessun entry point di produzione (CLI/UI). Nessun comando li espone, quindi **nessuna di queste fasi è validabile end-to-end**.
7. **Documentazione materialmente fuorviante**: `docs/ROADMAP.md` marca `PENDING` le fasi che lo stesso commit implementa; il documento di remediation descrive come attuali tre difetti già rimediati e cita test inesistenti; l'handoff è fermo al 30 agosto 2026.

**Raccomandazione operativa:** non aggiungere funzionalità. Riparare i difetti confermati, **separare il perimetro 1.0 da 1.1/2.x-A** e chiudere i gate nell'ordine proposto nel documento `audit/NEXT-STEPS-PLAN.md`.

---

## 3. I tre finding P1 realtime storici: verifica sul comportamento reale

| Finding storico | Esito | Evidenza |
|---|---|---|
| `P1-REALTIME-DEBOUNCE` (debounce pull-driven) | **CHIUSO** | `orchestrator.py:139-141` arma `loop.call_later(...)`; `_on_debounce_expired` (`:144-149`) crea il task. Prova: scenario A di `rt_probe.py` → **un singolo evento produce 1 scansione** dopo la finestra, senza ulteriori chiamate a `handle_events()`. Test esistente: `tests/test_realtime.py:110`. |
| `P1-REALTIME-QUEUE-BOUND` (limite coda incompleto) | **NON CHIUSO** | Il limite è calcolato su *path distinti* (`orchestrator.py:108`, `:197`: `len(_pending_events) + len(_active_scans)`, dove `_active_scans` è un `set[Path]` a `:53`). Con `max_queue_depth=3` si osservano **4 scansioni concorrenti** mentre l'accounting resta ≤ 3 (`stress_probe.py`, sola API pubblica). Il test esistente (`test_realtime.py:133`) verifica solo `dropped_events_count == 3`, mai l'invariante durante l'esecuzione. |
| `P1-REALTIME-RECURSIVE-WATCH` (watch non ricorsivi) | **CHIUSO PARZIALMENTE** | I casi richiesti funzionano: sottodirectory preesistenti (`I1`), directory create dopo il watch (`I2`), directory **spostate dentro** l'albero (`I3`), directory cancellate e ricreate (`I5`). Manca però la gestione del caso inverso: directory **spostate fuori** dall'albero → watch stale (vedi `P2-RT-05`). |

---

## 4. Finding realtime (verificati empiricamente)

### [P1] `P1-RT-01` — Scansioni duplicate concorrenti dello stesso percorso

**File:** `clamguardian/realtime/orchestrator.py:151-164` (in particolare `:161`), `:144-149`

**Evidenza.** `_dispatch_scan` rimuove il timer dalla mappa **senza cancellarlo**:

```python
async def _dispatch_scan(self, path: Path, on_complete=None) -> None:
    async with self._lock:
        ...
        self._pending_events.pop(path, None)
        self._debounce_timers.pop(path, None)   # <-- handle rimossa ma NON cancellata
        self._active_scans.add(path)
```

Se un nuovo evento per lo stesso path viene gestito tra lo scadere del timer e il primo step del task di dispatch (finestra di una iterazione del loop), `handle_events` ri-arma un timer (`:99-106`) che `_dispatch_scan` poi rimuove dalla mappa senza disinnescare: quel timer scade comunque, `_on_debounce_expired` (`:148-149`) crea un secondo task, e `_dispatch_scan` **non verifica `_active_scans`** → due scansioni concorrenti dello stesso file.

Prove:
- `rt_probe.py` scenario B: 2 scansioni concorrenti dello stesso path (`max concurrent scans of one path = 2`), timer ancora armato quando il dispatch parte.
- `race_probe.py`: riproducibile con sola API pubblica, con jitter da 0 a +5 ms sull'istante di scadenza → **2 scansioni** in tutti i casi.
- `stress_probe.py` (60 batch di eventi randomizzati, sola API pubblica): duplicati in 4 seed su 5 (`f1.txt:2`, `f5.txt:2`).

**Impatto:** la deduplicazione dichiarata nel docstring e nel design doc non regge; doppio consumo di CPU/I-O, due righe di History per lo stesso evento, e — per via del punto `P1-RT-02` — il conteggio del backlog non rappresenta più il lavoro reale.

**Correzione minima:** in `_dispatch_scan`, se l'handle esiste ancora va `.cancel()` prima del `pop`; in alternativa il timer va rimosso dalla mappa in `_on_debounce_expired` all'atto dello scadere. Aggiungere inoltre in `_dispatch_scan` una guardia `if path in self._active_scans: self._dirty_paths.add(path); return`.

### [P1] `P1-RT-02` — Il bound della coda non è un bound sul lavoro reale

**File:** `clamguardian/realtime/orchestrator.py:53`, `:108-111`, `:195-203`

**Evidenza.** L'unità di conto è il **percorso**, non il task: `self._active_scans: set[Path]` (`:53`). N task concorrenti sullo stesso path contano 1. Misurato con `stress_probe.py` (`max_queue_depth=3`, `max_concurrency=4`):

```
peak(pending+active)=3   peak_concurrent_engine_scans=4   duplicate_dispatches=['f1.txt:2', 'f5.txt:2']
```

**Impatto:** `max_queue_depth` non limita il numero di scansioni in volo; sotto event storm il consumo reale può superare il limite dichiarato. Il gate `P1-REALTIME-QUEUE-BOUND` **non può essere considerato chiuso**.

**Correzione minima:** contabilizzare i task (`len(self._active_tasks)` al netto delle voci non attive) oppure un contatore intero incrementato/decrementato attorno a `_active_scans.add/discard`; rendere `_active_scans` un `dict[Path, int]`.

### [P1] `P1-RT-03` — Scansioni avviate dopo `close()` (shutdown non deterministico)

**File:** `clamguardian/core/runner.py:46-49` e `:74-80`; `clamguardian/realtime/orchestrator.py:205-215`

**Evidenza.** In `ScanTaskRunner.submit` il task viene registrato in `_tasks` **solo dopo** l'acquisizione del semaforo:

```python
async with self._semaphore:          # attesa potenzialmente lunga
    task = asyncio.current_task()
    if task is not None:
        self._tasks.add(task)        # registrazione tardiva
```

`cancel_all()` cancella solo ciò che è già in `_tasks`, quindi i task in attesa sul semaforo non vengono mai cancellati e **partono dopo lo shutdown**. Prova (`rt_probe.py` scenario D, `max_concurrency=1`, 3 path, `close()` durante la prima scansione):

```
scans started AFTER close()=1   (engine.started=[d0, d1, d2])
_active_tasks leaked after an aborted dispatch=1
```

**Impatto:** viola l'invariante "nessun task orfano / nessuna scansione dopo la chiusura" richiesto dalla checklist del gate 2.x-A.

**Correzione minima:** registrare il task in `_tasks` **prima** dell'attesa sul semaforo (o usare un `asyncio.TaskGroup`/contatore di pending con cancellazione esplicita), e far sì che `cancel_all` attenda anche i task non ancora partiti.

### [P2] `P2-RT-04` — `CancelledError` inghiottita: la cancellazione non è osservabile

**File:** `clamguardian/realtime/orchestrator.py:189-190`

```python
except asyncio.CancelledError:
    return ScanResult.cancelled(str(path))   # non viene ri-sollevata
```

**Evidenza** (`rt_probe.py` scenario E): dopo `close()` durante una scansione, lo stato del task di dispatch è `(done=True, cancelled=False)`; `await asyncio.gather(...)` restituisce un `ScanResult` invece di propagare la cancellazione.

**Impatto:** il chiamante non può distinguere una scansione cancellata da una completata, e la cancellazione non si propaga al di fuori del task. Inoltre l'esito `CANCELLED` **non viene registrato in History** (il ramo `except` precede la registrazione), mentre l'esito `ERROR` di un file sparito **sì** (`:170-182`): incoerenza nel contratto di History.

**Correzione minima:** registrare l'esito (best-effort) e poi `raise`; oppure restituire il risultato *senza* inghiottire la cancellazione usando `asyncio.current_task().uncancel()` consapevolmente.

### [P2] `P2-RT-05` — Watch stale su directory spostate fuori dall'albero: percorsi fantasma

**File:** `clamguardian/realtime/inotify.py:33-40` (mask con `MOVED_FROM`), `:126-138` (la mask è presente ma `MOVED_FROM` non è gestita)

**Evidenza.** `MOVED_FROM` è nella mask ma cade nel ramo `else: continue` (`:137-138`), quindi la mappa `_wd_map`/`_path_map` non viene ripulita quando una directory esce dall'albero monitorato.

- `inot_probe.py` scenario I4: dopo `mv root/sub → fuori/sub`, la creazione di `fuori/sub/escaped.txt` produce eventi con path **`…/root/sub/escaped.txt`** (percorso che non esiste più).
- `phantom_probe.py` (end-to-end monitor + orchestrator + History):

```
events from the monitor: ['/tmp/audit/phantom/root/sub/escaped.txt', ...]
real file on disk      : /tmp/audit/phantom/out/sub/escaped.txt exists: True
engine actually scanned: []
history row -> target=…/root/sub/escaped.txt status=error error='File disappeared or changed before scan'
```

**Impatto:** il file reale **non viene mai scansionato**, e in History vengono scritte righe di errore su un percorso inesistente. Riguarda direttamente la voce di checklist "directory spostate o eliminate, watch obsoleti".

**Correzione minima:** gestire `MOVED_FROM` con `IN_ISDIR` rimuovendo i watch del sottoalbero uscito (equivalente di `remove_watch` sul wd), e scartare gli eventi il cui `parent` non appartiene più all'insieme dei root watch.

### [P2] `P2-RT-06` — Saturazione dei watch inotify silenziosa (`ENOSPC`)

**File:** `clamguardian/realtime/inotify.py:58-70` (`_add_single_watch` cattura `OSError` e ritorna `-1`), `:42-56` (`add_watch` ritorna `-1` senza segnalare)

**Evidenza** (`inot_probe.py` I6, con `inotify_add_watch` che solleva `ENOSPC`): `add_watch(root)` ritorna `-1`, **nessuna eccezione, nessun contatore, nessun log**, e `read_events` resta vuoto. Il monitoraggio risulta silenziosamente assente.

**Impatto:** su sistemi con `max_user_watches` esaurito (nel sandbox: 12288) il realtime smette di funzionare senza che il chiamante possa accorgersene. `InotifyMonitor` non espone alcuno stato di salute.

**Correzione minima:** esporre un contatore/`last_error` e far fallire esplicitamente `add_watch` sul root, invece di ritornare `-1`.

### [P2] `P2-RT-07` — Overflow della coda inotify silenzioso (`IN_Q_OVERFLOW`)

**File:** `clamguardian/realtime/inotify.py:100-112`

**Evidenza** (`inot_probe.py` I8): creati 20 000 file senza leggere (limite kernel `max_queued_events=16384`), `read_events` restituisce esattamente 16 384 eventi e **nessuna indicazione di perdita**. L'evento di overflow arriva con `wd = -1` e viene scartato dal ramo `parent is None` (`:111-112`).

**Impatto:** sotto carico il monitor perde eventi in modo invisibile; i file non scansionati non vengono recuperati. Voce di checklist "saturazione delle risorse inotify".

**Correzione minima:** intercettare `flags.Q_OVERFLOW` (o `wd == -1`) e segnalarlo al chiamante (contatore + eccezione/errore tipizzato), così l'orchestratore può decidere un rescan completo della radice.

### [P3] `P3-RT-08` — Perdita di voci in `_active_tasks` quando il dispatch viene abortito da `close()`

**File:** `clamguardian/realtime/orchestrator.py:148-149` (inserimento) vs `:154-158` (uscita anticipata senza pulizia)

**Evidenza:** `rt_probe.py` scenario D → `_active_tasks leaked after an aborted dispatch=1`. Il task non viene mai atteso né rimosso (possibile warning "Task exception was never retrieved").

### [P3] `P3-RT-09` — `read_events` non contiene gli errori di `add_watch` (finestra TOCTOU)

**File:** `clamguardian/realtime/inotify.py:118-124`

`add_watch` (che esegue `Path(path).resolve(strict=True)`, `:44`) è chiamato senza `try/except`; la guardia `item_path.exists()` a `:122` è un controllo TOCTOU. Un `FileNotFoundError`/`OSError` in quella finestra risale al chiamante e interrompe il ciclo di lettura. **Inspection-only**: riproducibile solo con una finestra di gara reale.

### [P3] `P3-RT-10` — Nessun driver, nessuna integrazione: 2.x-A non è eseguibile

**Evidenza:** `grep -rn 'handle_events|read_events|add_watch' clamguardian | grep -v realtime/` → **nessun risultato**: `FileMonitor`, `InotifyMonitor` e `RealtimeScanOrchestrator` sono raggiunti solo dai test. Nessun sottocomando CLI (`clamguardian/cli/main.py`: solo `scan`, `profiles`, `version`, `history list|show|purge`), nessuna pagina UI. Inoltre `read_events` è sincrona e bloccante (`select` + `INotify.read`, `:89-96`) e non è mai eseguita su un executor/`add_reader`.

**Impatto:** la fase 2.x-A non è validabile end-to-end (nessun processo che la esegua), e il gate 08 non può essere chiuso per assenza di superficie d'uso. Stessa condizione per USB (`P2-USB-01`) e Threat Intelligence.

### [P3] `P3-RT-11` — Sottoalberi con symlink non sorvegliati, senza segnalazione

**File:** `clamguardian/realtime/inotify.py:49-54`, `:118-123` · **Evidenza:** `inot_probe.py` I7 → nessun evento per file creati dietro un link simbolico. È una scelta di sicurezza ragionevole (non uscire dall'albero), ma non è documentata né segnalata all'utente.

---

## 5. Finding M4 / M5 (revisione incrociata, ricontrollati sul codice)

### [P1] `P1-DB-01` — Il digest dei database è opzionale: installazione senza verifica di integrità

**File:** `clamguardian/databases/provider.py:47-49`, `clamguardian/databases/models.py:21` e `:44-47`, `clamguardian/ui/database_pages.py:190-191`

```python
# provider.py
if artifact.sha256:                 # se assente, nessuna verifica
    verify_sha256(temporary, artifact.sha256)
temporary.replace(output)           # installazione comunque
```

`DatabaseArtifact.sha256` è `str | None = None` (`models.py:21`), la validazione del formato scatta solo se il digest c'è (`models.py:44-47`), e la UI lo rende opzionale (`sha256=values["sha256"] or None`). Un artefatto senza digest viene scaricato e **installato senza alcun controllo di integrità**.

**Impatto:** è l'obiettivo M5 "database download integrity". Le definizioni antivirus sono il cuore del prodotto: accettare artefatti non verificati vanifica l'hardening. Nessun test copre questo percorso (`FileDatabaseProvider` non è mai istanziato nei test).

**Correzione minima:** rendere `sha256` obbligatorio (o introdurre un opt-out esplicito e tracciato) e testare il rifiuto.

### [P1] `P1-ENG-01` — SHA-256 assente sul percorso primario (clamd)

**File:** `clamguardian/engines/clamav.py:61-73` (ramo clamd con `return` anticipato) vs `:80-84` (hash solo dopo `_run_cli_scan`)

```python
if self.socket_path.exists():
    ...
    result.metadata["profile_id"] = profile.id
    return result                      # <-- nessun compute_file_sha256
...
sha256 = compute_file_sha256(target)   # solo sul fallback clamscan
```

**Evidenza:** confermato per lettura del codice; il revisore lo ha riprodotto con un socket finto (scan di un file singolo via clamd → `'sha256' in metadata == False`). I test coprono solo il fallback (socket inesistente), quindi la regressione è invisibile in CI.

**Impatto:** su una macchina con `clamd` attivo (percorso preferito, indicato nel README) **nessuno scan di file singolo registra l'hash**, quindi l'obiettivo M4 "Compute SHA-256 for single-file scan artifacts" non è soddisfatto sul percorso principale, e il seam di Threat Intelligence (lookup per hash) resta senza dato.

### [P2] `P2-HIST-01` — `profile_id` non validato, derivato da `result.metadata` non attendibile

**File:** `clamguardian/history/models.py:191-199`

Se `profile is None` e `metadata["profile_id"]` non è nel registry, l'eccezione viene inghiottita (`except Exception: profile = None`) e `profile_id` resta il **valore grezzo non validato** (verificato a runtime: `profile_id='totally-bogus-untrusted'`, `profile_snapshot=None`). Un id arbitrario finisce in DB ed è filtrabile via `list_scans(profile_id=...)`.

### [P2] `P2-HIST-02` — `DEFAULT_PROFILE` non è nel registry: snapshot perso sul percorso realtime

**File:** `clamguardian/core/profiles.py:115` (`DEFAULT_PROFILE.id = "default"`), `:151-153` (`DEFAULT_REGISTRY` = `quick/home/full/custom`), `clamguardian/engines/clamav.py:72,81`, `clamguardian/realtime/orchestrator.py:47,182`

L'engine marca sempre `metadata["profile_id"] = profile.id`, incluso `"default"`, che però non è risolvibile dal registry: sul percorso realtime (dove `profile=None`) la History registra `profile_id='default'` con `profile_snapshot=None` (verificato a runtime). La propagazione "deterministica" dei profili richiesta da M4 Final non è quindi garantita; nessun test realtime/USB asserisce `profile_id`/`profile_snapshot`.

### [P2] `P2-DBG-02` — `DatabaseManager.update_all` non esiste ma è invocato dalla UI

**File:** `clamguardian/ui/database_pages.py:395` (`run_async(self._manager.update_all(), _done)`) vs `clamguardian/databases/manager.py` (metodi presenti: `update` `:93`, `update_enabled` `:152`; `update_all` assente in tutto il repo).

Il pulsante "Update all" solleva `AttributeError` a runtime. Non rilevato in CI perché in headless la pagina diventa uno shim `_GtkNotAvailable` e nessun test istanzia il percorso reale.

### [P2] `P2-USB-01` — Nessuna validazione "mount rimovibile" e nessun call-site

**File:** `clamguardian/core/usb.py:46-55` (`is_removable_mount`), `:57-79` (`scan_device` controlla solo `exists()`/`is_dir()`)

`scan_device` non invoca mai `is_removable_mount`; il test esistente (`tests/test_usb.py:47-64`) scansiona una directory temporanea qualsiasi. Inoltre `grep` su tutto il package → **0 call-site** di `USBDeviceScanner` fuori dai test: la fase 1.1 è codice non cablato.

### [P2] `P2-TGT-01` — Nessun rifiuto esplicito dei file speciali (FIFO/socket/device)

**File:** `clamguardian/engines/clamav.py:55` (`Path(target).expanduser().resolve(strict=True)`, nessun controllo di tipo)

`docs/PROJECT_PLAN.md:74` dichiara l'obiettivo "verification of file types prior to scanning … special devices, FIFOs, and sockets … handled explicitly and safely": non implementato (solo l'hashing è None-safe: `core/base.py:26-28` → verificato `None` per FIFO e socket).

### [P2] `P2-QRN-01` — Quarantine legge l'intero file in memoria (nessun encryption streaming/chunked)

**File:** `clamguardian/core/quarantine.py:61` (`plaintext = source.read_bytes()`), `:121` (`raw = self._path(item_id).read_bytes()`)

La roadmap M5 elenca esplicitamente "Quarantine streaming/chunked AES-256-GCM encryption" come PENDING e nel codice non esiste chunking: un file molto grande può esaurire la memoria del processo. Il test "large" copre 3 MiB.

### [P3] `P3-ENG-02` — Falso positivo nel parsing delle detection

**File:** `clamguardian/engines/clamav.py:250-254`

```python
if line.strip().endswith("FOUND") or ": " in line and " FOUND" in line
```

La seconda condizione è troppo larga: una riga di output che contiene `" FOUND"` (es. un percorso come `/tmp/my FOUND report.txt: OK`) viene classificata come threat → `status=INFECTED`. Rilevanza limitata perché `_run_cli_scan` usa `--no-summary` senza `--verbose` (`:188`), ma la condizione va ristretta alla forma canonica `percorso: <firma> FOUND`.

### [P3] `P3-SHA-TOCTOU` — Hash calcolato dopo lo scan ri-risolvendo il path

`clamguardian/engines/clamav.py:82` + `core/base.py:26-30`: tra la scansione e il calcolo dell'hash il file può essere sostituito, quindi l'hash registrato può non corrispondere ai byte scansionati. Nessun test.

### [P3] `P3-DBG-03` — Rollback non atomico per artefatto

`clamguardian/databases/manager.py:112-119`: se `path.replace(destination)` fallisce dopo che l'originale è già stato spostato in `backup_path`, la coppia non entra in `moved` e il rollback (`:132-136`) non ripristina quell'artefatto.

### [P3] `P3-ARCH-01` — `core` importa `history` sotto `TYPE_CHECKING`

`clamguardian/core/usb.py:9,15-16`: nessun accoppiamento a runtime (import verificati senza cicli), ma alla lettera l'Architecture Freeze v1 dice "core non importa history". Igiene, non bloccante.

---

## 6. Finding documentazione / CI / packaging (ricontrollati)

### [P1] `P1-DOC-01` — `docs/ROADMAP.md` marca `PENDING` fasi implementate nello stesso commit

**File:** `docs/ROADMAP.md:96` (Phase 7 M6), `:101` (Phase 8&9 M7), `:106` (Phase 10 USB), `:111` (Phase 11 Threat Intelligence), `:116` (Phase 12 2.x-A) — tutte `**Status:** PENDING`; anche `:71` (Phase 1) e `:76` (Phase 2) sono dichiarate NEXT/PENDING mentre `history/models.py:198-210` e `core/base.py:17` le implementano.

Il diff della PR aggiunge `docs/ROADMAP.md` **insieme** a `ci.yml`, `core/usb.py`, `realtime/*`, `packaging/flatpak/*`: le fasi sono marcate pendenti nel commit che le implementa. La roadmap si autodefinisce autoritativa (`:3`).

**Impatto:** un revisore esterno non può determinare cosa è realmente consegnato. È la stessa incoerenza già segnalata nel report precedente, **non ancora corretta**.

### [P1] `P1-DOC-02` — Il design doc 2.x-A descrive come attuali difetti già rimediati, e cita test inesistenti

**File:** `docs/design/2.x-A-realtime-remediation-design.md:7,9-11,46,66-70,344,346`

- `:7` "evaluated the subsystem as **NOT READY / BLOCKED**. Three P1 defects were confirmed"
- `:46` **HEAD SHA: `60bf0ebeeea16e1fa3ea2a7aff2f4bf53220afbe`** → è il *parent* di HEAD, non HEAD
- `:344-346` "READY FOR IMPLEMENTATION / implementation can proceed in a subsequent phase" → l'implementazione è già nel commit che introduce il documento (`git diff --stat 60bf0eb..3bf0873`: `orchestrator.py` +145, `inotify.py` +91, `test_realtime.py` +84)
- `:257-264` cita `test_debounce_push_driven_single_event`, `test_debounce_coalescing_resets_timer`, `test_queue_depth_bounds_pending_plus_active`, `test_inotify_recursive_nested_creation`: **nessuno esiste** con quel nome (i test reali sono `test_orchestrator_push_debounce_single_event`, `test_orchestrator_debouncing_and_deduplication`, `test_orchestrator_queue_backpressure_bound`, `test_inotify_monitor_recursive_nested_creation`)

**Impatto:** documento di sicurezza fuorviante in entrambe le direzioni (problemi già risolti presentati come aperti; prove di test inesistenti).

### [P1] `P1-DOC-03` — M7 / gate 1.0 non chiudibile: icona assente e metainfo AppStream incompleto

**File:** `data/io.github.clamguardian.ClamGuardian.desktop:6`, `data/io.github.clamguardian.ClamGuardian.metainfo.xml:1-22`

- `Icon=io.github.clamguardian.ClamGuardian`, ma nel repository **non esiste alcun asset grafico** (`find . -name '*.svg' -o -name '*.png'` → nessun risultato)
- il metainfo contiene `id`, `name`, `summary`, `description`, `launchable`, `releases` (con `<release version="1.0.0" date="2026-09-12">`) ma **mancano** `<developer>`, `<content_rating>`, `<url>`, `<screenshots>`: la validazione AppStream/Flathub per `desktop-application` non passa

### [P2] `P2-DOC-04` — Manifest Flatpak non pinnato e senza integrazione desktop

**File:** `packaging/flatpak/io.github.clamguardian.ClamGuardian.yml:16-22`

`type: dir` + `path: ../..` (build dal working tree locale, nessun `commit`/`tag`); `build-commands` contiene solo `pip install --no-deps --prefix=/app .`: nessuna installazione di `.desktop`, metainfo o icone in `/app/share/...`. I `finish-args` (`:6-13`) non includono `--share=network` (necessario per VirusTotal e download database), l'accesso al socket clamd né i mount USB.

### [P2] `P2-DOC-05` — Gate `pip-audit` più debole di quanto implicato

**File:** `.github/workflows/ci.yml:31,37`

`python -m pip install --upgrade pip setuptools` precede l'audit (l'upgrade è stato aggiunto proprio nel commit `60bf0eb` "fix(ci): upgrade setuptools before pip-audit"), e `pip-audit` gira **senza `--strict`** e senza auditare `uv.lock`: l'insieme verificato non è quello risolto/pinnato. Il gate è verde ma non dimostra l'assenza di vulnerabilità nelle dipendenze dichiarate.

### [P2] `P2-DOC-06` — `docs/CLAMGUARDIAN_HANDOFF.md` è stale e internamente contraddittorio

**File:** `docs/CLAMGUARDIAN_HANDOFF.md:5` (`2026-08-30`), `:11` (`HEAD: a33d6a6b…`), `:99` (`pytest: 194 passed`), `:101` e `:169` (`mypy … 29 source files`), `:167` (`179 passed, 2 skipped`)

Stato reale: HEAD `3bf0873…`, **213 passed + 2 skipped**, `mypy … 36 source files`. Le due sezioni di validazione dello stesso documento si contraddicono (194 vs 179+2). Il documento è il punto di ripresa dichiarato per la sessione successiva (`:285-308`) e cita anche un file inesistente (`:299` `docs/CLAMGUARD_HANDOFF.md`).

### [P2] `P2-DOC-07` — README disallineato su CLI, CI e dipendenze

- il CLI espone anche `history list|show|purge` (`clamguardian/cli/main.py:149,162,187,200`): **`grep -i history README.md` → 0 occorrenze**
- `README.md:264` dice che la CI esegue `ruff` e `pytest` su ogni PR e su push a `main`; in realtà esegue anche `mypy` e `pip-audit` e i trigger includono `feature` e `development` (`ci.yml:5-6,33-39`)
- `README.md:51` elenca le dipendenze core senza `inotify-simple` (`pyproject.toml:16`)
- `README.md:58,68` dichiarano PyGObject `>= 3.53`, mentre l'extra `gtk` dichiara `>=3.46` (`pyproject.toml:24`)

### [P3] `P3-DOC-08` — Igiene documentale residua

`ROADMAP.md` non menziona `M4-B8` citato dall'handoff (`:28`); `[tool.hatch.build.targets.wheel] packages = ["clamguardian"]` non include `data/*` (wheel senza integrazione desktop); `docs/design/2.x-A-remediation-design.md` non è etichettato come documento storico.

---

## 7. Aree verificate e risultate corrette (per non gonfiare i rilievi)

- **Debounce push-driven**: risolto e coperto da test (`test_realtime.py:110`), verificato anche con il probe A.
- **Watch ricorsivi sui casi dichiarati**: sottodirectory preesistenti, create dopo, spostate dentro, cancellate e ricreate (I1, I2, I3, I5) funzionano.
- **Best-effort di History**: un fallimento di persistenza non altera l'esito di una scansione già completata; il backend converte i fallimenti sqlite in `HistoryError` (`history/backend.py:362-368`) con `BEGIN IMMEDIATE`/`ROLLBACK` e test dedicati.
- **Semantica `sha256=None`**: None-safe sia su `ScanResult` (`core/base.py:110-113`) sia su `HistoryRecord` (`history/models.py:167-170`); per directory/FIFO/socket il valore è `None` (verificato a runtime) e non viene mai scritto un hash fuorviante.
- **Crypto della quarantena**: AES-256-GCM, chiave 32 byte obbligatoria, nonce casuale per record, AAD legato all'`item_id`, scrittura atomica `mkstemp`+`os.replace`+`fsync`, permessi `0o700`/`0o600`, `item_id` hex-only. Le proprietà di sicurezza principali sono **testate** (chiave errata, ciphertext corrotto, AAD corrotto, traversal, id inesistente, TOCTOU sorgente).
- **Confini architetturali**: `sqlite3` compare **solo** in `history/backend.py`; la traduzione profilo → argomenti ClamAV avviene **solo** in `engines/clamav.py` (`_clamscan_args`); nessun import circolare; le opzioni non onorabili da clamd sono riportate in `metadata["profile_unsupported_clamd"]` invece di essere ignorate.
- **Quality gate riproducibili**: `ruff` e `mypy` puliti sul commit esaminato, suite verde in locale, CI verde sui tre interpreti (3.11/3.12/3.13).
- **Versione coerente**: `pyproject.toml:7`, `clamguardian/__init__.py:3` e `metainfo.xml:16` dichiarano `1.0.0`; app-id Flatpak, nome del desktop entry e `<id>` del metainfo coincidono; entry point `clamguardian` coerente.

---

## 8. Stato dei gate dopo l'audit

| Gate | Stato | Motivo |
|---|---|---|
| **Audit read-only PR #5 (step 01)** | **CHIUSO per il percorso critico** | Report + riproduttori versionati; restano non riproducibili in sandbox solo `pip-audit` (TLS proxy) e i runtime ClamAV/Flatpak/GTK |
| **M4 Final** | **NON CHIUDIBILE** | `P1-ENG-01` (SHA-256 assente su clamd), `P2-HIST-01`, `P2-HIST-02`; manca il report finale M4 |
| **M5** | **NON CHIUDIBILE** | `P1-DB-01` (integrità update opzionale), `P2-QRN-01`, `P2-TGT-01`, `P2-DBG-02`, `P3-DBG-03` |
| **M6** | **CHIUDIBILE con riserva** | ruff/mypy/pytest riprodotti sul commit; `pip-audit` verde in CI ma non riproducibile qui e gate indebolito (`P2-DOC-05`) |
| **M7 / 1.0** | **NON CHIUDIBILE** | `P1-DOC-03` (icona assente, metainfo non validabile), `P2-DOC-04` (manifest non pinnato, nessuna integrazione desktop), runtime Flatpak mai eseguito |
| **1.1 USB** | **NON CHIUDIBILE** | `P2-USB-01` (nessuna validazione mount, nessun call-site) |
| **Threat Intelligence** | **NON CHIUDIBILE end-to-end** | Seam corretto (digest validato, nessun upload, rate-limit 429) ma nessun call-site; dipende da `P1-ENG-01` per l'hash sul percorso clamd |
| **2.x-A** | **NON CHIUDIBILE** | `P1-RT-01`, `P1-RT-02`, `P1-RT-03`, `P2-RT-04..07`, `P3-RT-10` |
| **2.x-B / 2.x-C** | **RINVIATI** | Nessun codice `fanotify`/`clamonacc`/daemon nel repo: coerente con la decisione di scope |

---

## 9. Limiti di questo audit

1. **Non riproducibile in sandbox:** `pip-audit` (verifica TLS del proxy di rete) — verificato solo l'esito CI; build Flatpak e `appstreamcli validate` (strumenti assenti); runtime ClamAV reale (`clamscan`/`clamd`/`freshclam` non installati) — i rami engine sono stati analizzati per lettura e con socket/command-runner finti; UI GTK4 (PyGObject assente → 2 test skippati e le classi reali sostituite da shim headless, quindi `P2-DBG-02` è provato per lettura); mount USB reali assenti.
2. **`git` in clone parziale:** ho eseguito `git fetch --unshallow` (sola lettura, nessuna scrittura sui ref remoti) per poter diffare `a33d6a6` e `60bf0eb`; il branch `feature` remoto non è stato toccato.
3. **Prove realtime**: i difetti `P1-RT-01`/`P1-RT-02` richiedono che un evento venga gestito nella stessa iterazione del loop in cui scade il debounce. È una finestra di gara, ma **non teorica**: riprodotta 4 volte su 5 con sola API pubblica e timing randomizzato (`stress_probe.py`). `P1-RT-03` e `P2-RT-04` sono invece deterministici.
4. **Nessuna modifica applicata**: nessun fix, nessun commit sul branch della PR, nessun merge.

---

## 10. Conclusione

Il branch contiene molto più codice della baseline `a33d6a6`, e la parte History/M4-A..B7 resta solida. La remediation realtime ha **davvero** chiuso il difetto di debounce e i casi principali di ricorsione dei watch, ma:

- il bound della coda **non** è un bound sul lavoro reale;
- la deduplicazione per percorso **non** è garantita;
- lo shutdown **non** è deterministico;
- il monitoraggio inotify perde eventi e watch **in silenzio**;
- tre obiettivi di gate (SHA-256 su clamd, integrità database, packaging 1.0) **non** sono soddisfatti;
- la documentazione **contraddice** lo stato reale.

Il prossimo passo corretto non è una nuova milestone funzionale, ma la **remediation mirata** descritta in `audit/NEXT-STEPS-PLAN.md`, con una decisione preliminare sul perimetro della PR (split 1.0 vs 1.1/2.x-A).
