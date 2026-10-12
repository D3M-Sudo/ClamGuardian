## Verifica eseguita (comandi/letture, per ciascuna area)

**Letture (read-only, nessuna modifica):**
- Core: `clamguardian/core/{base,profiles,errors,runner,quarantine,usb}.py`
- History: `clamguardian/history/{models,interface,backend,__init__}.py`
- Databases: `clamguardian/databases/{models,provider,verifier,manager,__init__}.py`
- Engine: `clamguardian/engines/clamav.py`
- Intelligence: `clamguardian/intelligence/{manager,virustotal,__init__}.py`
- UI: `clamguardian/ui/{controller,database_pages}.py`
- Realtime (call-site): `clamguardian/realtime/orchestrator.py`
- CLI (call-site): `clamguardian/cli/main.py` (righe 240-560)
- Docs: `docs/design/architecture-freeze-v1.md`, `docs/ROADMAP.md`, `docs/PROJECT_PLAN.md`, `docs/CLAMGUARDIAN_HANDOFF.md`, `docs/design/2.x-A-realtime-remediation-design.md`
- Tests: tutti i file in `/workspace/tests/*.py`

**Comandi (read-only):**
- `git --no-pager log/status` (HEAD `3bf0873`, working tree pulito)
- `grep -rn` per: `compute_file_sha256`, `record_scan`, `suppress(Exception)`, `USBDeviceScanner`, `import sqlite3`, `clamscan|--recursive|CONTSCAN`, import di `core/*` verso engines/history/ui, `update_all`, `TYPE_CHECKING`
- Snippet Python (`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/workspace /home/node/venvs/audit/bin/python -c`):
  1. `history_record_from_scan` con `metadata={"profile_id":"totally-bogus-untrusted"}` → `profile_id='totally-bogus-untrusted'`, `snapshot=None`
  2. `compute_file_sha256` su FIFO e socket → `None` (entrambi `is_file()=False`)
  3. import di `core.usb`, `history`, `core.base`, `ui.controller`, `realtime.orchestrator` → nessun import circolare
  4. `DEFAULT_REGISTRY` ids = `['custom','full','home','quick']`; `DEFAULT_PROFILE.id='default' in registry: False`; record realtime-style → `profile_id='default'`, `snapshot=None`
  5. scan via ramo **clamd** (socket finto) su file singolo → `'sha256' in metadata = False`, `res.sha256=None`
  6. `ClamAVEngine._result(...)` su output `"/tmp/my FOUND report.txt: OK"` → `status=infected`

**Non eseguito:** la suite pytest completa (per non consumare il budget "una sola volta" senza necessità); i giudizi sulla *qualità* dei test derivano dalla lettura del codice, salvo dove indicato "verificato a runtime".

---

## Finding

### [P1] DBG-1 — Verifica del digest dei database scaricati è opzionale, non applicata (integrità update non garantita)
**File:** `clamguardian/databases/provider.py:47-48`, `clamguardian/databases/models.py:21,44-47`, `clamguardian/ui/database_pages.py:191`
**Evidenza:**
```python
# provider.py:47
if artifact.sha256:
    verify_sha256(temporary, artifact.sha256)
```
`DatabaseArtifact.sha256` è `str | None = None` (`models.py:21`) e la validazione in `__post_init__` scatta **solo se** il digest è presente (`models.py:44-47`). La UI consente di aggiungere una sorgente senza digest: `sha256=values["sha256"] or None` (`database_pages.py:191`). Quindi un artefatto senza `sha256` viene scaricato, spostato in `database_dir` e installato **senza alcuna verifica di integrità** (`provider.py:49 temporary.replace(output)`).
**Impatto:** le definizioni AV (firmare di terze parti) possono essere installate corrotte o manomesse da un MITM/CDN compromesso senza rilevazione. È esattamente l'obiettivo M5 "database download integrity" (Roadmap Phase 5).
**Come verificarlo:** creare una `DatabaseSource` con `DatabaseArtifact(..., sha256=None)` e un provider reale/mocked che scrive byte arbitrari: `manager.update()` completa con `DatabaseStatus.INSTALLED`. Nessun test lo copre: `tests/test_databases.py:69-88` testa solo `verify_sha256` in isolamento; `FileDatabaseProvider` non è mai istanziato in `tests/`.

### [P2] HIST-1 — `profile_id` può essere derivato da `result.metadata` non attendibile e persistito senza validazione
**File:** `clamguardian/history/models.py:191-199`
**Evidenza:**
```python
meta_profile_id = result.metadata.get("profile_id") if result.metadata else None
if profile is None and meta_profile_id:
    try:
        profile = DEFAULT_REGISTRY.get(meta_profile_id)
    except Exception:
        profile = None
profile_id = profile.id if profile is not None else meta_profile_id
```
Se `profile` è `None` e `metadata["profile_id"]` non è nel registry, l'eccezione viene inghiottita e `profile_id` resta il valore grezzo. Verificato a runtime: `metadata={"profile_id":"totally-bogus-untrusted"}` → `HistoryRecord.profile_id == 'totally-bogus-untrusted'`, `profile_snapshot=None`.
**Impatto:** un `profile_id` arbitrario/non validato finisce in DB e diventa filtrabile via `list_scans(profile_id=...)`; rompe l'invariante "profile_id ∈ registry". Nessun test copre l'id non registrato (`test_record_from_scan_resolves_profile_from_metadata` usa solo `"quick"`, valido).
**Come verificarlo:** snippet 1 sopra; oppure `pytest tests/test_history.py -k resolves_profile_from_metadata` non esercita il ramo `except`.

### [P2] HIST-2 — Profilo di default non risolvibile dal registry: `profile_snapshot` perso sul percorso realtime
**File:** `clamguardian/core/profiles.py:115,151-153`, `clamguardian/engines/clamav.py:72,81`, `clamguardian/history/models.py:192-199`, `clamguardian/realtime/orchestrator.py:47,178,182`
**Evidenza:** `DEFAULT_PROFILE = ScanProfile(id="default", ...)` (`profiles.py:115`) **non** è registrato: `DEFAULT_REGISTRY` contiene solo `quick/home/full/custom` (`profiles.py:151-153`). L'engine marca sempre `metadata["profile_id"] = profile.id` (`clamav.py:72,81`), incluso `"default"`. L'orchestrator, con `self.profile=None` di default (`orchestrator.py:47`), chiama `record_scan(result, profile=self.profile)` (`orchestrator.py:182`). Verificato a runtime: `profile_id='default'`, `profile_snapshot=None`.
**Impatto:** sul percorso realtime (profilo non esplicito) la history registra `profile_id` ma **non** lo snapshot, pur essendo stato applicato `DEFAULT_PROFILE` dall'engine. La propagazione "deterministica" di `profile_snapshot` (Roadmap Phase 1) non è garantita in questo caso. Nessun test realtime/USB asserisce `profile_id`/`profile_snapshot` (grep su `tests/test_realtime.py`, `tests/test_usb.py`, `tests/test_engine.py` → 0 risultati).
**Come verificarlo:** snippet 4; oppure costruire `RealtimeScanOrchestrator(runner, history_store=store, debounce_seconds=0)` senza `profile` e leggere `store.list_scans()[0].profile_snapshot` → `None`.

### [P2] ENG-1 — SHA-256 calcolato solo sul ramo clamscan, mai sul ramo clamd (content-hash M4 assente sul percorso primario)
**File:** `clamguardian/engines/clamav.py:61-73` (ramo socket con `return` anticipato), `:82-84` (hash solo dopo `_run_cli_scan`)
**Evidenza:**
```python
if self.socket_path.exists():
    ...
    result.metadata["profile_id"] = profile.id
    return result            # <-- nessun compute_file_sha256
...
result.metadata["profile_id"] = profile.id
sha256 = compute_file_sha256(target)   # solo qui
if sha256 is not None:
    result.metadata["sha256"] = sha256
```
Verificato a runtime con socket finto: scan di un **file singolo** via clamd → `'sha256' in metadata = False`, `res.sha256=None`, mentre l'hash del file era calcolabile.
**Impatto:** su un sistema con `clamd` attivo (percorso preferito, `README`), nessuno scan di file singolo registra `sha256`, violando l'obiettivo M4 Phase 2 ("Compute SHA-256 for single-file scan artifacts"). I test coprono solo il fallback (`socket_path=tmp_path/"missing.sock"`), quindi la regressione è invisibile.
**Come verificarlo:** snippet 5 (riproduce il ramo clamd senza ClamAV installato).

### [P2] DBG-2 — `DatabaseManager.update_all` non esiste ma è chiamato dalla UI ("Update all" → `AttributeError`)
**File:** `clamguardian/ui/database_pages.py:395`, `clamguardian/databases/manager.py` (metodi: `update` @93, `update_enabled` @152; **nessun** `update_all`)
**Evidenza:** `run_async(self._manager.update_all(), _done)` (`database_pages.py:395`); `grep -rn 'def update' manager.py` → solo `update` e `update_enabled`; `grep -rn 'update_all' clamguardian/ tests/` → solo `database_pages.py`.
**Impatto:** il pulsante "Update all" solleva `AttributeError` a runtime (il toast "All databases updated" non compare mai). Non rilevato dai test headless perché `ThirdPartyDatabasesPage` diventa uno shim `_GtkNotAvailable` senza GTK (`database_pages.py:102-106`) e nessun test importa/istanzia il metodo reale.
**Come verificarlo:** con PyGObject/GTK4 attivi, cliccare "Update all"; oppure `grep -n 'update_all' clamguardian/databases/manager.py` (nessun match).

### [P2] USB-1 — `scan_device` non valida che il target sia un mount rimovibile; `USBDeviceScanner` non è invocato da nessuna parte
**File:** `clamguardian/core/usb.py:46-55` (`is_removable_mount`), `:57-79` (`scan_device` valida solo `exists()`/`is_dir()`), `:23`
**Evidenza:** `scan_device` non chiama mai `is_removable_mount`; controlla solo esistenza e tipo directory:
```python
target = Path(mount_point).expanduser().resolve()
if not target.exists(): ... ERROR
if not target.is_dir(): ... ERROR
```
Il test `tests/test_usb.py:47-64` scansiona con successo una directory temporanea arbitraria (`tmp_path/"usb_drive"`, non un mount). Inoltre `grep -rn 'USBDeviceScanner|usb' clamguardian/` (escluso `core/usb.py`) → **0 risultati**: nessun call-site in CLI/UI/daemon; il modulo è raggiunto solo dai suoi test.
**Impatto:** il controllo "removable mount" promesso dal docstring non è applicato: chiunque possa invocare `scan_device` può scansionare qualsiasi directory. Inoltre il componente 1.1 è di fatto **codice non cablato** (dead code rispetto all'applicazione), quindi l'obiettivo "USB Auto-Scan" non è end-to-end.
**Come verificarlo:** `scanner.scan_device(Path.home())` restituisce un risultato CLEAN invece di rifiutare (inspection-only: non eseguito per non avviare scansioni reali); confermato dal test esistente che usa una dir non-mount.

### [P2] TGT-1 — Nessun rifiuto esplicito di file speciali (FIFO/socket/device) prima della scansione
**File:** `clamguardian/engines/clamav.py:55` (solo `resolve(strict=True)`), `clamguardian/core/base.py:26-28`
**Evidenza:** l'engine risolve il target e lo passa direttamente a clamd/clamscan senza controlli di tipo:
```python
target = Path(target).expanduser().resolve(strict=True)   # nessun is_file()/tipo check
```
L'hashing è invece None-safe (`compute_file_sha256` → `if not resolved.is_file(): return None`, `base.py:27-28`) — verificato a runtime per FIFO e socket (`None`). `docs/PROJECT_PLAN.md:74` dichiara però l'obiettivo: *"Verification of file types prior to scanning to ensure special devices, FIFOs, and sockets are handled explicitly and safely"* (M5 Phase 5 "explicit scan target validation").
**Impatto:** FIFO/device/socket raggiungono ClamAV senza validazione esplicita; un FIFO può bloccare la lettura del motore. La proprietà di sicurezza dichiarata non è implementata (solo l'hashing è protetto).
**Come verificarlo:** `tests/test_engine.py:108-141` verifica solo `compute_file_sha256` (non il rifiuto del target); per provarlo: `await engine.scan(fifo_path)` non solleva e non rifiuta (inspection-only senza ClamAV).

### [P2] QRN-1 — Quarantine carica l'intero file in memoria (`read_bytes`), nessun encryption streaming/chunked
**File:** `clamguardian/core/quarantine.py:61` (`plaintext = source.read_bytes()`), `:121` (`raw = self._path(item_id).read_bytes()`)
**Evidenza:** l'intero contenuto è letto in RAM e poi cifrato in un colpo solo (`self._aes.encrypt(nonce, plaintext, aad)`). La Roadmap Phase 5 (M5) elenca esplicitamente *"Quarantine streaming/chunked AES-256-GCM encryption"* come PENDING; il test "large" usa solo 3 MiB (`tests/test_quarantine.py:107-121`).
**Impatto:** un file molto grande mette in crisi la memoria del processo (DoS / OOM) e non c'è protezione dimensionale.
**Come verificarlo:** `grep -n 'read_bytes' clamguardian/core/quarantine.py`; quarantinare un file di diversi GB (non eseguito).

### [P3] HIST-3 — `contextlib.suppress(Exception)` silenzioso intorno a `record_scan` nasconde ogni errore (non solo `HistoryError`)
**File:** `clamguardian/core/usb.py:96`, `clamguardian/realtime/orchestrator.py:181`, `:185`, `:201`, `clamguardian/cli/main.py:274`, `:297`, `:461` (e `:436` try/except)
**Evidenza / elenco completo dei siti di soppressione:**
- `core/usb.py:96` `with contextlib.suppress(Exception): await self.history_store.record_scan(...)` — best-effort, **senza log**.
- `realtime/orchestrator.py:181` idem `record_scan` — best-effort, **senza log**.
- `realtime/orchestrator.py:185` `with contextlib.suppress(Exception): on_complete(result)` — nasconde errori del callback.
- `realtime/orchestrator.py:201` `with contextlib.suppress(RuntimeError):` (get_running_loop) — corretto.
- `cli/main.py:274,297` `suppress(Exception)` su `store.close()` in `finally` — best-effort corretto.
- `cli/main.py:461` `suppress(Exception)` su `recorder.close()` — best-effort corretto.
- `cli/main.py:436` `except Exception as exc: print("warning: could not record scan history...")` — best-effort **con** log.
**Giudizio:** la soppressione *non* altera l'outcome (vedi Aree corrette sotto), ma in `usb.py`/`orchestrator.py` sopprime **tutte** le `Exception` (incluse `AttributeError`/`TypeError` da bug di programmazione) senza alcuna osservabilità. Il contratto (`history/interface.py:43`) prevede `HistoryError` per i fallimenti di storage: sopprimere `HistoryError` sarebbe più preciso. Nessun test copre uno store che fallisce su questi due percorsi.
**Come verificarlo:** iniettare uno store con `record_scan` che solleva `AttributeError` e osservare che lo scan torna comunque CLEAN senza alcun warning.

### [P3] ENG-2 — Parsing delle detection falsi-positivi su path contenenti " FOUND"
**File:** `clamguardian/engines/clamav.py:250-254`
**Evidenza:**
```python
threats = tuple(
    line.strip()
    for line in output.splitlines()
    if line.strip().endswith("FOUND") or ": " in line and " FOUND" in line
)
```
Verificato a runtime: output `"/tmp/my FOUND report.txt: OK"` con exit code 0 → `status=infected`, `threats=('/tmp/my FOUND report.txt: OK',)`.
**Impatto:** un file pulito il cui percorso contiene la sottostringa `" FOUND"` viene classificato INFECTED (falso positivo), con exit code 1 e registrazione threat. La condizione `": " in line and " FOUND" in line` è più larga del necessario.
**Come verificarlo:** snippet 6.

### [P3] SHA-TOCTOU — Il digest è calcolato dopo lo scan ri-risolvendo il path (possibile disallineamento)
**File:** `clamguardian/engines/clamav.py:82`, `clamguardian/core/base.py:26-30`
**Evidenza:** l'engine scansiona `target` (già risolto) e poi chiama `compute_file_sha256(target)`, che ri-esegue `Path(path).resolve(strict=True)` e `resolved.open("rb")` (`base.py:26-30`). Tra scan e hash il file può cambiare (swap/sostituzione).
**Impatto:** l'hash registrato può non corrispondere ai byte effettivamente scansionati (integrità del record). Non c'è test.
**Come verificarlo:** inspection-only; per provarlo servirebbe un monkeypatch che sostituisce il file tra `scan` e `compute_file_sha256`.

### [P3] DBG-3 — Gap di rollback atomico in `DatabaseManager.update`
**File:** `clamguardian/databases/manager.py:112-119`
**Evidenza:**
```python
if destination.exists():
    destination.replace(backup_path)
path.replace(destination)
moved.append((destination, backup_path))
```
Se `path.replace(destination)` solleva dopo che l'originale è già stato spostato in `backup_path`, la coppia non viene aggiunta a `moved` e il rollback (`manager.py:132-136`) non ripristina quell'artefatto → potenziale perdita del database precedente.
**Impatto:** edge case di filesystem; il rollback non è atomico per-artefatto. I test coprono solo il fallimento *prima* della fase di move (`tests/test_databases.py:45-54`).
**Come verificarlo:** monkeypatch di `Path.replace` che fallisce al secondo artefatto (inspection-only).

### [P3] ARCH-1 — `core` importa `history` (solo sotto `TYPE_CHECKING`)
**File:** `clamguardian/core/usb.py:9,15-16`
**Evidenza:**
```python
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..history import HistoryStore
```
Nessun coupling a runtime (verificato: import di `core.usb`+`history` senza cicli), ma alla lettera "core non importa history". Segnalato come hygiene, non bloccante.
**Come verificarlo:** `grep -n 'history' clamguardian/core/usb.py`; snippet 3 (import ok).

---

## Aree verificate e risultate corrette (con file:line)

- **Best-effort history non altera l'outcome (Q3):** corretto. `usb.py:92-98` ritorna `result` invariato; `orchestrator.py:178-188` ritorna `result` invariato; `cli/main.py:434-437` stampa warning e ritorna. `HistoryError` è documentato (`history/interface.py:20-26,43`) e il backend converte i fallimenti sqlite: `backend.py:362-368` (`ROLLBACK` + `raise HistoryError(...)`).
- **`record_scan` atomico e typed:** `backend.py:318-369` — `BEGIN IMMEDIATE`/`COMMIT`/`ROLLBACK`, INSERT master + threats nella stessa transazione; `_require_conn` solleva `HistoryError` se non inizializzato (`backend.py:301-304`). Test: `tests/test_history.py:673-695` (rollback su threat failure), `:483-487` (HistoryError su backend failure).
- **sha256 None-safe:** `ScanResult.sha256` (`base.py:110-113`) e `HistoryRecord.sha256` (`models.py:167-170`) leggono `.get("sha256")` → `None` se assente; directory → `None` (`base.py:27-28`, test `test_core_models.py:296-299`); FIFO/socket → `None` (verificato a runtime). Nessuno store di hash "fuorviante" per directory: l'engine scrive `sha256` solo se non-`None` (`clamav.py:83-84`).
- **Quarantine crypto corretta (implementazione):** AES-256-GCM con chiave 32 byte obbligatoria (`quarantine.py:42-43,47`), nonce random 12 byte per record (`:70`), AAD = metadata JSON + verifica `item_id` (`:69,135-136`), magic/length-prefix con bound (`:73,122-128`), scrittura atomica `mkstemp`+`os.replace`+`fsync` (`:146-158`), permessi `0o700` dir / `0o600` file (`:45-46,96,150,156`), path traversal su `item_id` hex-only (`:112-118`).
- **Proprietà di sicurezza quarantine TESTATE:** wrong key → errore (`test_quarantine.py:26-36`); ciphertext corrotto → `InvalidTag`/`ValueError` (`:49-64`); AAD/metadata corrotto → `ValueError` (`:67-81`); item id traversal/invalidi → `ValueError` (`:84-92`); id inesistente → `FileNotFoundError` (`:95-104`); TOCTOU sorgente sparita (`:124-129`); chiave non-AES256 (`:39-41`).
- **Boundary architetturali (Q6):** `sqlite3` presente **solo** in `history/backend.py:13` (fuori dai test); nessun `import` di engines/history/ui a runtime in `core` (solo `usb.py` TYPE_CHECKING); traduzione profilo→argomenti ClamAV **esclusivamente** in `engines/clamav.py:153-185` (`_clamscan_args`); CLI non costruisce flag (`cli/main.py:17`, `cli/__init__.py:7`); nessun import circolare (snippet 3 ok); `ui/controller.py:19-22` importa solo core/engines (consentito).
- **`_clamd_unsupported_options` non silenzioso:** le opzioni non onorabili da clamd sono riportate in `metadata["profile_unsupported_clamd"]` (`clamav.py:66-71,126-151`), testato in `tests/test_profiles.py:204-244`.
- **Intelligence trust boundary:** `VirusTotalProvider` valida il digest 64-hex (`virustotal.py:26-27`), nessun metodo di upload (test `test_intelligence.py:25-30`), rate-limit 429 gestito (`virustotal.py:35-36`).
- **Database: validazione input e atomicità di base:** URL HTTPS obbligatorio e filename senza path component (`models.py:40-43`), digest validato se presente (`models.py:44-47`), install in staging + backup/rollback (`manager.py:100-150`), limite dimensione artefatto (`provider.py:33-45`), state persistito atomicamente (`manager.py:173-186`). Test: `tests/test_databases.py:33-61`, `test_ui_databases.py:125-149`.

---

## Punti non verificabili in questo ambiente (e perché)

- **Suite pytest completa non eseguita:** ho scelto di non lanciarla per rispettare il vincolo di risorse ("non più di una volta") e perché i quesiti sono coperti da lettura + snippet mirati. I giudizi sulla *qualità* dei test (invarianti vs mera esecuzione, rami non coperti) sono **inspection-only**.
- **Percorso clamd reale e `clamscan`/`freshclam`:** non installati; il ramo clamd è stato esercitato solo con socket/reader finti (snippet 5) e il ramo CLI con `_run_command` monkeypatchato. La conferma "end-to-end" con ClamAV reale non è disponibile.
- **UI GTK4/Libadwaita:** PyGObject non disponibile headless; `database_pages.py` è compilato ma le classi reali (`AddDatabaseDialog`, `ThirdPartyDatabaseRow`, `ThirdPartyDatabasesPage`) sono sostituite da `_GtkNotAvailable` (`:102-106`). Il bug `update_all` (DBG-2) è quindi provato per lettura (`database_pages.py:395` vs assenza in `manager.py`), non per esecuzione del click.
- **`is_removable_mount` / mount reali e `/media`,`/run/media`,`/mnt`:** l'ambiente sandbox non ha mount rimovibili; USB-1 provato per lettura + test esistente con dir non-mount.
- **File speciali (FIFO/socket/device) su device nodes:** ho verificato a runtime FIFO e socket UNIX; i device node (`/dev/*`) non sono stati creati (richiedono privilegi) — comportamento dedotto da `is_file()`.
- **pip-audit / mypy / ruff come gate:** non eseguiti (nessuna rete garantita per `pip-audit`; il gate M6 è comunque elencato come PENDING in `docs/ROADMAP.md:19`).

**Nota finale:** non ho modificato/creato/eliminato alcun file in `/workspace` né eseguito comandi git di scrittura; l'unica scrittura è stata in directory temporanee di sistema (`tempfile.mkdtemp`) per gli snippet e in `/tmp/audit/report_m4m5.md`, non tracciate dal repo.
