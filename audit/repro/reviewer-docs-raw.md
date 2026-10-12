## Verifica eseguita

Audit read-only su `/workspace` @ `3bf087316f683bac012ffcd370a8b3ffd149c951` (branch `feature-756467115717530540`), base PR #5 `a33d6a6b1f1d689f2bd8e273b34b4c7e4ff31d5a`. Nessun file modificato.

Comandi/evidenze eseguite:
- `git rev-parse HEAD`, `git cat-file -p <sha>` per `a33d6a6b`, `60bf0eb`, `3bf0873`; `git diff --stat` base→head e parent→head.
- `grep -c 'def test'` per file in `tests/` (somma = **211**).
- `find clamguardian -name '*.py' | wc -l` = **36**; `mypy` → `Success: no issues found in 36 source files`.
- `ruff check --no-cache .` → `All checks passed!`.
- `find . -name '*.svg' -o -name '*.png' …` → **nessun asset grafico**.
- `grep` su `tests/test_realtime.py`, `clamguardian/realtime/*.py`, `clamguardian/cli/main.py`, `uv.lock`.
- `git show 60bf0eb:clamguardian/realtime/{orchestrator,inotify}.py` (stato pre-fix citato dal design doc).

Catena rilevante: `06221c5` → `a33d6a6b` (base PR #5) → … → `60bf0eb` (parent di HEAD) → `3bf0873` (HEAD). Il design 2.x-A dichiara come "HEAD" il SHA `60bf0eb`, cioè il **parent** di HEAD.

---

## Tabella stato dichiarato vs codice reale (documento:riga | dichiarato | realtà | verdetto)

| documento:riga | dichiarato | realtà | verdetto |
|---|---|---|---|
| ROADMAP.md:36 | M0 COMPLETED | `pyproject.toml`, `LICENSE`, struttura repo | ✅ coerente |
| ROADMAP.md:40 | M0.5 COMPLETED | `clamguardian/core/base.py`, `engines/clamav.py` | ✅ coerente |
| ROADMAP.md:44 | F0 COMPLETED | `docs/design/architecture-freeze-v1.md` | ✅ coerente |
| ROADMAP.md:48 | M1 COMPLETED | `core/runner.py`, `tests/test_cancellation.py` (6 test) | ✅ coerente |
| ROADMAP.md:52 | M2 COMPLETED | `core/profiles.py`, `tests/test_profiles.py` (21 test) | ✅ coerente |
| ROADMAP.md:56 | M3 COMPLETED | `cli/main.py`, `tests/test_cli.py` (52 test) | ✅ coerente |
| ROADMAP.md:60 | M4-A COMPLETED | `history/models.py` (budget 8 KiB) | ✅ coerente |
| ROADMAP.md:64 | M4-B1..B7 COMPLETED | `history/backend.py`, `history list/show/purge` in `cli/main.py:162,187,200` | ✅ coerente |
| ROADMAP.md:71 | Phase 1 NEXT (M4 Profile-Aware History Propagation) | `history/models.py:198-210` imposta `profile_id`/`profile_snapshot`; colonne in `history/backend.py:43-44` | ❌ **contraddizione** (implementato) |
| ROADMAP.md:76 | Phase 2 PENDING (M4 Content Hash Model `sha256`) | `core/base.py:17 compute_file_sha256`, usato in `engines/clamav.py:82-84`, esposto in `history/models.py:168-170` | ❌ **contraddizione** (implementato) |
| ROADMAP.md:81 | Phase 3 PENDING (Security Test Gap Closure) | esistono `test_quarantine.py`(9), `test_databases.py`(5), `test_engine.py`(5), `test_cancellation.py`(6) | ⚠️ parziale (implementato in gran parte) |
| ROADMAP.md:86 | Phase 4 PENDING (M4 Finalization & Report) | nessun artefatto di report M4 nel repo | ✅ plausibile |
| ROADMAP.md:91 | Phase 5&6 PENDING (M5 hardening, quarantine streaming/chunked) | `core/quarantine.py:47` usa `AESGCM` monoblocco, nessun chunking | ✅ coerente |
| ROADMAP.md:96 | Phase 7 PENDING (M6: integrare mypy e pip-audit in CI) | `.github/workflows/ci.yml:34-37` esegue `mypy clamguardian` e `pip-audit` | ❌ **contraddizione** (implementato) |
| ROADMAP.md:101 | Phase 8&9 PENDING (M7 Packaging & 1.0 gate) | `data/*.desktop`, `data/*.metainfo.xml`, `packaging/flatpak/*.yml`, `version=1.0.0` | ❌ **contraddizione** (presente, con difetti) |
| ROADMAP.md:106 | Phase 10 PENDING (1.1 USB Auto-Scan) | `clamguardian/core/usb.py` (`USBDeviceScanner`), `tests/test_usb.py` (6 test) | ❌ **contraddizione** (implementato) |
| ROADMAP.md:111 | Phase 11 PENDING (Threat Intelligence Integration) | `intelligence/virustotal.py:24 lookup_hash`, `tests/test_intelligence.py` (4 test) | ❌ **contraddizione** (implementato) |
| ROADMAP.md:116 | Phase 12 PENDING (2.x-A Event-Driven Monitoring) | package `clamguardian/realtime/` + `tests/test_realtime.py` (9 test) | ❌ **contraddizione** (implementato) |
| ROADMAP.md:125,129 | 2.x-B/2.x-C DEFERRED | nessun `fanotify`/`clamonacc`/daemon nel codice | ✅ coerente |
| PROJECT_PLAN.md:85 | "Dependency vulnerability auditing: `pip-audit` in CI" | `ci.yml:37` | ✅ coerente |
| PROJECT_PLAN.md:99 | 1.1 USB come evoluzione post-1.0 | `core/usb.py` già presente | ⚠️ descrizione storica, non dichiara stato |
| PROJECT_PLAN.md:101 | 2.x-A `FileMonitor`/`RealtimeScanOrchestrator` come evoluzione | `realtime/monitor.py`, `realtime/orchestrator.py` già presenti | ⚠️ descrizione storica, non dichiara stato |
| CLAMGUARDIAN_HANDOFF.md:5,11 | data `2026-08-30`, `HEAD: a33d6a6b…` | HEAD reale `3bf0873…` | ❌ **contraddizione** (baseline stale) |
| CLAMGUARDIAN_HANDOFF.md:99 | `pytest: 194 passed in 3.25s` | 211 test function nel repo | ❌ **contraddizione** |
| CLAMGUARDIAN_HANDOFF.md:167 | `179 passed, 2 skipped` | 211 test function nel repo | ❌ **contraddizione** |
| CLAMGUARDIAN_HANDOFF.md:101,169 | `mypy: … 29 source files` | `mypy` reale: **36 source files** | ❌ **contraddizione** |
| CLAMGUARDIAN_HANDOFF.md:30,33 | `M4-FINAL PENDING`, "M4 is **not** complete" | coerente con assenza di report M4 | ✅ plausibile |
| design/2.x-A:7-11,13 | "NOT READY / BLOCKED", 3 difetti P1 aperti, "remediation design and implementation plan" | il codice a HEAD implementa già i 3 fix (vedi Finding F2) | ❌ **contraddizione** |
| design/2.x-A:46 | `HEAD SHA: 60bf0eb…` | HEAD reale `3bf0873…` (60bf0eb è il *parent*); base PR `a33d6a6b` | ❌ **contraddizione** |

---

## Finding

`[P1] F1 — ROADMAP.md dichiara PENDING fasi già implementate e testate (M6, M7, 1.1 USB, Threat Intelligence, 2.x-A)`
File: `docs/ROADMAP.md:96,101,106,111,116`
Evidenza: `docs/ROADMAP.md:96` "### Phase 7: M6 CI & Quality Gates / **Status:** PENDING" e `:101` "### Phase 8 & 9: M7 Packaging & 1.0 Release Gate / **Status:** PENDING", `:106` "### Phase 10: 1.1 USB Auto-Scan / **Status:** PENDING", `:111` "### Phase 11: Threat Intelligence Integration / **Status:** PENDING", `:116` "### Phase 12: 2.x-A Event-Driven Monitoring / **Status:** PENDING". Realtà: `.github/workflows/ci.yml:35` `run: mypy clamguardian`, `:37` `run: pip-audit`; `clamguardian/core/usb.py` (`class USBDeviceScanner`), `tests/test_usb.py` (6 test); `clamguardian/intelligence/virustotal.py:24 async def lookup_hash`; `clamguardian/realtime/` + `tests/test_realtime.py` (9 test). Il diff del PR (`a33d6a6b..3bf0873`) aggiunge `docs/ROADMAP.md (+130)` **insieme** a `ci.yml`, `core/usb.py`, `realtime/*`, `packaging/flatpak/*`: le fasi sono marcate PENDING nello stesso commit che le implementa.
Impatto: la roadmap, dichiarata "authoritative" (`ROADMAP.md:3`), è materialmente fuorviante sullo stato di completezza del prodotto 1.0; un revisore non può determinare cosa è realmente consegnato.
Correzione richiesta: aggiornare gli status di Phase 7–12 a COMPLETED (con commit/validazione), o spostarli a NEXT se mancano artefatti di gate specifici, e riconciliare con `CLAMGUARDIAN_HANDOFF.md`.

`[P1] F2 — docs/design/2.x-A-realtime-remediation-design.md descrive come "current" un codice che non esiste più a HEAD; lo stesso commit che lo introduce implementa i fix`
File: `docs/design/2.x-A-realtime-remediation-design.md:7,9-11,46,66-70,76-83,88-93,344,346`
Evidenza: `:7` "evaluated the subsystem as **NOT READY / BLOCKED**. Three P1 defects were confirmed"; `:46` "**HEAD SHA**: `60bf0ebeeea16e1fa3ea2a7aff2f4bf53220afbe`"; `:66` "# Lines 63-68 of orchestrator.py" seguito dal list-comprehension "pull-driven"; `:344` "**READY FOR IMPLEMENTATION**"; `:346` "Implementation can proceed in a subsequent phase following plan approval". Realtà a HEAD: `clamguardian/realtime/orchestrator.py:52` `self._debounce_timers: dict[Path, asyncio.TimerHandle] = {}`, `:108-111` `current_backlog = len(self._pending_events) + len(self._active_scans) … self._dropped_events_count += 1`, `:139-141` `loop.call_later(self.debounce_seconds, self._on_debounce_expired, …)` (debounce push-driven); `clamguardian/realtime/inotify.py:49` `for root, dirs, _files in os.walk(resolved, followlinks=False)` + `:118-124` registrazione dinamica su `CREATE|MOVED_TO` (watch ricorsivo). Le tre remediation sono già presenti. Inoltre `git diff --stat 60bf0eb..3bf0873` mostra che lo stesso commit modifica `orchestrator.py (+145)`, `inotify.py (+91)`, `test_realtime.py (+84)` **e** aggiunge il design doc (`+346`).
Impatto: documento di sicurezza materialmente fuorviante — dichiara tre difetti P1 bloccanti "currenti" su codice che a HEAD è già rimediato; chiude la questione "READY FOR IMPLEMENTATION" quando l'implementazione è già avvenuta.
Correzione richiesta: convertire il documento in "remediation report" con baseline = SHA del commit che ha applicato i fix, marcare i tre finding come RESOLVED con riferimento ai file/righe correnti, o rimuoverlo se non più attuale.

`[P1] F2b — Test nominati nel design 2.x-A inesistenti`
File: `docs/design/2.x-A-realtime-remediation-design.md:257-258,261,264`
Evidenza: dichiarati `test_debounce_push_driven_single_event`, `test_debounce_coalescing_resets_timer`, `test_queue_depth_bounds_pending_plus_active`, `test_inotify_recursive_nested_creation`. `grep -c` su `tests/test_realtime.py` → **0** per tutti e quattro. Esistono test funzionalmente analoghi ma con nomi diversi: `tests/test_realtime.py:110 test_orchestrator_push_debounce_single_event`, `:87 test_orchestrator_debouncing_and_deduplication`, `:133 test_orchestrator_queue_backpressure_bound`, `:196 test_inotify_monitor_recursive_nested_creation`.
Impatto: il documento cita prove di verifica che non esistono con quei nomi; non è possibile tracciare la copertura dichiarata.
Correzione richiesta: allineare i nomi citati ai test reali (o rinominare i test) e indicare file:riga.

`[P1] F3 — M7 / 1.0 release gate non chiudibile: icona referenziata assente e metainfo AppStream incompleto`
File: `data/io.github.clamguardian.ClamGuardian.desktop:6`, `data/io.github.clamguardian.ClamGuardian.metainfo.xml:1-22`
Evidenza: `desktop:6` `Icon=io.github.clamguardian.ClamGuardian` ma `find . -name '*.svg' -o -name '*.png' …` → **nessun risultato** (nessun asset grafico nel repo). `metainfo.xml` contiene `<id>`, `<summary>` (`:7`), `<description>` (`:8-13`), `<launchable>` (`:14`), `<releases><release version="1.0.0" date="2026-09-12">` (`:16`) ma **mancano** `<developer>`, `<content_rating>`, `<url>` e `<screenshots>` (file completo = 22 righe).
Impatto: `appstreamcli validate` / la validazione Flathub richiedono `developer` e `content_rating`; l'icona referenziata non esiste → il pacchetto desktop non è installabile/validabile; il gate "1.0 release readiness" (`ROADMAP.md:102`) non può chiudersi.
Correzione richiesta: aggiungere i file icona (es. `data/icons/hicolor/scalable/apps/io.github.clamguardian.ClamGuardian.svg`) e gli elementi `developer`/`content_rating` (+ `url`/`screenshots`) nel metainfo.


`[P2] F4 — Manifest Flatpak non pinna alcuna revisione e non installa desktop/metainfo`
File: `packaging/flatpak/io.github.clamguardian.ClamGuardian.yml:16-22`
Evidenza: `:20-22` `sources: - type: dir / path: ../..` → build dal working tree locale, **nessun** `type: git` con `commit:`/`tag:`; nessun `commit`/`branch` pinnato. `build-commands` (`:19`) contiene solo `pip install --no-deps --prefix=/app .`: nessuna installazione di `data/*.desktop`, `data/*.metainfo.xml` o icone.
Impatto: build non riproducibile (nessuna revisione fissata) e pacchetto Flatpak privo di integrazione desktop.
Correzione richiesta: usare `type: git` con `commit`/`tag` esplicito e aggiungere i passi di installazione di desktop entry, metainfo e icone in `/app/share/{applications,metainfo,icons}`.

`[P2] F5 — Gate CI `pip-audit` più debole di quanto implicato; `pip install --upgrade pip setuptools` altera l'insieme verificato`
File: `.github/workflows/ci.yml:31,37`
Evidenza: `:31` `run: python -m pip install --upgrade pip setuptools && python -m pip install '.[test,gtk]' ruff`; `:37` `run: pip-audit` (nessun `--strict`, nessun lockfile/`--require-hashes`). `uv.lock` è presente ma non viene usato per l'audit; l'upgrade di `pip`/`setuptools` a runtime cambia l'insieme delle distribuzioni ispezionate rispetto a `uv.lock`.
Impatto: senza `--strict` `pip-audit` non fallisce su dipendenze non verificabili; l'audit non riflette il set risolto/pinnato, quindi può mascherare (o falsare) i risultati attesi.
Correzione richiesta: rimuovere l'upgrade implicito prima dell'audit, usare `pip-audit --strict` e/o auditare il lockfile (`pip-audit -r`), documentare il perimetro del gate.

`[P2] F6 — README: versione PyGObject dell'extra `gtk` incoerente con pyproject`
File: `README.md:58,68` vs `pyproject.toml:24`
Evidenza: `README.md:58` "full desktop (adds PyGObject >= 3.53)", `README.md:68` "The `gtk` extra pins PyGObject >= 3.53"; `pyproject.toml:24` `"PyGObject>=3.46"`. (La `constraint-dependencies` a `:41` è `pygobject>=3.53`, ma l'extra è `>=3.46`; `uv.lock` risolve `pygobject 3.58.0`.)
Impatto: documentazione di installazione fuorviante sul vincolo effettivo.
Correzione richiesta: allineare l'extra a `>=3.53` (o correggere README).

`[P2] F7 — README non documenta i sottocomandi `history` presenti nel CLI`
File: `README.md:40,91-97` vs `clamguardian/cli/main.py:149,162,187,200`
Evidenza: `README.md:40` "`clamguardian scan|profiles|version`" e blocco Usage `:91-97` elenca solo `scan`, `profiles`, `version`. Il parser reale registra anche `history` con `list`/`show`/`purge` (`cli/main.py:149 sub.add_parser("history" …)`, `:162 history_sub.add_subparsers(…)`, `:187 "show"`, `:200 "purge"`). `grep -i history README.md` → **0 occorrenze**.
Impatto: la funzionalità di lifecycle/retention (M4-B7) è invisibile all'utente; README contraddice il CLI.
Correzione richiesta: aggiungere la sezione `history list|show|purge` con esempi e exit code.

`[P2] F8 — README descrive in modo errato trigger e comandi della CI`
File: `README.md:264` vs `.github/workflows/ci.yml:5-6,33-39`
Evidenza: `README.md:264` "runs `ruff` and `pytest` on Python 3.11, 3.12, and 3.13 … and triggers on every pull request plus pushes to `main`". CI reale: `ci.yml:5` `branches: [main, feature, development]`, `:6-7` `pull_request:`; i gate includono anche `:35 mypy clamguardian` e `:37 pip-audit` (oltre a `:33 ruff check .`, `:39 pytest`).
Impatto: sottostima i trigger (manca `feature`/`development`) e omette due gate di qualità.
Correzione richiesta: aggiornare la frase con i branch reali e i quattro gate.

`[P2] F9 — README "Scope" nega feature già implementate nel core`
File: `README.md:281`
Evidenza: `README.md:281` "A complete desktop product can build its … USB monitoring, real-time/on-access monitoring, scan profiles, and operational policy on top of these primitives." Realtà: `clamguardian/core/usb.py`, `clamguardian/realtime/` e `clamguardian/core/profiles.py` esistono già; `README.md:41` stesso documento dichiara "Scan profiles (M2) … shared by every front-end".
Impatto: contraddizione interna del README e sottostima della superficie funzionale consegnata.
Correzione richiesta: separare ciò che è nel core (profiles, realtime, usb) da ciò che è delegato al prodotto.

`[P2] F10 — CLAMGUARDIAN_HANDOFF.md: baseline, conteggi test e file sorgente obsoleti`
File: `docs/CLAMGUARDIAN_HANDOFF.md:5,11,99,101,167,169`
Evidenza: `:5` "2026-08-30"; `:11` "HEAD: `a33d6a6b1f1d689f2bd8e273b34b4c7e4ff31d5a`"; `:99` "pytest: 194 passed in 3.25s"; `:101` "mypy: Success: no issues found in 29 source files"; `:167` "pytest: 179 passed, 2 skipped in 2.01s"; `:169` "mypy: … 29 source files". Realtà: HEAD `3bf0873…`; 211 test function (`grep -c 'def test' tests/*.py` somma = 211); `mypy` → 36 source files; `find clamguardian -name '*.py' | wc -l` = 36.
Impatto: l'handoff, pensato come punto di ripresa per la sessione successiva (`:285-308`), è smentito dallo stato attuale; le due sezioni di validazione (`:99` e `:167`) si contraddicono tra loro (194 vs 179+2).
Correzione richiesta: aggiornare baseline SHA, data, conteggi test/sorgenti o marcare esplicitamente il documento come snapshot storico del 2026-08-30.


`[P3] F11 — Riferimento a file inesistente nel handoff`
File: `docs/CLAMGUARDIAN_HANDOFF.md:299`
Evidenza: `:299` `docs/CLAMGUARD_HANDOFF.md`, ma il file è `docs/CLAMGUARDIAN_HANDOFF.md` (`ls docs`).
Impatto: procedura di ripresa (`:296-300`) punta a un path errato.
Correzione richiesta: correggere il nome del file.

`[P3] F12 — README elenca le dipendenze core senza `inotify-simple`; wheel non impacchetta i data file`
File: `README.md:51`, `pyproject.toml:16,45-46`
Evidenza: `README.md:51` "Core dependencies are intentionally minimal (`cryptography`, `aiohttp`)"; `pyproject.toml:16` `"inotify-simple>=1.3.5; sys_platform == 'linux'"` è dipendenza core. `pyproject.toml:45-46` `[tool.hatch.build.targets.wheel] packages = ["clamguardian"]`: nessuna `shared-data`/`force-include`, quindi `data/*.desktop` e `data/*.metainfo.xml` non entrano nel wheel.
Impatto: descrizione dipendenze imprecisa; il wheel (entry point `clamguardian` presente a `pyproject.toml:20`) è importabile ma privo di integrazione desktop.
Correzione richiesta: aggiungere `inotify-simple` all'elenco; aggiungere `[tool.hatch.build.targets.wheel.shared-data]` per desktop/metainfo/icone.

`[P3] F13 — Flatpak `finish-args` insufficienti per gli use-case dichiarati (rete, quarantine, USB)`
File: `packaging/flatpak/io.github.clamguardian.ClamGuardian.yml:6-13`
Evidenza: finish-args presenti: `--socket=fallback-x11`, `--socket=wayland`, `--device=dri`, `--share=ipc`, `--talk-name=org.freedesktop.Flatpak`, `--filesystem=host:ro`, `--filesystem=xdg-data/clamguardian:create`. Assenti: `--share=network` (necessario per VirusTotal `intelligence/virustotal.py:29` e download DB), accesso al socket clamd (`/run/clamd.ctl` non è in `host:ro`), mount USB (`/media`, `/run/media`) e permessi di scrittura quarantine.
Impatto: a runtime il pacchetto Flatpak non può eseguire lookup VirusTotal, aggiornare DB o scansionare USB senza modifiche al manifest.
Correzione richiesta: aggiungere `--share=network`, `--filesystem=/run/clamd.ctl` (o socket host), `--filesystem=/media`/`/run/media`, e verificare la scrittura del vault.

`[P3] F14 — ROADMAP omette M4-B8 citato dal handoff`
File: `docs/ROADMAP.md:64,71` vs `docs/CLAMGUARDIAN_HANDOFF.md:28`
Evidenza: `CLAMGUARDIAN_HANDOFF.md:28` "M4-B8    NEXT / TO BE DEFINED"; `ROADMAP.md` elenca M4-B1→B7 (`:62-64`) e passa direttamente a "Phase 1" (`:71`), senza B8.
Impatto: due documenti di pianificazione non allineati sulla numerazione M4-B.
Correzione richiesta: riconciliare la numerazione o rimuovere B8 se assorbito.


---

## Sottocomandi CLI realmente esistenti (elenco)

Da `clamguardian/cli/main.py` (`add_parser`/`set_defaults`):
- `scan PATH [--profile ID] [--json]` — `:107`, `set_defaults` `:130`
- `profiles [--json]` — `:132`, `:140`
- `version` — `:142`, `:147`
- `history` (gruppo) — `:149`
  - `history list [--limit N] [--status STATUS] [--json]` — `:162`, `:185`
  - `history show ID [--json]` — `:187`, `:198`
  - `history purge [--before TS] [--status STATUS] [--json]` — `:200`, `:225`

Nessun sottocomando `realtime`, `usb`, `monitor`, `databases` o `intelligence` esiste nel CLI (coerente con `docs/design/cli.md:117-123` per `databases`).

---

## Aree verificate e risultate corrette

- **Coerenza versione**: `pyproject.toml:7 version = "1.0.0"` == `clamguardian/__init__.py:3 __version__ = "1.0.0"` == `metainfo.xml:16 <release version="1.0.0">`. Nessun disallineamento.
- **Identità Flatpak/desktop/metainfo**: `packaging/flatpak/…yml:1 app-id: io.github.clamguardian.ClamGuardian` == nome file desktop `io.github.clamguardian.ClamGuardian.desktop` == `metainfo.xml:3 <id>`; `command: clamguardian` (`yml:5`) == `desktop:5 Exec=clamguardian`; `metainfo.xml:14 <launchable type="desktop-id">io.github.clamguardian.ClamGuardian.desktop</launchable>` coerente.
- **Entry point wheel**: `pyproject.toml:19-20 [project.scripts] clamguardian = "clamguardian.cli.main:main"` corrisponde a `clamguardian/cli/main.py:547 def main() -> None:`; `clamguardian/cli/__main__.py` abilita `python -m clamguardian.cli` (README:79 coerente).
- **Build backend**: `pyproject.toml:1-3 hatchling` con `packages = ["clamguardian"]` — wheel importabile (limitazione data files in F12).
- **uv.lock vs pyproject**: tutte le versioni risolte soddisfano i vincoli — `cryptography 50.0.1>=43`, `aiohttp 3.14.3>=3.10`, `inotify-simple 2.0.1>=1.3.5`, `pytest 9.1.1>=8.0`, `pytest-asyncio 1.4.0>=0.23`, `mypy 2.3.1>=1.10`, `pip-audit 2.10.1>=2.7`, `pygobject 3.58.0>=3.53`.
- **Qualità codice a HEAD**: `ruff check --no-cache .` → `All checks passed!`; `mypy --cache-dir=/tmp/mypy_docs clamguardian` → `Success: no issues found in 36 source files` (coerente con i gate CI `ci.yml:33,35`).
- **CI wired sul branch corretto**: `ci.yml:5 branches: [main, feature, development]` + `:6-7 pull_request:` coprono sia il push sul branch `feature` sia la PR; `permissions: contents: read` (`:8-9`) minimale.
- **README exit codes** (`README.md:135-142`) coerenti con `docs/design/cli.md:89-96`.
- **README feature threat intelligence** (`README.md:182-197` VirusTotal + dynamic providers) corrisponde a `clamguardian/intelligence/virustotal.py:24 lookup_hash` e `intelligence/manager.py`.
- **M5 Phase 5&6** correttamente PENDING: `core/quarantine.py:47 self._aes = AESGCM(key)` non usa streaming/chunking.

---

## Non verificabile in questo ambiente

- **Esecuzione reale dei gate CI** (mypy/pip-audit/pytest sui tre interpreti, apt di PyGObject): non eseguiti (la suite è stata demandata ad altro auditor; nessuna rete).
- **Build effettiva del wheel** (`python -m build`/`hatchling`): non eseguita (dipendenze di build/rete); verificata solo la configurazione statica di `pyproject.toml`.
- **Build Flatpak** (`flatpak-builder`, `appstreamcli validate`): runtime/strumenti assenti; le carenze di metainfo/icona e la non-pin del sorgente sono dedotte dal manifest e dal file system.
- **Runtime ClamAV nel sandbox** (`clamd`, `/run/clamd.ctl`, `clamscan`/`freshclam`, definizioni, quarantine): non disponibile; le implicazioni sui `finish-args` sono inferite dal codice (`engines/clamav.py`, `intelligence/virustotal.py`).
- **Esito reale di `pip-audit`**: non eseguito (richiede rete/DB OSV); analizzata solo la configurazione del gate.
- **Contenuto del branch `feature` remoto**: clone superficiale (`git log --all` mostra solo `3bf0873`); gli SHA `a33d6a6b` e `60bf0eb` esistono come oggetti commit locali ma il loro rapporto con il remoto non è verificabile offline.
- **Conteggio esatto dei test "raccolti"** (211 è il numero di `def test` nei file, non il numero di test dopo parametrizzazione/skip); la discrepanza col handoff resta comunque dimostrata dal confronto con `mypy … 36 source files`.

