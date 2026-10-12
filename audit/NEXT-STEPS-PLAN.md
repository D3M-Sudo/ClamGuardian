# ClamGuardian — Piano dei prossimi passi (da validare prima di implementare)

**Riferimento:** `audit/PR5-AUDIT-REPORT.md` (audit read-only della PR #5, commit `3bf0873`).
**Stato:** proposta. Nessuna modifica al codice è stata applicata; attendo la tua validazione.

---

## 1. Come cambia il piano rispetto alla roadmap che avevi

Il tuo impianto resta valido — audit → remediation mirata → M4 Final → M5/M6 → M7 → RC 1.0 → 1.x → 2.x-A → 2.x-B/C — con tre correzioni che derivano dalle prove raccolte:

1. **Lo step 01 (audit) è chiuso per il percorso critico.** Non serve un altro audit generico: i difetti sono individuati, riprodotti e classificati. I due rami che restano non verificabili in sandbox (`pip-audit` reale, runtime Flatpak/ClamAV/GTK) vanno spostati nei gate che li richiedono (WP-6 e WP-7), non rifatti adesso.
2. **Lo step 02 (remediation) non è "correggere qualche dettaglio":** contiene 3 P1 realtime nuovi, 2 P1 di gate (digest database, SHA-256 su clamd) e 3 P1 documentali/packaging. Va spezzato in work package con test-first e con un ordine che protegge la 1.0.
3. **Serve una decisione di perimetro prima di scrivere codice.** La PR #5 impacchetta in un unico insieme 1.0 (M4/M5/M6/M7) + 1.1 (USB) + Threat Intelligence + 2.x-A (realtime). Il codice realtime è quello con i difetti più gravi e, insieme a USB e Threat Intelligence, **non è cablato in nessun entry point**: nessuna di quelle tre fasi è validabile end-to-end oggi.

---

## 2. Decisioni che ti chiedo di prendere (prima di implementare)

### D1 — Perimetro della PR: split o riparazione in loco?

| Opzione | Cosa comporta | Valutazione |
|---|---|---|
| **D1-a (raccomandata)** — *Split*: estrarre dal branch il perimetro 1.0 (M4 Final + M5 + M6 + M7 + docs) e lasciare 1.1/TI/2.x-A su un branch separato | La 1.0 può chiudere i gate senza dipendere dal realtime; i difetti realtime vengono riparati dopo, con il loro gate | Riduce il rischio di release e rispetta la riduzione di scope già concordata (1.0 = on-demand affidabile; realtime = 2.x) |
| **D1-b** — Riparare tutto sul branch attuale, in un'unica PR | Un solo flusso, ma la 1.0 resta ostaggio di codice non cablato e di una fase (2.x-A) che non è nel perimetro 1.0 | Più veloce a breve, più rischioso per il gate 1.0 |

Se scegli **D1-a**, la riparazione realtime (`WP-5`) diventa lavoro di una fase successiva e il branch 1.0 contiene solo `WP-1..WP-4`.

### D2 — USB (1.1), Threat Intelligence e realtime: cablare o differire?

Le tre fasi hanno oggi un seam corretto ma **nessun consumatore** (nessun sottocomando CLI, nessuna pagina UI, nessun daemon). Opzioni:

- **D2-a (raccomandata):** differirle esplicitamente fuori dalla 1.0, marcandole come `IMPLEMENTED — NOT WIRED` nella roadmap, e affrontarle in 1.1/2.x con un entry point progettato (es. `clamguardian usb scan`, `clamguardian watch --path`, lookup TI opzionale dentro `scan`).
- **D2-b:** cablarle subito in CLI (serve anche una politica di opt-in per la rete e per i permessi host).

Senza questa decisione, `WP-5`/`WP-6` rischiano di consolidare codice che nessun utente può eseguire.

### D3 — Dove consegnare la remediation

- **D3-a (raccomandata):** nuovi commit su un branch di remediation dedicato (es. `fix/pr5-audit-remediation`), con la PR #5 mantenuta come riferimento e una PR separata verso `feature`. Nessun force-push, nessun rebase della PR esistente.
- **D3-b:** commit aggiuntivi direttamente su `feature-756467115717530540`.

In ogni caso: **nessuna operazione Git (commit/push/merge) senza tua autorizzazione esplicita**, come da regola operativa n.1.

### D4 — Ordine: M4 Final prima del realtime?

Raccomandazione: **sì**. `WP-1` (M4 Final) è il gate che protegge la persistenza e la sicurezza di tutto il resto; il realtime (`WP-5`) è una fase 2.x e va dopo la 1.0 (coerente con D1-a).

---

## 3. Work package, con criteri di accettazione verificabili

Regola comune: **test mirato che fallisce prima del fix e passa dopo** (per i difetti), nessuna nuova funzionalità, nessuna modifica ai confini architetturali, un work package alla volta con report ed evidenze.

### WP-1 — M4 Final (percorso critico 1.0)

| # | Intervento | File | Criterio di accettazione |
|---|---|---|---|
| 1.1 | SHA-256 anche sul ramo clamd (o `sha256=None` esplicito e documentato se non calcolabile) | `engines/clamav.py:61-73` | Test che esercita il ramo clamd con socket finto e asserisce `metadata["sha256"]` per un file singolo, `None` per una directory |
| 1.2 | Propagazione deterministica del profilo: rendere risolvibile `DEFAULT_PROFILE` (o persistere lo snapshot dal profilo effettivamente applicato) | `core/profiles.py:115,151-153`, `history/models.py:191-199`, `engines/clamav.py:72,81` | Test: scan senza `profile` esplicito → History con `profile_id` **e** `profile_snapshot` coerenti; test: `profile_id` non presente nel registry → `None` (non valore grezzo) |
| 1.3 | Best-effort con osservabilità: sopprimere `HistoryError` (non `Exception`) e registrare un warning | `realtime/orchestrator.py:181,185`, `core/usb.py:96` | Test con store che solleva: lo scan resta CLEAN e il fallimento è segnalato |
| 1.4 | Report finale M4 | `docs/` | Documento con SHA, comandi, output, elenco test e limiti |

**Gate WP-1:** nessun difetto M4 aperto, prove documentate su un commit congelato, `ruff`/`mypy`/`pytest` verdi.

### WP-2 — M5 hardening

| # | Intervento | File | Criterio di accettazione |
|---|---|---|---|
| 2.1 | Digest obbligatorio per gli artefatti database (o opt-out esplicito, tracciato e visibile) | `databases/provider.py:47-49`, `databases/models.py:21,44-47`, `ui/database_pages.py:190-191` | Test: artefatto senza digest → rifiuto con errore tipizzato; nessun `replace()` senza verifica |
| 2.2 | Rifiuto esplicito dei target speciali (FIFO/socket/device) e gestione symlink dichiarata | `engines/clamav.py:55` | Test: target FIFO/socket → risultato `ERROR` tipizzato, nessuna apertura |
| 2.3 | Quarantine streaming/chunked con limite di dimensione | `core/quarantine.py:61,121` | Test: file oltre soglia cifrato/ripristinato a chunk, memoria limitata (misurare con `tracemalloc`) |
| 2.4 | Rollback atomico per artefatto + `update_all` mancante | `databases/manager.py:112-119`, `ui/database_pages.py:395` | Test: fallimento a metà move → rollback completo; `update_all` presente o UI corretta |
| 2.5 | Restringere il parsing delle detection | `engines/clamav.py:250-254` | Test: output con path contenente `" FOUND"` e exit code 0 → CLEAN |

**Gate WP-2:** ogni P1/P2 di M5 chiuso con test; valutazione P2 (rischi residui) scritta.

### WP-3 — M6 quality gate (chiusura con riserva)

| # | Intervento | Criterio di accettazione |
|---|---|---|
| 3.1 | `pip-audit --strict` e audit sul lockfile (`uv.lock`), senza upgrade implicito prima dell'audit | Output registrato nel report di gate; perimetro del gate dichiarato |
| 3.2 | Eseguire la suite senza rete e documentare i 2 skip (GTK) come attesi | Log completo allegato |

**Gate WP-3:** risultati riproducibili sul commit esaminato, registrati con comandi e output.

### WP-4 — M7 packaging e gate 1.0

| # | Intervento | File | Criterio di accettazione |
|---|---|---|---|
| 4.1 | Icona reale (`data/icons/hicolor/scalable/apps/io.github.clamguardian.ClamGuardian.svg`) e riferimento coerente | `data/…desktop:6` | File presente e percorso coerente con l'app-id |
| 4.2 | Metainfo completo (`<developer>`, `<content_rating>`, `<url>`, `<screenshots>`) | `data/…metainfo.xml` | `appstreamcli validate` senza errori |
| 4.3 | Manifest Flatpak: sorgente pinnata (`type: git` + `commit`/`tag`), installazione di desktop/metainfo/icone, `finish-args` coerenti (rete per TI/DB, socket clamd, mount USB se in perimetro) | `packaging/flatpak/…yml` | Build Flatpak eseguita e documentata (con limiti ambientali dichiarati) |
| 4.4 | Wheel con i data file (`shared-data`) o scelta esplicita di non impacchettarli | `pyproject.toml:45-46` | `python -m build` + ispezione del wheel |

**Gate WP-4:** test pratico end-to-end documentato (build, installazione, avvio, scansione), errori e limiti inclusi.

### WP-5 — 2.x-A realtime (dopo la 1.0, se D1-a)

| # | Intervento | File | Criterio di accettazione |
|---|---|---|---|
| 5.1 | Timer disinnescato correttamente + guardia su `_active_scans` | `realtime/orchestrator.py:151-164` | Test: due eventi a cavallo della scadenza → **una sola** scansione; `rt_probe.py` scenario B verde |
| 5.2 | Bound sul lavoro reale (task, non path) | `realtime/orchestrator.py:53,108,197` | Test d'invariante campionato durante l'esecuzione: `outstanding ≤ max_queue_depth` anche con duplicati |
| 5.3 | Shutdown deterministico (registrazione anticipata dei task, cancellazione dei task in attesa) | `core/runner.py:46-49,74-80` | Test: `close()` con N path e concorrenza 1 → nessuna scansione dopo la chiusura; nessun task residuo |
| 5.4 | Propagazione di `CancelledError` e registrazione dell'esito cancellato | `realtime/orchestrator.py:189-190` | Test: `task.cancelled()` vera; riga History con stato `cancelled` |
| 5.5 | Gestione `MOVED_FROM` su directory (watch stale) e scarto degli eventi fuori albero | `realtime/inotify.py:126-138` | Test: directory spostata fuori → nessun evento con path inesistente (`inot_probe.py` I4, `phantom_probe.py` verdi) |
| 5.6 | Segnalazione di `ENOSPC`/`IN_Q_OVERFLOW` e stato di salute del monitor | `realtime/inotify.py:58-70,100-112` | Test: `ENOSPC` simulato → errore/contatore osservabile; overflow → segnale al chiamante |
| 5.7 | Driver di monitoraggio (entry point) o differimento esplicito | nuovo modulo/CLI | Ciclo `read_events` → `handle_events` eseguito fuori dal thread dell'event loop, con shutdown pulito; oppure fase marcata `DEFERRED` con motivazione |

**Gate WP-5:** nessun P1 aperto, invarianti di concorrenza verificati, end-to-end eseguibile.

### WP-6 — 1.1 USB e Threat Intelligence (se D2-b)

Validazione mount rimovibile (`usb.py:57-79`), call-site CLI/UI, opt-in esplicito e privacy per la rete (`intelligence/`), test su dispositivi rimossi e percorsi non validi.

### WP-7 — Documentazione (va eseguita **dopo** i fix, non prima)

`docs/ROADMAP.md` (status reali), `docs/CLAMGUARDIAN_HANDOFF.md` (baseline, conteggi, nome file), `docs/PROJECT_PLAN.md`, `docs/design/2.x-A-realtime-remediation-design.md` (riclassificato come piano storico **oppure** aggiornato con esito verificabile per ogni P1), `README.md` (sottocomando `history`, trigger CI, dipendenze, versione PyGObject), rinominare/allineare i nomi dei test citati.

---

## 4. Sequenza consigliata e gate

```
D1/D2/D3 (decisioni)
   │
   ├─ WP-1  M4 Final  ──────────────► gate: nessun difetto M4, prove su commit congelato
   │                                     │
   ├─ WP-2  M5 hardening ───────────► gate: P1/P2 M5 chiusi con test
   │                                     │
   ├─ WP-3  M6 quality gate ────────► gate: risultati riproducibili e registrati
   │                                     │
   ├─ WP-4  M7 packaging ───────────► gate: build+installazione+avvio documentati
   │                                     │
   ├─ WP-7a Documentazione 1.0 ─────► gate: roadmap/handoff/README coerenti col codice
   │                                     │
   │                              RC 1.0 (checklist di rilascio)
   │
   ├─ WP-6  1.1 USB + TI ───────────► gate: opt-in, sicurezza, nessuna regressione on-demand
   │
   ├─ WP-5  2.x-A realtime ─────────► gate: nessun P1, invarianti di concorrenza verificati
   │
   └─ 2.x-B / 2.x-C  progettazione separata (threat model, permessi, lifecycle, piano test)
```

Se scegli **D1-a**, `WP-5` e `WP-6` escono dal branch 1.0 e la RC 1.0 si chiude con `WP-1..WP-4` + `WP-7a`.

---

## 5. Ordine di esecuzione pratico per la prossima sessione

1. **Conferma delle decisioni D1/D2/D3** (e, se vuoi, D4).
2. **Congelare un commit di riferimento**: annotare lo SHA su cui si lavora e la baseline di confronto.
3. **WP-1.1** (SHA-256 su clamd): è il difetto più piccolo e più a rischio gate — un test rosso, un fix, un test verde.
4. **WP-1.2** (propagazione profilo): secondo test rosso, secondo fix.
5. **WP-2.1** (digest database obbligatorio): il P1 di sicurezza più grave del perimetro 1.0.
6. Poi il resto dei work package, in ordine, con report di gate al termine di ciascuno.
7. **WP-7a** (documentazione) solo alla fine, sui fatti verificati.

---

## 6. Regole che mantengo per tutta la roadmap

1. Nessuna operazione Git di scrittura (commit, push, merge, rebase) senza tua autorizzazione esplicita; nessun force-push; la PR #5 non viene toccata senza istruzione.
2. Un gate alla volta: ogni fase termina con report, evidenze, stato di accettazione.
3. Niente feature creep prima della 1.0; niente estensione a 2.x-B/2.x-C.
4. Test mirato prima del fix; suite completa solo dopo.
5. Confini architetturali invariati (core / engines / history / cli / ui / integrazioni host).
6. Nessun bypass di sicurezza e nessun meccanismo privilegiato non previsto dal design approvato.

---

## 7. Cosa mi serve da te per partire

- **D1**: split (a) o riparazione in loco (b)?
- **D2**: differire 1.1/TI/realtime fuori dalla 1.0 (a) o cablarli subito (b)?
- **D3**: branch di remediation dedicato (a) o commit sul branch della PR (b)?
- **Autorizzazione** a modificare i file e a creare il branch scelto (finché non arriva, resto in sola lettura).
- **Conferma** che il perimetro 1.0 resta quello concordato: on-demand completo e affidabile (profili, CLI, History, cancellazione, progressione, quarantena, aggiornamento definizioni, hardening, CI, packaging).

Con D1-a + D2-a + D3-a posso iniziare da `WP-1.1` e `WP-1.2` e consegnarti, per ciascuno, il test rosso iniziale, il fix minimo e l'evidenza verde.

---

## 8. Artefatti di questo audit (branch `cline/1afzx1w5`)

```
audit/PR5-AUDIT-REPORT.md          report completo con finding e severità
audit/NEXT-STEPS-PLAN.md           questo piano
audit/repro/rt_probe.py            scenari A–G sull'orchestratore (debounce, duplicati, bound, shutdown, cancellazione, dirty, History)
audit/repro/inot_probe.py          scenari I1–I8 su InotifyMonitor (ricorsione, move in/out, ENOSPC, overflow, symlink)
audit/repro/stress_probe.py        invariante del backlog con sola API pubblica
audit/repro/phantom_probe.py       conseguenza end-to-end del watch stale su History
audit/repro/race_probe.py          riproduzione del duplicato con timing naturale
audit/repro/race_probe2.py         stessa prova con timeline strumentata
audit/repro/reviewer-m4m5-raw.md   report grezzo del revisore M4/M5 (audit incrociato)
audit/repro/reviewer-docs-raw.md   report grezzo del revisore documentazione/CI/packaging
```

Nessuno di questi file esiste sul branch della PR: sono su un branch di servizio creato solo per non perdere il lavoro.
