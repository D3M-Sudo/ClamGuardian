# M2 — Scan Profiles Design

Questo documento descrive l'astrazione **ScanProfile** introdotta in M2 e le
garanzie che la separano da ClamAV, dalla GTK UI e dal futuro CLI.

## Flusso architetturale

```text
                       ┌───────────────┐
                       │    GTK4/Adw   │
                       └───────┬───────┘
                               │ ScanProfile (oggetto, mai stringhe CLI)
                               ▼
                    ┌─────────────────────┐
                    │ ShieldTaskController │
                    └──────────┬──────────┘
                               ▼
                    ┌─────────────────────┐
                    │ ScanTaskRunner       │   (profilo inoltrato untouched)
                    └──────────┬──────────┘
                               ▼
                    ┌─────────────────────┐
                    │ BaseAVEngine         │
                    └──────────┬──────────┘
                               ▼
                    ┌─────────────────────┐
                    │ ClamAVEngine         │
                    │  _clamscan_args()    │  ← unica traduzione profilo→CLI
                    │  _clamd_unsupported()│
                    └──────────┬──────────┘
                 ┌─────────────┴─────────────┐
                 ▼                           ▼
              clamd                       clamscan
```

**Principio: UI ≠ ClamAV CLI options.** La UI conosce `ScanProfile` e
`ScanProfileRegistry`; i flag come `--max-filesize` esistono solo dentro
`clamguardian/engines/clamav.py`.

## Modello

`clamguardian/core/profiles.py` — `@dataclass(frozen=True, slots=True)`:

| Campo | Significato |
|---|---|
| `id`, `name`, `description` | identità del profilo |
| `recursive` | discesa nelle sottodirectory |
| `scan_archives` | ispezione interna degli archivi |
| `scan_mail` | ispezione file mail |
| `detect_pua` | rilevamento PUA |
| `max_filesize_mib` / `max_scansize_mib` | limiti dimensione (None = engine default) |
| `max_recursion` / `max_files` | limiti annidamento/numero file |
| `follow_symlinks` | `None` = policy di default dell'engine |

* **Immutabile**: `frozen=True, slots=True`; derivazione solo via
  `with_overrides()` (ritorna una nuova istanza validata).
* **Validato**: `validate()` in `__post_init__` e chiamato di nuovo dall'engine
  prima dell'esecuzione; errori → `ProfileError(ClamGuardianError)`
  (id/name vuoti, valori ≤ 0, `max_scansize_mib < max_filesize_mib`).
* **Agnostico**: nessuna dipendenza da GTK, subprocess o ClamAV.

## Registry

`ScanProfileRegistry`: `get(id)`, `list()`, `register(profile)`,
`in`. `DEFAULT_REGISTRY` contiene i quattro preset M2:

| Profile | Purpose | Options distintive |
|---|---|---|
| `quick` | aree ad alta rilevanza, veloce | no mail, `max_filesize=25M`, `max_scansize=100M`, `max_recursion=8` |
| `home` | home utente | archivi+mail, nessun limite artificiale |
| `full` | target completo | archivi+mail+PUA, nessun limite |
| `custom` | base configurabile utente | default, deriva con `with_overrides()` |

`DEFAULT_PROFILE` (`id="default"`) preserva il comportamento pre-M2 per le
chiamate legacy `scan(target, recursive=...)`.

## Traduzione engine

### clamscan
`ClamAVEngine._clamscan_args(profile)` produce (nell'ordine): `--recursive`,
`--scan-archive=yes|no`, `--scan-mail=yes|no`, `--pua`,
`--max-filesize=NM`, `--max-scansize=NM`, `--max-recursion=N`, `--max-files=N`,
`--follow-symlinks` / `--nofollow-symlinks`. Le opzioni `None` non generano
flag: l'engine applica il proprio default.

### clamd
clamd non ha un canale di opzioni per-connessione (sono impostazioni
server-side di `clamd.conf`). Politica esplicita:

* `recursive` + directory → comando `CONTSCAN`, altrimenti `SCAN`;
* tutte le altre opzioni **non** vengono passate e **non** sono ignorate in
  silenzio: l'elenco è riportato in
  `ScanResult.metadata["profile_unsupported_clamd"]`;
* `ScanResult.metadata["profile_id"]` riporta sempre il profilo usato.

In ogni caso il profilo non tocca `flatpak-spawn --host` (il prefisso è
applicato in `_run_command`, a valle della traduzione) e non modifica
`ScanResult`/`ScanStatus` né la semantica di cancellazione M0.5.

## Sicurezza

* il profilo non bypassa le validazioni del target (`resolve(strict=True)`
  resta nel motore);
* nessuna opzione user-controlled diventa una stringa CLI arbitraria: i campi
  sono tipizzati e validati, la traduzione è whitelist-based;
* nessun `shell=True`, nessuna interpolazione shell;
* nessun privilegio aggiuntivo (pkexec/systemd/D-Bus) introdotto per M2.
