# Audit tecnico indipendente — ClamGuardian

**Data:** 2026-10-19
**Oggetto:** commit `7ab9891dfc3377903979b2a7c78f81df66cacc8e` (branch `feature`, 30 commit avanti a `v1.0.0`)
**Tag di riferimento:** `v1.0.0` → commit `8ee8a56ccbdcaa4bae964bcc57cd1b301b530be7` (tag annotato, verificato via GitHub API)
**Perimetro:** codice applicativo, packaging/supply chain, runtime del container
**Metodo:** ispezione statica, esecuzione dei gate, riproduzione strumentata dei difetti, verifica indipendente delle asserzioni CI su GitHub, audit dipendenze via OSV

---

## 1. Valutazione globale

**Giudizio sintetico: 7.0/10 — B. Impianto solido e ben ingegnerizzato, ma un difetto P1 invalida la promessa principale del prodotto sul percorso di scansione primario.**

| Area | Punteggio | Motivazione sintetica |
|---|---:|---|
| Sicurezza del rilevamento (core AV) | **5.5/10** | `clamd` restituisce solo la prima riga di risultato: scansioni di directory possono essere dichiarate `CLEAN` con malware presente (AUD-01) |
| Integrità del software (quarantine, storage) | 8.0/10 | Crypto e formati ben progettati; gestione chiave desktop non atomica e keyring non funzionante (AUD-02/03) |
| Qualità del codice e dei test | 9.0/10 | `ruff` e `mypy` puliti, 308 test verdi, confini architetturali rispettati; manca copertura sul protocollo `clamd` multi-riga |
| Packaging e supply chain | 7.5/10 | Wheel pinnate con SHA-256, build offline, runtime 3.14 coerente; workflow con permessi di default e action pinnate a tag |
| Runtime e operatività | 7.5/10 | Container hardened (nessuna capability, `no_new_privs`, seccomp); porte in ascolto e segreti in ambiente da contenere |
| Configurazioni & Shell (`zsh`, alias, `.zshrc`) | **n/d** | Nessuna shell `zsh`, nessun file rc, nessun alias presente nel perimetro: voce non applicabile |

**Verdetto operativo:** adatto a un uso di laboratorio, **non raccomandato come controllo di sicurezza** finché AUD-01 non è corretto e coperto da test. La release `v1.0.0` contiene il difetto: `clamguardian/engines/clamav.py` è identico tra tag e `HEAD`.

---

## 2. Sintesi dei finding

| ID | Severità | Area | Titolo |
|---|---|---|---|
| AUD-01 | **P1** | Core AV | Falso negativo su scansioni directory: il client `clamd` si ferma alla prima riga |
| AUD-02 | P2 | Segreti | Secret Service non funzionante: fallback silenzioso a chiave in chiaro su file |
| AUD-03 | P2 | Integrità dati | Chiave di quarantena scritta in modo non atomico: rischio perdita definitiva del vault |
| AUD-04 | P2 | Sicurezza input | Injection di comandi `clamd` via `\n` nel path del target |
| AUD-05 | P2 | CI/CD | `release-gate.yml` senza blocco `permissions`, action pinnate a tag mutabili |
| AUD-06 | P2 | Runtime | Servizi in ascolto su `0.0.0.0` (infrastruttura di sessione, fuori dal repo) |
| AUD-07 | P3 | Test | CI non esegue Python 3.14, l'unica versione del runtime Flatpak |
| AUD-08 | P3 | Traversal | `_restore_target` non confina il path di ripristino |
| AUD-09 | P3 | Filesystem | Semantica symlink: `resolve()` + `unlink()` elimina il target, non il link |
| AUD-10 | P3 | Filesystem | `chmod 0700` su directory padre preesistente del DB storico |
| AUD-11 | P3 | Dead code | Provider VirusTotal presente ma non cablato in nessun flusso |
| AUD-12 | P3 | Output | Escape ANSI non neutralizzati nell'output umano della CLI |
| AUD-13 | P3 | Supply chain | Dipendenze di test/lint e pacchetti apt non pinnati in CI |
| AUD-14 | P3 | Runtime | Segreti ereditati dai sottoprocessi, zombie transitori, lock `0666` in cache |

---

## 3. Evidenze riscontrate

### 3.1 Integrità del Sistema

| Verifica | Comando | Esito |
|---|---|---|
| Integrità pacchetti Debian | `dpkg -V` | Nessuna discrepanza di checksum; solo file di documentazione mancanti (immagine alleggerita) |
| Audit database dpkg | `dpkg --audit` | Vuoto (nessun pacchetto in stato incoerente) |
| Aggiornamenti disponibili | `apt list --upgradable` | Nessun risultato, ma `/var/lib/apt/lists` è vuota: la verifica è **inconcludente** senza `apt update` (richiede rete e privilegi) |
| File sensibili nel repo | `git ls-files` | Nessun `quarantine-key`, `*.qtn`, `history.db`, `settings.json` o `.env` tracciato; `.gitignore` li copre |
| Segreti hardcoded | `rg -i 'api_key|secret|token'` | Nessuna credenziale nel codice; solo nomi di variabili e test |
| Provenienza release | GitHub API | `v1.0.0` è un tag annotato che punta a `8ee8a56`, coerente con `RELEASE-GATE-1.0.md`; **tag non firmato** |
| CI sul commit corrente | GitHub API | Run `39187995968`: successo (3.11, 3.12, 3.13 + dependency audit) |
| Release Gate sul tag | GitHub API | Run `38977065253` @ `8ee8a56`: **7/7 job verdi** (preflight, AppStream, ClamAV reale, GTK smoke, flatpak local, flatpak release, summary) |
| Dipendenze runtime | OSV `querybatch` su `uv.lock` (13 pacchetti runtime) | 0 vulnerabilità note alla data dell'audit; `uv lock --check` coerente |

**Rilievo di integrità principale:** la promessa "Authenticated quarantine / Tamper-evident metadata" è implementata correttamente (AES-256-GCM a chunk da 1 MiB, nonce derivato per indice, AAD che lega metadati, indice e flag di ultimo chunk: `clamguardian/core/quarantine.py:343-355`). Il punto debole non è il formato crittografico ma la **gestione della chiave** (AUD-02/03) e il **rilevamento** (AUD-01).

**Limite di verifica:** il clone locale è `grafted`/shallow (`git rev-list --count HEAD` = 1). La storia completa non è ispezionabile localmente; le asserzioni su tag e run sono state verificate via API GitHub, non con firme crittografiche locali.

### 3.2 Prestazioni & Processi

| Evidenza | Valore | Lettura |
|---|---|---|
| Processi utente | PID 1 `node` (~345 MB RSS, agente), wrapper shell, 1–2 zombie `[tail]`/`[bash]` | Gli zombie sono transitori del wrapper di sessione, non di ClamGuardian |
| Concorrenza scansioni | `Semaphore(max_concurrency=2)` (`core/runner.py:27`) | Limite esplicito e rispettato; nessuna unbounded task creation |
| Cancellazione | `killpg` SIGTERM → 5 s → SIGKILL (`engines/clamav.py:260-287`) | Corretta: nessun orfano ClamAV, `CancelledError` propagato |
| Memoria quarantena | chunk 1 MiB, cap 512 MiB (`core/quarantine.py:31-33`) | Streaming reale: footprint costante anche su file grandi |
| Memoria risposta `clamd` | `chunks: list[bytes]` senza limite (`engines/clamav.py:150-157`) | Accumulo non limitato se `clamd` invia output voluminoso (P3, parte di AUD-01) |
| Processi ClamAV | `clamscan`/`clamdscan`/`freshclam` assenti | Il percorso live non è eseguibile in questo container; la verifica end-to-end è stata fatta con un finto `clamd` su socket UNIX |
| Disco | 232 MB usati su 16 GB nel workspace | Nessuna pressione; cache `.venv` e artefatti test trascurabili |

Il container è **hardened**: `CapEff=0`, `CapPrm=0`, `NoNewPrivs=1`, `Seccomp=2` con 1 filtro attivo, utente non-root `uid=1000`. I binari setuid di sistema (`passwd`, `su`, `mount`, …) non sono sfruttabili senza capability effettive.

### 3.3 Configurazioni & Shell (`zsh`, alias, `.zshrc`)

**Voce non applicabile nel perimetro attuale, e va dichiarata tale anziché compilata per assunzione:**

- `zsh` non è installato (`command -v zsh` → MISSING); la shell è `/bin/bash`.
- `/home/node` non contiene `.zshrc`, `.bashrc`, `.profile` né `.config`: non esistono alias, funzioni o hook di shell da verificare.
- `nala`, `btop`, `batcat`, `fdfind`, `systemctl`, `journalctl` non sono installati; non esistono log di journal né unità systemd da ispezionare.

Ne consegue che le voci "pulizia alias", "stabilità shell" e "log di sistema" **non sono verificabili qui**. Se l'audit deve coprire una macchina desktop reale, va eseguito sul target con:

```bash
zsh -ic 'alias -L; typeset -p PATH; bindkey -L' > /tmp/zsh-audit.txt
systemctl --user --failed; journalctl --user -p warning -b --no-pager | tail -200
```

### 3.4 Superficie di rete e segreti d'ambiente

- In ascolto su `0.0.0.0`: **8080, 8081, 15001** (servizi dell'infrastruttura di sessione, non di ClamGuardian). Se l'host li espone oltre il loopback, sono raggiungibili dall'esterno: da segregare a livello di rete.
- Variabili d'ambiente con credenziali presenti nel processo dell'agente: `GH_TOKEN`, `LANGFUSE_SECRET_KEY`, `LANGFUSE_PUBLIC_KEY`, `CLINE_*`. Qualsiasi sottoprocesso le eredita; `diagnostics.py:129` invoca `flatpak-spawn --host which <name>` **senza** `env=` ristretto, quindi un binario host le riceve (AUD-14).
- File world-writable fuori dal repo: `/workspace/.cline-home/home/.cache/uv/.lock` (modo `0666`). Non impatta ClamGuardian, ma è igiene del runtime da correggere (`chmod 600`).

---

## 4. Finding dettagliati

### AUD-01 — P1 — Falso negativo su scansioni di directory via `clamd`

**File:** `clamguardian/engines/clamav.py:147-158` (identico nel tag `v1.0.0`)

```python
writer.write(command + b" " + os.fsencode(str(target)) + b"\n")
...
while True:
    chunk = await reader.read(65536)
    if not chunk:
        break
    chunks.append(chunk)
    if b"\n" in chunk and any(token in chunk for token in (b"FOUND", b"OK", b"ERROR")):
        break          # <-- esce al primo risultato, non a fine comando
```

**Evidenza riproducibile** (`docs/validation/repro-clamd-multiline.py`, socket UNIX che emula `clamd`):

```
=== CASE 1: multi-file directory scan ===
returned output: '/scan/clean-a.txt: OK\n'
returned exit code: 0
expected FOUND line present: False

=== CASE 3: end-to-end engine.scan(directory) ===
status: clean | threats: ()
clean flag: True | engine: clamd
```

`clamd` risponde a `CONTSCAN`/`SCAN` con **una riga per file**, inviate in streaming, e chiude la connessione a fine comando. Il client interrompe la lettura appena un chunk contiene `OK`, `FOUND` o `ERROR`: su una directory con più file restituisce solo il primo risultato. Se il primo file è pulito, `_result()` classifica `CLEAN`, `threats=()` e la CLI esce con codice `0`.

**Impatto:** bypass del rilevamento sul percorso **primario** (il ramo `clamd` è preferito quando `/run/clamd.ctl` esiste, come dichiarato nel README). Le scansioni `quick`/`home`/`full` sono scansioni di directory: un file infetto successivo al primo non viene né segnalato, né quarantinato, né registrato nello storico. Il difetto è nella release `v1.0.0`: `git diff v1.0.0..HEAD -- clamguardian/engines/clamav.py` è vuoto. Non è coperto dai test: i mock di `tests/test_engine.py` restituiscono una sola riga.

**Remediation (non distruttiva):** leggere fino a EOF, con limite di dimensione; eliminare il `break` anticipato.

```python
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024  # bound the buffer, not the scan

chunks: list[bytes] = []
total = 0
while True:
    chunk = await reader.read(65536)
    if not chunk:
        break  # clamd closes the connection when the command completes
    total += len(chunk)
    if total > _MAX_RESPONSE_BYTES:
        raise ValueError("clamd response exceeded the size limit")
    chunks.append(chunk)
output = b"".join(chunks).decode("utf-8", errors="replace")
```

Aggiungere un test di regressione con un server UNIX reale che invia tre righe con `await asyncio.sleep(0)` tra una e l'altra, e asserire `ScanStatus.INFECTED` e la presenza del nome della firma. Il test deve fallire sul codice attuale.

---

### AUD-02 — P2 — Secret Service non funzionante, fallback silenzioso

**File:** `clamguardian/ui/quarantine_key.py:81-114`

```python
password = Secret.password_lookup_sync("clamguardian", "quarantine-key", None)
...
Secret.password_store_sync("clamguardian", "quarantine-key", key.hex(), None)
```

L'API libsecret richiede un `Secret.Schema` e un dizionario di attributi:

- `Secret.password_lookup_sync(schema, attributes, cancellable)`
- `Secret.password_store_sync(schema, attributes, collection, label, password, cancellable)`

Il codice passa stringhe al posto di `Schema`/`dict` e chiama `password_store_sync` con 4 argomenti invece di 6. L'eccezione (`TypeError`) viene inghiottita da `except Exception: return None/False`, quindi **il keyring non viene mai usato**: la chiave finisce sempre nel file esadecimale. La docstring e il README dichiarano il contrario ("try Secret Service first").

**Impatto:** la chiave AES del vault è archiviata in chiaro (sia pure `0600`) su disco, fuori dal keyring di sessione; nessun segnale all'utente. Su ambienti multi-utente o backup domestici la protezione attesa non esiste.

**Remediation:** definire uno schema una volta e usare le firme corrette, con validazione della lunghezza:

```python
_SCHEMA = Secret.Schema.new(
    "io.github.clamguardian.Quarantine",
    Secret.SchemaFlags.NONE,
    {"purpose": Secret.SchemaAttributeType.STRING},
)
_ATTRS = {"purpose": "quarantine-key"}
password = Secret.password_lookup_sync(_SCHEMA, _ATTRS, None)
Secret.password_store_sync(
    _SCHEMA, _ATTRS, Secret.COLLECTION_DEFAULT,
    "ClamGuardian quarantine key", key.hex(), None,
)
```

Aggiungere un test con un modulo `gi.repository.Secret` finto che verifichi ordine e numero degli argomenti, e un log `WARNING` una tantum quando si degrada al file.

---

### AUD-03 — P2 — Chiave di quarantena non atomica: rischio perdita definitiva

**File:** `clamguardian/ui/quarantine_key.py:116-137`

```python
raw = path.read_bytes()
key = bytes.fromhex(raw.decode("ascii").strip())
...
path.write_text(key.hex())
os.chmod(path, KEY_FILE_MODE)
```

Tre problemi distinti:

1. `write_text` crea il file con `0666 & ~umask` (tipicamente `0644`) e solo dopo applica `0600`: esiste una finestra in cui la chiave è leggibile da altri utenti locali.
2. La scrittura non è atomica e non fa `fsync`: un crash a metà lascia un file troncato. Al riavvio `_load_file()` restituisce `None` (lunghezza errata) e `load_or_create()` **genera una nuova chiave**, rendendo definitivamente indecifrabili tutti i record già in quarantena.
3. `_load_secret_service()` non valida la lunghezza della chiave letta dal keyring; una voce corrotta fa fallire il costruttore di `QuarantineVault` con `ValueError`.

**Impatto:** perdita silenziosa e irreversibile dei file quarantinati (integrità del dato), più esposizione temporanea del segreto. Il modulo è stato introdotto **dopo** `v1.0.0` (file `A` nel diff dal tag): il difetto riguarda la prossima release, non il tag.

**Remediation:** riusare il pattern già presente in `QuarantineVault._atomic_writer` (mkstemp nella stessa directory, `fchmod(0600)`, `fsync`, `os.replace`) e **fallire in modo chiuso** se il file esiste ma non è valido:

```python
def _load_file(self) -> bytes | None:
    ...
    if len(key) != _KEY_SIZE:
        raise ValueError("quarantine key file is corrupt; refusing to rotate it")

def _store_file(self, key: bytes) -> None:
    fd, tmp = tempfile.mkstemp(prefix=".quarantine-key.", dir=self._key_dir)
    try:
        os.fchmod(fd, KEY_FILE_MODE)
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(key.hex())
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self._key_path())
    finally:
        Path(tmp).unlink(missing_ok=True)
```

Aprire con `O_NOFOLLOW` (o verificare `not path.is_symlink()`) per non seguire link creati nella directory.

---

### AUD-04 — P2 — Injection nel protocollo `clamd` via newline nel path

**File:** `clamguardian/engines/clamav.py:148`

Il comando è costruito concatenando il path al verbo e terminando con `\n`, senza validare i caratteri di controllo. Un file chiamato `evil\nSHUTDOWN` produce sul socket:

```
SCAN /tmp/.../evil
SHUTDOWN
```

Il repro conferma che il server riceve `SCAN /tmp/.../evil\n`; `clamd` interpreta la riga successiva come **secondo comando**. I comandi disponibili nel protocollo includono `SHUTDOWN`, `RELOAD`, `SCAN`, `CONTSCAN`, `STATS`. Il README dichiara "No shell, no injection": qui non c'è una shell, ma c'è injection a livello di protocollo.

**Impatto:** un nome file controllato dall'attaccante (download, archivio estratto, USB) può spegnere o ricaricare `clamd` (DoS) o forzare scansioni arbitrarie quando l'utente scansiona direttamente quel file. Richiede che l'utente selezioni il file; non è remoto.

**Remediation:** rifiutare i target che contengono `\n`, `\r` o NUL prima di qualsiasi I/O sul socket (e idealmente già in `CLI`/`UI`), con un `ScanResult` di stato `ERROR` e messaggio esplicito:

```python
raw = os.fsencode(str(target))
if b"\n" in raw or b"\r" in raw or b"\x00" in raw:
    raise ValueError("Unsupported scan target: control characters in path")
```

Il protocollo `clamd` non prevede quoting: la validazione è l'unica difesa corretta.

---

### AUD-05 — P2 — Least privilege e pinning delle GitHub Actions

**File:** `.github/workflows/release-gate.yml:1-18`, `.github/workflows/ci.yml:8-9,19-26`

`ci.yml` dichiara `permissions: contents: read`; `release-gate.yml` **non ha alcun blocco `permissions:`**, quindi il `GITHUB_TOKEN` eredita i permessi di default del repository. Inoltre le action sono referenziate per tag (`actions/checkout@v7`, `actions/setup-python@v7`, `actions/upload-artifact@v4`): un tag può essere spostato, un SHA no.

**Impatto:** un'azione compromessa o un tag riscritto può eseguire codice con token più ampi del necessario; superficie supply-chain non riproducibile.

**Remediation:** aggiungere in testa a `release-gate.yml`:

```yaml
permissions:
  contents: read
```

e fissare ogni action al commit SHA (Dependabot/Renovate gestiscono l'aggiornamento), con `persist-credentials: false` su `actions/checkout`.

---

### AUD-06 — P2 — Servizi in ascolto su tutte le interfacce (runtime)

**Evidenza:** `/proc/net/tcp` riporta listener su `0.0.0.0:8080`, `0.0.0.0:8081`, `0.0.0.0:15001` (servizi dell'infrastruttura di sessione, non di ClamGuardian). `ss`/`lsof` non sono installati, quindi la mappatura PID↔porta non è verificabile qui.

**Impatto:** se l'host espone queste porte oltre il loopback, i servizi sono raggiungibili dall'esterno. Fuori dal perimetro del repository, ma dentro il perimetro "runtime" richiesto.

**Remediation:** bind su `127.0.0.1`/socket UNIX, oppure regole firewall esplicite; verificare con `ss -ltnp` su un host con gli strumenti completi.

---

### AUD-07 — P3 — CI non esegue Python 3.14 (runtime Flatpak)

**File:** `.github/workflows/ci.yml:17`, `tests/test_packaging.py:276-315`

La matrice copre `3.11`, `3.12`, `3.13`; il test di packaging impone wheel `cp314` perché il runtime `org.gnome.Sdk//51` usa Python 3.14 (`_RUNTIME_PYTHON_TAG = "cp314"`). Nessun job esegue il codice sotto 3.14: un'incompatibilità di runtime (API rimosse, comportamento `asyncio`, PyGObject) non verrebbe intercettata prima della build Flatpak.

**Remediation:** aggiungere `"3.14"` alla matrice (o un job container basato su `org.gnome.Sdk//51` che esegua `python3 -c "import clamguardian.cli.main"` e la suite headless).

---

### AUD-08 — P3 — `_restore_target` non confina il path

**File:** `clamguardian/core/quarantine.py:286-293`

Il controllo rifiuta solo i path che iniziano con `..` o contengono `/../`. Un path assoluto (`/etc/...`), un path relativo con `..` in altre posizioni o un path che risolve fuori dalla directory utente vengono accettati. I metadati sono autenticati come AAD, quindi serve una chiave valida o un produttore malevolo del record per sfruttarlo: rischio residuo, non exploit remoto.

**Remediation:** di default confinare il ripristino a una radice esplicita (home o directory scelta dall'utente) con `Path.is_relative_to()`, rifiutando path assoluti nei metadati; mantenere un override esplicito per il ripristino "dove era".

---

### AUD-09 — P3 — Semantica symlink in quarantena

**File:** `clamguardian/core/quarantine.py:100-102,153-157,300-302`

`resolve(strict=True)` segue il link e `unlink()` elimina il **target**, lasciando un link pendente. Analogamente `_harden_permissions` fa `chmod` sulla directory risolta, che può essere un link a una directory condivisa. Un utente che quarantena un link si aspetta di rimuovere il link, non il file puntato.

**Remediation:** usare `os.lstat()` e rifiutare i symlink (o rimuovere il link senza seguirli); verificare `directory.is_symlink()` prima del `chmod`.

---

### AUD-10 — P3 — `chmod 0700` su directory padre preesistente

**File:** `clamguardian/history/backend.py:196-199`

`os.chmod(self.path.parent, _DIR_MODE)` viene eseguito anche se la directory esisteva già ed era condivisa (caso di un path custom che punta a `~/Documenti` o a `XDG_DATA_HOME` stesso): i permessi vengono cambiati silenziosamente.

**Remediation:** applicare il `chmod` solo alla directory appena creata (`mkdir` senza `exist_ok` in un `try/except FileExistsError`), e documentare che il path custom deve essere dedicato.

---

### AUD-11 — P3 — Provider VirusTotal non cablato

**File:** `clamguardian/intelligence/virustotal.py`, `clamguardian/intelligence/manager.py`

`rg 'ThreatProviderManager|VirusTotalProvider|lookup_hash'` trova solo la definizione astratta in `core/base.py`: il provider non è istanziato da CLI, UI o controller. È codice morto che gestisce un segreto (API key) e non ha test di integrazione né un percorso di storage sicuro.

**Remediation:** cablarlo con chiave in keyring e test dedicati, oppure rimuoverlo dal pacchetto per ridurre la superficie.

---

### AUD-12 — P3 — Escape ANSI non neutralizzati nell'output CLI

**File:** `clamguardian/cli/output.py:85-99`

`format_human` stampa `result.threats` e `result.metadata` senza sanificare i caratteri di controllo. Nomi di firma e path provengono da output di `clamd`/`clamscan`: un nome file con `ESC` può iniettare sequenze nel terminale (hyperlink OSC 8, riscrittura di riga, clipboard).

**Remediation:** sostituire i caratteri C0/C1 con escape visibili (`\x1b` → `\\x1b`) prima della stampa, mantenendo il JSON già sicuro per costruzione.

---

### AUD-13 — P3 — Dipendenze CI non pinnate

**File:** `.github/workflows/ci.yml:23-24,38`

`apt-get install` senza versioni, `pip install '.[test,gtk]' ruff` senza lock: ogni run risolve versioni diverse di pytest, ruff, mypy e delle librerie di sistema. L'audit delle dipendenze copre solo il set runtime (`uv export --no-emit-project`), non il tooling che esegue i test.

**Remediation:** pinnare le versioni del tooling (`ruff==`, `mypy==`, `pytest==`) o usare un lock dedicato; fissare le versioni apt dove possibile. Aggiungere `pip-audit` anche sul set di test.

---

### AUD-14 — P3 — Igiene del runtime

- `core/diagnostics.py:129` esegue `flatpak-spawn --host which <name>` senza `env=`: il sottoprocesso eredita `GH_TOKEN` e le chiavi Langfuse presenti nell'ambiente dell'agente. **Remediation:** passare un ambiente minimo (`{"PATH": "/usr/bin:/bin"}`) e non propagare credenziali.
- Zombie transitori (`[tail]`, `[bash]`) generati dal wrapper di sessione: non riguardano l'applicazione, ma vanno raccolti dal processo padre.
- `/workspace/.cline-home/home/.cache/uv/.lock` è `0666`: `chmod 600` (fuori dal repo).

---

## 5. Raccomandazioni operative (prioritarizzate, non distruttive)

### R1 — Immediata (P1, prima di qualsiasi uso come controllo di sicurezza)

1. Correggere AUD-01 leggendo la risposta `clamd` fino a EOF con cap di 8 MiB (snippet in §4).
2. Aggiungere il test di regressione multi-riga in `tests/test_engine.py` (socket UNIX reale, tre righe con `await asyncio.sleep(0)`), verificando che fallisca sul codice attuale e passi dopo la patch.
3. Ripetere la verifica manuale su un host con `clamd` reale: directory con `clean.txt` + `eicar.txt`; attendersi `status=infected`, `threats` non vuoto, exit code `1` (`EXIT_INFECTED`), non `0`.
4. Rilasciare `1.0.1` con nota di sicurezza: il difetto è in `v1.0.0`.

### R2 — Entro lo sprint (P2)

5. AUD-02: usare `Secret.Schema` + attributi e le firme corrette; log di degradazione; test con `gi.repository.Secret` finto.
6. AUD-03: scrittura atomica `mkstemp` + `fchmod(0600)` + `fsync` + `os.replace`; fallire in modo chiuso su chiave corrotta (non ruotare silenziosamente); validare la lunghezza anche dal keyring.
7. AUD-04: rifiutare `\n`, `\r`, NUL nei target prima del socket; test con nome file che contiene `\n`.
8. AUD-05: `permissions: contents: read` in `release-gate.yml`, action pinnate a SHA, `persist-credentials: false`.

### R3 — Entro la prossima release (P2/P3)

9. AUD-07: job Python 3.14 (o container `org.gnome.Sdk//51`) che importa il pacchetto ed esegue la suite headless.
10. AUD-08/09: confinamento del restore con `is_relative_to()`, policy esplicita sui symlink (`lstat`, rifiuto), test dedicati.
11. AUD-10: `chmod` solo su directory creata; AUD-12: escaping C0/C1 nell'output umano.

### R4 — Backlog tecnico (P3)

12. AUD-11: cablare o rimuovere VirusTotal; se cablato, chiave in keyring e test.
13. AUD-13: pinnare tooling di test/lint e versioni apt; estendere l'audit anche al set di test.
14. AUD-14: ambiente minimo nei sottoprocessi, raccolta zombie, `chmod 600` sul lock della cache.
15. Firmare tag e commit (gitsign/Sigstore) per rendere la provenienza verificabile offline, non solo via GitHub.

### R5 — Igiene dell'ambiente (fuori dal repo)

16. AUD-06: bind dei servizi su loopback o filtro di rete; verificare con `ss -ltnp` su un host completo.
17. Non esporre `GH_TOKEN`/`LANGFUSE_*` ai processi figli non necessari; ruotare le chiavi se il contesto è condiviso.

---

## 6. Verifiche eseguite e risultati

| Gate | Comando | Risultato |
|---|---|---|
| Lint | `python3 -m ruff check .` | **All checks passed** |
| Type check | `python3 -m mypy clamguardian` | **Success: no issues found in 42 source files** |
| Test suite | `PYTHONPATH=/workspace python3 -m pytest -q` | **308 passed, 13 skipped** (skip GTK/PyGObject, ambiente headless) |
| Lock coherence | `uv lock --check` | **54 pacchetti risolti**, nessuna divergenza |
| Audit dipendenze | OSV `POST /v1/querybatch` su 13 pacchetti runtime | **0 vulnerabilità note** |
| CI sul commit | GitHub API run `39187995968` | **success** — job 3.11, 3.12, 3.13, dependency audit |
| Release Gate sul tag | GitHub API run `38977065253` | **success 7/7** @ `8ee8a56` |
| Tag | GitHub API `git/tags/20e598a` | tag annotato → commit `8ee8a56` (coerente con i docs) |
| Integrità pacchetti | `dpkg -V`, `dpkg --audit` | nessuna discrepanza di checksum; audit vuoto |
| Capacità runtime | `/proc/self/status` | `CapEff=0`, `NoNewPrivs=1`, `Seccomp=2` |
| Riproduzione P1 | `docs/validation/repro-clamd-multiline.py` | `engine.scan(dir)` → **`clean`** con `FOUND` presente nel flusso |

**Nota sui numeri:** `RELEASE-GATE-1.0.md` dichiara 251 test al commit di release; il branch `feature` ne esegue 308 (13 skip GTK). La differenza è crescita fisiologica post-release, non una discrepanza.

---

## 7. Limiti dell'audit e voci non verificabili

| Limite | Conseguenza |
|---|---|
| Nessun `zsh`, nessun `.zshrc`/`.bashrc`, nessun alias | Sezione "Configurazioni & Shell" **n/d**, non compilata per assunzione |
| Nessun `systemd`/`journalctl` | Nessun log di sistema o unità da ispezionare |
| `nala`, `btop`, `batcat`, `fdfind` assenti | Strumenti consigliati non disponibili; usati `rg`, `ps`, `/proc`, `dpkg`, API GitHub |
| `clamscan`/`clamd` assenti | Percorso live non eseguibile; verifica protocol-level con socket finto |
| PyGObject/GTK assenti | 13 test UI skippati; nessuna verifica grafica locale (la CI la esegue sotto Xvfb) |
| Clone shallow (`grafted`) | Storia e firme dei tag non verificabili localmente; usata l'API GitHub |
| TLS aziendale/MITM su PyPI | `pip-audit` non raggiunge PyPI; audit sostituito con OSV API (curl) |
| `flatpak`/`flatpak-builder` assenti | Manifest non ricostruiti localmente; asserzioni coperte dall'evidenza CI |
| `apt` lists vuote | Nessuna verifica reale di aggiornamenti di sicurezza disponibili |

---

## Appendice A — Riproduzione di AUD-01

```bash
# prerequisiti: cryptography + aiohttp (solo per importare il pacchetto)
python3 -m pip install --user cryptography aiohttp
PYTHONPATH=/workspace python3 docs/validation/repro-clamd-multiline.py
```

Output atteso **sul codice attuale** (difetto presente):

```
status: clean | threats: ()
clean flag: True | engine: clamd
```

Output atteso **dopo la remediation**: `status: infected`, `threats` contenente `Eicar-Test-Signature FOUND`, `clean flag: False`.

## Appendice B — Indice file/riga

| Finding | File:riga |
|---|---|
| AUD-01 | `clamguardian/engines/clamav.py:147-158` |
| AUD-02 | `clamguardian/ui/quarantine_key.py:81-114` |
| AUD-03 | `clamguardian/ui/quarantine_key.py:116-137` |
| AUD-04 | `clamguardian/engines/clamav.py:148` |
| AUD-05 | `.github/workflows/release-gate.yml:1-18`; `.github/workflows/ci.yml:8-9` |
| AUD-07 | `.github/workflows/ci.yml:17`; `tests/test_packaging.py:276-315` |
| AUD-08 | `clamguardian/core/quarantine.py:286-293` |
| AUD-09 | `clamguardian/core/quarantine.py:100-102,153-157` |
| AUD-10 | `clamguardian/history/backend.py:196-199` |
| AUD-11 | `clamguardian/intelligence/virustotal.py` (non referenziato) |
| AUD-12 | `clamguardian/cli/output.py:96-106` |
| AUD-13 | `.github/workflows/ci.yml:23-24,38` |
| AUD-14 | `clamguardian/core/diagnostics.py:129` |

---

*Report prodotto da audit indipendente su evidenze strumentali. Nessuna modifica al codice applicativo è stata effettuata: le remediation sono proposte e devono passare da test di regressione e review.*

---

## 8. Addendum — stato della remediation (2026-10-19)

I fix sono stati implementati sul branch `cline/fhyn2bmx` e proposti con PR verso `feature`. Ogni voce chiusa ha un test di regressione dedicato. Le modifiche a `.github/workflows/*` non possono essere pushate dall'App `cline-cloud[bot]` (permesso `workflows` assente): sono consegnate come `docs/project/ci-hardening.patch`, con istruzioni in `docs/project/CI-HARDENING.md`.

| Finding | Stato | Evidenza |
|---|---|---|
| AUD-01 | **Corretto** | Lettura fino a EOF con cap 8 MiB; `test_clamd_directory_scan_reads_every_result_line` |
| AUD-02 | **Corretto** | `Secret.Schema` + attributi + 6 argomenti; test con `gi.repository.Secret` finto |
| AUD-03 | **Corretto** | Scrittura atomica `mkstemp`/`fchmod`/`fsync`/`replace`, fail-closed su chiave corrotta; 2 test |
| AUD-04 | **Corretto** | Rifiuto `NUL`/`\n`/`\r` in `scan()` e in `_scan_socket()`; test end-to-end |
| AUD-05 | **Patch pronto** | `permissions: contents: read` + action pinnate a SHA in `docs/project/ci-hardening.patch` |
| AUD-07 | **Patch pronto** | Job CI `runtime-python` su Python 3.14 headless nello stesso patch |
| AUD-08 | **Corretto** | Restore accetta solo path assoluti senza componenti `..`; test |
| AUD-09 | **Corretto** | Rifiuto symlink in quarantena e directory vault symlink; test |
| AUD-10 | **Corretto** | `chmod` solo sulla directory creata; test |
| AUD-12 | **Corretto** | Escaping C0/DEL in output umano e storico; test |
| AUD-13 | **Mitigato** | Runner `ubuntu-24.04` + eccezione apt documentata in `docs/project/CI-HARDENING.md` |
| AUD-14 | **Parziale** | Ambiente sanificato per `flatpak-spawn --host` + test; zombie e lock `0666` sono igiene dell'ambiente |
| AUD-06 | **Accettato e documentato** | `docs/project/RUNTIME-EXPOSURE.md` (servizi di sessione, non del repo) |
| AUD-11 | **Congelato con guardrail** | `docs/design/threat-intelligence.md`, extra `intelligence` vuoto, `tests/test_intelligence_frozen.py` |

Residuo dichiarato: nessun finding AUD resta senza fix, mitigazione o rischio accettato e tracciato. AUD-11 è congelato con guardrail fino alla Fase 11 (`v1.2.0`), AUD-13 è mitigato (runner pinnato, apt dichiarato come eccezione), AUD-06 è rischio accettato e documentato.
