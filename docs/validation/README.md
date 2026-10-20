# Manual validation (checklists and evidence)

Templates and recorded evidence for validation that happens on a real host,
outside CI.

| File | Purpose |
|---|---|
| `DESKTOP-TEST-1.0.md` | Manual desktop test checklist and result template (ROADMAP 1.0.x M2/M3: on-desktop click-through and Flatpak quarantine-restore verification). Copy per test session, e.g. `DESKTOP-TEST-1.0-<YYYY-MM-DD>.md`. |
| `DESKTOP-TEST-D4-2026-10-19.md` | D4 desktop session record (Settings, About, notifications, theme, chrome, quarantine ingest); fill on a real desktop. |
| `repro-clamd-multiline.py` | Evidence script for AUD-01: fake `clamd` that streams multiple result lines; shows the engine reporting `clean` while a `FOUND` line is present. Run with `PYTHONPATH=. python3 docs/validation/repro-clamd-multiline.py`. |
