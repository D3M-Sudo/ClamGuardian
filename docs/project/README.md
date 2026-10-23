# Project planning (vision and handoff)

High-level project documents: where ClamGuardian is going and how sessions hand
work over to each other. Milestone status and gates live in `../ROADMAP.md`.

| File | Purpose |
|---|---|
| `PROJECT_PLAN.md` | Master project plan: objectives, architecture direction, security/testing/packaging strategies, post-1.0 evolution |
| `HANDOFF-2026-10-18-DESKTOP-UI.md` | Active handoff: approved Phases 1–4 plan for the complete GTK4/Libadwaita desktop application (app shell, Scan/History/Quarantine/Databases/Diagnostics/Settings pages, About, notifications, theme), core inventory, constraints and next-session procedure — Phases 1–4 implemented, manual validation pending |
| `D4-RELEASE-GATE.md` | How the D4 desktop smoke reaches the release gate and why it ships as an applyable patch (`release-gate-1.0.1.patch`) |
| `CI-HARDENING.md` | AUD-05/07/13 CI hardening: what changed, what was applied, accepted apt exception |
| `RUNTIME-EXPOSURE.md` | Accepted risk AUD-06 (session-container listeners, no ClamGuardian port) |
| `archive/` | Superseded reference documents (see `archive/README.md`): the 2026-08-30 M4-era handoff |
