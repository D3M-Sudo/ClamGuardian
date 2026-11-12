# Documentation map

This directory separates current design/security references from milestone reports and historical project handoffs.

| Area | Contents | How to use it |
|---|---|---|
| [design/](design/) | Architecture contracts, scan profiles, CLI and threat-intelligence design | Read alongside corresponding source modules; versioned notes may describe an earlier contract |
| [security/](security/) | Filesystem boundary and VirusTotal evidence-storage invariants | Security contracts for reviewing implementation changes |
| [engineering/](engineering/) | Engineering inventories and handoffs | Historical snapshots unless explicitly marked current |
| [project/](project/) | Project plan, release-gate decisions, CI hardening and accepted risks | Planning context; check the roadmap for current status |
| [reports/](reports/) | Milestone, audit, benchmark and release reports | Historical evidence; do not treat old findings/status as current without checking later remediation |
| [validation/](validation/) | Manual desktop checklists and host-validation records | Evidence that cannot be established by headless CI alone |

## Current entry points

- [Changelog](../CHANGELOG.md) — unreleased changes and published version history.
- [Security policy](../SECURITY.md) — supported versions, reporting process and security boundaries.
- [Implementation roadmap](ROADMAP.md) — current branch milestone status and release gates.
- [Project plan](project/PROJECT_PLAN.md) — architecture and subsystem responsibilities.
- [Threat-intelligence design](design/threat-intelligence.md) — opt-in, profile eligibility, upload consent and shared enrichment.
- [Realtime filesystem boundary](security/realtime-filesystem-boundary.md) — descriptor-pinned scanning invariants.
- [VirusTotal evidence persistence](security/virustotal-evidence-storage.md) — schema and history contract.
- [Manual validation](validation/README.md) — desktop and host-side evidence.

**Status discipline:** CI success proves only the checks executed by that workflow. It does not prove manual desktop validation, VirusTotal legal/product eligibility, a published release, or a release promotion. The feature branch is the active integration branch; consult live branch and workflow state before making operational claims.