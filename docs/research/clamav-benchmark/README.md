# ClamAV Benchmark and Integration Research

**Status:** Research baseline complete; recommendations are proposals, not implementation approval.  
**ClamGuardian baseline:** `b42c01612d34ef20b980518aa9b3845f48ea4210`  
**ClamUI comparator:** `106e403c7cfea14ab38a97ccfd41bd12a1172e4f`

## Documents
1. [Executive summary](executive-summary.md)
2. [Scope and methodology](benchmark-scope-and-methodology.md)
3. [Comparative technical analysis](comparative-technical-analysis.md)
4. [Evidence and test results](evidence-and-test-results.md)
5. [Evolutionary recommendations](evolutionary-recommendations.md)
6. [Portability and cherry-pick assessment](portability-and-cherry-pick-assessment.md)
7. [File-manager integration study](file-manager-integration-study.md)
8. [ClamAV integration study](clamav-integration-study.md)
9. [Security and privilege analysis](security-and-privilege-analysis.md)
10. [Decisions register](decisions-register.md)
11. [Roadmap recommendation summary](roadmap-recommendations.md)

## Evidence vocabulary
- **VERIFIED** — confirmed in pinned source, authoritative documentation or identified test/run.
- **OBSERVED** — visible in repository artifact/test, not necessarily independently exercised here.
- **INFERRED** — conclusion derived from verified facts.
- **PROPOSED** — future design recommendation requiring approval.
- **BLOCKED** — not verified because required host/runtime conditions were unavailable.
- **DEFERRED** — intentionally outside the current implementation decision.

This dossier does not authorize implementation of a privileged daemon, setuid helper, Polkit workflow, fanotify prevention, new dependencies or file-manager extension. It does not change `docs/ROADMAP.md`. Re-check current branch state and upstream docs before implementation.
