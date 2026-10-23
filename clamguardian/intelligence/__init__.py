"""Frozen threat-intelligence framework (Phase 11, deferred to v1.2.0).

**Not wired.** Nothing in ``clamguardian.cli``, ``clamguardian.ui``,
``clamguardian.core`` or ``clamguardian.history`` imports this package, and no
``clamguardian.threat_providers`` entry point is declared, so it is unreachable
from the application. Importing it performs no network I/O and reads no
secrets.

The Phase 11 gate in ``docs/ROADMAP.md`` defines the opt-in contract and the
milestones that will add the real call site. Until then the package is kept
frozen behind the guards in ``tests/test_intelligence_frozen.py``: see
``docs/design/threat-intelligence.md``.
"""

from .manager import ThreatProviderManager
from .virustotal import VirusTotalProvider

__all__ = ["ThreatProviderManager", "VirusTotalProvider"]
