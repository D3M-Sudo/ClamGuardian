"""Typed, privacy-conscious models for VirusTotal operations."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class UploadPreview:
    path: Path
    filename: str
    size: int
    sha256: str
    warning: str = (
        "Submitting this file sends its complete contents to VirusTotal. "
        "VirusTotal may retain, analyze, and share submitted samples under its "
        "policies. Do not submit confidential, personal, regulated, proprietary, "
        "or otherwise sensitive data."
    )


@dataclass(frozen=True, slots=True)
class QuotaSnapshot:
    profile: str
    requests_used_today: int | None = None
    requests_daily_limit: int | None = None
    requests_remaining_today: int | None = None
    retry_after_seconds: int | None = None
