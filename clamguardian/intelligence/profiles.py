"""Explicit VirusTotal API profile selection and policy metadata."""
from __future__ import annotations

from enum import StrEnum


class APIProfile(StrEnum):
    PUBLIC = "public"
    PREMIUM = "premium"

    @classmethod
    def parse(cls, value: str | APIProfile) -> APIProfile:
        if isinstance(value, cls):
            return value
        try:
            return cls(value.strip().lower())
        except (AttributeError, ValueError) as exc:
            raise ValueError("API profile must be 'public' or 'premium'") from exc


def profile_secret_attribute(profile: APIProfile | str) -> str:
    return f"virustotal-{APIProfile.parse(profile).value}-api-key"


def profile_minute_interval(profile: APIProfile | str) -> float:
    # Public API is limited to four requests per minute. Premium throughput
    # is subscription-specific; server Retry-After responses remain authoritative.
    return 15.1 if APIProfile.parse(profile) is APIProfile.PUBLIC else 0.0
