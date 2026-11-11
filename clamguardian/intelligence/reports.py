"""Normalization of VirusTotal file and analysis reports."""
from __future__ import annotations

from typing import Any


def normalize_file_report(payload: dict[str, Any], sha256: str) -> dict[str, Any]:
    data = payload.get("data")
    if not isinstance(data, dict):
        raise RuntimeError("VirusTotal returned an invalid file report")
    attributes = data.get("attributes")
    if not isinstance(attributes, dict):
        raise RuntimeError("VirusTotal returned an invalid file report")
    reported_sha256 = attributes.get("sha256")
    if reported_sha256 is not None:
        if (
            not isinstance(reported_sha256, str)
            or len(reported_sha256) != 64
            or any(ch not in "0123456789abcdefABCDEF" for ch in reported_sha256)
            or reported_sha256.lower() != sha256.lower()
        ):
            raise RuntimeError("VirusTotal returned a report for a different SHA-256")
    stats = attributes.get("last_analysis_stats")
    if not isinstance(stats, dict):
        stats = {}
    allowed_stats = {
        "malicious",
        "suspicious",
        "harmless",
        "undetected",
        "timeout",
        "failure",
        "type-unsupported",
    }
    normalized_stats = {
        key: int(value)
        for key, value in stats.items()
        if key in allowed_stats and isinstance(value, (int, float))
    }
    return {
        "provider": "virustotal",
        "found": True,
        "sha256": sha256.lower(),
        "md5": attributes.get("md5"),
        "sha1": attributes.get("sha1"),
        "type_description": attributes.get("type_description"),
        "meaningful_name": attributes.get("meaningful_name"),
        "size": attributes.get("size"),
        "reputation": attributes.get("reputation"),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "last_analysis_stats": normalized_stats,
        "malicious": normalized_stats.get("malicious", 0) > 0,
        "permalink": f"https://www.virustotal.com/gui/file/{sha256.lower()}",
    }


def normalize_analysis_report(payload: dict[str, Any]) -> dict[str, Any]:
    data = payload.get("data")
    if not isinstance(data, dict):
        raise RuntimeError("VirusTotal returned an invalid analysis report")
    attributes = data.get("attributes")
    if not isinstance(attributes, dict):
        attributes = {}
    stats = attributes.get("stats")
    if not isinstance(stats, dict):
        stats = {}
    return {
        "provider": "virustotal",
        "analysis_id": data.get("id"),
        "status": attributes.get("status", "queued"),
        "stats": stats,
        "date": attributes.get("date"),
    }
