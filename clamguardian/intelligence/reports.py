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
    stats = attributes.get("last_analysis_stats")
    if not isinstance(stats, dict):
        stats = {}
    normalized_stats = {
        key: int(value) for key, value in stats.items()
        if key in {"malicious", "suspicious", "harmless", "undetected", "timeout", "failure", "type-unsupported"}
        and isinstance(value, (int, float))
    }
    return {
        "provider": "virustotal",
        "found": True,
        "sha256": str(attributes.get("sha256") or sha256).lower(),
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
