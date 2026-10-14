"""VirusTotal v3 threat-intelligence provider."""

from __future__ import annotations

from typing import Any

import aiohttp

from ..core.base import BaseThreatProvider


class VirusTotalProvider(BaseThreatProvider):
    """Query VirusTotal's v3 file endpoint by SHA-256 digest."""

    name = "virustotal"
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, *, timeout: float = 20.0) -> None:
        if not api_key or not api_key.strip():
            raise ValueError("VirusTotal API key is required")
        self._api_key = api_key.strip()
        self._timeout = aiohttp.ClientTimeout(total=timeout)

    async def lookup_hash(self, sha256: str) -> dict[str, Any]:
        """Return VirusTotal file attributes for a SHA-256 digest."""
        if len(sha256) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in sha256):
            raise ValueError("sha256 must be a 64-character hexadecimal digest")
        headers = {"x-apikey": self._api_key, "accept": "application/json"}
        url = f"{self.BASE_URL}/files/{sha256.lower()}"
        async with aiohttp.ClientSession(timeout=self._timeout, headers=headers) as session:
            try:
                async with session.get(url) as response:
                    if response.status == 404:
                        return {"provider": self.name, "found": False, "sha256": sha256.lower()}
                    if response.status == 429:
                        raise RuntimeError("VirusTotal API rate limit exceeded")
                    if response.status >= 400:
                        body = await response.text()
                        raise RuntimeError(f"VirusTotal API error {response.status}: {body[:500]}")
                    payload = await response.json()
            except TimeoutError as exc:
                raise TimeoutError("VirusTotal request timed out") from exc
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        return {
            "provider": self.name,
            "found": True,
            "sha256": attributes.get("sha256", sha256.lower()),
            "md5": attributes.get("md5"),
            "sha1": attributes.get("sha1"),
            "type_description": attributes.get("type_description"),
            "reputation": attributes.get("reputation"),
            "last_analysis_stats": stats,
            "malicious": int(stats.get("malicious", 0)) > 0,
            "permalink": f"https://www.virustotal.com/gui/file/{sha256.lower()}",
        }
