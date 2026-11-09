"""Explicit per-file consent and safe upload orchestration."""
from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from typing import Any

from .models import UploadPreview
from .virustotal import VirusTotalProvider


def preview_upload(path: Path) -> UploadPreview:
    target = Path(path).expanduser().resolve(strict=True)
    if not target.is_file():
        raise ValueError("Only regular files can be submitted to VirusTotal")
    if target.stat().st_size > 650 * 1024 * 1024:
        raise ValueError("VirusTotal file upload limit is 650 MiB")
    digest = hashlib.sha256()
    with target.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return UploadPreview(target, target.name, target.stat().st_size, digest.hexdigest())


async def submit_after_consent(
    provider: VirusTotalProvider,
    preview: UploadPreview,
    *,
    consent: bool,
    poll_interval: float = 3.0,
    max_polls: int = 20,
) -> dict[str, Any]:
    """No network request is made unless this call carries explicit consent."""
    if consent is not True:
        raise PermissionError("Explicit per-file consent is required before upload")
    current = preview_upload(preview.path)
    if current.sha256 != preview.sha256 or current.size != preview.size:
        raise RuntimeError("File changed after the upload preview; consent is invalidated")
    analysis_id = await provider.upload_file(preview.path, preview.sha256)
    report: dict[str, Any] = {"provider": "virustotal", "analysis_id": analysis_id, "status": "queued"}
    for _ in range(max_polls):
        report = await provider.get_analysis(analysis_id)
        if report.get("status") in {"completed", "failed"}:
            return report
        await asyncio.sleep(poll_interval)
    report["status"] = "pending"
    report["message"] = "Analysis is still processing; retrieve the report later"
    return report
