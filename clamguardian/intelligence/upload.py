"""Explicit per-file consent and safe upload orchestration."""
from __future__ import annotations

import asyncio
import hashlib
import os
import stat
from pathlib import Path
from typing import Any

from .models import UploadPreview
from .virustotal import VirusTotalProvider


def preview_upload(path: Path) -> UploadPreview:
    target = Path(path).expanduser().resolve(strict=True)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags)
    try:
        with os.fdopen(fd, "rb", closefd=False) as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("Only regular files can be submitted to VirusTotal")
            if before.st_size > 650 * 1024 * 1024:
                raise ValueError("VirusTotal file upload limit is 650 MiB")
            digest = hashlib.sha256()
            total = 0
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                total += len(chunk)
            after = os.fstat(handle.fileno())
            before_identity = (
                before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns,
            )
            after_identity = (
                after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns,
            )
            if before_identity != after_identity or total != before.st_size:
                raise RuntimeError("File changed while its upload preview was being calculated")
            return UploadPreview(target, target.name, total, digest.hexdigest())
    finally:
        os.close(fd)


async def submit_after_consent(
    provider: VirusTotalProvider,
    preview: UploadPreview,
    *,
    consent: bool,
    poll_interval: float = 3.0,
    max_polls: int = 20,
) -> dict[str, Any]:
    """No upload request is made unless this call carries explicit per-file consent."""
    if consent is not True:
        raise PermissionError("Explicit per-file consent is required before upload")
    if poll_interval < 0 or max_polls < 0:
        raise ValueError("Polling interval and count must be non-negative")
    current = await asyncio.to_thread(preview_upload, preview.path)
    if current.sha256 != preview.sha256 or current.size != preview.size:
        raise RuntimeError("File changed after the upload preview; consent is invalidated")
    analysis_id = await provider.upload_file(
        preview.path, preview.sha256, consent=True
    )
    report: dict[str, Any] = {
        "provider": "virustotal",
        "analysis_id": analysis_id,
        "status": "queued",
    }
    for _ in range(max_polls):
        report = await provider.get_analysis(analysis_id)
        if report.get("status") in {"completed", "failed"}:
            return report
        await asyncio.sleep(poll_interval)
    report["status"] = "pending"
    report["message"] = "Analysis is still processing; retrieve the report later"
    return report
