"""Cross-process VirusTotal rate and daily quota enforcement."""
from __future__ import annotations

import fcntl
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from .profiles import APIProfile


class QuotaExceeded(RuntimeError):
    """Raised before a request when the locally tracked quota is exhausted."""


class PersistentRateLimiter:
    """Atomic, owner-only rate state shared by desktop and CLI processes."""

    def __init__(
        self,
        profile: APIProfile | str,
        *,
        state_path: Path | None = None,
        min_interval: float | None = None,
        public_daily_limit: int = 500,
    ) -> None:
        from .profiles import profile_minute_interval

        self.profile = APIProfile.parse(profile)
        self.min_interval = (
            profile_minute_interval(self.profile) if min_interval is None else min_interval
        )
        self.public_daily_limit = public_daily_limit
        self.path = state_path or (
            Path.home() / ".local" / "share" / "clamguardian" / "virustotal-quota.json"
        )

    def defer(self, seconds: int | float) -> None:
        """Persist a server-provided Retry-After cooldown across processes."""
        if seconds <= 0:
            return
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            os.lseek(fd, 0, os.SEEK_SET)
            raw = os.read(fd, 65536)
            try:
                state = json.loads(raw.decode("utf-8")) if raw else {}
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError("VirusTotal quota state is corrupt; refusing network access") from exc
            today = datetime.now(timezone.utc).date().isoformat()
            entry = state.get(self.profile.value, {})
            if not isinstance(entry, dict):
                raise RuntimeError("VirusTotal quota state is corrupt; refusing network access")
            if entry.get("day") != today:
                entry = {"day": today, "daily_count": 0, "last_request": 0.0}
            entry["retry_after_until"] = max(
                float(entry.get("retry_after_until", 0.0)), time.time() + seconds
            )
            state[self.profile.value] = entry
            encoded = json.dumps(state, sort_keys=True).encode("utf-8")
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            os.write(fd, encoded)
            os.fsync(fd)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def reserve(self) -> float:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            os.lseek(fd, 0, os.SEEK_SET)
            raw = os.read(fd, 65536)
            try:
                state = json.loads(raw.decode("utf-8")) if raw else {}
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError("VirusTotal quota state is corrupt; refusing network access") from exc
            if not isinstance(state, dict):
                raise RuntimeError("VirusTotal quota state is corrupt; refusing network access")

            now = time.time()
            today = datetime.now(timezone.utc).date().isoformat()
            key = self.profile.value
            entry = state.get(key, {})
            if not isinstance(entry, dict):
                raise RuntimeError("VirusTotal quota state is corrupt; refusing network access")
            if entry.get("day") != today:
                entry = {"day": today, "daily_count": 0, "last_request": 0.0}
            count = entry.get("daily_count", 0)
            last = entry.get("last_request", 0.0)
            if not isinstance(count, int) or not isinstance(last, (int, float)):
                raise RuntimeError("VirusTotal quota state is corrupt; refusing network access")
            if self.profile is APIProfile.PUBLIC and count >= self.public_daily_limit:
                raise QuotaExceeded("VirusTotal Public API daily quota exhausted (500 requests/day)")
            retry_until = entry.get("retry_after_until", 0.0)
            if not isinstance(retry_until, (int, float)):
                raise RuntimeError("VirusTotal quota state is corrupt; refusing network access")
            remaining = max(
                0.0,
                self.min_interval - (now - float(last)),
                float(retry_until) - now,
            )
            if remaining > 0:
                return remaining

            entry["daily_count"] = count + 1
            entry["last_request"] = now
            state[key] = entry
            encoded = json.dumps(state, sort_keys=True).encode("utf-8")
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            os.write(fd, encoded)
            os.fsync(fd)
            return 0.0
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
