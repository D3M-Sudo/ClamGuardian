"""Cross-process VirusTotal rate and daily quota enforcement."""
from __future__ import annotations

import fcntl
import json
import math
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
        lock_timeout: float = 2.0,
    ) -> None:
        from .profiles import profile_minute_interval

        self.profile = APIProfile.parse(profile)
        self.min_interval = (
            profile_minute_interval(self.profile) if min_interval is None else float(min_interval)
        )
        if not math.isfinite(self.min_interval) or self.min_interval < 0:
            raise ValueError("min_interval must be a finite non-negative number")
        if (
            isinstance(public_daily_limit, bool)
            or not isinstance(public_daily_limit, int)
            or public_daily_limit < 0
        ):
            raise ValueError("public_daily_limit must be a non-negative integer")
        self.public_daily_limit = public_daily_limit
        if (
            isinstance(lock_timeout, bool)
            or not isinstance(lock_timeout, (int, float))
            or not math.isfinite(lock_timeout)
            or lock_timeout < 0
        ):
            raise ValueError("lock_timeout must be a finite non-negative number")
        self.lock_timeout = float(lock_timeout)
        self.path = state_path or (
            Path.home() / ".local" / "share" / "clamguardian" / "virustotal-quota.json"
        )

    @staticmethod
    def _read_state(fd: int) -> dict[str, Any]:
        os.lseek(fd, 0, os.SEEK_SET)
        raw = os.read(fd, 65536)
        try:
            state = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "VirusTotal quota state is corrupt; refusing network access"
            ) from exc
        if not isinstance(state, dict):
            raise RuntimeError("VirusTotal quota state is corrupt; refusing network access")
        return state

    @staticmethod
    def _write_state(fd: int, state: dict[str, Any]) -> None:
        encoded = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
        os.lseek(fd, 0, os.SEEK_SET)
        os.ftruncate(fd, 0)
        view = memoryview(encoded)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("Could not persist VirusTotal quota state")
            view = view[written:]
        os.fsync(fd)

    def _entry_for_today(self, state: dict[str, Any], today: str) -> dict[str, Any]:
        entry = state.get(self.profile.value, {})
        if not isinstance(entry, dict):
            raise RuntimeError("VirusTotal quota state is corrupt; refusing network access")
        retry_until = entry.get("retry_after_until", 0.0)
        if (
            isinstance(retry_until, bool)
            or not isinstance(retry_until, (int, float))
            or not math.isfinite(retry_until)
            or retry_until < 0
        ):
            raise RuntimeError("VirusTotal quota state is corrupt; refusing network access")
        if entry.get("day") != today:
            return {
                "day": today,
                "daily_count": 0,
                "last_request": 0.0,
                "retry_after_until": float(retry_until),
            }
        count = entry.get("daily_count", 0)
        last = entry.get("last_request", 0.0)
        if (
            isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
            or isinstance(last, bool)
            or not isinstance(last, (int, float))
            or not math.isfinite(last)
            or last < 0
        ):
            raise RuntimeError("VirusTotal quota state is corrupt; refusing network access")
        return entry

    def _acquire_lock(self, fd: int) -> None:
        """Acquire the cross-process state lock without an unbounded wait."""
        deadline = time.monotonic() + self.lock_timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        "Timed out waiting for VirusTotal quota state lock"
                    ) from None
                time.sleep(min(0.05, remaining))

    def defer(self, seconds: int | float) -> None:
        """Persist a server-provided Retry-After cooldown across processes."""
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
            raise ValueError("Retry-After must be a non-negative number")
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError("Retry-After must be a finite non-negative number")
        if seconds == 0:
            return
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        locked = False
        try:
            os.fchmod(fd, 0o600)
            self._acquire_lock(fd)
            locked = True
            state = self._read_state(fd)
            today = datetime.now(UTC).date().isoformat()
            entry = self._entry_for_today(state, today)
            entry["retry_after_until"] = max(
                float(entry.get("retry_after_until", 0.0)), time.time() + seconds
            )
            state[self.profile.value] = entry
            self._write_state(fd, state)
        finally:
            if locked:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def reserve(self) -> float:
        """Reserve a request slot, or return seconds until one becomes available."""
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        locked = False
        try:
            os.fchmod(fd, 0o600)
            self._acquire_lock(fd)
            locked = True
            state = self._read_state(fd)
            now = time.time()
            today = datetime.now(UTC).date().isoformat()
            entry = self._entry_for_today(state, today)
            count = entry["daily_count"]
            last = float(entry["last_request"])
            if self.profile is APIProfile.PUBLIC and count >= self.public_daily_limit:
                raise QuotaExceeded(
                    "VirusTotal Public API daily quota exhausted "
                    f"({self.public_daily_limit} requests/day)"
                )
            remaining = max(
                0.0,
                self.min_interval - (now - last),
                float(entry.get("retry_after_until", 0.0)) - now,
            )
            if remaining > 0:
                return remaining
            entry["daily_count"] = count + 1
            entry["last_request"] = now
            state[self.profile.value] = entry
            self._write_state(fd, state)
            return 0.0
        finally:
            if locked:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
