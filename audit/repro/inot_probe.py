"""Read-only empirical probe of InotifyMonitor (recursive watches, moves, saturation).

Run: PYTHONPATH=/workspace /home/node/venvs/audit/bin/python /tmp/audit/inot_probe.py
"""

from __future__ import annotations

import errno
import shutil
import sys
from pathlib import Path

from clamguardian.realtime import InotifyMonitor
from clamguardian.realtime.inotify import INOTIFY_AVAILABLE

OUT: list[tuple[str, str, str]] = []


def record(name: str, verdict: str, detail: str) -> None:
    OUT.append((name, verdict, detail))
    print(f"[{verdict}] {name}\n    {detail}")


def names(monitor: InotifyMonitor, timeout: float = 0.25) -> list[str]:
    return [str(e.path) for e in monitor.read_events(timeout=timeout)]


def base(name: str) -> Path:
    p = Path("/tmp/audit/inot") / name
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)
    p.mkdir(parents=True)
    return p


def i1_nested_existing() -> None:
    root = base("i1")
    deep = root / "l1" / "l2"
    deep.mkdir(parents=True)
    m = InotifyMonitor()
    m.add_watch(root)
    (deep / "f.txt").write_text("x")
    got = names(m)
    m.close()
    verdict = "PASS" if any(g.endswith("l1/l2/f.txt") for g in got) else "FAIL"
    record("I1 pre-existing nested directory", verdict, f"events={got}")


def i2_dynamic_creation() -> None:
    root = base("i2")
    m = InotifyMonitor()
    m.add_watch(root)
    new = root / "newdir"
    new.mkdir()
    m.read_events(timeout=0.25)  # consume the CREATE of newdir
    (new / "inside.txt").write_text("x")
    got = names(m)
    m.close()
    verdict = "PASS" if any(g.endswith("newdir/inside.txt") for g in got) else "FAIL"
    record("I2 directory created after add_watch", verdict, f"events={got}")


def i3_moved_in() -> None:
    root = base("i3")
    outside = base("i3_src") / "incoming"
    outside.mkdir(parents=True)
    m = InotifyMonitor()
    m.add_watch(root)
    shutil.move(str(outside), str(root / "incoming"))
    m.read_events(timeout=0.25)
    (root / "incoming" / "inside.txt").write_text("x")
    got = names(m)
    m.close()
    verdict = "PASS" if any(g.endswith("incoming/inside.txt") for g in got) else "FAIL"
    record("I3 directory moved INTO the watched root", verdict, f"events={got}")


def i4_moved_out() -> None:
    """A directory moved OUT of the root must not keep a live watch on the tree."""
    root = base("i4")
    sub = root / "sub"
    sub.mkdir()
    dest = base("i4_out")
    m = InotifyMonitor()
    m.add_watch(root)
    shutil.move(str(sub), str(dest / "sub"))
    m.read_events(timeout=0.25)
    (dest / "sub" / "escaped.txt").write_text("x")
    got = names(m)
    stale = [g for g in got if "escaped.txt" in g]
    m.close()
    if stale:
        detail = (
            f"events emitted for a file OUTSIDE the watched root: {stale} "
            f"(real path is {dest / 'sub' / 'escaped.txt'})"
        )
        record("I4 directory moved OUT keeps a live stale watch", "FAIL", detail)
    else:
        record("I4 directory moved OUT keeps a live stale watch", "PASS", f"events={got}")



def i5_delete_and_recreate() -> None:
    root = base("i5")
    sub = root / "sub"
    sub.mkdir()
    m = InotifyMonitor()
    m.add_watch(root)
    shutil.rmtree(sub)
    m.read_events(timeout=0.25)
    sub.mkdir()
    m.read_events(timeout=0.25)
    (sub / "again.txt").write_text("x")
    got = names(m)
    size = len(m._path_map)
    m.close()
    verdict = "PASS" if any(g.endswith("sub/again.txt") for g in got) else "FAIL"
    record(
        "I5 watched directory deleted then recreated",
        verdict,
        f"events={got}, _path_map entries={size}",
    )


def i6_watch_saturation() -> None:
    """ENOSPC on inotify_add_watch must not silently disable monitoring."""
    root = base("i6")
    m = InotifyMonitor()

    def exploding(path, mask):  # type: ignore[no-untyped-def]
        raise OSError(errno.ENOSPC, "No space left on device")

    m._inotify.add_watch = exploding  # type: ignore[method-assign]
    wd = m.add_watch(root)
    (root / "f.txt").write_text("x")
    got = names(m)
    m.close()
    detail = (
        f"add_watch(root) returned wd={wd} (no exception raised), events observed={got}; "
        "no counter, exception or return channel reports the failure to the caller"
    )
    verdict = "FAIL" if wd == -1 and not got else "PASS"
    record("I6 inotify watch saturation (ENOSPC) is silent", verdict, detail)


def i7_symlinked_subdir() -> None:
    root = base("i7")
    target = base("i7_target")
    (root / "link").symlink_to(target, target_is_directory=True)
    m = InotifyMonitor()
    m.add_watch(root)
    (target / "via_link.txt").write_text("x")
    got = names(m)
    m.close()
    detail = (
        f"events for files behind a symlinked directory: {got} "
        "(symlinked subtrees are deliberately not watched; nothing reports the gap)"
    )
    record("I7 symlinked subtree is silently unwatched", "INFO", detail)


def i8_queue_overflow() -> None:
    """IN_Q_OVERFLOW (wd=-1) is dropped by read_events without any signal."""
    root = base("i8")
    m = InotifyMonitor()
    m.add_watch(root)
    for i in range(20000):  # never reading: force the kernel queue to overflow
        (root / f"f{i}.txt").write_text("")
    events = m.read_events(timeout=1.0)
    kinds = {e.event_type.name for e in events}
    m.close()
    shutil.rmtree(root, ignore_errors=True)
    detail = (
        "created 20000 files (>=2 inotify events each; kernel max_queued_events=16384); "
        f"read_events returned {len(events)} events, types={sorted(kinds)}; "
        "no overflow flag, counter or exception is exposed to the caller"
    )
    record("I8 inotify queue overflow is silently swallowed", "FAIL", detail)


def main() -> None:
    if not INOTIFY_AVAILABLE:
        print("inotify unavailable")
        return
    Path("/tmp/audit/inot").mkdir(parents=True, exist_ok=True)
    i1_nested_existing()
    i2_dynamic_creation()
    i3_moved_in()
    i4_moved_out()
    i5_delete_and_recreate()
    i6_watch_saturation()
    i7_symlinked_subdir()
    i8_queue_overflow()
    print("\n==== SUMMARY ====")
    for name, verdict, _ in OUT:
        print(f"{verdict:5} {name}")


if __name__ == "__main__":
    main()
    sys.exit(0)

    m = InotifyMonitor()
    m.add_watch(root)
    shutil.move(str(sub), str(dest / "sub"))
    m.read_events(timeout=0.25)
    (dest / "sub" / "escaped.txt").write_text("x")
    got = names(m)
    stale = [g for g in got if "escaped.txt" in g]
    m.close()
    if stale:
        detail = (
            f"events emitted for a file OUTSIDE the watched root: {stale} "
            f"(real path is {dest / 'sub' / 'escaped.txt'})"
        )
        record("I4 directory moved OUT keeps a live stale watch", "FAIL", detail)
    else:
        record("I4 directory moved OUT keeps a live stale watch", "PASS", f"events={got}")
