# Realtime filesystem boundary

## Security invariant

An inotify event is a notification, not authority to scan an arbitrary pathname.
A realtime scan is permitted only when the event target can be opened as a
regular file beneath one of the configured monitoring roots, and the antivirus
engine consumes the object represented by that opened descriptor (or bytes read
from that same descriptor).

The realtime path never falls back to a pathname-based scan.

## Root handling

At service startup, each configured root is resolved and pinned with a
directory file descriptor. A configured root that is itself a symlink is
rejected. Every component of the canonical root is opened without following
symlinks, and the opened directory's device/inode identity is checked against
the configured path before and after watch registration.

Duplicate canonical roots are collapsed to one pinned descriptor and one
inotify watch.

## Event-target opening

The event path is normalized lexically; it is not resolved through the
filesystem. It must be a strict descendant of a configured root. The target is
then opened relative to the pinned root descriptor:

- every intermediate component must be a directory opened with O_NOFOLLOW;
- the final component is opened with O_NOFOLLOW and O_NONBLOCK;
- the final descriptor must refer to a regular file;
- symlinks, traversal outside the root, FIFOs, devices, and other special files
  are rejected.

This binds the scan to the opened inode. Renaming or replacing the pathname
after the open cannot redirect the antivirus engine to a different object.

## ClamAV transport

The engine prefers clamd's Unix-socket FILDES protocol when
VERSIONCOMMANDS advertises support. The descriptor is transferred using
SCM_RIGHTS in the protocol's ancillary-data packet.

If FILDES is unavailable, the engine uses clamd's INSTREAM protocol. It
reads chunks with pread() from the already-open descriptor and sends those
bytes to clamd; it does not reopen the event pathname. If the daemon rejects
the stream (including because of StreamMaxLength), the scan result is an
error, never a clean verdict.

An empty or unrecognized daemon response is also an error. If neither
descriptor-preserving transport can complete, the realtime scan fails closed.
There is no clamscan pathname fallback.

## Mutation detection

The engine records device, inode, size, modification time, and change time
before scanning. It compares those values after scanning and after SHA-256
calculation. A change during either operation produces an error result. The
SHA-256 digest is calculated from the same open descriptor using pread().

## Residual boundaries

- A hard link inside a monitored root is a directory entry inside that root,
  even if the same inode has another name elsewhere. This implementation does
  not attempt to identify or reject external hard-link aliases.
- Mount points and bind mounts below a monitored root are treated as part of
  that root. Preventing mount traversal would require an additional
  openat2(RESOLVE_NO_XDEV) or mount-ID policy.
- The metadata checks detect ordinary concurrent file mutation; they are not
  an immutable snapshot against a privileged actor capable of manipulating the
  underlying filesystem.
- inotify watch registration remains pathname-based. The root descriptor is
  pinned and checked around registration, and all actual scan opens remain
  anchored to it. Concurrent renames may cause missed or stale notifications,
  but cannot turn the scan open into a pathname traversal outside the pinned
  root.
- The configured local clamd socket is trusted. The protocol does not
  authenticate a malicious local daemon.

These residual boundaries do not permit a symlink or pathname replacement to
redirect a scan outside the pinned monitoring root.
