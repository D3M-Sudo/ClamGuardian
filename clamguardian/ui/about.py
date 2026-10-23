"""About dialog for the ClamGuardian desktop application.

The metadata mirrors ``data/io.github.clamguardian.ClamGuardian.metainfo.xml``
and the package version, so the About dialog cannot drift from the AppStream
metadata or the wheel.

The module is import-safe on headless systems without PyGObject.
"""

from __future__ import annotations

from .. import __version__

try:  # pragma: no cover - exercised only on systems with PyGObject
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gtk

    GTK_AVAILABLE = True
except Exception:  # pragma: no cover - headless environments
    GTK_AVAILABLE = False

__all__ = [
    "APP_ID",
    "COPYRIGHT",
    "DEVELOPER_NAME",
    "GTK_AVAILABLE",
    "ISSUE_URL",
    "WEBSITE",
    "about_metadata",
    "build_about_dialog",
]

APP_ID = "io.github.clamguardian.ClamGuardian"
DEVELOPER_NAME = "ClamGuardian contributors"
WEBSITE = "https://github.com/D3M-Sudo/ClamGuardian"
ISSUE_URL = f"{WEBSITE}/issues"
COPYRIGHT = "© 2026 ClamGuardian contributors"
COMMENTS = (
    "On-demand antivirus scanning for Linux desktops and servers, powered by "
    "ClamAV, with an encrypted quarantine vault and a scriptable CLI."
)


def about_metadata() -> dict[str, object]:
    """Return the About dialog metadata as a plain mapping.

    Pure function so the values can be asserted on headless machines and kept
    in sync with the AppStream metadata.
    """
    return {
        "application_name": "ClamGuardian",
        "application_icon": APP_ID,
        "developer_name": DEVELOPER_NAME,
        "version": __version__,
        "website": WEBSITE,
        "issue_url": ISSUE_URL,
        "copyright": COPYRIGHT,
        "comments": COMMENTS,
        "developers": [DEVELOPER_NAME],
    }


def build_about_dialog():
    """Build the About dialog (``Adw.AboutDialog`` or a Gtk fallback)."""
    if not GTK_AVAILABLE:  # pragma: no cover - defensive
        raise RuntimeError("build_about_dialog requires PyGObject with GTK 4 and Libadwaita")

    metadata = about_metadata()
    if hasattr(Adw, "AboutDialog"):
        return Adw.AboutDialog(
            application_name=str(metadata["application_name"]),
            application_icon=str(metadata["application_icon"]),
            developer_name=str(metadata["developer_name"]),
            version=str(metadata["version"]),
            website=str(metadata["website"]),
            issue_url=str(metadata["issue_url"]),
            copyright=str(metadata["copyright"]),
            comments=str(metadata["comments"]),
            developers=list(metadata["developers"]),
            license_type=Gtk.License.GPL_3_0,
        )

    # pragma: no cover - only on very old Libadwaita
    dialog = Gtk.AboutDialog(
        program_name=str(metadata["application_name"]),
        version=str(metadata["version"]),
        copyright=str(metadata["copyright"]),
        comments=str(metadata["comments"]),
        website=str(metadata["website"]),
        license_type=Gtk.License.GPL_3_0,
        authors=list(metadata["developers"]),
    )
    dialog.set_logo_icon_name(str(metadata["application_icon"]))
    return dialog
