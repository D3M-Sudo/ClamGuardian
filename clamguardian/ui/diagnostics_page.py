"""Diagnostics page for the GTK4/Libadwaita desktop application.

The page is a thin view over
:func:`~clamguardian.core.diagnostics.run_dependency_checks`: it renders one
card per component, a per-distro remedy expander for anything that is not OK
and a Recheck button. It never probes the system itself — all detection
lives in the Core diagnostics module, so the CLI ``doctor`` command and this
page always report the same facts.

The module is import-safe on headless systems without PyGObject, following
the shim pattern of :mod:`clamguardian.ui.database_pages`.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from ..core.diagnostics import (
    REMEDY_FAMILIES,
    CheckResult,
    CheckStatus,
    critical_missing,
    run_dependency_checks,
    summarize,
)

try:  # pragma: no cover - exercised only on systems with PyGObject
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gtk

    GTK_AVAILABLE = True
except (ImportError, ValueError):  # pragma: no cover - headless environments
    GTK_AVAILABLE = False

#: Symbolic icon per check status (used by both the cards and the banner).
STATUS_ICONS: dict[CheckStatus, str] = {
    CheckStatus.OK: "emblem-ok-symbolic",
    CheckStatus.WARNING: "dialog-warning-symbolic",
    CheckStatus.MISSING: "dialog-error-symbolic",
}

#: Human labels for the distro families the remedies cover.
FAMILY_LABELS: dict[str, str] = {
    "debian": "Debian / Ubuntu",
    "fedora": "Fedora / RHEL",
    "arch": "Arch Linux",
}

#: CSS class per global banner state (see ``clamguardian/ui/style.css``).
BANNER_CSS_CLASSES: dict[CheckStatus, str] = {
    CheckStatus.OK: "cg-banner-ok",
    CheckStatus.WARNING: "cg-banner-warning",
    CheckStatus.MISSING: "cg-banner-error",
}


def status_icon(status: CheckStatus) -> str:
    """Return the symbolic icon name for *status*."""
    return STATUS_ICONS[status]


def banner_content(results: Sequence[CheckResult]) -> tuple[str, str, str]:
    """Compute the global status banner as ``(icon, title, description)``.

    Pure function so the banner logic is unit-testable without GTK: critical
    failures lead with an actionable title, warnings are surfaced but never
    dressed up as failures, and a fully healthy system says so.
    """
    status = banner_status(results)
    missing = critical_missing(results)
    counts = summarize(results)
    if status is CheckStatus.MISSING:
        names = ", ".join(result.label for result in missing)
        return (
            STATUS_ICONS[CheckStatus.MISSING],
            "Action needed",
            f"Critical dependencies are missing: {names}. Scanning will not work until fixed.",
        )
    if status is CheckStatus.WARNING:
        warning_count = counts["warning"]
        return (
            STATUS_ICONS[CheckStatus.WARNING],
            "Ready with warnings",
            f"{warning_count} check(s) need attention. "
            "Scanning works via the clamscan fallback.",
        )
    return (
        STATUS_ICONS[CheckStatus.OK],
        "Ready to scan",
        "All ClamGuardian dependencies were found on this system.",
    )


def banner_status(results: Sequence[CheckResult]) -> CheckStatus:
    """Return the worst state across *results* (missing > warning > ok)."""
    if critical_missing(results):
        return CheckStatus.MISSING
    if summarize(results)["warning"]:
        return CheckStatus.WARNING
    return CheckStatus.OK


if GTK_AVAILABLE:  # pragma: no cover - exercised only on systems with PyGObject

    class DiagnosticsPage:
        """Global status banner + one card per dependency check."""

        def __init__(self, checks: Sequence[CheckResult] | None = None) -> None:
            self._checks: list[CheckResult] = list(
                checks if checks is not None else run_dependency_checks()
            )
            self._rows: dict[str, Adw.ExpanderRow] = {}
            self._root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
            self._banner = Adw.StatusPage()
            self._root.append(self._banner)
            self._page = Adw.PreferencesPage()
            self._root.append(self._page)
            self._render()

        # -- public API ----------------------------------------------------

        @property
        def root(self) -> Gtk.Widget:
            """The top-level widget to embed into the application shell."""
            return self._root

        @property
        def checks(self) -> tuple[CheckResult, ...]:
            return tuple(self._checks)

        def recheck(self, on_rechecked: Callable[[tuple[CheckResult, ...]], None] | None = None
                    ) -> None:
            """Re-run the Core checks off the GTK loop and re-render."""

            async def _probe() -> list[CheckResult]:
                return run_dependency_checks()

            def _done(result: object, error: Exception | None) -> None:
                if error is not None or not isinstance(result, list):
                    return
                self.set_checks(result)
                if on_rechecked is not None:
                    on_rechecked(tuple(self._checks))

            from .database_pages import run_async

            run_async(_probe(), _done)

        def set_checks(self, checks: Sequence[CheckResult]) -> None:
            """Replace the rendered results (used by recheck and tests)."""
            self._checks = list(checks)
            self._render()

        # -- internals -----------------------------------------------------

        def _render(self) -> None:
            icon, title, description = banner_content(self._checks)
            self._banner.set_icon_name(icon)
            self._banner.set_title(GLib.markup_escape_text(title))
            self._banner.set_description(GLib.markup_escape_text(description))
            self._banner.add_css_class("cg-status-banner")
            for css_class in BANNER_CSS_CLASSES.values():
                self._banner.remove_css_class(css_class)
            self._banner.add_css_class(BANNER_CSS_CLASSES[banner_status(self._checks)])

            # PreferencesPage.remove() only accepts groups, so a re-render
            # swaps in a fresh page instead of mutating children in place.
            self._root.remove(self._page)
            self._page = Adw.PreferencesPage()
            self._root.append(self._page)
            self._rows = {}

            components = Adw.PreferencesGroup(title="Components")
            recheck_button = Gtk.Button(label="Recheck")
            recheck_button.add_css_class("flat")
            recheck_button.connect("clicked", self._on_recheck_clicked)
            components.set_header_suffix(recheck_button)
            for check in self._checks:
                components.add(self._build_row(check))
            self._page.add(components)

        def _on_recheck_clicked(self, _button: Gtk.Button) -> None:
            self.recheck()

        def _build_row(self, check: CheckResult) -> Adw.ExpanderRow:
            # Adwaita rows interpret their text as Pango markup: escape every
            # dynamic string (remedy commands contain '&' and paths contain
            # characters that break markup parsing).
            row = Adw.ExpanderRow(
                title=GLib.markup_escape_text(check.label),
                subtitle=GLib.markup_escape_text(check.detail),
            )
            image = Gtk.Image(icon_name=status_icon(check.status))
            image.set_valign(Gtk.Align.CENTER)
            row.add_suffix(image)
            for family in REMEDY_FAMILIES:
                command = check.remedies.get(family)
                if not command:
                    continue
                remedy_row = Adw.ActionRow(
                    title=GLib.markup_escape_text(FAMILY_LABELS.get(family, family)),
                    subtitle=GLib.markup_escape_text(command),
                )
                remedy_row.set_activatable(False)
                row.add_row(remedy_row)
            self._rows[check.id] = row
            return row

else:

    class DiagnosticsPage:
        """Import-safety shim used on headless systems without PyGObject."""

        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs
            raise RuntimeError(
                "DiagnosticsPage requires PyGObject with GTK 4 and Libadwaita; "
                "install the 'gtk' extra or run the diagnostics via "
                "`clamguardian doctor` instead"
            )


__all__ = [
    "BANNER_CSS_CLASSES",
    "FAMILY_LABELS",
    "GTK_AVAILABLE",
    "STATUS_ICONS",
    "DiagnosticsPage",
    "banner_content",
    "banner_status",
    "status_icon",
]