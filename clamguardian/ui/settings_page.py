"""Settings page for the GTK4/Libadwaita desktop application.

The page is a thin view over :class:`~clamguardian.core.settings.SettingsStore`:
it edits the default scan profile, desktop notifications and the colour
scheme, and persists every change immediately.

The module is import-safe on headless systems without PyGObject.
"""

from __future__ import annotations

from collections.abc import Callable

from ..core.profiles import DEFAULT_REGISTRY
from ..core.settings import AppSettings, SettingsStore, profile_index
from .theme import apply_color_scheme

try:  # pragma: no cover - exercised only on systems with PyGObject
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gtk

    GTK_AVAILABLE = True
except Exception:  # pragma: no cover - headless environments
    GTK_AVAILABLE = False

__all__ = ["GTK_AVAILABLE", "SettingsPage", "profile_index"]


if GTK_AVAILABLE:  # pragma: no cover - exercised only on systems with PyGObject

    class SettingsPage:
        """Preferences: default profile, notifications, theme and About."""

        def __init__(
            self,
            store: SettingsStore,
            *,
            on_changed: Callable[[AppSettings], None] | None = None,
            on_about: Callable[[], None] | None = None,
        ) -> None:
            self._store = store
            self._settings = store.load()
            self._on_changed = on_changed
            self._on_about = on_about

            self._root = Adw.PreferencesPage()
            self._root.set_vexpand(True)
            self._root.set_hexpand(True)

            self._build_scanning_group()
            self._build_automation_group()
            self._build_notifications_group()
            self._build_appearance_group()
            self._build_about_group()

        # -- public API ----------------------------------------------------

        @property
        def root(self) -> Gtk.Widget:
            """The preferences page to embed into the application shell."""
            return self._root

        @property
        def settings(self) -> AppSettings:
            """The currently persisted settings."""
            return self._settings

        # -- groups --------------------------------------------------------

        def _build_scanning_group(self) -> None:
            group = Adw.PreferencesGroup(
                title="Scanning",
                description="Used as the preselected profile on the Scan page.",
            )
            profiles = DEFAULT_REGISTRY.list()
            model = Gtk.StringList.new([profile.name for profile in profiles])
            row = Adw.ComboRow(title="Default profile", model=model)
            row.set_selected(profile_index(self._settings.default_profile_id))
            row.connect("notify::selected", self._on_profile_changed)
            self._profile_row = row
            group.add(row)
            self._root.add(group)

        def _build_automation_group(self) -> None:
            group = Adw.PreferencesGroup(
                title="Automation & Protection",
                description="Background protection and scheduled scan settings.",
            )
            usb_row = Adw.SwitchRow(
                title="USB Auto-Scan",
                subtitle="Automatically scan removable media upon mount",
            )
            usb_row.set_active(self._settings.usb_autoscan_enabled)
            usb_row.connect("notify::active", self._on_usb_changed)
            self._usb_row = usb_row
            group.add(usb_row)

            intel_row = Adw.SwitchRow(
                title="Threat Intelligence",
                subtitle=(
                    "Opt-in hash-only VirusTotal lookups; API key: "
                    "'clamguardian intel set-key'. Network access remains gated "
                    "pending maintainer terms review."
                ),
            )
            intel_row.set_active(self._settings.intelligence_enabled)
            intel_row.connect("notify::active", self._on_intelligence_changed)
            self._intel_row = intel_row
            group.add(intel_row)

            rt_row = Adw.SwitchRow(
                title="Realtime Monitoring",
                subtitle="Event-driven filesystem monitoring for configured directories",
            )
            rt_row.set_active(self._settings.realtime_enabled)
            rt_row.connect("notify::active", self._on_realtime_changed)
            self._rt_row = rt_row
            group.add(rt_row)

            sched_row = Adw.SwitchRow(
                title="Scheduled Daily Scans",
                subtitle="Run automated scans daily during user sessions",
            )
            sched_row.set_active(self._settings.scheduled_scans_enabled)
            sched_row.connect("notify::active", self._on_scheduled_changed)
            self._sched_row = sched_row
            group.add(sched_row)

            autostart_row = Adw.SwitchRow(
                title="Start ClamGuardian at Login",
                subtitle="Automatically start background protection at login",
            )
            autostart_row.set_active(self._settings.autostart_enabled)
            autostart_row.connect("notify::active", self._on_autostart_changed)
            self._autostart_row = autostart_row
            group.add(autostart_row)

            self._realtime_status_row = Adw.ActionRow(
                title="Realtime runtime health",
                subtitle="Not started",
            )
            group.add(self._realtime_status_row)
            self._root.add(group)

        def set_realtime_runtime_status(self, status: dict[str, object]) -> None:
            """Display live monitor health, including watch and event-loss counters."""
            failures_obj = status.get("watch_failures", ())
            failures = failures_obj if isinstance(failures_obj, (list, tuple, set)) else ()
            raw_overflow = status.get("overflow_count", 0)
            overflow = int(raw_overflow) if isinstance(raw_overflow, (int, float, str)) else 0
            raw_dropped = status.get("dropped_events_count", 0)
            dropped = int(raw_dropped) if isinstance(raw_dropped, (int, float, str)) else 0
            running = bool(status.get("running", False))
            if failures:
                subtitle = f"Degraded — {len(failures)} watch registration failure(s)"
            elif running:
                subtitle = (
                    f"Active — {overflow} kernel overflow(s), "
                    f"{dropped} event(s) dropped"
                )
            else:
                subtitle = (
                    f"Stopped — {overflow} kernel overflow(s), "
                    f"{dropped} event(s) dropped in the last run"
                )
            self._realtime_status_row.set_subtitle(subtitle)

        def _build_notifications_group(self) -> None:
            group = Adw.PreferencesGroup(
                title="Notifications",
                description=(
                    "Show a desktop notification when a scan finishes while "
                    "ClamGuardian is in the background. Notification text never "
                    "contains file names or paths."
                ),
            )
            row = Adw.SwitchRow(title="Scan finished notifications")
            row.set_active(self._settings.notifications_enabled)
            row.connect("notify::active", self._on_notifications_changed)
            self._notifications_row = row
            group.add(row)
            self._root.add(group)

        def _build_appearance_group(self) -> None:
            group = Adw.PreferencesGroup(title="Appearance")
            model = Gtk.StringList.new(["Follow system", "Light", "Dark"])
            row = Adw.ComboRow(title="Theme", model=model)
            scheme_index = {"system": 0, "light": 1, "dark": 2}
            row.set_selected(scheme_index.get(self._settings.color_scheme, 0))
            row.connect("notify::selected", self._on_scheme_changed)
            self._scheme_row = row
            group.add(row)
            self._root.add(group)

        def _build_about_group(self) -> None:
            group = Adw.PreferencesGroup(title="About")
            row = Adw.ActionRow(
                title="About ClamGuardian",
                subtitle="Version, license and project links",
                activatable=True,
            )
            row.add_suffix(Gtk.Image(icon_name="go-next-symbolic"))
            row.connect("activated", self._on_about_activated)
            self._about_row = row
            group.add(row)
            self._root.add(group)

        # -- handlers ------------------------------------------------------

        def _on_profile_changed(self, combo: Adw.ComboRow, _pspec: object) -> None:
            profiles = DEFAULT_REGISTRY.list()
            index = combo.get_selected()
            if not (0 <= index < len(profiles)):
                return
            self._persist(
                AppSettings(
                    default_profile_id=profiles[index].id,
                    notifications_enabled=self._settings.notifications_enabled,
                    color_scheme=self._settings.color_scheme,
                    usb_autoscan_enabled=self._settings.usb_autoscan_enabled,
                    intelligence_enabled=self._settings.intelligence_enabled,
                    realtime_enabled=self._settings.realtime_enabled,
                    realtime_paths=self._settings.realtime_paths,
                    scheduled_scans_enabled=self._settings.scheduled_scans_enabled,
                    scheduled_hour=self._settings.scheduled_hour,
                    scheduled_minute=self._settings.scheduled_minute,
                    autostart_enabled=self._settings.autostart_enabled,
                )
            )

        def _on_usb_changed(self, row: Adw.SwitchRow, _pspec: object) -> None:
            self._persist(
                AppSettings(
                    default_profile_id=self._settings.default_profile_id,
                    notifications_enabled=self._settings.notifications_enabled,
                    color_scheme=self._settings.color_scheme,
                    usb_autoscan_enabled=row.get_active(),
                    intelligence_enabled=self._settings.intelligence_enabled,
                    realtime_enabled=self._settings.realtime_enabled,
                    realtime_paths=self._settings.realtime_paths,
                    scheduled_scans_enabled=self._settings.scheduled_scans_enabled,
                    scheduled_hour=self._settings.scheduled_hour,
                    scheduled_minute=self._settings.scheduled_minute,
                    autostart_enabled=self._settings.autostart_enabled,
                )
            )

        def _on_intelligence_changed(self, row: Adw.SwitchRow, _pspec: object) -> None:
            self._persist(
                AppSettings(
                    default_profile_id=self._settings.default_profile_id,
                    notifications_enabled=self._settings.notifications_enabled,
                    color_scheme=self._settings.color_scheme,
                    usb_autoscan_enabled=self._settings.usb_autoscan_enabled,
                    intelligence_enabled=row.get_active(),
                    realtime_enabled=self._settings.realtime_enabled,
                    realtime_paths=self._settings.realtime_paths,
                    scheduled_scans_enabled=self._settings.scheduled_scans_enabled,
                    scheduled_hour=self._settings.scheduled_hour,
                    scheduled_minute=self._settings.scheduled_minute,
                    autostart_enabled=self._settings.autostart_enabled,
                )
            )

        def _on_realtime_changed(self, row: Adw.SwitchRow, _pspec: object) -> None:
            self._persist(
                AppSettings(
                    default_profile_id=self._settings.default_profile_id,
                    notifications_enabled=self._settings.notifications_enabled,
                    color_scheme=self._settings.color_scheme,
                    usb_autoscan_enabled=self._settings.usb_autoscan_enabled,
                    intelligence_enabled=self._settings.intelligence_enabled,
                    realtime_enabled=row.get_active(),
                    realtime_paths=self._settings.realtime_paths,
                    scheduled_scans_enabled=self._settings.scheduled_scans_enabled,
                    scheduled_hour=self._settings.scheduled_hour,
                    scheduled_minute=self._settings.scheduled_minute,
                    autostart_enabled=self._settings.autostart_enabled,
                )
            )

        def _on_scheduled_changed(self, row: Adw.SwitchRow, _pspec: object) -> None:
            self._persist(
                AppSettings(
                    default_profile_id=self._settings.default_profile_id,
                    notifications_enabled=self._settings.notifications_enabled,
                    color_scheme=self._settings.color_scheme,
                    usb_autoscan_enabled=self._settings.usb_autoscan_enabled,
                    intelligence_enabled=self._settings.intelligence_enabled,
                    realtime_enabled=self._settings.realtime_enabled,
                    realtime_paths=self._settings.realtime_paths,
                    scheduled_scans_enabled=row.get_active(),
                    scheduled_hour=self._settings.scheduled_hour,
                    scheduled_minute=self._settings.scheduled_minute,
                    autostart_enabled=self._settings.autostart_enabled,
                )
            )

        def _on_autostart_changed(self, row: Adw.SwitchRow, _pspec: object) -> None:
            if row.get_active():
                from ..core.autostart import AutostartManager

                if AutostartManager._inside_flatpak():
                    self._show_error(
                        "Autostart unavailable in Flatpak",
                        "Host XDG autostart cannot be written from the sandbox. "
                        "A supported desktop Background portal integration is not yet available.",
                    )
                    row.set_active(False)
                    return
            self._persist(
                AppSettings(
                    default_profile_id=self._settings.default_profile_id,
                    notifications_enabled=self._settings.notifications_enabled,
                    color_scheme=self._settings.color_scheme,
                    usb_autoscan_enabled=self._settings.usb_autoscan_enabled,
                    intelligence_enabled=self._settings.intelligence_enabled,
                    realtime_enabled=self._settings.realtime_enabled,
                    realtime_paths=self._settings.realtime_paths,
                    scheduled_scans_enabled=self._settings.scheduled_scans_enabled,
                    scheduled_hour=self._settings.scheduled_hour,
                    scheduled_minute=self._settings.scheduled_minute,
                    autostart_enabled=row.get_active(),
                )
            )

        def _on_notifications_changed(self, row: Adw.SwitchRow, _pspec: object) -> None:
            self._persist(
                AppSettings(
                    default_profile_id=self._settings.default_profile_id,
                    notifications_enabled=row.get_active(),
                    color_scheme=self._settings.color_scheme,
                    usb_autoscan_enabled=self._settings.usb_autoscan_enabled,
                    intelligence_enabled=self._settings.intelligence_enabled,
                    realtime_enabled=self._settings.realtime_enabled,
                    realtime_paths=self._settings.realtime_paths,
                    scheduled_scans_enabled=self._settings.scheduled_scans_enabled,
                    scheduled_hour=self._settings.scheduled_hour,
                    scheduled_minute=self._settings.scheduled_minute,
                    autostart_enabled=self._settings.autostart_enabled,
                )
            )

        def _on_scheme_changed(self, combo: Adw.ComboRow, _pspec: object) -> None:
            schemes = ("system", "light", "dark")
            index = combo.get_selected()
            if not (0 <= index < len(schemes)):
                return
            self._persist(
                AppSettings(
                    default_profile_id=self._settings.default_profile_id,
                    notifications_enabled=self._settings.notifications_enabled,
                    color_scheme=schemes[index],
                    usb_autoscan_enabled=self._settings.usb_autoscan_enabled,
                    intelligence_enabled=self._settings.intelligence_enabled,
                    realtime_enabled=self._settings.realtime_enabled,
                    realtime_paths=self._settings.realtime_paths,
                    scheduled_scans_enabled=self._settings.scheduled_scans_enabled,
                    scheduled_hour=self._settings.scheduled_hour,
                    scheduled_minute=self._settings.scheduled_minute,
                    autostart_enabled=self._settings.autostart_enabled,
                )
            )

        def _on_about_activated(self, _row: Adw.ActionRow) -> None:
            if self._on_about is not None:
                self._on_about()

        def _persist(self, candidate: AppSettings) -> None:
            try:
                self._settings = self._store.save(candidate)
            except OSError as error:
                self._show_error("Could not save settings", str(error))
                return
            apply_color_scheme(self._settings.color_scheme)
            if self._on_changed is not None:
                self._on_changed(self._settings)

        def _show_error(self, heading: str, body: str) -> None:
            from .dialogs import alert_dialog, top_level_window

            dialog = alert_dialog(heading, body)
            window = top_level_window(self._root)
            if window is not None:
                dialog.present(window)

else:

    class SettingsPage:
        """Import-safety shim used on headless systems without PyGObject."""

        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs
            raise RuntimeError(
                "SettingsPage requires PyGObject with GTK 4 and Libadwaita; "
                "install the 'gtk' extra or edit settings.json directly"
            )
