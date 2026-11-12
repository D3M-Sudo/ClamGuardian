"""Settings page for the GTK4/Libadwaita desktop application.

The page is a thin view over :class:`~clamguardian.core.settings.SettingsStore`:
it edits the default scan profile, desktop notifications and the colour
scheme, and persists every change immediately.

The module is import-safe on headless systems without PyGObject.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from pathlib import Path

from ..core.profiles import DEFAULT_REGISTRY
from ..core.settings import AppSettings, SettingsStore, profile_index
from .theme import apply_color_scheme

try:  # pragma: no cover - exercised only on systems with PyGObject
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gtk

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
            self._build_intelligence_group()
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
                title="Automation &amp; Protection",
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
                    "Optional VirusTotal hash enrichment. Configure credentials "
                    "in the VirusTotal Integration section; Public access remains "
                    "blocked pending written eligibility authorization."
                ),
            )
            intel_row.set_active(self._settings.intelligence_enabled)
            intel_row.connect("notify::active", self._on_intelligence_changed)
            self._intel_row = intel_row
            group.add(intel_row)

            intel_profile_model = Gtk.StringList.new(["Public API", "Premium API"])
            intel_profile_row = Adw.ComboRow(
                title="VirusTotal API profile",
                subtitle="Select the credential and subscription explicitly",
                model=intel_profile_model,
            )
            selected_profile = (
                1 if self._settings.intelligence_profile == "premium" else 0
            )
            intel_profile_row.set_selected(selected_profile)
            intel_profile_row.connect("notify::selected", self._on_intelligence_profile_changed)
            self._intel_profile_row = intel_profile_row
            group.add(intel_profile_row)

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

        def _build_intelligence_group(self) -> None:
            group = Adw.PreferencesGroup(
                title="VirusTotal Integration",
                description=(
                    "Credentials are stored only in the operating system Secret Service. "
                    "Public API access remains blocked pending written eligibility "
                    "authorization; Premium requires a valid subscription entitlement."
                ),
            )
            self._credential_rows: dict[str, Adw.ActionRow] = {}
            for profile, label in (("public", "Public"), ("premium", "Premium")):
                row = Adw.ActionRow(
                    title=f"{label} API credential",
                    subtitle="Checking OS Secret Service…",
                )
                entry = Gtk.Entry()
                entry.set_visibility(False)
                entry.set_input_purpose(Gtk.InputPurpose.PASSWORD)
                entry.set_placeholder_text("API key (input hidden)")
                entry.set_hexpand(True)
                save_button = Gtk.Button(label="Save")
                save_button.connect(
                    "clicked", self._on_save_credential, profile, entry, row
                )
                controls = Gtk.Box(
                    orientation=Gtk.Orientation.HORIZONTAL,
                    spacing=6,
                )
                controls.append(entry)
                controls.append(save_button)
                row.add_suffix(controls)
                group.add(row)
                self._credential_rows[profile] = row

            upload_row = Adw.ActionRow(
                title="Submit a file for analysis",
                subtitle=(
                    "Looks up SHA-256 first. A full-file upload requires a separate "
                    "confirmation for that exact file."
                ),
            )
            upload_button = Gtk.Button(label="Choose file…")
            upload_button.connect("clicked", self._on_choose_upload_file)
            upload_row.add_suffix(upload_button)
            upload_row.set_sensitive(self._settings.intelligence_enabled)
            group.add(upload_row)
            self._intel_upload_row = upload_row
            self._intel_upload_button = upload_button
            self._root.add(group)
            self._refresh_credential_status()

        def _refresh_credential_status(self) -> None:
            from ..intelligence.secrets import (
                IntelligenceSecretStore,
                SecretStorageError,
            )

            store = IntelligenceSecretStore()
            for profile, row in self._credential_rows.items():
                try:
                    configured = bool(store.get_credential(profile))
                except SecretStorageError:
                    row.set_subtitle(
                        "Secret Service unavailable; plaintext storage is prohibited."
                    )
                else:
                    row.set_subtitle(
                        "Credential stored in OS Secret Service."
                        if configured
                        else "No credential configured."
                    )

        def _on_save_credential(
            self,
            _button: Gtk.Button,
            profile: str,
            entry: Gtk.Entry,
            row: Adw.ActionRow,
        ) -> None:
            from ..intelligence.secrets import (
                IntelligenceSecretStore,
                SecretStorageError,
            )

            credential = entry.get_text()
            if not credential.strip():
                self._show_error(
                    "Missing API credential",
                    "Enter the selected VirusTotal profile's API credential.",
                )
                return
            try:
                IntelligenceSecretStore().set_credential(profile, credential)
            except (SecretStorageError, ValueError):
                self._show_error(
                    "Credential not stored",
                    "The credential could not be stored in OS Secret Service. "
                    "No plaintext fallback was used.",
                )
                return
            entry.set_text("")
            row.set_subtitle("Credential stored in OS Secret Service.")

        def _on_choose_upload_file(self, _button: Gtk.Button) -> None:
            from .dialogs import top_level_window

            window = top_level_window(self._root)
            if window is None:
                self._show_error(
                    "File selection unavailable",
                    "The VirusTotal upload action requires an active application window.",
                )
                return
            if hasattr(Gtk, "FileDialog"):
                dialog = Gtk.FileDialog(title="Select a file for VirusTotal analysis")

                def _done(source: Gtk.FileDialog, result: object) -> None:
                    try:
                        selected = source.open_finish(result)
                    except GLib.Error:
                        return
                    filename = selected.get_path() if selected is not None else None
                    if filename:
                        self._start_upload_workflow(Path(filename))

                dialog.open(window, None, _done)
                return

            if hasattr(Gtk, "FileChooserNative"):  # pragma: no cover - older GTK4
                chooser = Gtk.FileChooserNative.new(
                    "Select a file for VirusTotal analysis",
                    window,
                    Gtk.FileChooserAction.OPEN,
                    "Select",
                    "Cancel",
                )

                def _response(dialog: object, response: int) -> None:
                    filename = (
                        dialog.get_filename()
                        if response == Gtk.ResponseType.ACCEPT
                        else None
                    )
                    dialog.destroy()
                    if filename:
                        self._start_upload_workflow(Path(filename))

                chooser.connect("response", _response)
                chooser.show()
                return

            self._show_error(
                "File selection unavailable",
                "This GTK version does not provide a file chooser.",
            )

        def _start_upload_workflow(self, path: Path) -> None:
            from ..intelligence.service import ThreatIntelligenceService
            from .database_pages import run_async

            service = ThreatIntelligenceService(settings_store=self._store)
            consent_event = threading.Event()
            consent_decision = {"accepted": False}
            self._intel_upload_button.set_sensitive(False)

            async def _workflow() -> tuple[str, dict[str, object] | None]:
                preview = service.preview_file_upload(path)
                lookup = await service.lookup_upload_candidate(preview)
                if lookup.get("found") is True:
                    return "existing", lookup
                if lookup.get("found") is not False:
                    raise RuntimeError(
                        "VirusTotal hash lookup did not establish whether a report exists"
                    )
                GLib.idle_add(
                    self._present_upload_consent,
                    preview,
                    consent_event,
                    consent_decision,
                )
                await asyncio.to_thread(consent_event.wait)
                if not consent_decision["accepted"]:
                    return "cancelled", None
                report = await service.upload_file(
                    preview,
                    consent=True,
                    lookup_report=lookup,
                )
                return "uploaded", report

            def _done(
                result: object,
                error: Exception | None,
            ) -> None:
                self._intel_upload_button.set_sensitive(
                    self._settings.intelligence_enabled
                )
                if error is not None:
                    self._show_error(
                        "VirusTotal operation failed",
                        f"The operation could not be completed ({type(error).__name__}).",
                    )
                    return
                if not isinstance(result, tuple) or len(result) != 2:
                    self._show_error(
                        "VirusTotal operation failed",
                        "The operation returned an invalid result.",
                    )
                    return
                status, report = result
                if status == "cancelled":
                    return
                if isinstance(report, dict):
                    self._show_upload_report(status, report)

            run_async(_workflow(), _done)

        def _present_upload_consent(
            self,
            preview: object,
            consent_event: threading.Event,
            consent_decision: dict[str, bool],
        ) -> bool:
            from .dialogs import alert_dialog, top_level_window

            filename = str(getattr(preview, "filename", "selected file"))
            filename = filename.replace("\\n", "\\\\n").replace("\\r", "\\\\r")
            size = int(getattr(preview, "size", 0))
            digest = str(getattr(preview, "sha256", ""))
            warning = str(getattr(preview, "warning", ""))
            body = (
                f"File: {filename}\n"
                f"Size: {size:,} bytes\n"
                f"SHA-256: {digest}\n\n"
                f"{warning}\n\n"
                "The file will be transmitted only if you explicitly choose Upload."
            )
            try:
                dialog = alert_dialog(
                    "Confirm VirusTotal file submission",
                    body,
                    responses=(("upload", "Upload file"), ("cancel", "Cancel")),
                    default_response="cancel",
                    close_response="cancel",
                )
                window = top_level_window(self._root)
                if window is None:
                    consent_event.set()
                    return False

                def _response(_dialog: object, response: str) -> None:
                    consent_decision["accepted"] = response == "upload"
                    consent_event.set()

                dialog.connect("response", _response)
                dialog.present(window)
            except Exception:
                # Fail closed: never leave the upload worker waiting or infer consent.
                consent_decision["accepted"] = False
                consent_event.set()
            return False

        def _show_upload_report(
            self,
            status: str,
            report: dict[str, object],
        ) -> None:
            if status == "existing":
                heading = "Existing VirusTotal report"
                stats = report.get("last_analysis_stats", {})
                permalink = report.get("permalink", "")
                body = (
                    "A report already exists for this SHA-256. No file was uploaded.\n"
                    f"Detection statistics: {stats}\n"
                    f"Report: {permalink}"
                )
            else:
                heading = "VirusTotal analysis submitted"
                stats = report.get("stats", {})
                body = (
                    f"Analysis status: {report.get('status', 'unknown')}\n"
                    f"Analysis ID: {report.get('analysis_id', 'unavailable')}\n"
                    f"Analysis statistics: {stats}\n\n"
                    "This remote assessment is supplemental and does not change "
                    "the local ClamAV verdict."
                )
            self._show_error(heading, body)

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
                    intelligence_profile=self._settings.intelligence_profile,
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
                    intelligence_profile=self._settings.intelligence_profile,
                    realtime_enabled=self._settings.realtime_enabled,
                    realtime_paths=self._settings.realtime_paths,
                    scheduled_scans_enabled=self._settings.scheduled_scans_enabled,
                    scheduled_hour=self._settings.scheduled_hour,
                    scheduled_minute=self._settings.scheduled_minute,
                    autostart_enabled=self._settings.autostart_enabled,
                )
            )

        def _on_intelligence_changed(self, row: Adw.SwitchRow, _pspec: object) -> None:
            self._intel_upload_row.set_sensitive(row.get_active())
            self._persist(
                AppSettings(
                    default_profile_id=self._settings.default_profile_id,
                    notifications_enabled=self._settings.notifications_enabled,
                    color_scheme=self._settings.color_scheme,
                    usb_autoscan_enabled=self._settings.usb_autoscan_enabled,
                    intelligence_enabled=row.get_active(),
                    intelligence_profile=self._settings.intelligence_profile,
                    realtime_enabled=self._settings.realtime_enabled,
                    realtime_paths=self._settings.realtime_paths,
                    scheduled_scans_enabled=self._settings.scheduled_scans_enabled,
                    scheduled_hour=self._settings.scheduled_hour,
                    scheduled_minute=self._settings.scheduled_minute,
                    autostart_enabled=self._settings.autostart_enabled,
                )
            )

        def _on_intelligence_profile_changed(self, combo: Adw.ComboRow, _pspec: object) -> None:
            profiles = ("public", "premium")
            index = combo.get_selected()
            if not (0 <= index < len(profiles)):
                return
            self._persist(
                AppSettings(
                    default_profile_id=self._settings.default_profile_id,
                    notifications_enabled=self._settings.notifications_enabled,
                    color_scheme=self._settings.color_scheme,
                    usb_autoscan_enabled=self._settings.usb_autoscan_enabled,
                    intelligence_enabled=self._settings.intelligence_enabled,
                    intelligence_profile=profiles[index],
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
                    intelligence_profile=self._settings.intelligence_profile,
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
                    intelligence_profile=self._settings.intelligence_profile,
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
                    intelligence_profile=self._settings.intelligence_profile,
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
                    intelligence_profile=self._settings.intelligence_profile,
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
                    intelligence_profile=self._settings.intelligence_profile,
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
