"""Release-gate tests for packaging metadata (M7).

These are the automated form of what `appstreamcli validate` and a Flatpak build
check, limited to the invariants that can be verified from the repository
contents on a headless machine. They are the reason the icon, the AppStream
metadata and the Flatpak manifests can no longer drift apart silently.
"""

from __future__ import annotations

import configparser
import importlib
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml

import clamguardian

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
APP_ID = "io.github.clamguardian.ClamGuardian"
FLATPAK = ROOT / "packaging" / "flatpak"
ICON = DATA / "icons" / "hicolor" / "scalable" / "apps" / f"{APP_ID}.svg"
MANIFESTS = (
    f"{APP_ID}.yml",  # release: pinned to a tag
    f"{APP_ID}.local.yml",  # development: builds the working tree
)


@pytest.fixture(scope="module")
def pyproject() -> dict:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


def _desktop_entry() -> dict[str, str]:
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str  # desktop-entry keys are case-sensitive
    parser.read(DATA / f"{APP_ID}.desktop", encoding="utf-8")
    return dict(parser["Desktop Entry"])


def _metainfo() -> ET.Element:
    return ET.parse(DATA / f"{APP_ID}.metainfo.xml").getroot()


def _manifest(name: str) -> dict:
    with (FLATPAK / name).open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def test_declared_version_is_consistent(pyproject: dict) -> None:
    assert pyproject["project"]["version"] == clamguardian.__version__


def test_console_script_target_is_importable_and_callable(pyproject: dict) -> None:
    scripts = pyproject["project"]["scripts"]
    assert list(scripts) == ["clamguardian"]
    module_name, _, attribute = scripts["clamguardian"].partition(":")
    assert module_name and attribute, "entry point must be 'module:attribute'"
    module = importlib.import_module(module_name)
    assert callable(getattr(module, attribute))


def test_desktop_entry_is_complete_and_matches_the_console_script() -> None:
    entry = _desktop_entry()
    for key in ("Name", "Comment", "Exec", "Icon", "Type", "Categories"):
        assert entry.get(key), f"desktop entry is missing {key}"
    assert entry["Type"] == "Application"
    assert entry["Exec"] == "clamguardian"
    assert entry["Icon"] == APP_ID


def test_icon_referenced_by_the_desktop_entry_exists() -> None:
    assert ICON.is_file(), f"icon referenced by the desktop entry is missing: {ICON}"
    assert ET.parse(ICON).getroot().tag.endswith("svg")


def test_metainfo_matches_the_desktop_entry_and_the_declared_release() -> None:
    root = _metainfo()
    assert root.findtext("id") == APP_ID
    launchable = root.find("launchable")
    assert launchable is not None
    assert launchable.get("type") == "desktop-id"
    assert launchable.text == f"{APP_ID}.desktop"
    assert (DATA / f"{APP_ID}.desktop").is_file()
    released = [release.get("version") for release in root.findall("releases/release")]
    assert clamguardian.__version__ in released


def test_metainfo_has_the_elements_a_desktop_application_requires() -> None:
    root = _metainfo()
    assert root.findtext("developer/name"), "AppStream requires a developer block"
    assert root.find("content_rating") is not None
    assert root.findtext("summary")
    assert root.find("description") is not None
    assert root.findtext("metadata_license")
    assert root.findtext("project_license")
    url_types = {url.get("type") for url in root.findall("url")}
    assert {"homepage", "bugtracker"} <= url_types


def test_wheel_ships_the_desktop_integration_files(pyproject: dict) -> None:
    shared = pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]["shared-data"]
    # Hatchling maps source (repository path) -> destination (wheel path).
    expected = {
        f"data/{APP_ID}.desktop": f"share/applications/{APP_ID}.desktop",
        f"data/{APP_ID}.metainfo.xml": f"share/metainfo/{APP_ID}.metainfo.xml",
        f"data/icons/hicolor/scalable/apps/{APP_ID}.svg": (
            f"share/icons/hicolor/scalable/apps/{APP_ID}.svg"
        ),
    }
    assert shared == expected
    for source in shared:
        assert (ROOT / source).is_file(), f"shared-data source does not exist: {source}"


@pytest.mark.parametrize("manifest_name", MANIFESTS)
def test_flatpak_manifest_identity_and_integration(manifest_name: str) -> None:
    manifest = _manifest(manifest_name)
    assert manifest["app-id"] == APP_ID
    assert manifest["command"] == "clamguardian"
    assert (DATA / f"{APP_ID}.desktop").is_file()

    commands = "\n".join(manifest["modules"][0]["build-commands"])
    for installed in (
        f"/app/share/applications/{APP_ID}.desktop",
        f"/app/share/metainfo/{APP_ID}.metainfo.xml",
        f"/app/share/icons/hicolor/scalable/apps/{APP_ID}.svg",
    ):
        assert installed in commands, f"{manifest_name} does not install {installed}"


def test_release_manifest_pins_an_immutable_source() -> None:
    sources = _manifest(f"{APP_ID}.yml")["modules"][0]["sources"]
    assert len(sources) == 1
    source = sources[0]
    assert source["type"] == "git", "a release build must not use a working-tree source"
    assert source.get("url"), "the pinned git source needs a url"
    assert source.get("tag") or source.get("commit"), "the source must be pinned to a tag or commit"


def test_development_manifest_builds_the_working_tree() -> None:
    sources = _manifest(f"{APP_ID}.local.yml")["modules"][0]["sources"]
    assert [source["type"] for source in sources] == ["dir"]
    assert sources[0]["path"] == "../.."


def test_flatpak_finish_args_cover_what_the_code_needs() -> None:
    manifest = _manifest(f"{APP_ID}.yml")
    finish_args = set(manifest["finish-args"])
    # clamscan/freshclam run on the host through flatpak-spawn --host.
    assert "--talk-name=org.freedesktop.Flatpak" in finish_args
    # third-party database downloads and freshclam updates use the network.
    assert "--share=network" in finish_args
    # quarantine vault, history and database state are written by the app.
    assert "--filesystem=xdg-data/clamguardian:create" in finish_args
    assert "--socket=fallback-x11" in finish_args or "--socket=x11" in finish_args
