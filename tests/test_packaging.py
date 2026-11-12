"""Release-gate tests for packaging metadata (M7).

These are the automated form of what `appstreamcli validate` and a Flatpak build
check, limited to the invariants that can be verified from the repository
contents on a headless machine. They are the reason the icon, the AppStream
metadata and the Flatpak manifests can no longer drift apart silently.
"""

from __future__ import annotations

import configparser
import importlib
import re
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
    # The launcher must open the desktop app, not the bare CLI: `clamguardian`
    # with no subcommand is an argparse error and shows nothing (desktop UI D1).
    assert entry["Exec"] == "clamguardian ui"
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


def _clamguardian_module(manifest: dict) -> dict:
    """Trova il modulo ``clamguardian`` per nome (non per indice)."""
    for module in manifest["modules"]:
        if module.get("name") == APP_ID.replace(".", "-") or module.get("name") == "clamguardian":
            return module
    raise AssertionError(f"manifest lacks a module named 'clamguardian': {manifest['modules']}")


@pytest.mark.parametrize("manifest_name", MANIFESTS)
def test_flatpak_manifest_identity_and_integration(manifest_name: str) -> None:
    manifest = _manifest(manifest_name)
    assert manifest["app-id"] == APP_ID
    assert manifest["command"] == "clamguardian"
    assert (DATA / f"{APP_ID}.desktop").is_file()

    module = _clamguardian_module(manifest)
    commands = "\n".join(module["build-commands"])
    for installed in (
        f"/app/share/applications/{APP_ID}.desktop",
        f"/app/share/metainfo/{APP_ID}.metainfo.xml",
        f"/app/share/icons/hicolor/scalable/apps/{APP_ID}.svg",
    ):
        assert installed in commands, f"{manifest_name} does not install {installed}"
    # Build offline: nessun download da PyPI durante i build-commands.
    assert "--no-index" in commands, f"{manifest_name} build-commands may attempt network downloads"
    assert "--no-build-isolation" in commands, (
        f"{manifest_name} must avoid build isolation (it would re-download hatchling)"
    )
    hatchling_cmds = [c for c in module["build-commands"] if "hatchling" in c]
    assert hatchling_cmds, f"{manifest_name} must install hatchling during build"
    assert any("--no-index" in c and "./" in c for c in hatchling_cmds), (
        f"{manifest_name} must install hatchling from a local wheel, not from PyPI"
    )
    assert not any("hatchling>=" in c for c in module["build-commands"]), (
        f"{manifest_name} must not attempt to download hatchling from PyPI"
    )
    # Ogni source tipo file deve essere pinned con sha256 (riproducibilità Flathub).
    for source in module["sources"]:
        if source.get("type") == "file":
            assert source.get("url"), f"{manifest_name}: file source missing url"
            assert source.get("sha256"), f"{manifest_name}: file source missing sha256 pin"


def test_release_manifest_pins_an_immutable_source() -> None:
    module = _clamguardian_module(_manifest(f"{APP_ID}.yml"))
    sources = module["sources"]
    # Il release manifest combina fonti offline (wheel con sha256) + sorgente git immutabile.
    git_sources = [s for s in sources if s.get("type") == "git"]
    assert len(git_sources) == 1, "a release build must pin exactly one immutable git source"
    source = git_sources[0]
    assert source.get("url"), "the pinned git source needs a url"
    assert source.get("tag") or source.get("commit"), "the source must be pinned to a tag or commit"


def test_release_manifest_pins_the_declared_version() -> None:
    """The release manifest must build the version the package declares.

    A version bump that forgets the Flatpak pin would publish a bundle whose
    AppStream metadata and CLI claim ``1.0.1`` while the sources still come from
    the previous tag.
    """
    module = _clamguardian_module(_manifest(f"{APP_ID}.yml"))
    source = next(s for s in module["sources"] if s.get("type") == "git")
    assert source.get("tag") == f"v{clamguardian.__version__}"


def test_development_manifest_builds_the_working_tree() -> None:
    module = _clamguardian_module(_manifest(f"{APP_ID}.local.yml"))
    sources = module["sources"]
    dir_sources = [s for s in sources if s.get("type") == "dir"]
    assert len(dir_sources) == 1, "the development manifest must build from the working tree"
    assert dir_sources[0].get("path") == "../.."


# Dipendenze del backend di build hatchling: non sono dipendenze runtime del
# progetto (hatchling è solo in [build-system]; packaging/pathspec/pluggy
# compaiono in uv.lock solo come transitive delle dev-dependencies e la loro
# versione lockata non è vincolante per la sandbox di build). Vengono quindi
# escluse dal confronto con uv.lock: la loro versione è dettata dai requisiti
# di hatchling, non dal lock.
BUILD_BACKEND_ONLY = {
    "hatchling",
    "packaging",
    "pathspec",
    "pluggy",
    "tomlkit",
    "trove-classifiers",
}


def test_vendored_runtime_wheels_match_uv_lock() -> None:
    """Le versioni runtime vendute nei manifest devono coincidere con uv.lock.

    È la difesa contro le divergenze che sorgono quando un `uv lock` aggiorna le
    versioni senza ribruciare le wheel vendute (e viceversa): senza questo test la
    build Flatpak può passare usando dipendenze diverse da quelle che `uv lock
    --check` e `pip-audit` verificano nel gate di release.
    """
    with (ROOT / "uv.lock").open("rb") as handle:
        lock = tomllib.load(handle)
    lock_versions = {pkg["name"]: pkg["version"] for pkg in lock.get("package", [])}

    wheel_re = re.compile(r"^(?P<name>[A-Za-z0-9_.]+)-(?P<version>[0-9][A-Za-z0-9_.]*?)-.+\.whl$")
    mismatches: list[str] = []

    for manifest_name in MANIFESTS:
        module = _clamguardian_module(_manifest(manifest_name))
        for source in module["sources"]:
            if source.get("type") != "file":
                continue
            filename = source["url"].rsplit("/", 1)[-1]
            match = wheel_re.match(filename)
            if match is None:
                mismatches.append(f"{manifest_name}: cannot parse wheel name {filename!r}")
                continue
            # I filename usano underscore (charset_normalizer), il lock i trattini.
            name = match.group("name").replace("_", "-").lower()
            if name in BUILD_BACKEND_ONLY:
                continue
            locked = lock_versions.get(name)
            if locked is None:
                continue  # non una dipendenza runtime del progetto
            if match.group("version") != locked:
                mismatches.append(
                    f"{manifest_name}: {name} vendored {match.group('version')} != uv.lock {locked}"
                )

    assert mismatches == [], (
        "vendored runtime wheels diverge from uv.lock, re-pin them: " + "; ".join(mismatches)
    )


def test_vendored_file_sources_end_with_declared_filename() -> None:
    """Ogni source `type: file` deve terminare con il filename usato in build.

    L'URL di files.pythonhosted.org contiene un path hash (`packages/xx/yy/…`)
    che cambia a ogni release: riusare il path di una versione precedente
    produce un 404 solo in CI (flatpak-builder lo scopre scaricando). Questo
    test lega URL e filename dichiarato nel `build-commands`, cosicché un path
    riciclato venga rilevato in locale prima del push.
    """
    problems: list[str] = []

    for manifest_name in MANIFESTS:
        module = _clamguardian_module(_manifest(manifest_name))
        build_text = "\n".join(module.get("build-commands", []))
        for source in module["sources"]:
            if source.get("type") != "file":
                continue
            url: str = source["url"]
            filename = url.rsplit("/", 1)[-1]
            if not url.endswith("/" + filename) or not filename:
                problems.append(f"{manifest_name}: malformed url {url!r}")
                continue
            if not filename.endswith(".whl"):
                continue
            if filename not in build_text:
                problems.append(
                    f"{manifest_name}: {filename!r} vendored but never installed by build-commands"
                )

    assert problems == [], "; ".join(problems)


# Binary wheels must target the Python of the Flatpak runtime. The
# org.gnome.Sdk//51 sandbox runs Python 3.14, so a compiled (non-pure) wheel
# is only usable if tagged cp314 (exact) or abi3 (forward compatible); a cp312
# wheel 404s or refuses to install inside the sandbox. Vendored pure-Python
# wheels (py3-none-any) are exempt.
_RUNTIME_PYTHON_TAG = "cp314"
_FORWARD_COMPAT_TAGS = ("abi3",)


def _vendored_wheel_filenames(manifest: dict) -> list[str]:
    module = _clamguardian_module(manifest)
    names: list[str] = []
    for source in module["sources"]:
        if source.get("type") != "file":
            continue
        filename = source["url"].rsplit("/", 1)[-1]
        if filename.endswith(".whl"):
            names.append(filename)
    return names


def test_binary_wheels_match_runtime_python() -> None:
    """Nessuna wheel compilata per un Python diverso da quello del runtime.

    Lo sha256 o la versione da soli non bastano (cp312 vs cp314 hanno la
    stessa versione in uv.lock): qui si validano i tag piattaforma.
    """
    offenders: list[str] = []

    for manifest_name in MANIFESTS:
        for filename in _vendored_wheel_filenames(_manifest(manifest_name)):
            if filename.endswith("-py3-none-any.whl"):
                continue
            tags = filename.removesuffix(".whl").split("-")
            if not any(_RUNTIME_PYTHON_TAG in tag or tag in _FORWARD_COMPAT_TAGS for tag in tags):
                offenders.append(f"{manifest_name}: {filename!r}")

    assert offenders == [], (
        "vendored wheels not installable on the Flatpak runtime "
        f"(expected {_RUNTIME_PYTHON_TAG} or abi3 tags): " + "; ".join(offenders)
    )


def test_release_and_local_manifests_stay_in_sync() -> None:
    """Le fonti vendorizzate dei due manifest devono essere identiche.

    Ogni fix applicato al manifest locale (es. un re-pin di piattaforma)
    deve arrivare anche al manifest di release, che la CI scarica solo sui
    tag: una divergenza silenziosa produce un 404 o un build rotto solo alla
    release. Le uniche differenze ammesse sono la sorgente dell'app
    (`type: git` pinnata al tag vs `type: dir` del working tree).
    """
    release = _clamguardian_module(_manifest(f"{APP_ID}.yml"))
    local = _clamguardian_module(_manifest(f"{APP_ID}.local.yml"))

    def file_entries(module: dict) -> dict[str, str]:
        return {
            source["url"].rsplit("/", 1)[-1]: source.get("sha256", "")
            for source in module["sources"]
            if source.get("type") == "file"
        }

    release_files, local_files = file_entries(release), file_entries(local)
    only_local = sorted(set(local_files) - set(release_files))
    only_release = sorted(set(release_files) - set(local_files))
    sha_diff = sorted(
        name
        for name in set(local_files) & set(release_files)
        if local_files[name] != release_files[name]
    )

    assert only_local == [] and only_release == [] and sha_diff == [], (
        f"manifest wheel sources diverged (fix applicato a uno solo dei due): "
        f"solo in local={only_local}, solo in release={only_release}, "
        f"sha diversi={sha_diff}"
    )

    def installed_wheels(module: dict) -> set[str]:
        text = "\n".join(module.get("build-commands", []))
        wheels: set[str] = set()
        for token in text.replace("\n", " ").split():
            if token.startswith("./") and token.endswith(".whl"):
                wheels.add(token[2:])
        return wheels

    assert installed_wheels(local) == installed_wheels(release), (
        "le wheel installate dai build-commands differiscono tra i due manifest"
    )


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


def test_flatpak_manifests_install_the_native_locked_wheelhouse() -> None:
    """Runtime wheels are selected natively from uv.lock, not hard-coded to x86_64."""
    for manifest_name in MANIFESTS:
        module = _clamguardian_module(_manifest(manifest_name))
        commands = "\n".join(module["build-commands"])
        assert "./packaging/flatpak/wheelhouse/*.whl" in commands
        assert "--no-index" in commands
        assert "--no-deps" in commands
        runtime_files = [
            source for source in module["sources"]
            if source.get("type") == "file"
            and re.search(r"/(cryptography|cffi|aiohttp)-", source.get("url", ""))
        ]
        assert runtime_files == []
    release = _clamguardian_module(_manifest(f"{APP_ID}.yml"))
    assert any(
        source.get("type") == "dir"
        and source.get("path") == "wheelhouse"
        and source.get("dest") == "packaging/flatpak/wheelhouse"
        for source in release["sources"]
    )
    local = _clamguardian_module(_manifest(f"{APP_ID}.local.yml"))
    assert any(
        source.get("type") == "dir" and source.get("path") == "../.."
        for source in local["sources"]
    )



def test_appimage_manual_appdir_pipeline_is_pinned_and_complete() -> None:
    appimage = ROOT / "packaging" / "appimage"
    scripts = (
        "AppRun",
        "build-appimage.sh",
        "bundle-runtime.sh",
        "install-linuxdeploy.sh",
        "prepare-wheelhouse.sh",
        "test-appimage.sh",
        "install-appimagetool.sh",
    )
    for script in scripts:
        path = appimage / script
        assert path.is_file(), f"missing AppImage build component: {script}"
        assert path.stat().st_mode & 0o111, f"{script} must be executable"

    assert not (appimage / "AppImageBuilder.yml").exists()
    assert not (appimage / "patch-appimage-builder.py").exists()
    assert not (appimage / "clamguardian-launcher.c").exists()

    apprun = (appimage / "AppRun").read_text(encoding="utf-8")
    for marker in (
        'PYTHONHOME="$APPDIR"',
        "GI_TYPELIB_PATH=",
        "GIO_EXTRA_MODULES=",
        "GSETTINGS_SCHEMA_DIR=",
        "SSL_CERT_FILE=",
        "gdk-pixbuf-query-loaders",
        "--python-interpreter",
    ):
        assert marker in apprun

    build = (appimage / "build-appimage.sh").read_text(encoding="utf-8")
    assert "appimage-builder" not in build.lower()
    assert "/usr/bin/python3.12" in build
    assert "python3-gi" in build and "python3-cairo" in build
    assert "bundle-runtime.sh" in build
    assert 'APPDIR/usr/share/applications/io.github.clamguardian.ClamGuardian.desktop' in build
    assert 'APPDIR/io.github.clamguardian.ClamGuardian.svg' in build
    assert 'APPDIR/usr/share/metainfo/io.github.clamguardian.ClamGuardian.appdata.xml' in build
    assert "APT_ARCH" not in build and "APT_MIRROR" not in build

    bundler = (appimage / "bundle-runtime.sh").read_text(encoding="utf-8")
    for marker in (
        "linuxdeploy", "--library", "libgtk-4.so.1", "libadwaita-1.so.0",
        "libsecret-1.so.0", "Gtk-4.0.typelib", "Adw-1.typelib",
        "Secret-1.typelib", "glib-compile-schemas", "gdk-pixbuf-query-loaders",
        "ca-certificates.crt", "ldd",
    ):
        assert marker in bundler

    linuxdeploy = (appimage / "install-linuxdeploy.sh").read_text(encoding="utf-8")
    assert "releases/download/continuous" in linuxdeploy
    assert "df908b19f1ed1cdafa79508d415aa12d6c56ce4d56d4149aa8c09286718706e5" in linuxdeploy
    assert "f38e4d7cebf20d8073ec4e00e0a167ac146cd8585fe2f8fe82df27d74f2bd8e1" in linuxdeploy
    assert "sha256sum --check" in linuxdeploy

    installer = (appimage / "install-appimagetool.sh").read_text(encoding="utf-8")
    assert "appimagetool-aarch64.AppImage" in installer
    assert "appimagetool-x86_64.AppImage" in installer
    assert "sha256sum --check" in installer
    assert "1.9.1" in installer
    assert "type2-runtime/releases/download/20251108" in installer

    appimage_test = (appimage / "test-appimage.sh").read_text(encoding="utf-8")
    assert "--appimage-extract" in appimage_test
    assert "--python-interpreter" in appimage_test
    assert "gtk-smoke.py" in appimage_test
    assert 'usr/share/metainfo/io.github.clamguardian.ClamGuardian.appdata.xml' in appimage_test
    assert "timeout --signal=TERM 20s" not in appimage_test


def test_generated_packaging_wheelhouses_are_ignored() -> None:
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "/packaging/flatpak/wheelhouse/" in gitignore
    assert "/packaging/appimage/wheelhouse/" in gitignore


def test_flatpak_manifests_install_the_shared_gtk_smoke_script() -> None:
    for manifest_name in MANIFESTS:
        module = _clamguardian_module(_manifest(manifest_name))
        commands = "\\n".join(module["build-commands"])
        assert "packaging/smoke/gtk-smoke.py" in commands
        assert "/app/share/clamguardian/gtk-smoke.py" in commands


def test_packaging_workflows_use_finite_gtk_construction_smoke() -> None:
    for workflow_name in (".github/workflows/ci.yml", ".github/workflows/release.yml"):
        workflow = (ROOT / workflow_name).read_text(encoding="utf-8")
        assert "flatpak run --command=python3" in workflow
        assert "/app/share/clamguardian/gtk-smoke.py" in workflow
        assert "timeout --signal=TERM 20s" not in workflow

    release_gate = (ROOT / ".github/workflows/release-gate.yml").read_text(encoding="utf-8")
    assert "packaging/smoke/gtk-smoke.py" in release_gate


def test_publish_workflow_scopes_write_permission_to_feature_branch() -> None:
    workflow = (ROOT / ".github" / "workflows" / "publish-release.yml").read_text(encoding="utf-8")
    assert "contents: read" in workflow
    assert "if: github.ref == 'refs/heads/feature'" in workflow
    job = workflow.split("  validate-and-publish:", 1)[1]
    assert "permissions:" in job
    assert "contents: write" in job


def test_shared_gtk_smoke_constructs_the_complete_application() -> None:
    smoke = (ROOT / "packaging" / "smoke" / "gtk-smoke.py").read_text(encoding="utf-8")
    for marker in (
        "ClamGuardianApp", "MainWindow", "DiagnosticsPage", "ScanPage",
        "build_about_dialog", "CLAMGUARDIAN_GTK_SMOKE_OK",
    ):
        assert marker in smoke
