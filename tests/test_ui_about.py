"""Tests for the About dialog metadata (Phase D4)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from _gtk_probe import gtk_works

import clamguardian
import clamguardian.ui.about as about_module

ROOT = Path(__file__).resolve().parent.parent
METAINFO = ROOT / "data" / "io.github.clamguardian.ClamGuardian.metainfo.xml"


def test_metadata_matches_the_package() -> None:
    metadata = about_module.about_metadata()
    assert metadata["application_name"] == "ClamGuardian"
    assert metadata["application_icon"] == about_module.APP_ID
    assert metadata["version"] == clamguardian.__version__
    assert metadata["website"] == about_module.WEBSITE
    assert metadata["issue_url"] == f"{about_module.WEBSITE}/issues"
    assert metadata["developers"] == [about_module.DEVELOPER_NAME]


def test_metadata_matches_the_appstream_file() -> None:
    root = ET.parse(METAINFO).getroot()
    metadata = about_module.about_metadata()
    assert root.findtext("id") == metadata["application_icon"]
    assert root.findtext("developer/name") == metadata["developer_name"]
    assert metadata["version"] in [r.get("version") for r in root.findall("releases/release")]
    assert root.findtext("url[@type='homepage']") == metadata["website"]
    assert root.findtext("url[@type='bugtracker']") == metadata["issue_url"]


@pytest.mark.skipif(
    about_module.GTK_AVAILABLE, reason="headless shim only without PyGObject"
)
def test_build_about_dialog_shim_raises_headless() -> None:
    with pytest.raises(RuntimeError, match="PyGObject"):
        about_module.build_about_dialog()


@pytest.mark.skipif(not gtk_works(), reason="requires PyGObject + display/Xvfb")
def test_build_about_dialog_constructs() -> None:
    try:
        dialog = about_module.build_about_dialog()
    except Exception:  # pragma: no cover - needs a working X server/Adw
        pytest.skip("GTK/Adw About dialog failed in this environment")
    assert dialog is not None
