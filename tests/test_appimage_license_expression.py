"""Regression tests for semantic SPDX license-expression validation."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "packaging" / "appimage" / "license_expression.py"


def _module() -> Any:
    assert MODULE.is_file(), "semantic SPDX expression validator is not implemented"
    spec = importlib.util.spec_from_file_location("appimage_license_expression", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _catalog(module: Any) -> tuple[set[str], set[str]]:
    return module.load_catalog(
        ROOT / "packaging/appimage/licenses/spdx-3.29.0-licenses.json",
        ROOT / "packaging/appimage/licenses/spdx-3.29.0-exceptions.json",
    )


def test_spdx_catalog_is_pinned_and_contains_current_ids() -> None:
    module = _module()
    licenses, exceptions = _catalog(module)
    assert "Apache-2.0" in licenses
    assert "X11" in licenses
    assert "Autoconf-exception-3.0" in exceptions


@pytest.mark.parametrize(
    "expression", ["bsd-3-snowball", "hylafax", "unknown-license-id"]
)
def test_rejects_non_spdx_identifiers(expression: str) -> None:
    module = _module()
    licenses, exceptions = _catalog(module)
    with pytest.raises(ValueError, match="unknown SPDX license identifier"):
        module.normalize_expression(expression, licenses, exceptions)


def test_normalizes_known_identifier_case_to_canonical_form() -> None:
    module = _module()
    licenses, exceptions = _catalog(module)
    assert module.normalize_expression("x11", licenses, exceptions) == "X11"


def test_normalizes_valid_composite_expression_and_exception() -> None:
    module = _module()
    licenses, exceptions = _catalog(module)
    expression = (
        "(apache-2.0 AND mit) OR "
        "GPL-2.0-or-later WITH Autoconf-exception-3.0"
    )
    expected = (
        "(Apache-2.0 AND MIT) OR "
        "GPL-2.0-or-later WITH Autoconf-exception-3.0"
    )
    assert module.normalize_expression(expression, licenses, exceptions) == expected


def test_rejects_malformed_expression_and_invalid_with_operand() -> None:
    module = _module()
    licenses, exceptions = _catalog(module)
    expressions = ("MIT AND", "MIT WITH Apache-2.0", "MIT OR (BSD-3-Clause")
    for expression in expressions:
        with pytest.raises(ValueError):
            module.normalize_expression(expression, licenses, exceptions)


def test_license_ref_requires_matching_non_placeholder_extracted_text() -> None:
    module = _module()
    licenses, exceptions = _catalog(module)
    valid = {"LicenseRef-Hylafax": "Hylafax redistribution terms ..."}
    assert module.normalize_expression(
        "LicenseRef-Hylafax", licenses, exceptions, valid
    ) == "LicenseRef-Hylafax"
    for text in ("NOASSERTION", "", None):
        invalid = {"LicenseRef-Hylafax": text}
        with pytest.raises(ValueError, match="LicenseRef.*extracted text"):
            module.normalize_expression(
                "LicenseRef-Hylafax", licenses, exceptions, invalid
            )


def test_spdx_document_rejects_license_ref_with_placeholder_text() -> None:
    module = _module()
    licenses, exceptions = _catalog(module)
    document = {
        "packages": [{"licenseDeclared": "LicenseRef-Apache-2.0"}],
        "hasExtractedLicensingInfos": [{
            "licenseId": "LicenseRef-Apache-2.0",
            "extractedText": "NOASSERTION",
        }],
    }
    with pytest.raises(ValueError, match="LicenseRef.*extracted text"):
        module.validate_spdx_document(document, licenses, exceptions)


def test_spdx_file_license_field_uses_spdx_23_plural_name() -> None:
    module = _module()
    licenses, exceptions = _catalog(module)
    document = {
        "files": [{
            "licenseInfoInFiles": ["x11"],
        }],
    }
    module.normalize_spdx_document(document, licenses, exceptions, {"licenses": []})
    assert document["files"][0]["licenseInfoInFiles"] == ["X11"]
    assert "licenseInfoInFile" not in document["files"][0]


def test_cyclonedx_normalizes_spdx_names_and_expressions() -> None:
    module = _module()
    licenses, exceptions = _catalog(module)
    licenses_data = json.loads(
        (ROOT / "packaging/appimage/licenses/spdx-3.29.0-licenses.json").read_text(
            encoding="utf-8"
        )
    )
    document = {
        "components": [
            {
                "name": "aiosignal",
                "licenses": [{"license": {"name": "Apache 2.0"}}],
            },
            {
                "name": "aiohttp",
                "licenses": [{"expression": "apache-2.0 AND mit"}],
            },
        ],
    }
    module.normalize_cyclonedx_document(
        document, licenses, exceptions, licenses_data
    )
    assert document["components"][0]["licenses"][0]["license"] == {
        "id": "Apache-2.0"
    }
    assert document["components"][1]["licenses"][0]["expression"] == (
        "Apache-2.0 AND MIT"
    )


def test_cyclonedx_custom_license_requires_actual_text() -> None:
    module = _module()
    licenses, exceptions = _catalog(module)
    licenses_data = json.loads(
        (ROOT / "packaging/appimage/licenses/spdx-3.29.0-licenses.json").read_text(
            encoding="utf-8"
        )
    )
    invalid = {
        "components": [{
            "name": "custom",
            "licenses": [{"license": {"name": "Hylafax"}}],
        }],
    }
    with pytest.raises(ValueError, match="custom license.*attached license text"):
        module.normalize_cyclonedx_document(
            invalid, licenses, exceptions, licenses_data
        )
    valid = {
        "components": [{
            "name": "custom",
            "licenses": [{
                "license": {
                    "name": "Hylafax",
                    "text": {"content": "Hylafax license full text"},
                }
            }],
        }],
    }
    module.normalize_cyclonedx_document(
        valid, licenses, exceptions, licenses_data
    )
    assert valid["components"][0]["licenses"][0]["license"]["text"]["content"] == (
        "Hylafax license full text"
    )


def test_spdx_catalog_rejects_modified_pinned_data(tmp_path: Path) -> None:
    module = _module()
    license_source = ROOT / "packaging/appimage/licenses/spdx-3.29.0-licenses.json"
    exception_source = ROOT / "packaging/appimage/licenses/spdx-3.29.0-exceptions.json"
    altered = tmp_path / "spdx-3.29.0-licenses.json"
    altered.write_text(
        license_source.read_text(encoding="utf-8").replace(
            '"licenseListVersion": "3.29.0"',
            '"licenseListVersion": "3.29.0-altered"',
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="pinned SPDX catalog hash mismatch"):
        module.load_catalog(altered, exception_source)


@pytest.mark.parametrize(
    "expression",
    ["NOASSERTION OR MIT", "NONE OR GPL-3.0-only", "MIT OR NOASSERTION"],
)
def test_spdx_special_identifiers_are_rejected_with_or(
    expression: str,
) -> None:
    module = _module()
    licenses, exceptions = _catalog(module)
    with pytest.raises(ValueError, match="NONE or NOASSERTION.*OR"):
        module.normalize_expression(expression, licenses, exceptions)


def test_spdx_special_identifiers_remain_allowed_with_and() -> None:
    module = _module()
    licenses, exceptions = _catalog(module)
    assert module.normalize_expression(
        "NOASSERTION AND MIT", licenses, exceptions
    ) == "NOASSERTION AND MIT"
