"""Regression tests for semantic SPDX license-expression validation."""

from __future__ import annotations

import importlib.util
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
