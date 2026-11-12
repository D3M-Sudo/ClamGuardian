from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "validate_changelog.py"
SPEC = importlib.util.spec_from_file_location("validate_changelog", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
validate_changelog = MODULE.validate_changelog

VALID = """# Changelog

## [Unreleased]

### Added

- **New capability:** useful description.

### Fixed

- **Corrected behavior:** useful description.

## [1.0.0] — 2026-01-01

### Tests

- Historical content is outside the validation scope.
"""


def test_accepts_valid_unreleased_and_ignores_historical_sections() -> None:
    assert validate_changelog(VALID) == []


def test_rejects_duplicate_category() -> None:
    content = VALID.replace(
        "### Fixed\n\n- **Corrected behavior:** useful description.",
        "### Added\n\n- **Another capability:** useful description.\n\n"
        "### Fixed\n\n- **Corrected behavior:** useful description.",
    )
    assert any("duplicate 'Added'" in error for error in validate_changelog(content))


def test_rejects_tests_category() -> None:
    content = VALID.replace("### Fixed", "### Tests")
    assert any("unsupported category 'Tests'" in error for error in validate_changelog(content))


def test_rejects_out_of_order_categories() -> None:
    content = VALID.replace(
        "### Added\n\n- **New capability:** useful description.\n\n"
        "### Fixed\n\n- **Corrected behavior:** useful description.",
        "### Fixed\n\n- **Corrected behavior:** useful description.\n\n"
        "### Added\n\n- **New capability:** useful description.",
    )
    assert any("out of order" in error for error in validate_changelog(content))


def test_rejects_empty_category() -> None:
    content = VALID.replace(
        "### Added\n\n- **New capability:** useful description.", "### Added"
    )
    assert any("'Added' section is empty" in error for error in validate_changelog(content))


def test_rejects_malformed_entry() -> None:
    content = VALID.replace(
        "- **New capability:** useful description.",
        "- New capability: useful description.",
    )
    assert any("entries must use" in error for error in validate_changelog(content))


def test_requires_exactly_one_unreleased_heading() -> None:
    content = VALID.replace("## [Unreleased]", "## [1.0.1]")
    assert any("expected exactly one" in error for error in validate_changelog(content))
