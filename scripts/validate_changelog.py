#!/usr/bin/env python3
"""Validate the structure and entry format of CHANGELOG.md's Unreleased section."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

CATEGORIES = ("Added", "Changed", "Deprecated", "Removed", "Fixed", "Security")
CATEGORY_INDEX = {name: index for index, name in enumerate(CATEGORIES)}
RELEASE_HEADING = re.compile(r"^## \[(?!Unreleased\])[^\]]+\].*$")
UNRELEASED_HEADING = "## [Unreleased]"
CATEGORY_HEADING = re.compile(r"^### (.+?)\s*$")
ENTRY = re.compile(r"^- \*\*[^*\n]+:\*\* .+\S\s*$")


def validate_changelog(content: str) -> list[str]:
    """Return all violations found in the Unreleased section."""
    lines = content.splitlines()
    positions = [i for i, line in enumerate(lines) if line.strip() == UNRELEASED_HEADING]
    if len(positions) != 1:
        return [f"expected exactly one '{UNRELEASED_HEADING}' heading; found {len(positions)}"]

    start = positions[0] + 1
    end = next(
        (i for i in range(start, len(lines)) if RELEASE_HEADING.match(lines[i])),
        len(lines),
    )
    errors: list[str] = []
    seen: set[str] = set()
    order: list[int] = []
    current: str | None = None
    has_entry = False
    has_category = False

    def finish_category(line_number: int) -> None:
        if current is not None and not has_entry:
            errors.append(f"line {line_number}: '{current}' section is empty")

    for offset, line in enumerate(lines[start:end]):
        number = start + offset + 1
        if line.startswith("### "):
            finish_category(number - 1)
            has_category = True
            category = CATEGORY_HEADING.match(line).group(1)
            if category not in CATEGORY_INDEX:
                errors.append(
                    f"line {number}: unsupported category '{category}'; "
                    f"allowed: {', '.join(CATEGORIES)}"
                )
                current, has_entry = None, False
                continue
            if category in seen:
                errors.append(f"line {number}: duplicate '{category}' heading")
            seen.add(category)
            order.append(CATEGORY_INDEX[category])
            current, has_entry = category, False
            continue
        if not line.strip():
            continue
        if current is None:
            errors.append(f"line {number}: content must belong to a valid category")
        elif line.startswith("- "):
            if ENTRY.match(line):
                has_entry = True
            else:
                errors.append(
                    f"line {number}: entries must use '- **Title:** description'"
                )
        elif line.startswith(("  ", "\t")) and has_entry:
            continue
        else:
            errors.append(f"line {number}: unexpected content; use a formatted bullet entry")

    finish_category(end)
    if not has_category:
        errors.append("Unreleased section must contain at least one category")
    if order != sorted(order):
        errors.append("category headings are out of order; expected: " + " > ".join(CATEGORIES))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("changelog", nargs="?", type=Path, default=Path("CHANGELOG.md"))
    path = parser.parse_args().changelog
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot read {path}: {exc}", file=sys.stderr)
        return 2
    errors = validate_changelog(content)
    if errors:
        print(f"CHANGELOG validation failed ({len(errors)} issue(s)):")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"CHANGELOG validation passed: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
