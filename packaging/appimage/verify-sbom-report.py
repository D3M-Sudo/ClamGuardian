#!/usr/bin/env python3
"""Fail-closed validation of the semantic and schema SBOM validation report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

EXPECTED_SEMANTIC_VALIDATION = {
    "spdx_license_expressions": "passed",
    "cyclonedx_license_declarations": "passed",
}
EXPECTED_DOCUMENTS = {
    "appdir-spdx",
    "aggregate-spdx",
    "appdir-cyclonedx",
    "aggregate-cyclonedx",
}


def validate_report(path: Path) -> dict[str, Any]:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read SBOM validation report {path}: {exc}") from exc
    if not isinstance(report, dict):
        raise ValueError("SBOM validation report must be a JSON object")
    if report.get("schema_validation") != "passed":
        raise ValueError("SBOM schema validation did not pass")
    if report.get("semantic_validation") != EXPECTED_SEMANTIC_VALIDATION:
        raise ValueError("SBOM semantic license validation is missing or unsuccessful")
    documents = report.get("documents")
    if not isinstance(documents, dict) or set(documents) != EXPECTED_DOCUMENTS:
        raise ValueError("SBOM validation report does not contain exactly four required documents")
    for name, result in documents.items():
        if not isinstance(result, dict) or result.get("status") != "passed":
            raise ValueError(f"SBOM validation failed for document: {name}")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args(argv)
    try:
        report = validate_report(args.report)
    except ValueError as exc:
        print(f"SBOM report validation failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"Verified {len(report['documents'])} SBOM documents: "
        "SPDX/CycloneDX semantics and schemas passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
