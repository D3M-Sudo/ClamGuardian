#!/usr/bin/env python3
"""Validate AppDir and aggregate SBOM JSON documents against official schemas."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def validate_documents(sbom_dir: Path, schema_dir: Path, architecture: str) -> dict[str, Any]:
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - CI installs the pinned validator
        raise RuntimeError("jsonschema==4.26.0 is required for SBOM schema validation") from exc

    schemas = {
        "spdx": json.loads((schema_dir / "spdx-schema-2.3.json").read_text(encoding="utf-8")),
        "cyclonedx": json.loads(
            (schema_dir / "cyclonedx-bom-1.6.schema.json").read_text(encoding="utf-8")
        ),
    }
    for schema in schemas.values():
        jsonschema.Draft7Validator.check_schema(schema)

    documents = {
        "appdir-spdx": (sbom_dir / "appdir.spdx.json", schemas["spdx"]),
        "aggregate-spdx": (sbom_dir / f"aggregate-{architecture}.spdx.json", schemas["spdx"]),
        "appdir-cyclonedx": (sbom_dir / "appdir.cdx.json", schemas["cyclonedx"]),
        "aggregate-cyclonedx": (
            sbom_dir / f"aggregate-{architecture}.cdx.json",
            schemas["cyclonedx"],
        ),
    }
    results: dict[str, Any] = {}
    for label, (path, schema) in documents.items():
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read {label} document {path}: {exc}") from exc
        validator = jsonschema.Draft7Validator(schema, format_checker=jsonschema.FormatChecker())
        errors = sorted(
            validator.iter_errors(document),
            key=lambda error: list(error.absolute_path),
        )
        if errors:
            first = errors[0]
            location = "/".join(str(part) for part in first.absolute_path) or "<root>"
            raise ValueError(f"{label} schema validation failed at {location}: {first.message}")
        results[label] = {"status": "passed", "file": path.name}

    report = {
        "schema_validation": "passed",
        "architecture": architecture,
        "schemas": {
            "spdx": "SPDX 2.3 (spdx/spdx-spec v2.3)",
            "cyclonedx": (
                "CycloneDX 1.6 "
                "(CycloneDX/specification@6470e34ef83f915868ece48934cff52e10c9eb49)"
            ),
        },
        "documents": results,
    }
    (sbom_dir / f"schema-validation-{architecture}.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom-dir", type=Path, required=True)
    parser.add_argument("--schema-dir", type=Path, required=True)
    parser.add_argument("--architecture", choices=("x86_64", "aarch64"), required=True)
    args = parser.parse_args(argv)
    try:
        report = validate_documents(args.sbom_dir, args.schema_dir, args.architecture)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"SBOM schema validation failed: {exc}", file=sys.stderr)
        return 1
    print(f"Validated {len(report['documents'])} SBOM documents against official schemas")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
