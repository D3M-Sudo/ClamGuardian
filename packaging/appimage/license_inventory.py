#!/usr/bin/env python3
"""Validate curated AppImage component and Type 2 runtime inventories."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from functools import lru_cache
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from license_expression import load_catalog, normalize_expression

_COMPONENT_FIELDS = {
    "id",
    "name",
    "version",
    "version_status",
    "architecture",
    "license",
    "license_status",
    "source",
    "source_package",
    "artifact_paths",
    "source_paths",
    "evidence_paths",
    "detection_method",
    "verification_status",
}
_VERSION_STATES = {"verified", "declared", "unknown"}
_LICENSE_STATES = {"verified", "declared", "unknown"}
_VERIFICATION_STATES = {"verified", "partial", "unverified"}
_ARCHITECTURES = {"all", "both", "x86_64", "aarch64"}
_SPDX_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")
_SPDX_OPERATORS = {"AND", "OR", "WITH", "(", ")"}


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    message: str
    component_id: str | None = None


@lru_cache(maxsize=1)
def _spdx_catalog() -> tuple[set[str], set[str]]:
    base = Path(__file__).resolve().parent / "licenses"
    return load_catalog(base / "spdx-3.29.0-licenses.json", base / "spdx-3.29.0-exceptions.json")


def _valid_license_expression(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    if value == "NOASSERTION":
        return True
    if value.lower() in {"unknown", "unclassified", "n/a", "tbd"}:
        return False
    tokens = value.replace("(", " ( ").replace(")", " ) ").split()
    if not tokens or not all(
        token in _SPDX_OPERATORS or _SPDX_TOKEN.fullmatch(token) is not None
        for token in tokens
    ):
        return False
    try:
        licenses, exceptions = _spdx_catalog()
        normalize_expression(value, licenses, exceptions)
    except (OSError, ValueError):
        return False
    return True


def _validate_component(component: Any, inventory_name: str) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if not isinstance(component, dict):
        return [
            ValidationIssue(
                "COMPONENT_NOT_OBJECT",
                f"{inventory_name} component must be an object",
            )
        ]

    component_id = component.get("id") if isinstance(component.get("id"), str) else None
    missing = sorted(_COMPONENT_FIELDS - component.keys())
    if missing:
        issues.append(
            ValidationIssue(
                "COMPONENT_REQUIRED_FIELD",
                f"Missing required fields: {', '.join(missing)}",
                component_id,
            )
        )

    for field in ("id", "name", "source", "detection_method"):
        value = component.get(field)
        if not isinstance(value, str) or not value.strip():
            issues.append(
                ValidationIssue(
                    "COMPONENT_INVALID_FIELD",
                    f"{field} must be a non-empty string",
                    component_id,
                )
            )

    version = component.get("version")
    version_status = component.get("version_status")
    if version == "":
        issues.append(
            ValidationIssue(
                "EMPTY_VERSION",
                "Empty version is not an unknown version",
                component_id,
            )
        )
    elif version is None and version_status != "unknown":
        issues.append(
            ValidationIssue(
                "VERSION_STATUS_MISMATCH",
                "A null version must have version_status='unknown'",
                component_id,
            )
        )
    elif isinstance(version, str) and version.strip() and version_status == "unknown":
        issues.append(
            ValidationIssue(
                "VERSION_STATUS_MISMATCH",
                "A known version cannot have version_status='unknown'",
                component_id,
            )
        )
    elif not (version is None or isinstance(version, str)):
        issues.append(
            ValidationIssue(
                "INVALID_VERSION", "version must be a string or null", component_id
            )
        )
    if version_status not in _VERSION_STATES:
        issues.append(
            ValidationIssue("INVALID_VERSION_STATUS", "Invalid version_status", component_id)
        )

    license_value = component.get("license")
    license_status = component.get("license_status")
    if not _valid_license_expression(license_value):
        issues.append(
            ValidationIssue(
                "UNCLASSIFIED_LICENSE",
                "license must be an SPDX expression or NOASSERTION; "
                "do not use free-text placeholders",
                component_id,
            )
        )
    if license_status not in _LICENSE_STATES:
        issues.append(
            ValidationIssue("INVALID_LICENSE_STATUS", "Invalid license_status", component_id)
        )
    if license_value == "NOASSERTION" and license_status != "unknown":
        issues.append(
            ValidationIssue(
                "LICENSE_STATUS_MISMATCH",
                "NOASSERTION requires license_status='unknown'",
                component_id,
            )
        )

    if component.get("architecture") not in _ARCHITECTURES:
        issues.append(
            ValidationIssue("INVALID_ARCHITECTURE", "Invalid architecture scope", component_id)
        )
    if component.get("verification_status") not in _VERIFICATION_STATES:
        issues.append(
            ValidationIssue(
                "INVALID_VERIFICATION_STATUS", "Invalid verification_status", component_id
            )
        )
    for field in ("artifact_paths", "source_paths", "evidence_paths"):
        value = component.get(field)
        if not isinstance(value, list) or not value or any(
            not isinstance(item, str) or not item.strip() for item in value
        ):
            issues.append(
                ValidationIssue(
                    "INVALID_PATH_LIST",
                    f"{field} must be a non-empty list of paths",
                    component_id,
                )
            )
    source_package = component.get("source_package")
    if source_package is not None and (
        not isinstance(source_package, str) or not source_package.strip()
    ):
        issues.append(
            ValidationIssue(
                "INVALID_SOURCE_PACKAGE",
                "source_package must be a non-empty string or null",
                component_id,
            )
        )
    return issues


def validate_inventories(appdir: Any, runtime: Any) -> list[ValidationIssue]:
    """Return all structural and cross-inventory issues without mutating inputs."""
    issues: list[ValidationIssue] = []
    for label, inventory in (("AppDir", appdir), ("runtime", runtime)):
        if not isinstance(inventory, dict) or inventory.get("schema_version") != 1:
            issues.append(
                ValidationIssue(
                    "INVALID_INVENTORY_HEADER",
                    f"{label} inventory requires schema_version=1",
                )
            )
        if not isinstance(inventory, dict) or not isinstance(inventory.get("components"), list):
            issues.append(
                ValidationIssue(
                    "INVALID_COMPONENTS",
                    f"{label} inventory requires a components list",
                )
            )

    if any(issue.code in {"INVALID_INVENTORY_HEADER", "INVALID_COMPONENTS"} for issue in issues):
        return issues

    all_components = [("AppDir", item) for item in appdir["components"]]
    all_components.extend(("runtime", item) for item in runtime["components"])
    seen: set[str] = set()
    for label, component in all_components:
        issues.extend(_validate_component(component, label))
        if isinstance(component, dict) and isinstance(component.get("id"), str):
            component_id = component["id"]
            if component_id in seen:
                issues.append(
                    ValidationIssue(
                        "DUPLICATE_COMPONENT_ID",
                        "Component IDs must be globally unique",
                        component_id,
                    )
                )
            seen.add(component_id)

    runtime_meta = runtime.get("runtime")
    if not isinstance(runtime_meta, dict):
        issues.append(
            ValidationIssue(
                "INVALID_RUNTIME_METADATA", "Runtime metadata object is required"
            )
        )
    else:
        artifacts = runtime_meta.get("artifacts")
        if not isinstance(artifacts, dict):
            issues.append(
                ValidationIssue(
                    "RUNTIME_ARTIFACT_HASH_MISSING",
                    "Runtime artifact hashes are required",
                )
            )
        else:
            for architecture in ("x86_64", "aarch64"):
                digest = artifacts.get(architecture)
                if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                    issues.append(
                        ValidationIssue(
                            "RUNTIME_ARTIFACT_HASH_MISSING",
                            f"Missing or invalid SHA-256 for {architecture}",
                        )
                    )

    runtime_names = {
        item.get("name", "").casefold()
        for item in runtime.get("components", [])
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    if "mimalloc" not in runtime_names:
        issues.append(
            ValidationIssue(
                "RUNTIME_MISSING_MIMALLOC",
                "Type 2 runtime inventory must include mimalloc",
            )
        )
    return issues


def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("appdir_inventory", type=Path)
    parser.add_argument("runtime_inventory", type=Path)
    args = parser.parse_args(argv)
    try:
        appdir = _load_json(args.appdir_inventory)
        runtime = _load_json(args.runtime_inventory)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"inventory load failed: {exc}", file=sys.stderr)
        return 2
    issues = validate_inventories(appdir, runtime)
    for issue in issues:
        subject = f" [{issue.component_id}]" if issue.component_id else ""
        print(f"{issue.code}{subject}: {issue.message}", file=sys.stderr)
    if issues:
        return 1
    print("AppDir and Type 2 runtime inventories are structurally valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
