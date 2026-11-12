#!/usr/bin/env python3
"""Verify detached AppImage SBOM evidence against the final artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SUPPORTED_ARCHITECTURES = {"x86_64", "aarch64"}


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object in {path}")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()




def _normalized_name(value: Any) -> str:
    return str(value).casefold().replace("_", "-").replace(".", "-")


def _verify_component_records(
    expected_components: list[dict[str, Any]],
    spdx_packages: list[dict[str, Any]],
    cdx_components: list[dict[str, Any]],
    inventory_name: str,
) -> None:
    for expected in expected_components:
        name = str(expected.get("name", ""))
        normalized = _normalized_name(name)
        version = expected.get("version")
        spdx_match = next((
            item for item in spdx_packages
            if _normalized_name(item.get("name", "")) == normalized
            and (version is None or str(item.get("versionInfo", "")) == str(version))
        ), None)
        cdx_match = next((
            item for item in cdx_components
            if _normalized_name(item.get("name", "")) == normalized
            and (version is None or str(item.get("version", "")) == str(version))
        ), None)
        if spdx_match is None or cdx_match is None:
            raise ValueError(
                f"{inventory_name} component missing or version mismatch in aggregate SBOMs: "
                f"{name}@{version}"
            )
        license_expression = expected.get("license", "NOASSERTION")
        if license_expression and license_expression != "NOASSERTION":
            if spdx_match.get("licenseDeclared") != license_expression:
                raise ValueError(
                    f"SPDX declared license mismatch for {name}: "
                    f"expected {license_expression}, got {spdx_match.get('licenseDeclared')}"
                )
            cdx_expressions = set()
            for entry in cdx_match.get("licenses", []):
                if entry.get("expression"):
                    cdx_expressions.add(entry["expression"])
                elif isinstance(entry.get("license"), dict):
                    license_data = entry["license"]
                    cdx_expressions.add(license_data.get("id") or license_data.get("name"))
            if license_expression not in cdx_expressions:
                raise ValueError(
                    f"CycloneDX license mismatch for {name}: expected {license_expression}, "
                    f"got {sorted(str(item) for item in cdx_expressions)}"
                )


def verify(
    artifact: Path, architecture: str, sbom_dir: Path, runtime_path: Path,
    native_inventory_path: Path | None = None,
    appdir_inventory_path: Path | None = None,
) -> None:
    if architecture not in SUPPORTED_ARCHITECTURES:
        raise ValueError(f"unsupported architecture: {architecture}")
    if not artifact.is_file() or artifact.stat().st_size == 0:
        raise ValueError(f"AppImage artifact is missing or empty: {artifact}")
    digest = _sha256(artifact)
    manifest = _load(sbom_dir / f"artifact-{architecture}.json")
    if manifest.get("architecture") != architecture:
        raise ValueError("artifact manifest architecture mismatch")
    if manifest.get("sha256") != digest:
        raise ValueError("artifact SHA-256 does not match SBOM manifest")
    if manifest.get("artifact") != artifact.name:
        raise ValueError("artifact filename does not match SBOM manifest")

    appdir_spdx = _load(sbom_dir / "appdir.spdx.json")
    aggregate_spdx = _load(sbom_dir / f"aggregate-{architecture}.spdx.json")
    appdir_cdx = _load(sbom_dir / "appdir.cdx.json")
    aggregate_cdx = _load(sbom_dir / f"aggregate-{architecture}.cdx.json")
    if (
        appdir_spdx.get("spdxVersion") != "SPDX-2.3"
        or aggregate_spdx.get("spdxVersion") != "SPDX-2.3"
    ):
        raise ValueError("SPDX documents must use SPDX-2.3")
    for document in (appdir_cdx, aggregate_cdx):
        if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.6":
            raise ValueError("CycloneDX documents must use version 1.6")

    runtime = _load(runtime_path)
    artifacts = runtime.get("runtime", {}).get("artifacts", {})
    if not re.fullmatch(r"[0-9a-f]{64}", str(artifacts.get(architecture, ""))):
        raise ValueError(f"runtime inventory has no valid hash for {architecture}")
    spdx_packages = aggregate_spdx.get("packages", [])
    cdx_components = aggregate_cdx.get("components", [])
    runtime_components = [
        item for item in runtime.get("components", [])
        if item.get("architecture") in {"all", "both", architecture}
    ]
    _verify_component_records(runtime_components, spdx_packages, cdx_components, "runtime")
    if appdir_inventory_path is not None:
        appdir_inventory = _load(appdir_inventory_path)
        appdir_components = appdir_inventory.get("components", [])
        if not isinstance(appdir_components, list):
            raise ValueError("AppDir component inventory is malformed")
        _verify_component_records(appdir_components, spdx_packages, cdx_components, "AppDir")
    if native_inventory_path is not None:
        native_inventory = _load(native_inventory_path)
        if native_inventory.get("architecture") != architecture:
            raise ValueError("native package inventory architecture mismatch")
        if native_inventory.get("missing_copyright_packages"):
            raise ValueError("native package inventory reports missing copyright documents")
        if native_inventory.get("missing_embedded_component_evidence"):
            raise ValueError("native package inventory reports missing embedded component evidence")
        native_components = []
        for package in native_inventory.get("packages", []):
            native_components.append({
                "name": str(package.get("package", "")).split(":", 1)[0],
                "version": package.get("version"),
                "license": package.get("license", "NOASSERTION"),
            })
        native_components.extend(native_inventory.get("embedded_components", []))
        _verify_component_records(native_components, spdx_packages, cdx_components, "native")
    print(f"Verified {architecture} AppImage SBOMs against SHA-256 {digest}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--architecture", required=True, choices=sorted(SUPPORTED_ARCHITECTURES))
    parser.add_argument("--sbom-dir", type=Path, required=True)
    parser.add_argument("--runtime-inventory", type=Path, required=True)
    parser.add_argument("--native-inventory", type=Path, required=True)
    parser.add_argument("--appdir-inventory", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        verify(
            args.artifact, args.architecture, args.sbom_dir,
            args.runtime_inventory, args.native_inventory, args.appdir_inventory,
        )
    except (OSError, ValueError) as exc:
        print(f"SBOM verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
