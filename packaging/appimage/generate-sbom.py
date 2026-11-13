#!/usr/bin/env python3
"""Generate AppDir SBOMs and aggregate them with the Type 2 runtime inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SUPPORTED_ARCHITECTURES = {"x86_64", "aarch64"}


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read JSON document {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON document must contain an object: {path}")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_spdx_id(component_id: str, used: set[str]) -> str:
    stem = re.sub(r"[^A-Za-z0-9.-]+", "-", component_id).strip("-.") or "runtime-component"
    candidate = f"SPDXRef-{stem}"
    suffix = 2
    while candidate in used:
        candidate = f"SPDXRef-{stem}-{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def _component_properties(component: dict[str, Any]) -> list[dict[str, str]]:
    properties: list[dict[str, str]] = []
    for field in (
        "version_status", "license_status", "source", "source_package",
        "binary_package", "apk_revision", "detection_method",
        "verification_status", "architecture",
    ):
        value = component.get(field)
        if value is not None:
            properties.append({"name": f"clamguardian:{field}", "value": str(value)})
    for field in ("artifact_paths", "source_paths", "evidence_paths"):
        for value in component.get(field, []):
            properties.append({"name": f"clamguardian:{field}", "value": str(value)})
    return properties


def _runtime_components(runtime: dict[str, Any], architecture: str) -> list[dict[str, Any]]:
    if architecture not in SUPPORTED_ARCHITECTURES:
        raise ValueError(f"unsupported architecture: {architecture}")
    metadata = runtime.get("runtime")
    artifacts = metadata.get("artifacts") if isinstance(metadata, dict) else None
    if not isinstance(artifacts, dict) or not re.fullmatch(
        r"[0-9a-f]{64}", str(artifacts.get(architecture, ""))
    ):
        raise ValueError(f"runtime inventory has no valid runtime SHA-256 for {architecture}")
    components = runtime.get("components")
    if not isinstance(components, list):
        raise ValueError("runtime inventory must contain a components list")
    selected = [
        item for item in components
        if isinstance(item, dict) and item.get("architecture") in {"all", "both", architecture}
    ]
    if not selected:
        raise ValueError(f"runtime inventory has no components for {architecture}")
    if not any(item.get("name", "").casefold() == "mimalloc" for item in selected):
        raise ValueError("runtime inventory is missing mimalloc")
    return selected


def _native_inventory_components(
    native_inventory: dict[str, Any], architecture: str
) -> list[dict[str, Any]]:
    if native_inventory.get("architecture") not in {architecture, "unknown"}:
        raise ValueError("native package inventory architecture mismatch")
    packages = native_inventory.get("packages")
    if not isinstance(packages, list):
        raise ValueError("native package inventory must contain a packages list")
    if native_inventory.get("missing_copyright_packages"):
        raise ValueError("native package inventory reports missing copyright documents")
    if native_inventory.get("missing_embedded_component_evidence"):
        raise ValueError("native package inventory reports missing embedded component evidence")
    components = []
    for package in packages:
        if (
            not isinstance(package, dict)
            or not package.get("package")
            or not package.get("version")
        ):
            raise ValueError("native package inventory contains an incomplete package record")
        package_name = str(package["package"]).split(":", 1)[0]
        evidence = package.get("copyright_artifact_path")
        if not evidence:
            raise ValueError(f"native package has no copyright evidence path: {package_name}")
        components.append({
            "id": f"debian-{package_name}",
            "name": package_name,
            "version": str(package["version"]),
            "version_status": "verified",
            "architecture": architecture,
            "license": package.get("license", "NOASSERTION"),
            "license_status": package.get("license_status", "unknown"),
            "source": "Installed Debian package database and package copyright file",
            "source_package": package.get("source_package"),
            "artifact_paths": list(package.get("artifact_paths", [])),
            "source_paths": [f"/var/lib/dpkg/info/{package['package']}.list"],
            "evidence_paths": [str(evidence)],
            "detection_method": "dpkg-file-list",
            "verification_status": "partial",
        })
    for embedded in native_inventory.get("embedded_components", []):
        if not isinstance(embedded, dict) or not embedded.get("name"):
            raise ValueError("native inventory contains an invalid embedded component")
        components.append(embedded)
    return components


def aggregate_sboms(
    appdir_spdx_path: Path,
    appdir_cyclonedx_path: Path,
    runtime_inventory_path: Path,
    output_dir: Path,
    architecture: str,
    artifact_path: Path,
    native_inventory_path: Path | None = None,
) -> dict[str, Path]:
    """Merge curated runtime components into Syft AppDir SBOMs.

    The final AppImage digest is recorded in a detached manifest to avoid a
    self-referential digest inside the AppImage itself.
    """
    if architecture not in SUPPORTED_ARCHITECTURES:
        raise ValueError(f"unsupported architecture: {architecture}")
    if not artifact_path.is_file() or artifact_path.stat().st_size == 0:
        raise ValueError(f"AppImage artifact is missing or empty: {artifact_path}")

    spdx = _read_json(appdir_spdx_path)
    cdx = _read_json(appdir_cyclonedx_path)
    runtime = _read_json(runtime_inventory_path)
    if spdx.get("spdxVersion") != "SPDX-2.3":
        raise ValueError("AppDir SPDX document must use SPDX-2.3")
    if cdx.get("bomFormat") != "CycloneDX" or cdx.get("specVersion") != "1.6":
        raise ValueError("AppDir CycloneDX document must use version 1.6")
    if (
        not isinstance(spdx.get("packages"), list)
        or not isinstance(spdx.get("relationships"), list)
    ):
        raise ValueError("AppDir SPDX document is missing packages or relationships")
    if not isinstance(cdx.get("components"), list) or not isinstance(cdx.get("dependencies"), list):
        raise ValueError("AppDir CycloneDX document is missing components or dependencies")

    runtime_components = _runtime_components(runtime, architecture)
    native_components = (
        _native_inventory_components(_read_json(native_inventory_path), architecture)
        if native_inventory_path is not None else []
    )
    curated_components = runtime_components + native_components
    output_dir.mkdir(parents=True, exist_ok=True)
    digest = _sha256(artifact_path)
    created = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    aggregate_spdx = dict(spdx)
    aggregate_spdx["packages"] = list(spdx["packages"])
    aggregate_spdx["relationships"] = list(spdx["relationships"])
    used_spdx_ids = {
        item.get("SPDXID")
        for key in ("packages", "files", "snippets")
        for item in aggregate_spdx.get(key, []) if isinstance(item, dict)
    }
    for component in curated_components:
        existing_package = next((
            item for item in aggregate_spdx["packages"]
            if isinstance(item, dict)
            and item.get("name") == component["name"]
            and item.get("versionInfo") == component.get("version")
        ), None)
        if existing_package is not None:
            expected_license = component.get("license") or "NOASSERTION"
            current_license = existing_package.get("licenseDeclared") or "NOASSERTION"
            if expected_license != "NOASSERTION":
                if current_license not in {"NOASSERTION", expected_license}:
                    raise ValueError(
                        f"conflicting SPDX license evidence for {component['name']}: "
                        f"Syft={current_license}, curated={expected_license}"
                    )
                existing_package["licenseDeclared"] = expected_license
            source_info = str(component.get("source", "Curated inventory"))
            existing_package["sourceInfo"] = "; ".join(
                filter(None, (existing_package.get("sourceInfo"), source_info))
            )
            continue
        spdx_id = _safe_spdx_id(str(component["id"]), used_spdx_ids)
        version = component.get("version")
        package: dict[str, Any] = {
            "name": component["name"],
            "SPDXID": spdx_id,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": component.get("license") or "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "sourceInfo": str(component.get("source", "Runtime inventory")),
            "externalRefs": [],
        }
        if version:
            package["versionInfo"] = str(version)
        aggregate_spdx["packages"].append(package)
        aggregate_spdx["relationships"].append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": spdx_id,
        })
    aggregate_spdx["name"] = f"ClamGuardian AppImage {architecture}"
    aggregate_spdx["documentNamespace"] = (
        f"https://spdx.org/spdxdocs/ClamGuardian-AppImage-{architecture}-{digest}"
    )
    aggregate_spdx["comment"] = (
        f"Aggregate AppImage SBOM for {architecture}; AppDir inventory generated by Syft "
        f"and Type 2 runtime components added from the curated runtime inventory. "
        f"Final AppImage SHA-256: {digest}."
    )
    aggregate_spdx.setdefault("creationInfo", {})["created"] = created

    aggregate_cdx = dict(cdx)
    aggregate_cdx["components"] = list(cdx["components"])
    aggregate_cdx["dependencies"] = [dict(item) for item in cdx["dependencies"]]
    existing_refs = {
        item.get("bom-ref") for item in aggregate_cdx["components"] if isinstance(item, dict)
    }
    curated_refs: list[str] = []
    for component in curated_components:
        existing_component = next((
            item for item in aggregate_cdx["components"]
            if isinstance(item, dict)
            and item.get("name") == component["name"]
            and item.get("version") == component.get("version")
        ), None)
        if existing_component is not None:
            expected_license = component.get("license") or "NOASSERTION"
            if expected_license != "NOASSERTION":
                existing_expressions = set()
                for entry in existing_component.get("licenses", []):
                    if entry.get("expression"):
                        existing_expressions.add(entry["expression"])
                    elif isinstance(entry.get("license"), dict):
                        license_data = entry["license"]
                        existing_expressions.add(license_data.get("id") or license_data.get("name"))
                if existing_expressions and expected_license not in existing_expressions:
                    raise ValueError(
                        f"conflicting CycloneDX license evidence for {component['name']}: "
                        f"Syft={sorted(str(item) for item in existing_expressions)}, "
                        f"curated={expected_license}"
                    )
                if not existing_expressions:
                    existing_component["licenses"] = [{"expression": expected_license}]
            existing_component.setdefault("properties", []).extend(_component_properties(component))
            continue
        prefix = "runtime" if component in runtime_components else "debian"
        bom_ref = f"urn:clamguardian:{prefix}:{component['id']}"
        if bom_ref in existing_refs:
            raise ValueError(f"duplicate CycloneDX bom-ref: {bom_ref}")
        existing_refs.add(bom_ref)
        curated_refs.append(bom_ref)
        item: dict[str, Any] = {
            "type": "library",
            "name": str(component["name"]),
            "bom-ref": bom_ref,
            "properties": _component_properties(component),
        }
        if component.get("version"):
            item["version"] = str(component["version"])
        license_value = component.get("license")
        if license_value and license_value != "NOASSERTION":
            item["licenses"] = [{"expression": str(license_value)}]
        aggregate_cdx["components"].append(item)

    metadata = aggregate_cdx.setdefault("metadata", {})
    if not isinstance(metadata.get("component"), dict) or not metadata["component"].get("bom-ref"):
        raise ValueError(
            "AppDir CycloneDX document requires a metadata root component with bom-ref"
        )
    properties = metadata.setdefault("properties", [])
    properties.extend([
        {"name": "clamguardian:architecture", "value": architecture},
        {"name": "clamguardian:artifact-sha256", "value": digest},
        {"name": "clamguardian:sbom-scope", "value": "AppDir plus AppImage Type 2 runtime"},
        {
            "name": "clamguardian:runtime-release",
            "value": str(runtime.get("runtime", {}).get("release", "unknown")),
        },
    ])
    dependencies = aggregate_cdx["dependencies"]
    root_ref = metadata.get("component", {}).get("bom-ref")
    if root_ref:
        root_dependency = next((item for item in dependencies if item.get("ref") == root_ref), None)
        if root_dependency is None:
            root_dependency = {"ref": root_ref, "dependsOn": []}
            dependencies.append(root_dependency)
        root_dependency["dependsOn"] = sorted(
            set(root_dependency.get("dependsOn", [])) | set(curated_refs)
        )

    outputs = {
        "spdx": output_dir / f"aggregate-{architecture}.spdx.json",
        "cyclonedx": output_dir / f"aggregate-{architecture}.cdx.json",
        "manifest": output_dir / f"artifact-{architecture}.json",
    }
    outputs["spdx"].write_text(
        json.dumps(aggregate_spdx, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    outputs["cyclonedx"].write_text(
        json.dumps(aggregate_cdx, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest = {
        "schema_version": 1,
        "artifact": artifact_path.name,
        "architecture": architecture,
        "sha256": digest,
        "sbom_files": [outputs["spdx"].name, outputs["cyclonedx"].name],
        "runtime_release": runtime.get("runtime", {}).get("release"),
        "runtime_upstream_commit": runtime.get("runtime", {}).get("upstream_commit"),
        "created": created,
    }
    outputs["manifest"].write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return outputs


def generate_appdir_sboms(appdir: Path, syft_binary: str, output_dir: Path) -> tuple[Path, Path]:
    if not appdir.is_dir():
        raise ValueError(f"AppDir does not exist: {appdir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    spdx_path = output_dir / "appdir.spdx.json"
    cdx_path = output_dir / "appdir.cdx.json"
    subprocess.run(
        [
            syft_binary,
            "scan",
            f"dir:{appdir}",
            "--output",
            f"spdx-json@2.3={spdx_path}",
            "--output",
            f"cyclonedx-json@1.6={cdx_path}",
        ],
        check=True,
    )
    _read_json(spdx_path)
    _read_json(cdx_path)
    return spdx_path, cdx_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--appdir", type=Path, required=True)
    parser.add_argument("--runtime-inventory", type=Path, required=True)
    parser.add_argument("--native-inventory", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--architecture", required=True, choices=sorted(SUPPORTED_ARCHITECTURES))
    parser.add_argument("--syft", default="syft")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        appdir_spdx, appdir_cdx = generate_appdir_sboms(args.appdir, args.syft, args.output_dir)
        outputs = aggregate_sboms(
            appdir_spdx, appdir_cdx, args.runtime_inventory, args.output_dir,
            args.architecture, args.artifact, args.native_inventory,
        )
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"SBOM generation failed: {exc}", file=sys.stderr)
        return 1
    for name, path in outputs.items():
        print(f"{name}: {path}")
    print(f"AppDir SBOMs: {appdir_spdx} {appdir_cdx}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
