"""Behavioral tests for the AppImage license inventory contract."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "packaging" / "appimage" / "license_inventory.py"


def _load_validator() -> Any:
    assert MODULE_PATH.is_file(), "AppImage license inventory validator is not implemented"
    spec = importlib.util.spec_from_file_location("appimage_license_inventory", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _valid_inventories() -> tuple[dict[str, Any], dict[str, Any]]:
    appdir = {
        "schema_version": 1,
        "components": [
            {
                "id": "python-aiohttp",
                "name": "aiohttp",
                "version": "3.14.5",
                "version_status": "verified",
                "architecture": "all",
                "license": "Apache-2.0",
                "license_status": "verified",
                "source": "https://pypi.org/project/aiohttp/",
                "source_package": "aiohttp",
                "artifact_paths": ["opt/python/aiohttp"],
                "source_paths": ["wheelhouse/aiohttp-3.14.5.whl"],
                "evidence_paths": ["opt/python/aiohttp-3.14.5.dist-info/licenses"],
                "detection_method": "wheel-metadata",
                "verification_status": "verified",
            }
        ],
    }
    runtime = {
        "schema_version": 1,
        "runtime": {
            "release": "20251108",
            "upstream_commit": "dd6cebedcbddde9c82f89b011e8e1d40b6e43868",
            "artifacts": {
                "x86_64": "2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d",
                "aarch64": "00cbdfcf917cc6c0ff6d3347d59e0ca1f7f45a6df1a428a0d6d8a78664d87444",
            },
        },
        "components": [
            {
                "id": "runtime-mimalloc",
                "name": "mimalloc",
                "version": None,
                "version_status": "unknown",
                "architecture": "both",
                "license": "MIT",
                "license_status": "declared",
                "source": "AppImage type2-runtime upstream build recipe",
                "source_package": None,
                "artifact_paths": ["AppImage Type 2 runtime executable"],
                "source_paths": ["runtime upstream Makefile link inputs"],
                "evidence_paths": ["runtime upstream Makefile link inputs"],
                "detection_method": "upstream-build-recipe",
                "verification_status": "partial",
            }
        ],
    }
    return appdir, runtime


def test_valid_appdir_and_runtime_inventories_are_accepted() -> None:
    validator = _load_validator()
    appdir, runtime = _valid_inventories()

    assert validator.validate_inventories(appdir, runtime) == []


def test_component_missing_required_field_is_rejected() -> None:
    validator = _load_validator()
    appdir, runtime = _valid_inventories()
    del appdir["components"][0]["detection_method"]

    issues = validator.validate_inventories(appdir, runtime)

    assert any(issue.code == "COMPONENT_REQUIRED_FIELD" for issue in issues)


def test_duplicate_component_ids_are_rejected_across_inventories() -> None:
    validator = _load_validator()
    appdir, runtime = _valid_inventories()
    runtime["components"][0]["id"] = appdir["components"][0]["id"]

    issues = validator.validate_inventories(appdir, runtime)

    assert any(issue.code == "DUPLICATE_COMPONENT_ID" for issue in issues)


def test_empty_version_is_not_accepted_as_a_verified_version() -> None:
    validator = _load_validator()
    appdir, runtime = _valid_inventories()
    appdir["components"][0]["version"] = ""

    issues = validator.validate_inventories(appdir, runtime)

    assert any(issue.code == "EMPTY_VERSION" for issue in issues)


def test_unknown_version_requires_null_and_explicit_unknown_status() -> None:
    validator = _load_validator()
    appdir, runtime = _valid_inventories()
    component = appdir["components"][0]
    component["version"] = None
    component["version_status"] = "verified"

    issues = validator.validate_inventories(appdir, runtime)

    assert any(issue.code == "VERSION_STATUS_MISMATCH" for issue in issues)


def test_unclassified_license_value_is_rejected() -> None:
    validator = _load_validator()
    appdir, runtime = _valid_inventories()
    appdir["components"][0]["license"] = "unknown"
    appdir["components"][0]["license_status"] = "verified"

    issues = validator.validate_inventories(appdir, runtime)

    assert any(issue.code == "UNCLASSIFIED_LICENSE" for issue in issues)


def test_runtime_inventory_must_include_mimalloc() -> None:
    validator = _load_validator()
    appdir, runtime = _valid_inventories()
    runtime["components"].clear()

    issues = validator.validate_inventories(appdir, runtime)

    assert any(issue.code == "RUNTIME_MISSING_MIMALLOC" for issue in issues)


def test_runtime_inventory_requires_both_architecture_hashes() -> None:
    validator = _load_validator()
    appdir, runtime = _valid_inventories()
    del runtime["runtime"]["artifacts"]["aarch64"]

    issues = validator.validate_inventories(appdir, runtime)

    assert any(issue.code == "RUNTIME_ARTIFACT_HASH_MISSING" for issue in issues)


def test_project_gpl_license_payload_is_full_text() -> None:
    license_path = ROOT / "packaging" / "appimage" / "licenses" / "GPL-3.0-or-later.txt"

    assert license_path.is_file()
    content = license_path.read_text(encoding="utf-8")
    assert len(content) > 30_000
    assert "GNU GENERAL PUBLIC LICENSE" in content
    assert "Version 3, 29 June 2007" in content
    assert "END OF TERMS AND CONDITIONS" in content


def test_curated_inventory_covers_the_locked_runtime_wheels() -> None:
    inventory_path = ROOT / "packaging" / "appimage" / "licenses" / "components.json"
    inventory = __import__("json").loads(inventory_path.read_text(encoding="utf-8"))
    actual = {item["name"] for item in inventory["components"]}
    expected = {
        "aiohappyeyeballs", "aiohttp", "aiosignal", "attrs", "cffi", "cryptography",
        "frozenlist", "idna", "multidict", "propcache", "pycparser", "typing_extensions", "yarl",
    }

    assert expected <= actual


def test_license_staging_copies_project_license_into_appdir(tmp_path: Path) -> None:
    import subprocess

    source = ROOT / "packaging" / "appimage" / "licenses"
    appdir = tmp_path / "AppDir"
    result = subprocess.run(
        [
            "bash",
            str(ROOT / "packaging" / "appimage" / "stage-license-documents.sh"),
            str(source),
            str(appdir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    staged = appdir / "usr" / "share" / "licenses" / "ClamGuardian" / "GPL-3.0-or-later.txt"
    assert result.returncode == 0, result.stderr
    assert staged.read_bytes() == (source / "GPL-3.0-or-later.txt").read_bytes()


def test_repository_license_is_complete_and_project_copyright_is_separate() -> None:
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    copyright_path = ROOT / "packaging" / "appimage" / "licenses" / "ClamGuardian-COPYRIGHT.txt"

    assert len(license_text) > 30_000
    assert "Version 3, 29 June 2007" in license_text
    assert copyright_path.is_file()
    assert "Copyright (C) 2026 ClamGuardian contributors" in copyright_path.read_text(
        encoding="utf-8"
    )


def test_component_requires_original_source_paths_for_provenance() -> None:
    validator = _load_validator()
    appdir, runtime = _valid_inventories()
    del appdir["components"][0]["source_paths"]

    issues = validator.validate_inventories(appdir, runtime)

    assert any(issue.code == "COMPONENT_REQUIRED_FIELD" for issue in issues)


@pytest.mark.parametrize(
    ("architecture", "asset_arch"),
    [("x86_64", "amd64"), ("aarch64", "arm64")],
)
def test_syft_installer_rejects_checksum_mismatch(
    tmp_path: Path, architecture: str, asset_arch: str
) -> None:
    import os
    import subprocess

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    curl = fake_bin / "curl"
    curl.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "printf '%s\\n' \"$*\" > \"$CURL_CAPTURE\"\n"
        "while (($#)); do\n"
        "  if [[ $1 == --output ]]; then printf tampered > \"$2\"; shift 2; else shift; fi\n"
        "done\n",
        encoding="utf-8",
    )
    curl.chmod(0o755)
    capture = tmp_path / "curl-args.txt"
    install_dir = tmp_path / "bin-install"
    env = os.environ | {
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "APPIMAGE_ARCH": architecture,
        "CURL_CAPTURE": str(capture),
        "SYFT_INSTALL_DIR": str(install_dir),
        "SYFT_CACHE_DIR": str(tmp_path / "cache"),
    }
    result = subprocess.run(
        ["bash", str(ROOT / "packaging" / "appimage" / "install-syft.sh")],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "checksums file" in result.stderr.lower()
    captured = capture.read_text(encoding="utf-8")
    assert "syft_1.57.1_checksums.txt" in captured
    assert f"syft_1.57.1_linux_{asset_arch}.tar.gz" not in captured
    assert not (install_dir / "syft").exists()


def test_sbom_aggregator_adds_runtime_components_to_both_formats(tmp_path: Path) -> None:
    import json

    module_path = ROOT / "packaging" / "appimage" / "generate-sbom.py"
    assert module_path.is_file(), "AppImage SBOM generator is not implemented"
    spec = importlib.util.spec_from_file_location("appimage_sbom_generator", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    spdx = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "ClamGuardian AppDir",
        "documentNamespace": "https://example.invalid/spdx/appdir",
        "creationInfo": {"creators": ["Tool: Syft"], "created": "2026-11-12T00:00:00Z"},
        "packages": [],
        "relationships": [],
    }
    cdx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "ClamGuardian",
                "bom-ref": "app",
            }
        },
        "components": [],
        "dependencies": [{"ref": "app", "dependsOn": []}],
    }
    spdx_path = tmp_path / "appdir.spdx.json"
    cdx_path = tmp_path / "appdir.cdx.json"
    runtime_path = tmp_path / "runtime.json"
    native_path = tmp_path / "native.json"
    output_dir = tmp_path / "out"
    artifact = tmp_path / "ClamGuardian-x86_64.AppImage"
    artifact.write_bytes(b"appimage-fixture")
    spdx_path.write_text(json.dumps(spdx), encoding="utf-8")
    cdx_path.write_text(json.dumps(cdx), encoding="utf-8")
    runtime_path.write_text(json.dumps(_valid_inventories()[1]), encoding="utf-8")
    native_path.write_text(json.dumps({
        "schema_version": 1,
        "architecture": "x86_64",
        "packages": [{
            "package": "ca-certificates:amd64",
            "version": "20260816ubuntu0.24.04.2",
            "source_package": "ca-certificates",
            "artifact_paths": ["etc/ssl/certs/ca-certificates.crt"],
            "copyright_artifact_path": "third-party/native/ca-certificates/copyright",
        }],
        "missing_copyright_packages": [],
    }), encoding="utf-8")

    outputs = module.aggregate_sboms(
        spdx_path, cdx_path, runtime_path, output_dir, "x86_64", artifact, native_path
    )

    aggregate_spdx = json.loads(outputs["spdx"].read_text(encoding="utf-8"))
    aggregate_cdx = json.loads(outputs["cyclonedx"].read_text(encoding="utf-8"))
    assert any(item["name"] == "mimalloc" for item in aggregate_spdx["packages"])
    assert any(item["name"] == "mimalloc" for item in aggregate_cdx["components"])
    assert any(item["name"] == "ca-certificates" for item in aggregate_spdx["packages"])
    assert any(item["name"] == "ca-certificates" for item in aggregate_cdx["components"])
    assert aggregate_spdx["comment"].find("x86_64") >= 0
    assert aggregate_cdx["metadata"]["properties"]
    assert outputs["manifest"].is_file()


def test_sbom_aggregator_rejects_invalid_artifact_architecture(tmp_path: Path) -> None:
    import json

    module_path = ROOT / "packaging" / "appimage" / "generate-sbom.py"
    assert module_path.is_file(), "AppImage SBOM generator is not implemented"
    spec = importlib.util.spec_from_file_location("appimage_sbom_generator_invalid", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    for filename, payload in (
        (
            "spdx.json",
            {
                "spdxVersion": "SPDX-2.3",
                "packages": [],
                "relationships": [],
                "creationInfo": {},
            },
        ),
        (
            "cdx.json",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [],
                "dependencies": [],
                "metadata": {},
            },
        ),
        ("runtime.json", _valid_inventories()[1]),
    ):
        (tmp_path / filename).write_text(json.dumps(payload), encoding="utf-8")
    artifact = tmp_path / "artifact.AppImage"
    artifact.write_bytes(b"artifact")

    with pytest.raises(ValueError, match="architecture"):
        module.aggregate_sboms(
            tmp_path / "spdx.json", tmp_path / "cdx.json", tmp_path / "runtime.json",
            tmp_path / "out", "mips64", artifact,
        )


def test_appimage_build_generates_aggregate_sboms_after_packaging() -> None:
    build = (ROOT / "packaging" / "appimage" / "build-appimage.sh").read_text(encoding="utf-8")
    assert "install-syft.sh" in build
    assert "generate-sbom.py" in build
    assert "--artifact \"$output\"" in build
    assert "--runtime-inventory" in build
    assert "collect-licenses.py" in build
    assert "--native-inventory" in build


def test_native_appimage_ci_uploads_sbom_evidence_for_both_architectures() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert '"dist/sbom/${{ matrix.arch }}"' in workflow
    assert "dist/sbom/${{ matrix.arch }}/*" in workflow


def test_sbom_verifier_rejects_artifact_digest_mismatch(tmp_path: Path) -> None:
    import hashlib
    import json

    module_path = ROOT / "packaging" / "appimage" / "verify-sbom.py"
    spec = importlib.util.spec_from_file_location("appimage_sbom_verifier", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    artifact = tmp_path / "app.AppImage"
    artifact.write_bytes(b"real artifact")
    sbom_dir = tmp_path / "sbom"
    sbom_dir.mkdir()
    (sbom_dir / "artifact-x86_64.json").write_text(json.dumps({
        "architecture": "x86_64", "sha256": hashlib.sha256(b"wrong").hexdigest(),
        "artifact": artifact.name,
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256"):
        module.verify(artifact, "x86_64", sbom_dir, tmp_path / "runtime.json")


def test_sbom_verifier_accepts_matching_aggregate_runtime_evidence(tmp_path: Path) -> None:
    import hashlib
    import json

    module_path = ROOT / "packaging" / "appimage" / "verify-sbom.py"
    spec = importlib.util.spec_from_file_location("appimage_sbom_verifier_valid", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    artifact = tmp_path / "app.AppImage"
    artifact.write_bytes(b"verified artifact")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    sbom_dir = tmp_path / "sbom"
    sbom_dir.mkdir()
    runtime = _valid_inventories()[1]
    (tmp_path / "runtime.json").write_text(json.dumps(runtime), encoding="utf-8")
    (sbom_dir / "artifact-x86_64.json").write_text(json.dumps({
        "architecture": "x86_64", "sha256": digest, "artifact": artifact.name,
    }), encoding="utf-8")
    (sbom_dir / "appdir.spdx.json").write_text(json.dumps({
        "spdxVersion": "SPDX-2.3", "packages": [],
    }), encoding="utf-8")
    (sbom_dir / "aggregate-x86_64.spdx.json").write_text(json.dumps({
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {"name": "mimalloc", "versionInfo": "2.2.3", "licenseDeclared": "MIT"}
        ],
    }), encoding="utf-8")
    (sbom_dir / "appdir.cdx.json").write_text(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "components": [],
    }), encoding="utf-8")
    (sbom_dir / "aggregate-x86_64.cdx.json").write_text(json.dumps({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {"name": "mimalloc", "version": "2.2.3", "licenses": [{"expression": "MIT"}]}
        ],
    }), encoding="utf-8")

    module.verify(artifact, "x86_64", sbom_dir, tmp_path / "runtime.json")


def test_native_license_collector_copies_exact_dpkg_copyright_and_versions(tmp_path: Path) -> None:
    import importlib.util

    module_path = ROOT / "packaging" / "appimage" / "collect-licenses.py"
    assert module_path.is_file(), "native package license collector is not implemented"
    spec = importlib.util.spec_from_file_location("appimage_native_license_collector", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    appdir = tmp_path / "AppDir"
    info = tmp_path / "dpkg-info"
    docs = tmp_path / "doc"
    output = appdir / "usr/share/licenses/ClamGuardian"
    (appdir / "etc/ssl/certs").mkdir(parents=True)
    (appdir / "etc/ssl/certs/ca-certificates.crt").write_text("CA bundle", encoding="utf-8")
    info.mkdir()
    docs.mkdir()
    (info / "ca-certificates.list").write_text(
        "/etc/ssl/certs/ca-certificates.crt\n", encoding="utf-8"
    )
    (docs / "ca-certificates").mkdir()
    exact_copyright = "Ubuntu ca-certificates package copyright evidence\n"
    (docs / "ca-certificates/copyright").write_text(exact_copyright, encoding="utf-8")

    result = module.collect_package_provenance(
        appdir,
        info,
        docs,
        output,
        package_metadata_resolver=lambda package: {
            "version": "20260816ubuntu0.24.04.2",
            "source_package": "ca-certificates",
            "source_version": "20260816ubuntu0.24.04.2",
        },
    )

    copied = output / "third-party/native/ca-certificates/copyright"
    assert copied.read_text(encoding="utf-8") == exact_copyright
    assert result["packages"][0]["version"] == "20260816ubuntu0.24.04.2"
    assert result["packages"][0]["copyright_status"] == "present"
    assert (output / "native-packages.json").is_file()


def test_native_license_collector_fails_closed_when_copyright_is_missing(tmp_path: Path) -> None:
    import importlib.util

    module_path = ROOT / "packaging" / "appimage" / "collect-licenses.py"
    assert module_path.is_file(), "native package license collector is not implemented"
    spec = importlib.util.spec_from_file_location(
        "appimage_native_license_collector_missing", module_path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    appdir = tmp_path / "AppDir"
    info = tmp_path / "dpkg-info"
    docs = tmp_path / "doc"
    (appdir / "usr/lib").mkdir(parents=True)
    (appdir / "usr/lib/libexample.so").write_bytes(b"ELF fixture")
    info.mkdir()
    docs.mkdir()
    (info / "libexample1:amd64.list").write_text("/usr/lib/libexample.so\n", encoding="utf-8")

    with pytest.raises(ValueError, match="copyright"):
        module.collect_package_provenance(
            appdir, info, docs, appdir / "usr/share/licenses/ClamGuardian",
            package_metadata_resolver=lambda package: {
                "version": "1.0-1", "source_package": "libexample", "source_version": "1.0-1",
            },
        )


def test_native_license_collector_records_embedded_libmpdec_with_unknown_library_version(
    tmp_path: Path,
) -> None:
    import importlib.util

    module_path = ROOT / "packaging" / "appimage" / "collect-licenses.py"
    spec = importlib.util.spec_from_file_location(
        "appimage_native_license_collector_mpdec", module_path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    appdir = tmp_path / "AppDir"
    info = tmp_path / "dpkg-info"
    docs = tmp_path / "doc"
    extension = "usr/lib/python3.12/lib-dynload/_decimal.cpython-312-x86_64-linux-gnu.so"
    (appdir / extension).parent.mkdir(parents=True)
    (appdir / extension).write_bytes(b"extension fixture")
    info.mkdir()
    docs.mkdir()
    (info / "libpython3.12-stdlib:amd64.list").write_text(
        f"/{extension}\n", encoding="utf-8"
    )
    (docs / "libpython3.12-stdlib").mkdir()
    (docs / "libpython3.12-stdlib/copyright").write_text(
        "Python standard library copyright; libmpdec; Stefan Krah\n", encoding="utf-8"
    )

    result = module.collect_package_provenance(
        appdir, info, docs, appdir / "usr/share/licenses/ClamGuardian",
        package_metadata_resolver=lambda package: {
            "version": "3.12.3-1ubuntu0.17",
            "source_package": "python3.12",
            "source_version": "3.12.3-1ubuntu0.17",
        },
        architecture="x86_64",
    )

    embedded = result["embedded_components"]
    assert len(embedded) == 1
    assert embedded[0]["name"] == "libmpdec"
    assert embedded[0]["version"] is None
    assert embedded[0]["license"] == "NOASSERTION"
    assert embedded[0]["evidence_paths"]


def test_sbom_schema_validator_checks_all_four_documents(tmp_path: Path) -> None:
    pytest.importorskip("jsonschema")
    import importlib.util
    import json

    module_path = ROOT / "packaging" / "appimage" / "validate-sbom.py"
    spec = importlib.util.spec_from_file_location("appimage_sbom_schema_validator", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    sbom_dir = tmp_path / "sbom"
    schema_dir = tmp_path / "schemas"
    sbom_dir.mkdir()
    schema_dir.mkdir()
    spdx_schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["spdxVersion"],
    }
    cdx_schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["bomFormat", "specVersion"],
    }
    (schema_dir / "spdx-schema-2.3.json").write_text(json.dumps(spdx_schema), encoding="utf-8")
    (schema_dir / "cyclonedx-bom-1.6.schema.json").write_text(
        json.dumps(cdx_schema), encoding="utf-8"
    )
    for filename in ("appdir.spdx.json", "aggregate-x86_64.spdx.json"):
        (sbom_dir / filename).write_text(json.dumps({"spdxVersion": "SPDX-2.3"}), encoding="utf-8")
    for filename in ("appdir.cdx.json", "aggregate-x86_64.cdx.json"):
        (sbom_dir / filename).write_text(
            json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6"}),
            encoding="utf-8",
        )

    report = module.validate_documents(sbom_dir, schema_dir, "x86_64")

    assert report["schema_validation"] == "passed"
    assert len(report["documents"]) == 4
    assert (sbom_dir / "schema-validation-x86_64.json").is_file()


def test_sbom_build_pipeline_runs_schema_validation() -> None:
    build = (ROOT / "packaging" / "appimage" / "build-appimage.sh").read_text(encoding="utf-8")
    test_script = (ROOT / "packaging" / "appimage" / "test-appimage.sh").read_text(encoding="utf-8")
    assert "install-sbom-validator.sh" in build
    assert "validate-sbom.py" in build
    assert "schema-validation-$expected_arch.json" in test_script


def test_runtime_inventory_has_explicit_mimalloc_and_upstream_license_evidence() -> None:
    import json

    validator = _load_validator()
    appdir = json.loads(
        (ROOT / "packaging/appimage/licenses/components.json").read_text(encoding="utf-8")
    )
    runtime = json.loads(
        (ROOT / "packaging/appimage/licenses/runtime-type2.json").read_text(encoding="utf-8")
    )
    assert validator.validate_inventories(appdir, runtime) == []
    names = {item["name"] for item in runtime["components"]}
    assert {
        "AppImage Type 2 runtime", "musl", "libfuse", "squashfuse",
        "zstd", "zlib", "mimalloc",
    } <= names
    mimalloc = next(item for item in runtime["components"] if item["name"] == "mimalloc")
    assert mimalloc["license"] == "MIT"
    assert mimalloc["version_status"] == "declared"
    assert mimalloc["evidence_paths"]


def test_runtime_license_collector_rejects_tampered_upstream_text(tmp_path: Path) -> None:
    import os
    import subprocess

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    curl = fake_bin / "curl"
    curl.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "while (($#)); do\n"
        "  if [[ $1 == --output ]]; then printf tampered > \"$2\"; shift 2; else shift; fi\n"
        "done\n",
        encoding="utf-8",
    )
    curl.chmod(0o755)
    env = os.environ | {"PATH": f"{fake_bin}:{os.environ['PATH']}"}
    result = subprocess.run(
        [
            "bash",
            str(ROOT / "packaging/appimage/collect-runtime-licenses.sh"),
            str(tmp_path / "licenses"),
        ],
        env=env, check=False, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "Git blob SHA mismatch" in result.stderr


def test_runtime_license_collection_is_integrated_before_appdir_staging() -> None:
    build = (ROOT / "packaging/appimage/build-appimage.sh").read_text(encoding="utf-8")
    assert "collect-runtime-licenses.sh" in build
    assert build.index("collect-runtime-licenses.sh") < build.index("stage-license-documents.sh")


def test_debian_copyright_license_aliases_map_to_spdx_expressions() -> None:
    import importlib.util

    module_path = ROOT / "packaging/appimage/collect-licenses.py"
    spec = importlib.util.spec_from_file_location("appimage_debian_license_parser", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    expression, status = module._debian_license_expression(
        b"Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n\n"
        b"Files: *\nCopyright: Example\nLicense: LGPL-2.1+\n"
    )

    assert expression == "LGPL-2.1-or-later"
    assert status == "verified"


def test_debian_copyright_with_multiple_unreconciled_licenses_stays_noassertion() -> None:
    import importlib.util

    module_path = ROOT / "packaging/appimage/collect-licenses.py"
    spec = importlib.util.spec_from_file_location(
        "appimage_debian_license_parser_multiple", module_path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    expression, status = module._debian_license_expression(
        b"Files: src/*\nCopyright: Example\nLicense: MIT\n\n"
        b"Files: docs/*\nCopyright: Example\nLicense: GPL-2+\n"
    )

    assert expression == "NOASSERTION"
    assert status == "unknown"


def test_runtime_license_sources_are_immutable_and_blob_pinned() -> None:
    script = (ROOT / "packaging/appimage/collect-runtime-licenses.sh").read_text(encoding="utf-8")
    expected = {
        "AppImage-type2-runtime-MIT.txt": "a9fd00b042f392357a84fd81b7789976a53f5b4e",
        "musl-COPYRIGHT.txt": "c1628e9ac84f927fe791124ec172fb61c760bb9b",
        "libfuse-LGPL2.txt": "4362b49151d7b34ef83b3067a8f9c9f877d72a0e",
        "squashfuse-LICENSE.txt": "2c821bbaa662c7e863424b0523f032b77ab75d87",
        "zstd-LICENSE.txt": "75800288cc243f164b9d130f125e2ffae28f8e39",
        "zlib-LICENSE.txt": "ab8ee6f71428c3e4646b12b64ad387cde33462e5",
        "mimalloc-LICENSE.txt": "53315ebee557ac22f3396ea1781df0440c26bb15",
    }
    for filename, blob_sha in expected.items():
        assert filename in script
        assert blob_sha in script


def test_libmpdec_inventory_requires_matching_copyright_stanza(tmp_path: Path) -> None:
    import importlib.util

    module_path = ROOT / "packaging/appimage/collect-licenses.py"
    spec = importlib.util.spec_from_file_location("appimage_libmpdec_missing_evidence", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    appdir = tmp_path / "AppDir"
    info = tmp_path / "dpkg-info"
    docs = tmp_path / "doc"
    extension = "usr/lib/python3.12/lib-dynload/_decimal.cpython-312-x86_64-linux-gnu.so"
    (appdir / extension).parent.mkdir(parents=True)
    (appdir / extension).write_bytes(b"extension fixture")
    info.mkdir()
    docs.mkdir()
    (info / "python3.12-stdlib:amd64.list").write_text(f"/{extension}\n", encoding="utf-8")
    (docs / "python3.12-stdlib").mkdir()
    (docs / "python3.12-stdlib/copyright").write_text(
        "Files: Modules/_decimal/*\nCopyright: unrelated author\nLicense: MIT\n", encoding="utf-8"
    )

    with pytest.raises(ValueError, match="libmpdec copyright/license evidence"):
        module.collect_package_provenance(
            appdir, info, docs, appdir / "usr/share/licenses/ClamGuardian",
            package_metadata_resolver=lambda package: {
                "version": "3.12.3-1ubuntu0.17",
                "source_package": "python3.12",
                "source_version": "3.12.3-1ubuntu0.17",
            },
            architecture="x86_64",
        )


def test_syft_installer_rejects_archive_checksum_mismatch(tmp_path: Path) -> None:
    import os
    import subprocess

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    curl = fake_bin / "curl"
    curl.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
while (($#)); do
  if [[ $1 == --output ]]; then
    output=$2; shift 2
    if [[ $output == *checksums.txt ]]; then
      printf '%s  %s\n' \
        '0000000000000000000000000000000000000000000000000000000000000000' \
        'syft_1.57.1_linux_amd64.tar.gz' > "$output"
    else
      printf tampered > "$output"
    fi
  else
    shift
  fi
done
""",
        encoding="utf-8",
    )
    curl.chmod(0o755)
    sha = fake_bin / "sha256sum"
    sha.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "if [[ ${1:-} == --check ]]; then exit 1; fi\n"
        "printf '%s  %s\\n' "
        "'92466b2b1a4695ee908f8a1567f4ff074e0fbb4f34da28463927a2630901fe2c' "
        "\"$1\"\n",
        encoding="utf-8",
    )
    sha.chmod(0o755)
    env = os.environ | {
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "APPIMAGE_ARCH": "x86_64",
        "SYFT_INSTALL_DIR": str(tmp_path / "install"),
        "SYFT_CACHE_DIR": str(tmp_path / "cache"),
    }
    result = subprocess.run(
        ["bash", str(ROOT / "packaging/appimage/install-syft.sh")],
        env=env, check=False, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "Syft checksum mismatch" in result.stderr
    assert not (tmp_path / "install/syft").exists()


def test_sbom_verifier_reconciles_curated_appdir_packages_and_licenses(tmp_path: Path) -> None:
    import hashlib
    import importlib.util
    import json

    module_path = ROOT / "packaging/appimage/verify-sbom.py"
    spec = importlib.util.spec_from_file_location("appimage_sbom_verifier_appdir", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    artifact = tmp_path / "app.AppImage"
    artifact.write_bytes(b"verified artifact")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    sbom_dir = tmp_path / "sbom"
    sbom_dir.mkdir()
    runtime = _valid_inventories()[1]
    runtime_component = runtime["components"][0]
    runtime_component.update({"version": "2.2.3", "license": "MIT"})
    runtime["runtime"]["artifacts"]["x86_64"] = "0" * 64
    (tmp_path / "runtime.json").write_text(json.dumps(runtime), encoding="utf-8")
    appdir_inventory = {"schema_version": 1, "components": [{
        "id": "python-demo", "name": "demo-package", "version": "1.2.3",
        "license": "MIT", "architecture": "all",
    }]}
    (tmp_path / "components.json").write_text(json.dumps(appdir_inventory), encoding="utf-8")
    (sbom_dir / "artifact-x86_64.json").write_text(json.dumps({
        "architecture": "x86_64", "sha256": digest, "artifact": artifact.name,
    }), encoding="utf-8")
    (sbom_dir / "appdir.spdx.json").write_text(
        json.dumps({"spdxVersion": "SPDX-2.3", "packages": []}), encoding="utf-8"
    )
    (sbom_dir / "aggregate-x86_64.spdx.json").write_text(json.dumps({
        "spdxVersion": "SPDX-2.3", "packages": [
            {"name": "demo-package", "versionInfo": "1.2.3", "licenseDeclared": "MIT"},
            {"name": "mimalloc", "versionInfo": "2.2.3", "licenseDeclared": "MIT"},
        ],
    }), encoding="utf-8")
    (sbom_dir / "appdir.cdx.json").write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}),
        encoding="utf-8",
    )
    (sbom_dir / "aggregate-x86_64.cdx.json").write_text(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
            {"name": "demo-package", "version": "1.2.3", "licenses": [{"expression": "MIT"}]},
            {"name": "mimalloc", "version": "2.2.3", "licenses": [{"expression": "MIT"}]},
        ],
    }), encoding="utf-8")

    module.verify(
        artifact, "x86_64", sbom_dir, tmp_path / "runtime.json",
        appdir_inventory_path=tmp_path / "components.json",
    )



def test_syft_output_formats_pin_spdx_and_cyclonedx_schema_versions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module_path = ROOT / "packaging" / "appimage" / "generate-sbom.py"
    spec = importlib.util.spec_from_file_location("appimage_sbom_generator_format_pin", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    appdir = tmp_path / "AppDir"
    appdir.mkdir()
    output = tmp_path / "sbom"
    captured: list[str] = []

    def fake_run(command: list[str], *, check: bool) -> None:
        captured.extend(command)
        for argument in command:
            if argument.startswith("spdx-json@2.3="):
                Path(argument.split("=", 1)[1]).write_text("{}", encoding="utf-8")
            if argument.startswith("cyclonedx-json@1.6="):
                Path(argument.split("=", 1)[1]).write_text("{}", encoding="utf-8")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    module.generate_appdir_sboms(appdir, "syft", output)

    assert any(value.startswith("spdx-json@2.3=") for value in captured)
    assert any(value.startswith("cyclonedx-json@1.6=") for value in captured)
