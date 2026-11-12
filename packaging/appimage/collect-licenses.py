#!/usr/bin/env python3
"""Collect copyright evidence for Debian packages that own bundled AppDir files."""

from __future__ import annotations

import argparse
import gzip
import json
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any


def query_package_metadata(package: str) -> dict[str, str | None]:
    result = subprocess.run(
        [
            "dpkg-query", "-W",
            "-f=${Version}\\t${source:Package}\\t${source:Version}",
            package,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ValueError(
            f"cannot query installed package metadata for {package}: {result.stderr.strip()}"
        )
    fields = result.stdout.rstrip("\n").split("\t")
    if len(fields) != 3 or not fields[0].strip():
        raise ValueError(f"dpkg-query returned incomplete metadata for {package}")
    return {
        "version": fields[0].strip(),
        "source_package": fields[1].strip() or package.split(":", 1)[0],
        "source_version": fields[2].strip() or fields[0].strip(),
    }


def _package_file_owners(dpkg_info_dir: Path) -> dict[str, set[str]]:
    owners: dict[str, set[str]] = {}
    for list_file in sorted(dpkg_info_dir.glob("*.list")):
        package = list_file.name[:-5]
        for raw_path in list_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if raw_path.startswith("/"):
                owners.setdefault(raw_path, set()).add(package)
    return owners


def _copyright_document(
    doc_root: Path, package: str, source_package: str
) -> tuple[bytes | None, str | None]:
    candidates = []
    for name in dict.fromkeys((package.split(":", 1)[0], source_package)):
        candidates.extend((doc_root / name / "copyright", doc_root / name / "copyright.gz"))
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            if candidate.suffix == ".gz":
                with gzip.open(candidate, "rb") as handle:
                    return handle.read(), str(candidate)
            return candidate.read_bytes(), str(candidate)
        except (OSError, EOFError) as exc:
            raise ValueError(f"cannot read copyright evidence {candidate}: {exc}") from exc
    return None, None


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9.+_-]+", "_", value)


def _debian_license_expression(content: bytes) -> tuple[str, str]:
    """Extract a conservative SPDX expression from Debian copyright stanzas."""
    text = content.decode("utf-8", errors="replace")
    expressions: list[str] = []
    current: dict[str, str] = {}
    for line in text.splitlines() + [""]:
        if not line.strip():
            if "Files" in current and "License" in current:
                expressions.append(current["License"].splitlines()[0].strip())
            current = {}
            continue
        if line[:1].isspace() and current:
            last_key = next(reversed(current))
            current[last_key] += "\n" + line.strip()
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            current[key.strip()] = value.strip()
    if not expressions:
        return "NOASSERTION", "unknown"

    aliases = {
        "gpl-2+": "GPL-2.0-or-later",
        "gpl-2": "GPL-2.0-only",
        "gpl-3+": "GPL-3.0-or-later",
        "gpl-3": "GPL-3.0-only",
        "lgpl-2.1+": "LGPL-2.1-or-later",
        "lgpl-2.1": "LGPL-2.1-only",
        "lgpl-3+": "LGPL-3.0-or-later",
        "lgpl-3": "LGPL-3.0-only",
        "bsd-3-clause": "BSD-3-Clause",
        "bsd-2-clause": "BSD-2-Clause",
        "apache-2": "Apache-2.0",
        "apache-2.0": "Apache-2.0",
        "expat": "MIT",
        "zlib": "Zlib",
        "psf-2": "PSF-2.0",
        "cc-by-sa-3.0-us": "CC-BY-SA-3.0-US",
        "cc-by-sa-3.0": "CC-BY-SA-3.0",
        "mpl-1.1": "MPL-1.1",
        "mpl-2.0": "MPL-2.0",
        "mit": "MIT",
        "isc": "ISC",
        "cc0-1.0": "CC0-1.0",
    }
    normalized: list[str] = []
    for expression in expressions:
        value = expression.casefold()
        for debian_name, spdx_name in aliases.items():
            pattern = rf"(?<![a-z0-9.+-]){re.escape(debian_name)}(?![a-z0-9.+-])"
            value = re.sub(pattern, spdx_name, value)
        value = re.sub(r"(?<![A-Za-z0-9.+-])or(?![A-Za-z0-9.+-])", "OR", value, flags=re.IGNORECASE)
        value = re.sub(
            r"(?<![A-Za-z0-9.+-])and(?![A-Za-z0-9.+-])",
            "AND",
            value,
            flags=re.IGNORECASE,
        )
        value = re.sub(r"\s+", " ", value).strip()
        # SPDX identifiers and operators are case-sensitive; aliases above
        # normalize common Debian names. Unknown syntax remains unasserted.
        if not value or re.search(r"[^A-Za-z0-9.+() -]", value):
            return "NOASSERTION", "unknown"
        tokens = value.replace("(", " ( ").replace(")", " ) ").split()
        if any(
            token not in {"AND", "OR", "WITH", "(", ")"}
            and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]*", token)
            for token in tokens
        ):
            return "NOASSERTION", "unknown"
        normalized.append(value)
    if len(set(normalized)) != 1:
        return "NOASSERTION", "unknown"
    return normalized[0], "verified"


def _libmpdec_evidence(content: bytes) -> tuple[bool, str, str]:
    text = content.decode("utf-8", errors="replace")
    matching_stanzas = []
    for stanza in re.split(r"\n\s*\n", text):
        lowered = stanza.casefold()
        if "stefan krah" in lowered and ("libmpdec" in lowered or "_decimal" in lowered):
            matching_stanzas.append(stanza.encode("utf-8"))
    if not matching_stanzas:
        return False, "NOASSERTION", "unknown"
    expression, status = _debian_license_expression(b"\n\n".join(matching_stanzas))
    return True, expression, status


def collect_package_provenance(
    appdir: Path,
    dpkg_info_dir: Path,
    doc_root: Path,
    output_dir: Path,
    package_metadata_resolver: Callable[[str], dict[str, str | None]] = query_package_metadata,
    architecture: str = "unknown",
) -> dict[str, Any]:
    """Map AppDir files to installed Debian packages and stage their copyright.

    Every package mapped to a bundled file must have a readable copyright file.
    Missing documents are reported and cause a fail-closed ValueError.
    """
    if not appdir.is_dir():
        raise ValueError(f"AppDir does not exist: {appdir}")
    if not dpkg_info_dir.is_dir():
        raise ValueError(f"dpkg info directory does not exist: {dpkg_info_dir}")
    if not doc_root.is_dir():
        raise ValueError(f"package documentation directory does not exist: {doc_root}")

    owners_by_path = _package_file_owners(dpkg_info_dir)
    package_paths: dict[str, list[str]] = {}
    for appdir_path in sorted(appdir.rglob("*")):
        if appdir_path.is_dir():
            continue
        try:
            relative = appdir_path.relative_to(appdir)
        except ValueError:
            continue
        host_path = "/" + relative.as_posix()
        for package in owners_by_path.get(host_path, set()):
            package_paths.setdefault(package, []).append(relative.as_posix())

    output_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    missing: list[str] = []
    package_evidence: dict[str, str] = {}
    package_copyright: dict[str, bytes] = {}
    for package in sorted(package_paths):
        metadata = package_metadata_resolver(package)
        version = metadata.get("version")
        source_package = metadata.get("source_package") or package.split(":", 1)[0]
        if not isinstance(version, str) or not version.strip():
            raise ValueError(f"installed package version is unknown for {package}")
        content, source_document = _copyright_document(doc_root, package, source_package)
        package_directory = _safe_name(package.split(":", 1)[0])
        destination_relative = f"third-party/native/{package_directory}/copyright"
        destination = output_dir / destination_relative
        copyright_status = "present" if content is not None else "missing"
        license_expression, license_status = (
            _debian_license_expression(content)
            if content is not None
            else ("NOASSERTION", "unknown")
        )
        if content is not None:
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists() and destination.read_bytes() != content:
                raise ValueError(
                    f"refusing to overwrite different copyright evidence: {destination}"
                )
            destination.write_bytes(content)
            package_evidence[package] = destination_relative
            package_copyright[package] = content
        else:
            missing.append(package)
        records.append({
            "package": package,
            "version": version,
            "source_package": source_package,
            "source_version": metadata.get("source_version") or version,
            "architecture": architecture,
            "artifact_paths": sorted(set(package_paths[package])),
            "copyright_status": copyright_status,
            "copyright_source": source_document,
            "copyright_artifact_path": destination_relative if content is not None else None,
            "license": license_expression,
            "license_status": license_status,
        })

    embedded_components: list[dict[str, Any]] = []
    missing_embedded_evidence: list[str] = []
    for package, paths in package_paths.items():
        decimal_paths = [
            path for path in paths
            if Path(path).name.startswith("_decimal") and Path(path).suffix == ".so"
        ]
        if not decimal_paths:
            continue
        evidence_path = package_evidence.get(package)
        content = package_copyright.get(package)
        if evidence_path is None or content is None:
            missing_embedded_evidence.append(package)
            continue
        has_notice, embedded_license, embedded_license_status = _libmpdec_evidence(content)
        if not has_notice:
            missing_embedded_evidence.append(package)
            continue
        embedded_components.append({
            "id": "embedded-libmpdec",
            "name": "libmpdec",
            "version": None,
            "version_status": "unknown",
            "architecture": architecture,
            "license": embedded_license,
            "license_status": embedded_license_status,
            "source": (
                "Embedded in the bundled Ubuntu Python 3.12 _decimal extension; package "
                "copyright stanza identifies Stefan Krah and the _decimal/libmpdec source"
            ),
            "source_package": package.split(":", 1)[0],
            "artifact_paths": sorted(decimal_paths),
            "source_paths": [f"/var/lib/dpkg/info/{package}.list"],
            "evidence_paths": [evidence_path],
            "detection_method": "dpkg-file-list-and-python-extension-path",
            "verification_status": "partial",
        })
        break

    manifest = {
        "schema_version": 1,
        "architecture": architecture,
        "detection_method": "dpkg-file-list-to-AppDir-path-mapping",
        "packages": records,
        "embedded_components": embedded_components,
        "missing_copyright_packages": missing,
        "missing_embedded_component_evidence": missing_embedded_evidence,
    }
    manifest_path = output_dir / "native-packages.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if missing:
        raise ValueError("missing package copyright documents for: " + ", ".join(missing))
    if missing_embedded_evidence:
        raise ValueError(
            "missing libmpdec copyright/license evidence for: "
            + ", ".join(missing_embedded_evidence)
        )
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--appdir", type=Path, required=True)
    parser.add_argument("--dpkg-info-dir", type=Path, default=Path("/var/lib/dpkg/info"))
    parser.add_argument("--doc-root", type=Path, default=Path("/usr/share/doc"))
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--architecture", required=True, choices=("x86_64", "aarch64"))
    args = parser.parse_args(argv)
    try:
        result = collect_package_provenance(
            args.appdir, args.dpkg_info_dir, args.doc_root, args.output_dir,
            architecture=args.architecture,
        )
    except (OSError, ValueError) as exc:
        print(f"native license collection failed: {exc}", file=sys.stderr)
        return 1
    print(f"Collected copyright evidence for {len(result['packages'])} bundled Debian packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
