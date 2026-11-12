from __future__ import annotations

import json
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APPIMAGE = ROOT / "packaging" / "appimage"


def _load_collector():
    path = APPIMAGE / "collect-licenses.py"
    spec = importlib.util.spec_from_file_location("collect_licenses", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_libmpdec_two_clause_license_is_resolved_from_scoped_notice():
    notice = b"""Files: Modules/_decimal/libmpdec/*
Copyright: Copyright (c) 2008-2012 Stefan Krah. All rights reserved.
License: Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met.
 .
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 .
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 .
 THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 SUCH DAMAGE.
"""
    assert _load_collector()._libmpdec_evidence(notice) == (
        True,
        "BSD-2-Clause",
        "verified",
    )


def test_libmpdec_license_requires_both_source_and_binary_conditions():
    incomplete = b"""Files: Modules/_decimal/libmpdec/*
Copyright: Stefan Krah
License: Redistribution and use in source and binary forms are permitted.
 1. Redistributions of source code must retain this notice.
"""
    assert _load_collector()._libmpdec_evidence(incomplete) == (
        True,
        "NOASSERTION",
        "unknown",
    )


def test_runtime_inventory_does_not_claim_unproven_mimalloc_version():
    inventory = json.loads(
        (APPIMAGE / "licenses" / "runtime-type2.json").read_text(encoding="utf-8")
    )
    components = {item["id"]: item for item in inventory["components"]}
    mimalloc = components["runtime-mimalloc"]
    assert mimalloc["version"] is None
    assert mimalloc["version_status"] == "unknown"
    assert mimalloc["source_package"] is None
    assert mimalloc["verification_status"] == "partial"


def test_runtime_inventory_matches_embedded_zstd_version_evidence():
    inventory = json.loads(
        (APPIMAGE / "licenses" / "runtime-type2.json").read_text(encoding="utf-8")
    )
    components = {item["id"]: item for item in inventory["components"]}
    zstd = components["runtime-zstd"]
    assert zstd["version"] == "1.5.6"
    assert zstd["version_status"] == "verified"
    assert "runtime binary" in zstd["source"].casefold()
