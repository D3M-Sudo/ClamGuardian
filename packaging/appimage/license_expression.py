#!/usr/bin/env python3
"""Semantic SPDX 2.3 license-expression validation against a pinned SPDX catalog."""
from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Any

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9][A-Za-z0-9.:-]*(?:\+)?)")
_LICENSE_REF = re.compile(r"^(?:DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-[A-Za-z0-9.-]+$")
_SPECIAL = {"NONE", "NOASSERTION"}
_REFERENCE_TOKEN = re.compile(r"(?<![A-Za-z0-9.-])(?:DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-[A-Za-z0-9.-]+(?![A-Za-z0-9.-])")
_APACHE_ALIASES = {"apache 2.0": "Apache-2.0", "apache license 2.0": "Apache-2.0"}

def load_catalog(licenses_path: Path, exceptions_path: Path) -> tuple[set[str], set[str]]:
    licenses_data = json.loads(licenses_path.read_text(encoding="utf-8"))
    exceptions_data = json.loads(exceptions_path.read_text(encoding="utf-8"))
    if licenses_data.get("licenseListVersion") != "3.29.0" or exceptions_data.get("licenseListVersion") != "3.29.0":
        raise ValueError("SPDX license and exception catalogs must be version 3.29.0")
    licenses = {item["licenseId"] for item in licenses_data.get("licenses", [])}
    exceptions = {item["licenseExceptionId"] for item in exceptions_data.get("exceptions", [])}
    if not licenses or not exceptions:
        raise ValueError("SPDX license catalog or exception catalog is empty")
    return licenses, exceptions

def _canonical_identifier(value: str, identifiers: set[str], kind: str) -> str:
    if value in identifiers:
        return value
    matches = [item for item in identifiers if item.casefold() == value.casefold()]
    if len(matches) == 1:
        return matches[0]
    raise ValueError(f"unknown SPDX {kind} identifier: {value}")

def _is_license_ref(value: str) -> bool:
    return _LICENSE_REF.fullmatch(value) is not None

class _ExpressionParser:
    def __init__(self, expression: str, licenses: set[str], exceptions: set[str], refs: dict[str, Any]) -> None:
        self.licenses, self.exceptions, self.refs = licenses, exceptions, refs
        self.tokens = self._tokenize(expression)
        self.position = 0

    @staticmethod
    def _tokenize(expression: str) -> list[str]:
        tokens, position = [], 0
        while position < len(expression):
            match = _TOKEN.match(expression, position)
            if not match:
                raise ValueError(f"invalid SPDX license expression near: {expression[position:position + 24]!r}")
            tokens.append(match.group(1))
            position = match.end()
        if not tokens:
            raise ValueError("SPDX license expression is empty")
        return tokens

    def peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def take(self) -> str:
        token = self.peek()
        if token is None:
            raise ValueError("unexpected end of SPDX license expression")
        self.position += 1
        return token

    def atom(self) -> str:
        token = self.take()
        if token == "(":
            value = self.or_expr()
            if self.take() != ")":
                raise ValueError("unbalanced parentheses in SPDX license expression")
            return f"({value})"
        if token in {")", "AND", "OR", "WITH"}:
            raise ValueError(f"expected SPDX license identifier, got {token}")
        if token in _SPECIAL:
            return token
        if _is_license_ref(token):
            text = self.refs.get(token)
            if not isinstance(text, str) or not text.strip() or text.strip().upper() in _SPECIAL:
                raise ValueError(f"LicenseRef {token} requires non-placeholder extracted text")
            return token
        if token.endswith("+"):
            return _canonical_identifier(token[:-1], self.licenses, "license") + "+"
        return _canonical_identifier(token, self.licenses, "license")

    def with_expr(self) -> str:
        value = self.atom()
        if self.peek() == "WITH":
            self.take()
            if value.startswith("(") or value in _SPECIAL or _is_license_ref(value):
                raise ValueError("SPDX WITH requires a simple SPDX license identifier")
            value += " WITH " + _canonical_identifier(self.take(), self.exceptions, "license exception")
        return value

    def and_expr(self) -> str:
        values = [self.with_expr()]
        while self.peek() == "AND":
            self.take()
            values.append(self.with_expr())
        return " AND ".join(values)

    def or_expr(self) -> str:
        values = [self.and_expr()]
        while self.peek() == "OR":
            self.take()
            values.append(self.and_expr())
        return " OR ".join(values)

    def parse(self) -> str:
        value = self.or_expr()
        if self.peek() is not None:
            raise ValueError(f"unexpected token in SPDX license expression: {self.take()}")
        return value

def normalize_expression(expression: str, licenses: set[str], exceptions: set[str], refs: dict[str, Any] | None = None) -> str:
    if not isinstance(expression, str) or not expression.strip():
        raise ValueError("SPDX license expression must be a non-empty string")
    return _ExpressionParser(expression.strip(), licenses, exceptions, refs or {}).parse()

def _ref_map(document: dict[str, Any]) -> dict[str, Any]:
    return {item["licenseId"]: item.get("extractedText") for item in document.get("hasExtractedLicensingInfos", [])
            if isinstance(item, dict) and isinstance(item.get("licenseId"), str)}

def canonicalize_named_license_refs(document: dict[str, Any], licenses_data: dict[str, Any]) -> None:
    """Canonicalize Syft LicenseRefs only when their names identify an SPDX-list license."""
    by_name: dict[str, str] = {}
    for item in licenses_data.get("licenses", []):
        key = " ".join(str(item.get("name", "")).split()).casefold()
        if key and key not in by_name:
            by_name[key] = item["licenseId"]
        elif key and by_name[key] != item["licenseId"]:
            by_name.pop(key, None)
    by_name.update(_APACHE_ALIASES)
    replacements, retained = {}, []
    for item in document.get("hasExtractedLicensingInfos", []):
        if not isinstance(item, dict):
            retained.append(item)
            continue
        ref = item.get("licenseId")
        name = " ".join(str(item.get("name", "")).split()).casefold()
        text = item.get("extractedText")
        canonical = by_name.get(name)
        if isinstance(ref, str) and canonical and (
            not isinstance(text, str) or not text.strip() or text.strip().upper() in _SPECIAL
        ):
            replacements[ref] = canonical
        else:
            retained.append(item)
    if not replacements:
        return
    for group, fields in (("packages", ("licenseDeclared", "licenseConcluded")), ("files", ("licenseInfoInFile",))):
        for record in document.get(group, []):
            if not isinstance(record, dict):
                continue
            for field in fields:
                value = record.get(field)
                if isinstance(value, str):
                    record[field] = _REFERENCE_TOKEN.sub(lambda m: replacements.get(m.group(0), m.group(0)), value)
                elif isinstance(value, list):
                    record[field] = [_REFERENCE_TOKEN.sub(lambda m: replacements.get(m.group(0), m.group(0)), v)
                                     if isinstance(v, str) else v for v in value]
    document["hasExtractedLicensingInfos"] = retained

def validate_spdx_document(document: dict[str, Any], licenses: set[str], exceptions: set[str]) -> None:
    refs = _ref_map(document)
    for package in document.get("packages", []):
        if isinstance(package, dict):
            for field in ("licenseDeclared", "licenseConcluded"):
                value = package.get(field)
                if isinstance(value, str):
                    normalize_expression(value, licenses, exceptions, refs)
    for file_record in document.get("files", []):
        if isinstance(file_record, dict):
            for value in file_record.get("licenseInfoInFile", []):
                if isinstance(value, str):
                    normalize_expression(value, licenses, exceptions, refs)
    for ref, text in refs.items():
        if not isinstance(text, str) or not text.strip() or text.strip().upper() in _SPECIAL:
            raise ValueError(f"LicenseRef {ref} requires non-placeholder extracted text")

def normalize_spdx_document(document: dict[str, Any], licenses: set[str], exceptions: set[str], licenses_data: dict[str, Any]) -> None:
    canonicalize_named_license_refs(document, licenses_data)
    refs = _ref_map(document)
    for package in document.get("packages", []):
        if isinstance(package, dict):
            for field in ("licenseDeclared", "licenseConcluded"):
                value = package.get(field)
                if isinstance(value, str):
                    package[field] = normalize_expression(value, licenses, exceptions, refs)
    for file_record in document.get("files", []):
        if isinstance(file_record, dict):
            values = file_record.get("licenseInfoInFile", [])
            if isinstance(values, list):
                file_record["licenseInfoInFile"] = [normalize_expression(v, licenses, exceptions, refs)
                                                    if isinstance(v, str) else v for v in values]
    validate_spdx_document(document, licenses, exceptions)
