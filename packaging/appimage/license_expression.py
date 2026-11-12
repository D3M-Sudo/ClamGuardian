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
_REFERENCE_TOKEN = re.compile(
    r"(?<![A-Za-z0-9.-])(?:DocumentRef-[A-Za-z0-9.-]+:)?"
    r"LicenseRef-[A-Za-z0-9.-]+(?![A-Za-z0-9.-])"
)
_APACHE_ALIASES = {
    "apache 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
}


def load_catalog(
    licenses_path: Path, exceptions_path: Path
) -> tuple[set[str], set[str]]:
    licenses_data = json.loads(licenses_path.read_text(encoding="utf-8"))
    exceptions_data = json.loads(exceptions_path.read_text(encoding="utf-8"))
    if (
        licenses_data.get("licenseListVersion") != "3.29.0"
        or exceptions_data.get("licenseListVersion") != "3.29.0"
    ):
        raise ValueError("SPDX catalogs must both be version 3.29.0")
    licenses = {item["licenseId"] for item in licenses_data.get("licenses", [])}
    exceptions = {
        item["licenseExceptionId"] for item in exceptions_data.get("exceptions", [])
    }
    if not licenses or not exceptions:
        raise ValueError("SPDX license or exception catalog is empty")
    return licenses, exceptions


def _canonical_identifier(
    value: str, identifiers: set[str], kind: str
) -> str:
    if value in identifiers:
        return value
    matches = [item for item in identifiers if item.casefold() == value.casefold()]
    if len(matches) == 1:
        return matches[0]
    raise ValueError(f"unknown SPDX {kind} identifier: {value}")


def _is_license_ref(value: str) -> bool:
    return _LICENSE_REF.fullmatch(value) is not None


class _ExpressionParser:
    def __init__(
        self,
        expression: str,
        licenses: set[str],
        exceptions: set[str],
        refs: dict[str, Any],
    ) -> None:
        self.licenses = licenses
        self.exceptions = exceptions
        self.refs = refs
        self.tokens = self._tokenize(expression)
        self.position = 0

    @staticmethod
    def _tokenize(expression: str) -> list[str]:
        tokens: list[str] = []
        position = 0
        while position < len(expression):
            match = _TOKEN.match(expression, position)
            if not match:
                excerpt = expression[position : position + 24]
                raise ValueError(f"invalid SPDX expression near: {excerpt!r}")
            tokens.append(match.group(1))
            position = match.end()
        if not tokens:
            raise ValueError("SPDX license expression is empty")
        return tokens

    def peek(self) -> str | None:
        if self.position >= len(self.tokens):
            return None
        return self.tokens[self.position]

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
                raise ValueError("unbalanced SPDX expression parentheses")
            return f"({value})"
        if token in {")", "AND", "OR", "WITH"}:
            raise ValueError(f"expected SPDX license identifier, got {token}")
        if token in _SPECIAL:
            return token
        if _is_license_ref(token):
            extracted = self.refs.get(token)
            invalid_text = (
                not isinstance(extracted, str)
                or not extracted.strip()
                or extracted.strip().upper() in _SPECIAL
            )
            if invalid_text:
                raise ValueError(
                    f"LicenseRef {token} requires non-placeholder extracted text"
                )
            return token
        if token.endswith("+"):
            base = _canonical_identifier(token[:-1], self.licenses, "license")
            return f"{base}+"
        return _canonical_identifier(token, self.licenses, "license")

    def with_expr(self) -> str:
        value = self.atom()
        if self.peek() == "WITH":
            self.take()
            if value.startswith("(") or value in _SPECIAL or _is_license_ref(value):
                raise ValueError("SPDX WITH requires a simple SPDX license identifier")
            exception = _canonical_identifier(
                self.take(), self.exceptions, "license exception"
            )
            value = f"{value} WITH {exception}"
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
            raise ValueError(
                f"unexpected SPDX expression token: {self.take()}"
            )
        return value


def normalize_expression(
    expression: str,
    licenses: set[str],
    exceptions: set[str],
    refs: dict[str, Any] | None = None,
) -> str:
    if not isinstance(expression, str) or not expression.strip():
        raise ValueError("SPDX license expression must be non-empty")
    return _ExpressionParser(
        expression.strip(), licenses, exceptions, refs or {}
    ).parse()


def _ref_map(document: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for item in document.get("hasExtractedLicensingInfos", []):
        if isinstance(item, dict) and isinstance(item.get("licenseId"), str):
            result[item["licenseId"]] = item.get("extractedText")
    return result


def canonicalize_named_license_refs(
    document: dict[str, Any], licenses_data: dict[str, Any]
) -> None:
    """Canonicalize LicenseRefs only when their names identify an SPDX-list license."""
    by_name: dict[str, str] = {}
    for item in licenses_data.get("licenses", []):
        name = " ".join(str(item.get("name", "")).split()).casefold()
        if name and name not in by_name:
            by_name[name] = item["licenseId"]
        elif name and by_name[name] != item["licenseId"]:
            by_name.pop(name, None)
    by_name.update(_APACHE_ALIASES)

    replacements: dict[str, str] = {}
    retained: list[dict[str, Any]] = []
    for item in document.get("hasExtractedLicensingInfos", []):
        if not isinstance(item, dict):
            retained.append(item)
            continue
        reference = item.get("licenseId")
        name = " ".join(str(item.get("name", "")).split()).casefold()
        text = item.get("extractedText")
        canonical = by_name.get(name)
        placeholder = (
            not isinstance(text, str)
            or not text.strip()
            or text.strip().upper() in _SPECIAL
        )
        if isinstance(reference, str) and canonical and placeholder:
            replacements[reference] = canonical
        else:
            retained.append(item)

    if not replacements:
        return
    groups = (
        ("packages", ("licenseDeclared", "licenseConcluded")),
        ("files", ("licenseInfoInFile",)),
    )
    for group, fields in groups:
        for record in document.get(group, []):
            if not isinstance(record, dict):
                continue
            for field in fields:
                value = record.get(field)
                if isinstance(value, str):
                    record[field] = _replace_refs(value, replacements)
                elif isinstance(value, list):
                    record[field] = [
                        _replace_refs(entry, replacements)
                        if isinstance(entry, str) else entry
                        for entry in value
                    ]
    document["hasExtractedLicensingInfos"] = retained


def _replace_refs(value: str, replacements: dict[str, str]) -> str:
    return _REFERENCE_TOKEN.sub(
        lambda match: replacements.get(match.group(0), match.group(0)), value
    )


def validate_spdx_document(
    document: dict[str, Any], licenses: set[str], exceptions: set[str]
) -> None:
    refs = _ref_map(document)
    for package in document.get("packages", []):
        if not isinstance(package, dict):
            continue
        for field in ("licenseDeclared", "licenseConcluded"):
            value = package.get(field)
            if isinstance(value, str):
                normalize_expression(value, licenses, exceptions, refs)
    for file_record in document.get("files", []):
        if not isinstance(file_record, dict):
            continue
        for value in file_record.get("licenseInfoInFile", []):
            if isinstance(value, str):
                normalize_expression(value, licenses, exceptions, refs)
    for reference, extracted in refs.items():
        placeholder = (
            not isinstance(extracted, str)
            or not extracted.strip()
            or extracted.strip().upper() in _SPECIAL
        )
        if placeholder:
            raise ValueError(
                f"LicenseRef {reference} requires non-placeholder extracted text"
            )


def normalize_spdx_document(
    document: dict[str, Any],
    licenses: set[str],
    exceptions: set[str],
    licenses_data: dict[str, Any],
) -> None:
    canonicalize_named_license_refs(document, licenses_data)
    refs = _ref_map(document)
    for package in document.get("packages", []):
        if not isinstance(package, dict):
            continue
        for field in ("licenseDeclared", "licenseConcluded"):
            value = package.get(field)
            if isinstance(value, str):
                package[field] = normalize_expression(
                    value, licenses, exceptions, refs
                )
    for file_record in document.get("files", []):
        if not isinstance(file_record, dict):
            continue
        values = file_record.get("licenseInfoInFile", [])
        if isinstance(values, list):
            file_record["licenseInfoInFile"] = [
                normalize_expression(value, licenses, exceptions, refs)
                if isinstance(value, str) else value
                for value in values
            ]
    validate_spdx_document(document, licenses, exceptions)
