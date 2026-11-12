#!/usr/bin/env python3
"""Semantic SPDX 2.3 license-expression validation against a pinned SPDX catalog."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9][A-Za-z0-9.-]*(?:\+)?)")
_LICENSE_REF = re.compile(r"^(?:DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-[A-Za-z0-9.-]+$")
_SPECIAL = {"NONE", "NOASSERTION"}


def load_catalog(licenses_path: Path, exceptions_path: Path) -> tuple[set[str], set[str]]:
    """Load canonical SPDX license and exception identifiers from pinned JSON."""
    licenses_data = json.loads(licenses_path.read_text(encoding="utf-8"))
    exceptions_data = json.loads(exceptions_path.read_text(encoding="utf-8"))
    if licenses_data.get("licenseListVersion") != "3.29.0":
        raise ValueError("SPDX license catalog must be version 3.29.0")
    if exceptions_data.get("licenseListVersion") != "3.29.0":
        raise ValueError("SPDX exception catalog must be version 3.29.0")
    licenses = {item["licenseId"] for item in licenses_data.get("licenses", [])}
    exceptions = {item["licenseExceptionId"] for item in exceptions_data.get("exceptions", [])}
    if not licenses or not exceptions:
        raise ValueError("SPDX license catalog or exception catalog is empty")
    return licenses, exceptions


def _canonical_identifier(
    value: str, identifiers: set[str], *, kind: str
) -> str:
    if value in identifiers:
        return value
    matches = [item for item in identifiers if item.casefold() == value.casefold()]
    if len(matches) == 1:
        return matches[0]
    raise ValueError(f"unknown SPDX {kind} identifier: {value}")


class _ExpressionParser:
    def __init__(
        self,
        expression: str,
        licenses: set[str],
        exceptions: set[str],
        license_refs: dict[str, Any],
    ) -> None:
        self.expression = expression
        self.licenses = licenses
        self.exceptions = exceptions
        self.license_refs = license_refs
        self.tokens = self._tokenize(expression)
        self.position = 0

    @staticmethod
    def _tokenize(expression: str) -> list[str]:
        tokens: list[str] = []
        position = 0
        while position < len(expression):
            match = _TOKEN.match(expression, position)
            if not match:
                raise ValueError(
                    f"invalid SPDX license expression near: {expression[position:position + 24]!r}"
                )
            tokens.append(match.group(1))
            position = match.end()
        if not tokens:
            raise ValueError("SPDX license expression is empty")
        return tokens

    def _peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def _take(self) -> str:
        token = self._peek()
        if token is None:
            raise ValueError("unexpected end of SPDX license expression")
        self.position += 1
        return token

    def _license_atom(self) -> str:
        token = self._take()
        if token == "(":
            value = self._or_expression()
            if self._take() != ")":
                raise ValueError("unbalanced parentheses in SPDX license expression")
            return f"({value})"
        if token in {")", "AND", "OR", "WITH"}:
            raise ValueError(f"expected SPDX license identifier, got {token}")
        if token in _SPECIAL:
            return token
        if _LICENSE_REF.fullmatch(token):
            extracted = self.license_refs.get(token)
            if not isinstance(extracted, str) or not extracted.strip() or extracted.strip().upper() in _SPECIAL:
                raise ValueError(
                    f"LicenseRef {token} requires non-placeholder extracted text"
                )
            return token
        if token.endswith("+"):
            base = _canonical_identifier(token[:-1], self.licenses, kind="license")
            return f"{base}+"
        return _canonical_identifier(token, self.licenses, kind="license")

    def _with_expression(self) -> str:
        value = self._license_atom()
        if self._peek() == "WITH":
            self._take()
            if value.startswith("(") or value in _SPECIAL or value.startswith("LicenseRef-"):
                raise ValueError("SPDX WITH requires a simple SPDX license identifier")
            exception = self._canonical_identifier(
                self._take(), self.exceptions, kind="license exception"
            )
            value = f"{value} WITH {exception}"
        return value

    def _and_expression(self) -> str:
        values = [self._with_expression()]
        while self._peek() == "AND":
            self._take()
            values.append(self._with_expression())
        return " AND ".join(values)

    def _or_expression(self) -> str:
        values = [self._and_expression()]
        while self._peek() == "OR":
            self._take()
            values.append(self._and_expression())
        return " OR ".join(values)

    def parse(self) -> str:
        value = self._or_expression()
        if self._peek() is not None:
            token = self._take()
            raise ValueError(f"unexpected token in SPDX license expression: {token}")
        return value


def normalize_expression(
    expression: str,
    licenses: set[str],
    exceptions: set[str],
    license_refs: dict[str, Any] | None = None,
) -> str:
    """Validate and canonicalize a single SPDX 2.3 expression."""
    if not isinstance(expression, str) or not expression.strip():
        raise ValueError("SPDX license expression must be a non-empty string")
    return _ExpressionParser(
        expression.strip(), licenses, exceptions, license_refs or {}
    ).parse()


def _license_ref_map(document: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for item in document.get("hasExtractedLicensingInfos", []):
        if isinstance(item, dict) and isinstance(item.get("licenseId"), str):
            result[item["licenseId"]] = item.get("extractedText")
    return result


def validate_spdx_document(
    document: dict[str, Any], licenses: set[str], exceptions: set[str]
) -> None:
    """Validate all SPDX license expressions and extracted LicenseRef definitions."""
    refs = _license_ref_map(document)
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
        if not isinstance(extracted, str) or not extracted.strip() or extracted.strip().upper() in _SPECIAL:
            raise ValueError(f"LicenseRef {reference} requires non-placeholder extracted text")


def normalize_spdx_document(document: dict[str, Any], licenses: set[str], exceptions: set[str]) -> None:
    """Canonicalize SPDX identifiers in declared/concluded and file-level expressions."""
    refs = _license_ref_map(document)
    for package in document.get("packages", []):
        if not isinstance(package, dict):
            continue
        for field in ("licenseDeclared", "licenseConcluded"):
            value = package.get(field)
            if isinstance(value, str):
                package[field] = normalize_expression(value, licenses, exceptions, refs)
    for file_record in document.get("files", []):
        if not isinstance(file_record, dict):
            continue
        values = file_record.get("licenseInfoInFile", [])
        if isinstance(values, list):
            file_record["licenseInfoInFile"] = [
                normalize_expression(value, licenses, exceptions, refs)
                if isinstance(value, str) else value for value in values
            ]
