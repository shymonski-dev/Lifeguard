"""Structured JSON parsing for model responses."""

from __future__ import annotations

import json
import re
from typing import Any, Optional


class JSONExtractError(Exception):
    """Raised when no JSON payload can be located."""


class JSONParseError(Exception):
    """Raised when a JSON payload cannot be parsed."""


class SchemaValidationError(Exception):
    """Raised when parsed JSON violates the provided schema."""


class JSONParser:
    """Lightweight JSON extraction and validation helper."""

    def parse(self, content: str, schema: Optional[dict] = None) -> dict:
        json_block = self._extract_block(content)
        try:
            result = json.loads(json_block)
        except json.JSONDecodeError:
            fixed = self._fix_common_errors(json_block)
            try:
                result = json.loads(fixed)
            except json.JSONDecodeError as exc:  # pragma: no cover
                raise JSONParseError(
                    f"Failed to parse JSON: {exc}, content: {fixed[:200]}"
                ) from exc

        if schema:
            self._validate_against_schema(result, schema)
        if not isinstance(result, dict):
            raise JSONParseError("Expected JSON object at top level.")
        return result

    def _extract_block(self, content: str) -> str:
        match = re.search(r"```(?:json)?\s*\n?([\s\S]*?)\n?\s*```", content)
        if match:
            json_str = match.group(1).strip()
        else:
            brace_start = content.find("{")
            brace_end = content.rfind("}")
            bracket_start = content.find("[")
            bracket_end = content.rfind("]")

            if bracket_start != -1 and bracket_end > bracket_start:
                json_str = content[bracket_start : bracket_end + 1]
            elif brace_start != -1 and brace_end > brace_start:
                json_str = content[brace_start : brace_end + 1]
            else:
                json_str = ""

        if not json_str:
            raise JSONExtractError("No JSON found in response")
        return json_str

    def _fix_common_errors(self, json_str: str) -> str:
        def _replace_python_literals(match: re.Match[str]) -> str:
            value = match.group(1)
            trailer = match.group(2)
            mapping = {"True": "true", "False": "false", "None": "null"}
            return f": {mapping[value]}{trailer}"

        fixes = [
            (r"([{,]\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:", r'\1"\2":'),
            (r",\s*([\]}])", r"\1"),
        ]

        for pattern, replacement in fixes:
            json_str = re.sub(pattern, replacement, json_str)
        json_str = re.sub(
            r":\s*(True|False|None)\s*([,}])",
            _replace_python_literals,
            json_str,
        )

        json_str = json_str.strip()

        if not (json_str.startswith("{") or json_str.startswith("[")):
            for index, char in enumerate(json_str):
                if char in "{[":
                    json_str = json_str[index:]
                    break

        if not (json_str.endswith("}") or json_str.endswith("]")):
            for index in range(len(json_str) - 1, -1, -1):
                if json_str[index] in "}]":
                    json_str = json_str[: index + 1]
                    break

        return json_str

    def _validate_against_schema(self, instance: Any, schema: dict) -> None:
        try:
            from jsonschema import ValidationError, validate
        except ImportError as exc:  # pragma: no cover
            raise SchemaValidationError("jsonschema is required for schema validation") from exc

        try:
            validate(instance=instance, schema=schema)
        except ValidationError as exc:
            raise SchemaValidationError(f"JSON validation failed: {exc.message}") from exc
