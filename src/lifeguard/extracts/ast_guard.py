"""Minimal source validation guard.

This is intentionally dependency-free so Lifeguard can run in minimal
container images. It provides a compatible surface for the adapter layer.
"""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass(frozen=True)
class ValidationResult:
    success: bool
    message: str = ""
    rule: str = "builtin"
    metadata: dict[str, Any] = field(default_factory=dict)


class ASTGuard:
    def validate(
        self,
        *,
        path: Path,
        new_source: str,
        original_source: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> ValidationResult:
        del original_source, context
        suffix = path.suffix.lower()
        if suffix == ".py":
            try:
                ast.parse(new_source)
            except SyntaxError as exc:
                return ValidationResult(
                    success=False,
                    message=str(exc),
                    rule="python.syntax",
                    metadata={"lineno": getattr(exc, "lineno", None)},
                )
            return ValidationResult(success=True, message="Python syntax ok", rule="python.syntax")
        if suffix == ".json":
            try:
                json.loads(new_source)
            except json.JSONDecodeError as exc:
                return ValidationResult(
                    success=False,
                    message=str(exc),
                    rule="json.syntax",
                    metadata={"pos": exc.pos},
                )
            return ValidationResult(success=True, message="JSON syntax ok", rule="json.syntax")

        return ValidationResult(success=True, message="No validation rules for file type")


_DEFAULT_GUARD = ASTGuard()


def get_ast_guard() -> ASTGuard:
    return _DEFAULT_GUARD

