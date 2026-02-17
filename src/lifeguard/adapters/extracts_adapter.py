from __future__ import annotations

import importlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from .base import BaseActionAdapter
from .contract import (
    AdapterToolSchema,
)


class AdapterUnavailableError(RuntimeError):
    """Raised when an adapter target cannot be loaded or used."""


@dataclass(frozen=True)
class AdapterModuleStatus:
    adapter_name: str
    module_path: str
    available: bool
    detail: str = ""


_SELECTED_MODULES: dict[str, str] = {
    "circuit_breaker": "lifeguard.extracts.circuit_breaker",
    "retry": "lifeguard.extracts.retry",
    "json_parser": "lifeguard.extracts.json_parser",
    "security_preflight": "lifeguard.extracts.security_preflight",
    "analyzer_usage": "lifeguard.extracts.analyzer_usage",
    "model_registry": "lifeguard.extracts.model_registry",
    "ast_guard": "lifeguard.extracts.ast_guard",
}

_FORBIDDEN_TERMS = (
    "evolution",
    "darwin",
    "godel",
    "mutation",
    "population",
    "genetic",
    "selection",
    "fitness",
)

_ACTION_TO_MODULE: dict[str, str] = {
    "module_status.list": "none",
    "json.parse": "json_parser",
    "security_preflight.run": "security_preflight",
    "budget.set_session": "analyzer_usage",
    "budget.status": "analyzer_usage",
    "budget.check_gate": "analyzer_usage",
    "budget.record_usage": "analyzer_usage",
    "model_registry.get_model_id": "model_registry",
    "model_registry.list_known_models": "model_registry",
    "ast_guard.validate_source": "ast_guard",
}

_TOOL_SCHEMAS: tuple[AdapterToolSchema, ...] = (
    AdapterToolSchema(
        tool_name="module_status",
        action_name="module_status.list",
        description="List selected module availability for adapter readiness checks.",
        required_module="none",
        output_schema={
            "type": "object",
            "required": ["statuses"],
            "properties": {"statuses": {"type": "array"}},
        },
    ),
    AdapterToolSchema(
        tool_name="json_parser",
        action_name="json.parse",
        description="Parse model text into a JSON object with repair support.",
        required_module="json_parser",
        input_schema={
            "type": "object",
            "required": ["content"],
            "properties": {"content": {"type": "string"}, "schema": {"type": "object"}},
        },
        output_schema={
            "type": "object",
            "required": ["data"],
            "properties": {"data": {"type": "object"}},
        },
    ),
    AdapterToolSchema(
        tool_name="security_preflight",
        action_name="security_preflight.run",
        description="Run workspace preflight checks and optional secret scan.",
        required_module="security_preflight",
        input_schema={
            "type": "object",
            "properties": {"repo_path": {"type": "string"}},
        },
        output_schema={
            "type": "object",
            "required": ["passed", "error"],
            "properties": {"passed": {"type": "boolean"}, "error": {"type": "string"}},
        },
    ),
    AdapterToolSchema(
        tool_name="analyzer_usage",
        action_name="budget.set_session",
        description="Set the active budget session identifier.",
        required_module="analyzer_usage",
        input_schema={
            "type": "object",
            "required": ["session_id"],
            "properties": {"session_id": {"type": "string"}},
        },
        output_schema={
            "type": "object",
            "required": ["session_id"],
            "properties": {"session_id": {"type": "string"}},
        },
    ),
    AdapterToolSchema(
        tool_name="analyzer_usage",
        action_name="budget.status",
        description="Read budget status for a session.",
        required_module="analyzer_usage",
        input_schema={
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
        },
        output_schema={
            "type": "object",
            "required": ["status"],
            "properties": {"status": {"type": "object"}},
        },
    ),
    AdapterToolSchema(
        tool_name="analyzer_usage",
        action_name="budget.check_gate",
        description="Check budget gate readiness by estimated token usage.",
        required_module="analyzer_usage",
        input_schema={
            "type": "object",
            "properties": {
                "estimated_tokens": {"type": "integer"},
                "session_id": {"type": "string"},
            },
        },
        output_schema={
            "type": "object",
            "required": ["allowed", "reason"],
            "properties": {"allowed": {"type": "boolean"}, "reason": {"type": "string"}},
        },
    ),
    AdapterToolSchema(
        tool_name="analyzer_usage",
        action_name="budget.record_usage",
        description="Record token and call usage in a budget session.",
        required_module="analyzer_usage",
        input_schema={
            "type": "object",
            "properties": {
                "calls": {"type": "integer"},
                "tokens": {"type": "integer"},
                "session_id": {"type": "string"},
            },
        },
        output_schema={
            "type": "object",
            "required": ["recorded"],
            "properties": {"recorded": {"type": "boolean"}},
        },
    ),
    AdapterToolSchema(
        tool_name="model_registry",
        action_name="model_registry.get_model_id",
        description="Get one model identifier by pricing tier name.",
        required_module="model_registry",
        input_schema={
            "type": "object",
            "required": ["tier_name"],
            "properties": {"tier_name": {"type": "string"}},
        },
        output_schema={
            "type": "object",
            "required": ["model_id", "tier_name"],
            "properties": {"model_id": {"type": "string"}, "tier_name": {"type": "string"}},
        },
    ),
    AdapterToolSchema(
        tool_name="model_registry",
        action_name="model_registry.list_known_models",
        description="List known models and metadata from the model registry.",
        required_module="model_registry",
        output_schema={
            "type": "object",
            "required": ["models"],
            "properties": {"models": {"type": "object"}},
        },
    ),
    AdapterToolSchema(
        tool_name="ast_guard",
        action_name="ast_guard.validate_source",
        description="Run source validation using syntax and rule checks.",
        required_module="ast_guard",
        input_schema={
            "type": "object",
            "required": ["path", "new_source"],
            "properties": {
                "path": {"type": "string"},
                "new_source": {"type": "string"},
                "original_source": {"type": "string"},
                "context": {"type": "object"},
            },
        },
        output_schema={
            "type": "object",
            "required": ["result"],
            "properties": {"result": {"type": "object"}},
        },
    ),
)


class LifeguardExtractsAdapterLayer(BaseActionAdapter):
    """Stable wrapper over selected Lifeguard extracted modules."""

    adapter_name = "lifeguard_extracts"
    action_to_module = _ACTION_TO_MODULE

    def __init__(self) -> None:
        self._module_cache: dict[str, Any] = {}

    def list_tool_schemas(self) -> tuple[AdapterToolSchema, ...]:
        return _TOOL_SCHEMAS

    def _action_payload_error_types(self) -> tuple[type[BaseException], ...]:
        return super()._action_payload_error_types() + (AdapterUnavailableError,)

    def list_module_status(self) -> tuple[AdapterModuleStatus, ...]:
        statuses: list[AdapterModuleStatus] = []
        for adapter_name, module_path in _SELECTED_MODULES.items():
            try:
                self._load_module(adapter_name)
            except AdapterUnavailableError as exc:
                statuses.append(
                    AdapterModuleStatus(
                        adapter_name=adapter_name,
                        module_path=module_path,
                        available=False,
                        detail=str(exc),
                    )
                )
                continue

            statuses.append(
                AdapterModuleStatus(
                    adapter_name=adapter_name,
                    module_path=module_path,
                    available=True,
                )
            )
        return tuple(statuses)

    def create_circuit_breaker(
        self,
        failure_threshold: int = 5,
        success_threshold: int = 3,
        reset_timeout: float = 60.0,
    ) -> Any:
        module = self._load_module("circuit_breaker")
        return module.CircuitBreaker(
            failure_threshold=failure_threshold,
            success_threshold=success_threshold,
            reset_timeout=reset_timeout,
        )

    def call_with_circuit_breaker(self, breaker: Any, func: Callable[[], Any]) -> Any:
        return breaker.call(func)

    def build_retry_config(
        self,
        max_retries: int = 3,
        initial_backoff: float = 1.0,
        max_backoff: float = 60.0,
        backoff_multiplier: float = 2.0,
        jitter: float = 0.1,
    ) -> Any:
        module = self._load_module("retry")
        return module.RetryConfig(
            max_retries=max_retries,
            initial_backoff=initial_backoff,
            max_backoff=max_backoff,
            backoff_multiplier=backoff_multiplier,
            jitter=jitter,
        )

    def retry_with_backoff(
        self,
        func: Callable[[], Any],
        config: Optional[Any] = None,
        on_retry: Optional[Callable[[int, BaseException, float], None]] = None,
    ) -> Any:
        module = self._load_module("retry")
        return module.retry_with_backoff(func, config=config, on_retry=on_retry)

    def parse_json_response(
        self, content: str, schema: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        module = self._load_module("json_parser")
        parser = module.JSONParser()
        parse_error_types: tuple[type[BaseException], ...] = tuple(
            error_type
            for error_name in ("JSONExtractError", "JSONParseError", "SchemaValidationError")
            if (error_type := getattr(module, error_name, None)) is not None
            and isinstance(error_type, type)
        )
        try:
            result = parser.parse(content, schema=schema)
        except parse_error_types as exc:  # type: ignore[misc]
            raise ValueError(str(exc)) from exc
        if not isinstance(result, dict):
            raise AdapterUnavailableError("Expected JSON parser to return a JSON object.")
        return result

    def run_security_preflight(self, repo_path: Optional[Path]) -> Optional[str]:
        module = self._load_module("security_preflight")
        return module.run_preflight(repo_path)

    def set_budget_session(self, session_id: str) -> Any:
        module = self._load_module("analyzer_usage")
        return module.set_budget_session(session_id)

    def get_budget_status(self, session_id: Optional[str] = None) -> dict[str, Any]:
        module = self._load_module("analyzer_usage")
        status = module.get_budget_status(session_id)
        if hasattr(status, "to_dict"):
            return status.to_dict()
        raise AdapterUnavailableError("Budget status object is missing to_dict().")

    def check_budget_gate(
        self, estimated_tokens: int = 0, session_id: Optional[str] = None
    ) -> tuple[bool, Optional[str]]:
        module = self._load_module("analyzer_usage")
        return module.check_budget_gate(
            estimated_tokens=estimated_tokens,
            session_id=session_id,
        )

    def record_budget_usage(
        self, calls: int = 1, tokens: int = 0, session_id: Optional[str] = None
    ) -> None:
        module = self._load_module("analyzer_usage")
        module.record_budget_usage(calls=calls, tokens=tokens, session_id=session_id)

    def get_model_id(self, tier_name: str) -> str:
        module = self._load_module("model_registry")
        try:
            tier = module.ModelTier[tier_name.strip().upper()]
        except KeyError as exc:
            raise AdapterUnavailableError(f"Unknown model tier: {tier_name}") from exc
        return module.get_model_id(tier)

    def list_known_models(self) -> dict[str, dict[str, Any]]:
        module = self._load_module("model_registry")
        return module.get_known_models()

    def validate_source_with_ast_guard(
        self,
        path: Path,
        new_source: str,
        original_source: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        module = self._load_module("ast_guard")
        guard = module.get_ast_guard()
        result = guard.validate(
            path=path,
            new_source=new_source,
            original_source=original_source,
            context=context,
        )
        return {
            "success": bool(result.success),
            "message": str(result.message),
            "rule": getattr(result, "rule", ""),
            "metadata": dict(getattr(result, "metadata", {})),
        }

    def _resolve_action_handler(
        self, action_name: str
    ) -> Optional[Callable[[dict[str, Any]], dict[str, Any]]]:
        handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "module_status.list": self._action_module_status_list,
            "json.parse": self._action_json_parse,
            "security_preflight.run": self._action_security_preflight_run,
            "budget.set_session": self._action_budget_set_session,
            "budget.status": self._action_budget_status,
            "budget.check_gate": self._action_budget_check_gate,
            "budget.record_usage": self._action_budget_record_usage,
            "model_registry.get_model_id": self._action_model_registry_get_model_id,
            "model_registry.list_known_models": self._action_model_registry_list_known_models,
            "ast_guard.validate_source": self._action_ast_guard_validate_source,
        }
        return handlers.get(action_name)

    def _action_module_status_list(self, payload: dict[str, Any]) -> dict[str, Any]:
        del payload
        statuses = self.list_module_status()
        return {
            "statuses": [
                {
                    "adapter_name": status.adapter_name,
                    "module_path": status.module_path,
                    "available": status.available,
                    "detail": status.detail,
                }
                for status in statuses
            ]
        }

    def _action_json_parse(self, payload: dict[str, Any]) -> dict[str, Any]:
        content = _require_string(payload, "content")
        schema_value = payload.get("schema")
        if schema_value is not None and not isinstance(schema_value, dict):
            raise ValueError("schema must be an object when provided.")
        parsed = self.parse_json_response(content=content, schema=schema_value)
        return {"data": parsed}

    def _action_security_preflight_run(self, payload: dict[str, Any]) -> dict[str, Any]:
        repo_path_value = _optional_string(payload, "repo_path")
        repo_path = Path(repo_path_value) if repo_path_value else None
        error = self.run_security_preflight(repo_path)
        return {"passed": error is None, "error": error or ""}

    def _action_budget_set_session(self, payload: dict[str, Any]) -> dict[str, Any]:
        session_id = _require_string(payload, "session_id")
        self.set_budget_session(session_id)
        return {"session_id": session_id}

    def _action_budget_status(self, payload: dict[str, Any]) -> dict[str, Any]:
        session_id = _optional_string(payload, "session_id")
        status = self.get_budget_status(session_id=session_id)
        return {"status": status}

    def _action_budget_check_gate(self, payload: dict[str, Any]) -> dict[str, Any]:
        session_id = _optional_string(payload, "session_id")
        estimated_tokens = int(payload.get("estimated_tokens", 0))
        allowed, reason = self.check_budget_gate(
            estimated_tokens=estimated_tokens,
            session_id=session_id,
        )
        return {"allowed": allowed, "reason": reason or ""}

    def _action_budget_record_usage(self, payload: dict[str, Any]) -> dict[str, Any]:
        session_id = _optional_string(payload, "session_id")
        calls = int(payload.get("calls", 1))
        tokens = int(payload.get("tokens", 0))
        self.record_budget_usage(calls=calls, tokens=tokens, session_id=session_id)
        return {
            "recorded": True,
            "calls": calls,
            "tokens": tokens,
            "session_id": session_id or "",
        }

    def _action_model_registry_get_model_id(self, payload: dict[str, Any]) -> dict[str, Any]:
        tier_name = _require_string(payload, "tier_name")
        model_id = self.get_model_id(tier_name=tier_name)
        return {"model_id": model_id, "tier_name": tier_name}

    def _action_model_registry_list_known_models(self, payload: dict[str, Any]) -> dict[str, Any]:
        del payload
        return {"models": self.list_known_models()}

    def _action_ast_guard_validate_source(self, payload: dict[str, Any]) -> dict[str, Any]:
        path = Path(_require_string(payload, "path"))
        new_source = _require_string(payload, "new_source")
        original_source = _optional_string(payload, "original_source")
        context = payload.get("context")
        if context is not None and not isinstance(context, dict):
            raise ValueError("context must be an object when provided.")
        result = self.validate_source_with_ast_guard(
            path=path,
            new_source=new_source,
            original_source=original_source,
            context=context,
        )
        return {"result": result}

    def _load_module(self, adapter_name: str) -> Any:
        if adapter_name not in _SELECTED_MODULES:
            raise AdapterUnavailableError(f"Unknown adapter module: {adapter_name}")

        module_path = _SELECTED_MODULES[adapter_name]
        self._assert_non_evolution_module(module_path)

        cached = self._module_cache.get(module_path)
        if cached is not None:
            return cached

        try:
            module = importlib.import_module(module_path)
        except Exception as exc:  # pragma: no cover
            raise AdapterUnavailableError(
                f"Failed to load module '{module_path}': {exc}"
            ) from exc
        self._module_cache[module_path] = module
        return module

    def _assert_non_evolution_module(self, module_path: str) -> None:
        lowered = module_path.lower()
        for term in _FORBIDDEN_TERMS:
            if term in lowered:
                raise AdapterUnavailableError(
                    f"Refusing to load blocked module path: {module_path}"
                )

def _require_string(payload: dict[str, Any], key: str) -> str:
    value = str(payload.get(key, "")).strip()
    if not value:
        raise ValueError(f"'{key}' is required and must not be empty.")
    return value


def _optional_string(payload: dict[str, Any], key: str) -> Optional[str]:
    raw = payload.get(key)
    if raw is None:
        return None
    cleaned = str(raw).strip()
    return cleaned or None
