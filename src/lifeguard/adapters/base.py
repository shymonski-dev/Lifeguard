from __future__ import annotations

from typing import Any, Callable, Mapping, Optional

from ..spec_schema import ToolSpec
from .contract import (
    ADAPTER_CONTRACT_VERSION,
    AdapterActionRequest,
    AdapterActionResult,
    AdapterError,
    AdapterTrustMetadata,
)

ActionHandler = Callable[[dict[str, Any]], dict[str, Any]]


class BaseActionAdapter:
    """Shared request validation and action execution flow for adapters."""

    adapter_name: str = ""
    action_to_module: Mapping[str, str] = {}

    @property
    def contract_version(self) -> str:
        return ADAPTER_CONTRACT_VERSION

    def execute_action(self, request: AdapterActionRequest) -> AdapterActionResult:
        if not isinstance(request, AdapterActionRequest):
            return self._error_result(
                action_name="invalid",
                request_id="",
                code="invalid_request_type",
                message="request must be AdapterActionRequest.",
                category="validation",
                trust=None,
            )

        action_name = request.action_name.strip().lower()
        metadata = self._build_metadata(action_name=action_name, request=request)

        if request.contract_version != self.contract_version:
            return self._error_result(
                action_name=action_name,
                request_id=request.request_id,
                code="contract_version_mismatch",
                message=(
                    f"Unsupported contract version '{request.contract_version}'. "
                    f"Expected '{self.contract_version}'."
                ),
                category="configuration",
                trust=request.trust,
                metadata=metadata,
            )

        handler = self._resolve_action_handler(action_name)
        if handler is None:
            return self._error_result(
                action_name=action_name,
                request_id=request.request_id,
                code="unknown_action",
                message=f"Unknown action '{action_name}'.",
                category="validation",
                trust=request.trust,
                metadata=metadata,
            )

        try:
            output = handler(request.payload)
        except self._action_payload_error_types() as exc:
            return self._error_result(
                action_name=action_name,
                request_id=request.request_id,
                code="invalid_action_payload",
                message=str(exc),
                category="validation",
                trust=request.trust,
                metadata=metadata,
            )
        except Exception as exc:  # pragma: no cover - safety guard
            return self._error_result(
                action_name=action_name,
                request_id=request.request_id,
                code="action_runtime_error",
                message=str(exc),
                category="runtime",
                trust=request.trust,
                metadata=metadata,
            )

        return AdapterActionResult(
            action_name=action_name,
            ok=True,
            output=output,
            metadata=metadata,
            contract_version=self.contract_version,
            trust=request.trust,
        )

    def _resolve_action_handler(self, action_name: str) -> Optional[ActionHandler]:
        raise NotImplementedError("Subclasses must implement _resolve_action_handler().")

    def _build_metadata(
        self, action_name: str, request: AdapterActionRequest
    ) -> dict[str, Any]:
        metadata: dict[str, Any] = {
            "adapter": self.adapter_name,
            "request_id": request.request_id,
        }
        module_name = self.action_to_module.get(action_name)
        if module_name is not None:
            metadata["required_module"] = module_name
        if request.tool_name.strip():
            metadata["tool_name"] = request.tool_name.strip()
        return metadata

    def _action_payload_error_types(self) -> tuple[type[BaseException], ...]:
        return (TypeError, ValueError, KeyError)

    def _default_trust_metadata(self) -> AdapterTrustMetadata:
        return AdapterTrustMetadata()

    def _error_result(
        self,
        action_name: str,
        request_id: str,
        code: str,
        message: str,
        category: str,
        trust: AdapterTrustMetadata | None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> AdapterActionResult:
        result_metadata = dict(metadata or {})
        if request_id:
            result_metadata["request_id"] = request_id
        return AdapterActionResult(
            action_name=action_name,
            ok=False,
            errors=(AdapterError(code=code, message=message, category=category),),
            metadata=result_metadata,
            contract_version=self.contract_version,
            trust=trust if trust is not None else self._default_trust_metadata(),
        )


def tool_spec_to_dict(tool: ToolSpec) -> dict[str, Any]:
    return {
        "name": tool.name,
        "command": tool.command,
        "can_write_files": tool.can_write_files,
        "can_access_network": tool.can_access_network,
        "timeout_seconds": tool.timeout_seconds,
    }
