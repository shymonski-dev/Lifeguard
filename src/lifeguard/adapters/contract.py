from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

ADAPTER_CONTRACT_VERSION = "1.0.0"
_VALID_RISK_LEVELS = {"", "low", "medium", "high"}
_VALID_ERROR_CATEGORIES = {
    "validation",
    "configuration",
    "availability",
    "runtime",
    "timeout",
}


class AdapterContractError(ValueError):
    """Raised when adapter contract data is invalid."""


@dataclass(frozen=True)
class AdapterTrustMetadata:
    risk_level: str = ""
    trust_profile_id: str = ""
    allowed_domains: tuple[str, ...] = ()
    high_trust_domains: tuple[str, ...] = ()
    medium_trust_domains: tuple[str, ...] = ()
    min_trusted_citations: int = 0
    min_independent_trusted_domains: int = 0
    enforce_freshness: bool = True
    require_publication_dates: bool = False

    def __post_init__(self) -> None:
        if self.risk_level not in _VALID_RISK_LEVELS:
            raise AdapterContractError(
                "trust.risk_level must be one of '', 'low', 'medium', 'high'."
            )
        if "\n" in self.trust_profile_id:
            raise AdapterContractError("trust.trust_profile_id must be single-line.")
        for host in (*self.allowed_domains, *self.high_trust_domains, *self.medium_trust_domains):
            cleaned = host.strip()
            if not cleaned:
                raise AdapterContractError("trust domains must not be empty.")
            if " " in cleaned:
                raise AdapterContractError(
                    f"trust domain '{host}' must not contain whitespace."
                )
        if self.min_trusted_citations < 0:
            raise AdapterContractError("trust.min_trusted_citations must be at least 0.")
        if self.min_independent_trusted_domains < 0:
            raise AdapterContractError(
                "trust.min_independent_trusted_domains must be at least 0."
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_level": self.risk_level,
            "trust_profile_id": self.trust_profile_id,
            "allowed_domains": list(self.allowed_domains),
            "high_trust_domains": list(self.high_trust_domains),
            "medium_trust_domains": list(self.medium_trust_domains),
            "min_trusted_citations": self.min_trusted_citations,
            "min_independent_trusted_domains": self.min_independent_trusted_domains,
            "enforce_freshness": self.enforce_freshness,
            "require_publication_dates": self.require_publication_dates,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> AdapterTrustMetadata:
        return cls(
            risk_level=str(payload.get("risk_level", "")).strip(),
            trust_profile_id=str(payload.get("trust_profile_id", "")).strip(),
            allowed_domains=tuple(str(item).strip() for item in payload.get("allowed_domains", [])),
            high_trust_domains=tuple(
                str(item).strip() for item in payload.get("high_trust_domains", [])
            ),
            medium_trust_domains=tuple(
                str(item).strip() for item in payload.get("medium_trust_domains", [])
            ),
            min_trusted_citations=int(payload.get("min_trusted_citations", 0)),
            min_independent_trusted_domains=int(
                payload.get("min_independent_trusted_domains", 0)
            ),
            enforce_freshness=bool(payload.get("enforce_freshness", True)),
            require_publication_dates=bool(payload.get("require_publication_dates", False)),
        )


@dataclass(frozen=True)
class AdapterToolSchema:
    tool_name: str
    action_name: str
    description: str
    required_module: str
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)
    can_write_files: bool = False
    can_access_network: bool = False
    default_timeout_seconds: int = 30

    def __post_init__(self) -> None:
        if not self.tool_name.strip():
            raise AdapterContractError("tool_name must not be empty.")
        if not self.action_name.strip():
            raise AdapterContractError("action_name must not be empty.")
        if not self.required_module.strip():
            raise AdapterContractError("required_module must not be empty.")
        if self.default_timeout_seconds <= 0:
            raise AdapterContractError("default_timeout_seconds must be positive.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "action_name": self.action_name,
            "description": self.description,
            "required_module": self.required_module,
            "input_schema": dict(self.input_schema),
            "output_schema": dict(self.output_schema),
            "can_write_files": self.can_write_files,
            "can_access_network": self.can_access_network,
            "default_timeout_seconds": self.default_timeout_seconds,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> AdapterToolSchema:
        input_schema = payload.get("input_schema", {})
        output_schema = payload.get("output_schema", {})
        return cls(
            tool_name=str(payload.get("tool_name", "")).strip(),
            action_name=str(payload.get("action_name", "")).strip(),
            description=str(payload.get("description", "")).strip(),
            required_module=str(payload.get("required_module", "")).strip(),
            input_schema=dict(input_schema) if isinstance(input_schema, dict) else {},
            output_schema=dict(output_schema) if isinstance(output_schema, dict) else {},
            can_write_files=bool(payload.get("can_write_files", False)),
            can_access_network=bool(payload.get("can_access_network", False)),
            default_timeout_seconds=int(payload.get("default_timeout_seconds", 30)),
        )


@dataclass(frozen=True)
class AdapterActionRequest:
    action_name: str
    payload: dict[str, Any] = field(default_factory=dict)
    contract_version: str = ADAPTER_CONTRACT_VERSION
    request_id: str = ""
    tool_name: str = ""
    trust: AdapterTrustMetadata = field(default_factory=AdapterTrustMetadata)
    context: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.action_name.strip():
            raise AdapterContractError("action_name must not be empty.")
        if not self.contract_version.strip():
            raise AdapterContractError("contract_version must not be empty.")
        if "\n" in self.request_id:
            raise AdapterContractError("request_id must be single-line.")
        if "\n" in self.tool_name:
            raise AdapterContractError("tool_name must be single-line.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_name": self.action_name,
            "payload": dict(self.payload),
            "contract_version": self.contract_version,
            "request_id": self.request_id,
            "tool_name": self.tool_name,
            "trust": self.trust.to_dict(),
            "context": dict(self.context),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> AdapterActionRequest:
        request_payload = payload.get("payload", {})
        context_payload = payload.get("context", {})
        trust_payload = payload.get("trust", {})
        return cls(
            action_name=str(payload.get("action_name", "")).strip(),
            payload=dict(request_payload) if isinstance(request_payload, dict) else {},
            contract_version=str(payload.get("contract_version", ADAPTER_CONTRACT_VERSION)).strip(),
            request_id=str(payload.get("request_id", "")).strip(),
            tool_name=str(payload.get("tool_name", "")).strip(),
            trust=AdapterTrustMetadata.from_dict(trust_payload)
            if isinstance(trust_payload, dict)
            else AdapterTrustMetadata(),
            context=dict(context_payload) if isinstance(context_payload, dict) else {},
        )


@dataclass(frozen=True)
class AdapterError:
    code: str
    message: str
    category: str = "runtime"
    retriable: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.code.strip():
            raise AdapterContractError("error code must not be empty.")
        if not self.message.strip():
            raise AdapterContractError("error message must not be empty.")
        if self.category not in _VALID_ERROR_CATEGORIES:
            raise AdapterContractError(
                "error category must be one of "
                f"{sorted(_VALID_ERROR_CATEGORIES)}."
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "category": self.category,
            "retriable": self.retriable,
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> AdapterError:
        details = payload.get("details", {})
        return cls(
            code=str(payload.get("code", "")).strip(),
            message=str(payload.get("message", "")).strip(),
            category=str(payload.get("category", "runtime")).strip(),
            retriable=bool(payload.get("retriable", False)),
            details=dict(details) if isinstance(details, dict) else {},
        )


@dataclass(frozen=True)
class AdapterActionResult:
    action_name: str
    ok: bool
    output: dict[str, Any] = field(default_factory=dict)
    errors: tuple[AdapterError, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)
    contract_version: str = ADAPTER_CONTRACT_VERSION
    trust: AdapterTrustMetadata = field(default_factory=AdapterTrustMetadata)

    def __post_init__(self) -> None:
        if not self.action_name.strip():
            raise AdapterContractError("action_name must not be empty.")
        if not self.contract_version.strip():
            raise AdapterContractError("contract_version must not be empty.")
        if self.ok and self.errors:
            raise AdapterContractError("result cannot be ok=True when errors are present.")
        if not self.ok and not self.errors:
            raise AdapterContractError("result cannot be ok=False with no errors.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_name": self.action_name,
            "ok": self.ok,
            "output": dict(self.output),
            "errors": [error.to_dict() for error in self.errors],
            "metadata": dict(self.metadata),
            "contract_version": self.contract_version,
            "trust": self.trust.to_dict(),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> AdapterActionResult:
        errors_payload = payload.get("errors", [])
        output_payload = payload.get("output", {})
        metadata_payload = payload.get("metadata", {})
        trust_payload = payload.get("trust", {})
        return cls(
            action_name=str(payload.get("action_name", "")).strip(),
            ok=bool(payload.get("ok", False)),
            output=dict(output_payload) if isinstance(output_payload, dict) else {},
            errors=tuple(
                AdapterError.from_dict(item) for item in errors_payload if isinstance(item, dict)
            ),
            metadata=dict(metadata_payload) if isinstance(metadata_payload, dict) else {},
            contract_version=str(payload.get("contract_version", ADAPTER_CONTRACT_VERSION)).strip(),
            trust=AdapterTrustMetadata.from_dict(trust_payload)
            if isinstance(trust_payload, dict)
            else AdapterTrustMetadata(),
        )


class StableAdapterContract(Protocol):
    @property
    def contract_version(self) -> str:
        """Returns the adapter contract version string."""

    def list_tool_schemas(self) -> tuple[AdapterToolSchema, ...]:
        """Returns all supported tool schema definitions."""

    def execute_action(self, request: AdapterActionRequest) -> AdapterActionResult:
        """Executes one action and returns a typed result."""

