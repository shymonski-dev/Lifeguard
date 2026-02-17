from __future__ import annotations

import importlib.util
import re
from typing import Any, Callable, Optional

from ..spec_schema import AgentSpec, ToolSpec
from .base import BaseActionAdapter, tool_spec_to_dict
from .contract import AdapterToolSchema


class ModelContextProtocolCompatibilityAdapterError(RuntimeError):
    """Raised when Model Context Protocol compatibility actions cannot be completed."""


_PINNED_VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z._-]+)?$")
_BLOCKED_STARTUP_KEYS = (
    "startup_command",
    "launch_command",
    "autostart_command",
    "auto_start_command",
    "init_command",
    "post_install_command",
)
_BLOCKED_STARTUP_FLAGS = (
    "one_click_start",
    "auto_start",
    "auto_run",
    "run_on_load",
)

_ACTION_TO_MODULE: dict[str, str] = {
    "mcp.module_status.list": "mcp",
    "mcp.export.agent_spec": "none",
    "mcp.import.server_bundle": "none",
}

_TOOL_SCHEMAS: tuple[AdapterToolSchema, ...] = (
    AdapterToolSchema(
        tool_name="mcp_compatibility",
        action_name="mcp.module_status.list",
        description="List local Model Context Protocol package availability status.",
        required_module="none",
        output_schema={
            "type": "object",
            "required": ["modules"],
            "properties": {"modules": {"type": "array"}},
        },
    ),
    AdapterToolSchema(
        tool_name="mcp_compatibility",
        action_name="mcp.export.agent_spec",
        description=(
            "Translate one Lifeguard agent specification into a Model Context Protocol server bundle."
        ),
        required_module="none",
        input_schema={
            "type": "object",
            "required": ["agent_spec"],
            "properties": {
                "agent_spec": {"type": "object"},
                "server_name": {"type": "string"},
                "server_version": {"type": "string"},
                "trust_profile_id": {"type": "string"},
            },
        },
        output_schema={
            "type": "object",
            "required": ["agent_name", "server_bundle", "policy_hints"],
            "properties": {
                "agent_name": {"type": "string"},
                "server_bundle": {"type": "object"},
                "policy_hints": {"type": "object"},
            },
        },
    ),
    AdapterToolSchema(
        tool_name="mcp_compatibility",
        action_name="mcp.import.server_bundle",
        description=(
            "Translate a Model Context Protocol server bundle into Lifeguard tool declarations and "
            "security gating metadata."
        ),
        required_module="none",
        input_schema={
            "type": "object",
            "required": ["server_bundle"],
            "properties": {"server_bundle": {"type": "object"}},
        },
        output_schema={
            "type": "object",
            "required": ["tools", "data_scope_hints", "gating", "warnings"],
            "properties": {
                "tools": {"type": "array"},
                "data_scope_hints": {"type": "object"},
                "gating": {"type": "object"},
                "warnings": {"type": "array"},
            },
        },
    ),
)


class ModelContextProtocolCompatibilityAdapter(BaseActionAdapter):
    """External compatibility adapter for Model Context Protocol server bundles."""

    adapter_name = "mcp_compatibility"
    action_to_module = _ACTION_TO_MODULE

    def list_tool_schemas(self) -> tuple[AdapterToolSchema, ...]:
        return _TOOL_SCHEMAS

    def _action_payload_error_types(self) -> tuple[type[BaseException], ...]:
        return super()._action_payload_error_types() + (
            ModelContextProtocolCompatibilityAdapterError,
        )

    def _resolve_action_handler(
        self, action_name: str
    ) -> Optional[Callable[[dict[str, Any]], dict[str, Any]]]:
        handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "mcp.module_status.list": self._action_module_status_list,
            "mcp.export.agent_spec": self._action_export_agent_spec,
            "mcp.import.server_bundle": self._action_import_server_bundle,
        }
        return handlers.get(action_name)

    def _action_module_status_list(self, payload: dict[str, Any]) -> dict[str, Any]:
        del payload
        module_names = ("mcp", "mcp.client", "mcp.server")
        modules = [
            {
                "module_name": module_name,
                "available": _module_available(module_name),
            }
            for module_name in module_names
        ]
        return {"modules": modules}

    def _action_export_agent_spec(self, payload: dict[str, Any]) -> dict[str, Any]:
        spec_payload = payload.get("agent_spec")
        if not isinstance(spec_payload, dict):
            raise ModelContextProtocolCompatibilityAdapterError("agent_spec must be an object.")
        spec = AgentSpec.from_dict(spec_payload)

        server_name_raw = str(payload.get("server_name", "")).strip()
        server_name = _normalize_server_name(server_name_raw or f"{spec.name}-server")
        server_version_raw = str(payload.get("server_version", "")).strip()
        server_version = _normalize_pinned_version(server_version_raw or "1.0.0")
        trust_profile_id_raw = str(payload.get("trust_profile_id", "")).strip()
        trust_profile_id = _resolve_trust_profile_id(trust_profile_id_raw, spec=spec)

        tool_bundle = [
            _tool_to_mcp_descriptor(
                tool,
                risk_level=spec.risk_level,
                read_paths=spec.data_scope.read_paths,
                write_paths=spec.data_scope.write_paths,
                allowed_hosts=spec.data_scope.allowed_hosts,
            )
            for tool in spec.tools
        ]
        server_bundle = {
            "schema": "mcp_server_bundle_v1",
            "server": {
                "server_name": server_name,
                "server_version": server_version,
                "transport": "stdio",
                "trust_profile_id": trust_profile_id,
            },
            "tools": tool_bundle,
        }
        policy_hints = {
            "risk_level": spec.risk_level,
            "runtime_environment": spec.runtime_environment,
            "read_paths": list(spec.data_scope.read_paths),
            "write_paths": list(spec.data_scope.write_paths),
            "allowed_hosts": list(spec.data_scope.allowed_hosts),
            "max_runtime_seconds": spec.max_runtime_seconds,
            "budget_limit_usd": spec.budget_limit_usd,
            "gating_mode": "deny_by_default",
            "advisory_only": False,
        }
        return {
            "agent_name": spec.name,
            "server_bundle": server_bundle,
            "policy_hints": policy_hints,
        }

    def _action_import_server_bundle(self, payload: dict[str, Any]) -> dict[str, Any]:
        server_bundle = payload.get("server_bundle")
        if not isinstance(server_bundle, dict):
            raise ModelContextProtocolCompatibilityAdapterError("server_bundle must be an object.")
        _reject_local_startup_execution(server_bundle)

        server_payload = server_bundle.get("server")
        if not isinstance(server_payload, dict):
            raise ModelContextProtocolCompatibilityAdapterError(
                "server_bundle.server must be an object."
            )
        schema = str(server_bundle.get("schema", "")).strip()
        if schema and schema != "mcp_server_bundle_v1":
            raise ModelContextProtocolCompatibilityAdapterError(
                "server_bundle.schema must be 'mcp_server_bundle_v1' when provided."
            )
        gating = _validate_server_gating(server_payload)

        tools_payload = server_bundle.get("tools")
        if not isinstance(tools_payload, list):
            raise ModelContextProtocolCompatibilityAdapterError(
                "server_bundle.tools must be a list."
            )

        tools: list[ToolSpec] = []
        warnings: list[str] = []
        allowed_hosts: set[str] = set()
        write_paths: set[str] = set()
        read_paths: set[str] = set()

        for entry in tools_payload:
            if not isinstance(entry, dict):
                warnings.append("Skipping non-object tool descriptor.")
                continue

            tool = _mcp_descriptor_to_tool(entry)
            tools.append(tool)

            metadata = entry.get("metadata", {})
            if isinstance(metadata, dict):
                for host in metadata.get("allowed_hosts", []):
                    cleaned = str(host).strip()
                    if cleaned:
                        allowed_hosts.add(cleaned)
                for path in metadata.get("write_paths", []):
                    cleaned = str(path).strip()
                    if cleaned:
                        write_paths.add(cleaned)
                for path in metadata.get("read_paths", []):
                    cleaned = str(path).strip()
                    if cleaned:
                        read_paths.add(cleaned)

        if not tools:
            raise ModelContextProtocolCompatibilityAdapterError(
                "server_bundle must contain at least one valid tool descriptor."
            )

        requires_network = any(tool.can_access_network for tool in tools)
        if requires_network and not allowed_hosts:
            raise ModelContextProtocolCompatibilityAdapterError(
                "Network-enabled tool descriptors must provide non-empty allowed_hosts metadata."
            )

        return {
            "tools": [tool_spec_to_dict(tool) for tool in tools],
            "data_scope_hints": {
                "read_paths": sorted(read_paths),
                "write_paths": sorted(write_paths),
                "allowed_hosts": sorted(allowed_hosts),
            },
            "gating": gating,
            "warnings": warnings,
        }


def _module_available(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ModuleNotFoundError, ImportError, ValueError):
        return False


def _normalize_server_name(server_name: str) -> str:
    cleaned = server_name.strip()
    if not cleaned:
        raise ModelContextProtocolCompatibilityAdapterError("server_name must not be empty.")
    if "\n" in cleaned:
        raise ModelContextProtocolCompatibilityAdapterError("server_name must be single-line.")
    return cleaned


def _normalize_pinned_version(server_version: str) -> str:
    cleaned = server_version.strip()
    if not cleaned:
        raise ModelContextProtocolCompatibilityAdapterError("server_version must not be empty.")
    if cleaned.lower() == "latest":
        raise ModelContextProtocolCompatibilityAdapterError(
            "server_version must be pinned and must not use 'latest'."
        )
    if "*" in cleaned:
        raise ModelContextProtocolCompatibilityAdapterError(
            "server_version must be pinned and must not use wildcards."
        )
    if not _PINNED_VERSION_PATTERN.match(cleaned):
        raise ModelContextProtocolCompatibilityAdapterError(
            "server_version must use pinned semantic version format."
        )
    return cleaned


def _resolve_trust_profile_id(raw_value: str, *, spec: AgentSpec) -> str:
    cleaned = raw_value.strip() or spec.live_data.trust_profile_id.strip()
    if not cleaned:
        raise ModelContextProtocolCompatibilityAdapterError(
            "trust_profile_id is required for fail-closed gating and must be explicit."
        )
    if "\n" in cleaned:
        raise ModelContextProtocolCompatibilityAdapterError(
            "trust_profile_id must be single-line."
        )
    return cleaned


def _validate_server_gating(server_payload: dict[str, Any]) -> dict[str, Any]:
    server_name = _normalize_server_name(str(server_payload.get("server_name", "")))
    server_version = _normalize_pinned_version(str(server_payload.get("server_version", "")))
    trust_profile_id = str(server_payload.get("trust_profile_id", "")).strip()
    if not trust_profile_id:
        raise ModelContextProtocolCompatibilityAdapterError(
            "server.trust_profile_id is required for fail-closed gating."
        )
    if "\n" in trust_profile_id:
        raise ModelContextProtocolCompatibilityAdapterError(
            "server.trust_profile_id must be single-line."
        )
    transport = str(server_payload.get("transport", "stdio")).strip().lower() or "stdio"
    if transport not in {"stdio", "http"}:
        raise ModelContextProtocolCompatibilityAdapterError(
            "server.transport must be either 'stdio' or 'http'."
        )
    return {
        "server_name": server_name,
        "server_version": server_version,
        "trust_profile_id": trust_profile_id,
        "transport": transport,
        "version_pinned": True,
        "trust_profile_required": True,
        "default_deny": True,
        "host_allow_list_required_for_network_tools": True,
        "startup_commands_blocked": True,
        "advisory_only": False,
        "enforcement_mode": "enforced",
    }


def _tool_to_mcp_descriptor(
    tool: ToolSpec,
    risk_level: str,
    read_paths: tuple[str, ...],
    write_paths: tuple[str, ...],
    allowed_hosts: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "name": tool.name,
        "description": f"Execute approved command template for tool '{tool.name}'.",
        "input_schema": {
            "type": "object",
            "properties": {
                "arguments": {"type": "array", "items": {"type": "string"}},
                "working_directory": {"type": "string"},
            },
            "additionalProperties": False,
        },
        "metadata": {
            "command_template": tool.command,
            "can_write_files": tool.can_write_files,
            "can_access_network": tool.can_access_network,
            "timeout_seconds": tool.timeout_seconds,
            "risk_level": risk_level,
            "read_paths": list(read_paths),
            "write_paths": list(write_paths),
            "allowed_hosts": list(allowed_hosts),
            "gating_mode": "deny_by_default",
            "advisory_only": False,
        },
    }


def _mcp_descriptor_to_tool(payload: dict[str, Any]) -> ToolSpec:
    name = str(payload.get("name", "")).strip()
    if not name:
        raise ModelContextProtocolCompatibilityAdapterError(
            "Tool descriptor is missing 'name'."
        )

    metadata = payload.get("metadata", {})
    command = ""
    can_write_files = False
    can_access_network = False
    timeout_seconds = int(payload.get("timeout_seconds", 30))

    if isinstance(metadata, dict):
        command = str(metadata.get("command_template", "")).strip()
        can_write_files = bool(metadata.get("can_write_files", False))
        can_access_network = bool(metadata.get("can_access_network", False))
        timeout_seconds = int(metadata.get("timeout_seconds", timeout_seconds))

    if not command:
        command = str(payload.get("command", "")).strip()
    if not command:
        raise ModelContextProtocolCompatibilityAdapterError(
            f"Tool descriptor '{name}' is missing command template metadata."
        )

    return ToolSpec(
        name=name,
        command=command,
        can_write_files=can_write_files,
        can_access_network=can_access_network,
        timeout_seconds=timeout_seconds,
    )


def _reject_local_startup_execution(payload: Any) -> None:
    for path, value in _iter_blocked_startup_entries(payload, path_prefix="server_bundle"):
        if value:
            raise ModelContextProtocolCompatibilityAdapterError(
                f"{path} is not allowed because local startup command execution is blocked."
            )


def _iter_blocked_startup_entries(payload: Any, *, path_prefix: str) -> list[tuple[str, Any]]:
    matches: list[tuple[str, Any]] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            key_text = str(key).strip().lower()
            child_path = f"{path_prefix}.{key}" if path_prefix else str(key)
            if key_text in _BLOCKED_STARTUP_KEYS:
                cleaned = str(value).strip() if value is not None else ""
                if cleaned:
                    matches.append((child_path, cleaned))
            if key_text in _BLOCKED_STARTUP_FLAGS and bool(value):
                matches.append((child_path, value))
            matches.extend(_iter_blocked_startup_entries(value, path_prefix=child_path))
    elif isinstance(payload, list):
        for index, entry in enumerate(payload):
            matches.extend(
                _iter_blocked_startup_entries(entry, path_prefix=f"{path_prefix}[{index}]")
            )
    return matches
