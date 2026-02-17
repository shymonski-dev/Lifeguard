from __future__ import annotations

import importlib.util
from typing import Any, Callable, Optional

from ..spec_schema import AgentSpec, ToolSpec
from .base import BaseActionAdapter, tool_spec_to_dict
from .contract import (
    AdapterToolSchema,
)


class LangChainCompatibilityAdapterError(RuntimeError):
    """Raised when LangChain compatibility actions cannot be completed."""


_ACTION_TO_MODULE: dict[str, str] = {
    "langchain.module_status.list": "langchain",
    "langchain.export.agent_spec": "none",
    "langchain.import.tool_bundle": "none",
}

_TOOL_SCHEMAS: tuple[AdapterToolSchema, ...] = (
    AdapterToolSchema(
        tool_name="langchain_compatibility",
        action_name="langchain.module_status.list",
        description="List local LangChain package availability status.",
        required_module="none",
        output_schema={
            "type": "object",
            "required": ["modules"],
            "properties": {"modules": {"type": "array"}},
        },
    ),
    AdapterToolSchema(
        tool_name="langchain_compatibility",
        action_name="langchain.export.agent_spec",
        description=(
            "Translate one Lifeguard agent specification into a LangChain-compatible tool bundle."
        ),
        required_module="none",
        input_schema={
            "type": "object",
            "required": ["agent_spec"],
            "properties": {"agent_spec": {"type": "object"}},
        },
        output_schema={
            "type": "object",
            "required": ["agent_name", "tool_bundle", "policy_hints"],
            "properties": {
                "agent_name": {"type": "string"},
                "tool_bundle": {"type": "array"},
                "policy_hints": {"type": "object"},
            },
        },
    ),
    AdapterToolSchema(
        tool_name="langchain_compatibility",
        action_name="langchain.import.tool_bundle",
        description=(
            "Translate a LangChain-style tool bundle into Lifeguard tool declarations and scope hints."
        ),
        required_module="none",
        input_schema={
            "type": "object",
            "required": ["tool_bundle"],
            "properties": {"tool_bundle": {"type": "array"}},
        },
        output_schema={
            "type": "object",
            "required": ["tools", "data_scope_hints", "warnings"],
            "properties": {
                "tools": {"type": "array"},
                "data_scope_hints": {"type": "object"},
                "warnings": {"type": "array"},
            },
        },
    ),
)


class LangChainCompatibilityAdapter(BaseActionAdapter):
    """External compatibility adapter for LangChain tool descriptions."""

    adapter_name = "langchain_compatibility"
    action_to_module = _ACTION_TO_MODULE

    def list_tool_schemas(self) -> tuple[AdapterToolSchema, ...]:
        return _TOOL_SCHEMAS

    def _action_payload_error_types(self) -> tuple[type[BaseException], ...]:
        return super()._action_payload_error_types() + (LangChainCompatibilityAdapterError,)

    def _resolve_action_handler(
        self, action_name: str
    ) -> Optional[Callable[[dict[str, Any]], dict[str, Any]]]:
        handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "langchain.module_status.list": self._action_module_status_list,
            "langchain.export.agent_spec": self._action_export_agent_spec,
            "langchain.import.tool_bundle": self._action_import_tool_bundle,
        }
        return handlers.get(action_name)

    def _action_module_status_list(self, payload: dict[str, Any]) -> dict[str, Any]:
        del payload
        module_names = ("langchain", "langchain_core", "langgraph")
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
            raise LangChainCompatibilityAdapterError("agent_spec must be an object.")
        spec = AgentSpec.from_dict(spec_payload)

        tool_bundle = [
            _tool_to_langchain_descriptor(
                tool,
                risk_level=spec.risk_level,
                read_paths=spec.data_scope.read_paths,
                write_paths=spec.data_scope.write_paths,
                allowed_hosts=spec.data_scope.allowed_hosts,
            )
            for tool in spec.tools
        ]
        policy_hints = {
            "risk_level": spec.risk_level,
            "runtime_environment": spec.runtime_environment,
            "read_paths": list(spec.data_scope.read_paths),
            "write_paths": list(spec.data_scope.write_paths),
            "allowed_hosts": list(spec.data_scope.allowed_hosts),
            "max_runtime_seconds": spec.max_runtime_seconds,
            "budget_limit_usd": spec.budget_limit_usd,
        }
        return {
            "agent_name": spec.name,
            "tool_bundle": tool_bundle,
            "policy_hints": policy_hints,
        }

    def _action_import_tool_bundle(self, payload: dict[str, Any]) -> dict[str, Any]:
        tool_bundle = payload.get("tool_bundle")
        if not isinstance(tool_bundle, list):
            raise LangChainCompatibilityAdapterError("tool_bundle must be a list.")

        tools: list[ToolSpec] = []
        warnings: list[str] = []
        allowed_hosts: set[str] = set()
        write_paths: set[str] = set()
        read_paths: set[str] = set()

        for item in tool_bundle:
            if not isinstance(item, dict):
                warnings.append("Skipping non-object tool bundle item.")
                continue

            tool = _langchain_descriptor_to_tool(item)
            tools.append(tool)

            metadata = item.get("metadata", {})
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
            raise LangChainCompatibilityAdapterError(
                "tool_bundle did not contain at least one valid tool descriptor."
            )

        return {
            "tools": [tool_spec_to_dict(tool) for tool in tools],
            "data_scope_hints": {
                "read_paths": sorted(read_paths),
                "write_paths": sorted(write_paths),
                "allowed_hosts": sorted(allowed_hosts),
            },
            "warnings": warnings,
        }


def _module_available(module_name: str) -> bool:
    return importlib.util.find_spec(module_name) is not None


def _tool_to_langchain_descriptor(
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
        },
    }


def _langchain_descriptor_to_tool(payload: dict[str, Any]) -> ToolSpec:
    name = str(payload.get("name", "")).strip()
    if not name:
        raise LangChainCompatibilityAdapterError("Tool descriptor is missing 'name'.")

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
        raise LangChainCompatibilityAdapterError(
            f"Tool descriptor '{name}' is missing command template metadata."
        )

    return ToolSpec(
        name=name,
        command=command,
        can_write_files=can_write_files,
        can_access_network=can_access_network,
        timeout_seconds=timeout_seconds,
    )
