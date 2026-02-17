from __future__ import annotations

import importlib.util
from typing import Any, Callable, Optional

from ..spec_schema import AgentSpec, ToolSpec
from .base import BaseActionAdapter, tool_spec_to_dict
from .contract import (
    AdapterToolSchema,
)


class LangGraphCompatibilityAdapterError(RuntimeError):
    """Raised when LangGraph compatibility actions cannot be completed."""


_ACTION_TO_MODULE: dict[str, str] = {
    "langgraph.module_status.list": "langgraph",
    "langgraph.export.agent_spec": "none",
    "langgraph.import.flow_definition": "none",
}

_TOOL_SCHEMAS: tuple[AdapterToolSchema, ...] = (
    AdapterToolSchema(
        tool_name="langgraph_compatibility",
        action_name="langgraph.module_status.list",
        description="List local LangGraph package availability status.",
        required_module="none",
        output_schema={
            "type": "object",
            "required": ["modules"],
            "properties": {"modules": {"type": "array"}},
        },
    ),
    AdapterToolSchema(
        tool_name="langgraph_compatibility",
        action_name="langgraph.export.agent_spec",
        description="Translate one Lifeguard agent specification into a LangGraph-style flow.",
        required_module="none",
        input_schema={
            "type": "object",
            "required": ["agent_spec"],
            "properties": {"agent_spec": {"type": "object"}},
        },
        output_schema={
            "type": "object",
            "required": ["agent_name", "flow_definition", "policy_hints"],
            "properties": {
                "agent_name": {"type": "string"},
                "flow_definition": {"type": "object"},
                "policy_hints": {"type": "object"},
            },
        },
    ),
    AdapterToolSchema(
        tool_name="langgraph_compatibility",
        action_name="langgraph.import.flow_definition",
        description=(
            "Translate a LangGraph-style flow definition into Lifeguard tool declarations and scope hints."
        ),
        required_module="none",
        input_schema={
            "type": "object",
            "required": ["flow_definition"],
            "properties": {"flow_definition": {"type": "object"}},
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


class LangGraphCompatibilityAdapter(BaseActionAdapter):
    """External compatibility adapter for LangGraph flow definitions."""

    adapter_name = "langgraph_compatibility"
    action_to_module = _ACTION_TO_MODULE

    def list_tool_schemas(self) -> tuple[AdapterToolSchema, ...]:
        return _TOOL_SCHEMAS

    def _action_payload_error_types(self) -> tuple[type[BaseException], ...]:
        return super()._action_payload_error_types() + (LangGraphCompatibilityAdapterError,)

    def _resolve_action_handler(
        self, action_name: str
    ) -> Optional[Callable[[dict[str, Any]], dict[str, Any]]]:
        handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "langgraph.module_status.list": self._action_module_status_list,
            "langgraph.export.agent_spec": self._action_export_agent_spec,
            "langgraph.import.flow_definition": self._action_import_flow_definition,
        }
        return handlers.get(action_name)

    def _action_module_status_list(self, payload: dict[str, Any]) -> dict[str, Any]:
        del payload
        module_names = ("langgraph", "langgraph.graph", "langchain_core")
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
            raise LangGraphCompatibilityAdapterError("agent_spec must be an object.")
        spec = AgentSpec.from_dict(spec_payload)

        flow_definition = _build_flow_definition(spec)
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
            "flow_definition": flow_definition,
            "policy_hints": policy_hints,
        }

    def _action_import_flow_definition(self, payload: dict[str, Any]) -> dict[str, Any]:
        flow_definition = payload.get("flow_definition")
        if not isinstance(flow_definition, dict):
            raise LangGraphCompatibilityAdapterError("flow_definition must be an object.")

        nodes = flow_definition.get("nodes")
        if not isinstance(nodes, list):
            raise LangGraphCompatibilityAdapterError("flow_definition.nodes must be a list.")

        tools: list[ToolSpec] = []
        warnings: list[str] = []
        allowed_hosts: set[str] = set()
        write_paths: set[str] = set()
        read_paths: set[str] = set()

        for node in nodes:
            if not isinstance(node, dict):
                warnings.append("Skipping non-object flow node.")
                continue

            node_type = str(node.get("type", "")).strip().lower()
            if node_type != "tool":
                continue

            tool = _flow_node_to_tool(node)
            tools.append(tool)

            metadata = node.get("metadata", {})
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
            raise LangGraphCompatibilityAdapterError(
                "flow_definition did not contain at least one tool node."
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
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ModuleNotFoundError, ImportError, ValueError):
        return False


def _build_flow_definition(spec: AgentSpec) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = [
        {
            "id": "prepare_context",
            "type": "system",
            "name": "prepare_context",
            "description": "Prepare task context and constraints.",
        }
    ]
    edges: list[dict[str, str]] = []

    previous_node_id = "prepare_context"
    for index, tool in enumerate(spec.tools):
        node_id = f"tool_{index+1}_{tool.name}"
        nodes.append(
            {
                "id": node_id,
                "type": "tool",
                "name": tool.name,
                "description": f"Execute tool '{tool.name}'.",
                "metadata": {
                    "command_template": tool.command,
                    "can_write_files": tool.can_write_files,
                    "can_access_network": tool.can_access_network,
                    "timeout_seconds": tool.timeout_seconds,
                    "read_paths": list(spec.data_scope.read_paths),
                    "write_paths": list(spec.data_scope.write_paths),
                    "allowed_hosts": list(spec.data_scope.allowed_hosts),
                },
            }
        )
        edges.append({"from": previous_node_id, "to": node_id})
        previous_node_id = node_id

    nodes.append(
        {
            "id": "finalize",
            "type": "system",
            "name": "finalize",
            "description": "Finalize result and evidence payload.",
        }
    )
    edges.append({"from": previous_node_id, "to": "finalize"})

    return {
        "format": "langgraph_flow_v1",
        "entry_node": "prepare_context",
        "nodes": nodes,
        "edges": edges,
    }


def _flow_node_to_tool(node: dict[str, Any]) -> ToolSpec:
    name = str(node.get("name", "")).strip() or str(node.get("id", "")).strip()
    if not name:
        raise LangGraphCompatibilityAdapterError("Tool node must include name or id.")

    metadata = node.get("metadata", {})
    command = ""
    can_write_files = False
    can_access_network = False
    timeout_seconds = int(node.get("timeout_seconds", 30))

    if isinstance(metadata, dict):
        command = str(metadata.get("command_template", "")).strip()
        can_write_files = bool(metadata.get("can_write_files", False))
        can_access_network = bool(metadata.get("can_access_network", False))
        timeout_seconds = int(metadata.get("timeout_seconds", timeout_seconds))

    if not command:
        command = str(node.get("command", "")).strip()
    if not command:
        raise LangGraphCompatibilityAdapterError(
            f"Tool node '{name}' is missing command template metadata."
        )

    return ToolSpec(
        name=name,
        command=command,
        can_write_files=can_write_files,
        can_access_network=can_access_network,
        timeout_seconds=timeout_seconds,
    )
