from __future__ import annotations

from lifeguard.adapters import (
    ADAPTER_CONTRACT_VERSION,
    AdapterActionRequest,
    LangGraphCompatibilityAdapter,
)


def _sample_agent_spec() -> dict[str, object]:
    return {
        "name": "flow-compat-agent",
        "description": "Review runtime findings with explicit tool controls.",
        "risk_level": "high",
        "runtime_environment": "container",
        "budget_limit_usd": 100.0,
        "max_runtime_seconds": 1200,
        "tools": [
            {
                "name": "query_advisories",
                "command": "python query_advisories.py --input /workspace/sbom.json",
                "can_write_files": False,
                "can_access_network": True,
                "timeout_seconds": 60,
            },
            {
                "name": "summarize_findings",
                "command": "python summarize_findings.py --input /workspace/findings.json",
                "can_write_files": True,
                "can_access_network": False,
                "timeout_seconds": 45,
            },
        ],
        "data_scope": {
            "read_paths": ["/workspace"],
            "write_paths": ["/workspace/out"],
            "allowed_hosts": ["nvd.nist.gov", "api.osv.dev"],
        },
        "security_requirements": {
            "goals": [
                "Find critical runtime exposure quickly.",
                "Restrict write actions to known paths.",
            ],
            "threat_actors": [
                "External attacker with exploit kit.",
                "Insider with accidental misconfiguration.",
            ],
            "evidence_requirements": [
                "Store source references for every critical claim.",
                "Keep execution event log for review.",
            ],
        },
    }


def test_langgraph_compat_adapter_exposes_contract_and_schema() -> None:
    adapter = LangGraphCompatibilityAdapter()
    assert adapter.contract_version == ADAPTER_CONTRACT_VERSION
    actions = {schema.action_name for schema in adapter.list_tool_schemas()}
    assert actions == {
        "langgraph.module_status.list",
        "langgraph.export.agent_spec",
        "langgraph.import.flow_definition",
    }


def test_langgraph_compat_module_status_action_returns_modules() -> None:
    adapter = LangGraphCompatibilityAdapter()
    result = adapter.execute_action(
        AdapterActionRequest(action_name="langgraph.module_status.list", payload={})
    )
    assert result.ok
    module_names = {entry["module_name"] for entry in result.output["modules"]}
    assert module_names == {"langgraph", "langgraph.graph", "langchain_core"}


def test_langgraph_compat_export_agent_spec_action() -> None:
    adapter = LangGraphCompatibilityAdapter()
    result = adapter.execute_action(
        AdapterActionRequest(
            action_name="langgraph.export.agent_spec",
            payload={"agent_spec": _sample_agent_spec()},
        )
    )
    assert result.ok
    assert result.output["agent_name"] == "flow-compat-agent"
    flow = result.output["flow_definition"]
    assert flow["format"] == "langgraph_flow_v1"
    assert flow["entry_node"] == "prepare_context"
    tool_nodes = [node for node in flow["nodes"] if node.get("type") == "tool"]
    assert len(tool_nodes) == 2
    assert tool_nodes[0]["metadata"]["command_template"] == "python query_advisories.py --input /workspace/sbom.json"
    assert tool_nodes[1]["metadata"]["can_write_files"] is True


def test_langgraph_compat_import_flow_definition_action() -> None:
    adapter = LangGraphCompatibilityAdapter()
    flow_definition = {
        "format": "langgraph_flow_v1",
        "entry_node": "prepare_context",
        "nodes": [
            {
                "id": "prepare_context",
                "type": "system",
                "name": "prepare_context",
            },
            {
                "id": "tool_1_query_advisories",
                "type": "tool",
                "name": "query_advisories",
                "metadata": {
                    "command_template": "python query_advisories.py --input /workspace/sbom.json",
                    "can_access_network": True,
                    "can_write_files": False,
                    "timeout_seconds": 60,
                    "allowed_hosts": ["api.osv.dev"],
                    "read_paths": ["/workspace"],
                },
            },
        ],
        "edges": [{"from": "prepare_context", "to": "tool_1_query_advisories"}],
    }
    result = adapter.execute_action(
        AdapterActionRequest(
            action_name="langgraph.import.flow_definition",
            payload={"flow_definition": flow_definition},
        )
    )
    assert result.ok
    assert len(result.output["tools"]) == 1
    tool = result.output["tools"][0]
    assert tool["name"] == "query_advisories"
    assert tool["command"] == "python query_advisories.py --input /workspace/sbom.json"
    assert tool["can_access_network"] is True
    assert result.output["data_scope_hints"]["allowed_hosts"] == ["api.osv.dev"]
    assert result.output["warnings"] == []


def test_langgraph_compat_rejects_unknown_action() -> None:
    adapter = LangGraphCompatibilityAdapter()
    result = adapter.execute_action(
        AdapterActionRequest(action_name="langgraph.unknown", payload={})
    )
    assert not result.ok
    assert result.errors[0].code == "unknown_action"


def test_langgraph_compat_rejects_contract_version_mismatch() -> None:
    adapter = LangGraphCompatibilityAdapter()
    result = adapter.execute_action(
        AdapterActionRequest(
            action_name="langgraph.module_status.list",
            payload={},
            contract_version="0.0.1",
        )
    )
    assert not result.ok
    assert result.errors[0].code == "contract_version_mismatch"

