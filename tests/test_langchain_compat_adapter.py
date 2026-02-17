from __future__ import annotations

from lifeguard.adapters import (
    ADAPTER_CONTRACT_VERSION,
    AdapterActionRequest,
    LangChainCompatibilityAdapter,
)


def _sample_agent_spec() -> dict[str, object]:
    return {
        "name": "compatibility-agent",
        "description": "Review dependencies and report known risks.",
        "risk_level": "medium",
        "runtime_environment": "container",
        "budget_limit_usd": 120.0,
        "max_runtime_seconds": 900,
        "tools": [
            {
                "name": "dependency_scan",
                "command": "python scan_dependencies.py --path /workspace",
                "can_write_files": False,
                "can_access_network": True,
                "timeout_seconds": 45,
            }
        ],
        "data_scope": {
            "read_paths": ["/workspace"],
            "write_paths": [],
            "allowed_hosts": ["pypi.org", "nvd.nist.gov"],
        },
        "security_requirements": {
            "goals": [
                "Detect vulnerable dependency versions.",
                "Preserve repository confidentiality.",
            ],
            "threat_actors": [
                "Malicious package maintainers.",
                "External attackers probing exposed services.",
            ],
            "evidence_requirements": [
                "Produce a machine-readable findings report.",
                "Cite vulnerability source records.",
            ],
        },
    }


def test_langchain_compat_adapter_exposes_contract_and_schema() -> None:
    adapter = LangChainCompatibilityAdapter()
    assert adapter.contract_version == ADAPTER_CONTRACT_VERSION
    actions = {schema.action_name for schema in adapter.list_tool_schemas()}
    assert actions == {
        "langchain.module_status.list",
        "langchain.export.agent_spec",
        "langchain.import.tool_bundle",
    }


def test_langchain_compat_module_status_action_returns_modules() -> None:
    adapter = LangChainCompatibilityAdapter()
    result = adapter.execute_action(
        AdapterActionRequest(action_name="langchain.module_status.list", payload={})
    )
    assert result.ok
    module_names = {entry["module_name"] for entry in result.output["modules"]}
    assert module_names == {"langchain", "langchain_core", "langgraph"}


def test_langchain_compat_export_agent_spec_action() -> None:
    adapter = LangChainCompatibilityAdapter()
    result = adapter.execute_action(
        AdapterActionRequest(
            action_name="langchain.export.agent_spec",
            payload={"agent_spec": _sample_agent_spec()},
        )
    )
    assert result.ok
    assert result.output["agent_name"] == "compatibility-agent"
    assert len(result.output["tool_bundle"]) == 1
    descriptor = result.output["tool_bundle"][0]
    assert descriptor["metadata"]["command_template"] == "python scan_dependencies.py --path /workspace"
    assert descriptor["metadata"]["can_access_network"] is True
    assert result.output["policy_hints"]["allowed_hosts"] == ["pypi.org", "nvd.nist.gov"]


def test_langchain_compat_import_tool_bundle_action() -> None:
    adapter = LangChainCompatibilityAdapter()
    tool_bundle = [
        {
            "name": "dependency_lookup",
            "description": "Lookup dependency risk data.",
            "metadata": {
                "command_template": "python lookup_risk.py --input /workspace/dependencies.txt",
                "can_access_network": True,
                "can_write_files": False,
                "timeout_seconds": 30,
                "allowed_hosts": ["api.osv.dev"],
                "read_paths": ["/workspace"],
            },
        }
    ]
    result = adapter.execute_action(
        AdapterActionRequest(
            action_name="langchain.import.tool_bundle",
            payload={"tool_bundle": tool_bundle},
        )
    )
    assert result.ok
    assert len(result.output["tools"]) == 1
    tool = result.output["tools"][0]
    assert tool["name"] == "dependency_lookup"
    assert tool["command"] == "python lookup_risk.py --input /workspace/dependencies.txt"
    assert tool["can_access_network"] is True
    assert result.output["data_scope_hints"]["allowed_hosts"] == ["api.osv.dev"]
    assert result.output["warnings"] == []


def test_langchain_compat_rejects_unknown_action() -> None:
    adapter = LangChainCompatibilityAdapter()
    result = adapter.execute_action(
        AdapterActionRequest(action_name="langchain.unknown", payload={})
    )
    assert not result.ok
    assert result.errors[0].code == "unknown_action"


def test_langchain_compat_rejects_contract_version_mismatch() -> None:
    adapter = LangChainCompatibilityAdapter()
    result = adapter.execute_action(
        AdapterActionRequest(
            action_name="langchain.module_status.list",
            payload={},
            contract_version="0.0.1",
        )
    )
    assert not result.ok
    assert result.errors[0].code == "contract_version_mismatch"

