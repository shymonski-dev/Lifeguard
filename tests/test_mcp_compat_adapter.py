from __future__ import annotations

from lifeguard.adapters import (
    ADAPTER_CONTRACT_VERSION,
    AdapterActionRequest,
    ModelContextProtocolCompatibilityAdapter,
)


def _sample_agent_spec() -> dict[str, object]:
    return {
        "name": "mcp-compat-agent",
        "description": "Review dependencies through safe tool gating.",
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
            "allowed_hosts": ["osv.dev", "nvd.nist.gov"],
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


def test_model_context_protocol_compat_adapter_exposes_contract_and_schema() -> None:
    adapter = ModelContextProtocolCompatibilityAdapter()
    assert adapter.contract_version == ADAPTER_CONTRACT_VERSION
    actions = {schema.action_name for schema in adapter.list_tool_schemas()}
    assert actions == {
        "mcp.module_status.list",
        "mcp.export.agent_spec",
        "mcp.import.server_bundle",
    }


def test_model_context_protocol_module_status_action_returns_modules() -> None:
    adapter = ModelContextProtocolCompatibilityAdapter()
    result = adapter.execute_action(
        AdapterActionRequest(action_name="mcp.module_status.list", payload={})
    )
    assert result.ok
    module_names = {entry["module_name"] for entry in result.output["modules"]}
    assert module_names == {"mcp", "mcp.client", "mcp.server"}


def test_model_context_protocol_export_agent_spec_action() -> None:
    adapter = ModelContextProtocolCompatibilityAdapter()
    result = adapter.execute_action(
        AdapterActionRequest(
            action_name="mcp.export.agent_spec",
            payload={
                "agent_spec": _sample_agent_spec(),
                "server_name": "security-gateway-server",
                "server_version": "1.2.3",
                "trust_profile_id": "secure_code_review_primary",
            },
        )
    )
    assert result.ok
    assert result.output["agent_name"] == "mcp-compat-agent"
    server_bundle = result.output["server_bundle"]
    assert server_bundle["server"]["server_name"] == "security-gateway-server"
    assert server_bundle["server"]["server_version"] == "1.2.3"
    assert server_bundle["server"]["trust_profile_id"] == "secure_code_review_primary"
    assert result.output["policy_hints"]["allowed_hosts"] == ["osv.dev", "nvd.nist.gov"]
    assert result.output["policy_hints"]["gating_mode"] == "deny_by_default"
    assert result.output["policy_hints"]["advisory_only"] is False


def test_model_context_protocol_import_server_bundle_action() -> None:
    adapter = ModelContextProtocolCompatibilityAdapter()
    server_bundle = {
        "schema": "mcp_server_bundle_v1",
        "server": {
            "server_name": "security-gateway-server",
            "server_version": "1.2.3",
            "transport": "stdio",
            "trust_profile_id": "secure_code_review_primary",
        },
        "tools": [
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
        ],
    }
    result = adapter.execute_action(
        AdapterActionRequest(
            action_name="mcp.import.server_bundle",
            payload={"server_bundle": server_bundle},
        )
    )
    assert result.ok
    assert len(result.output["tools"]) == 1
    tool = result.output["tools"][0]
    assert tool["name"] == "dependency_lookup"
    assert tool["command"] == "python lookup_risk.py --input /workspace/dependencies.txt"
    assert tool["can_access_network"] is True
    assert result.output["data_scope_hints"]["allowed_hosts"] == ["api.osv.dev"]
    gating = result.output["gating"]
    assert gating["version_pinned"] is True
    assert gating["trust_profile_required"] is True
    assert gating["default_deny"] is True
    assert gating["host_allow_list_required_for_network_tools"] is True
    assert gating["startup_commands_blocked"] is True
    assert gating["advisory_only"] is False
    assert gating["server_version"] == "1.2.3"


def test_model_context_protocol_import_rejects_unpinned_server_version() -> None:
    adapter = ModelContextProtocolCompatibilityAdapter()
    result = adapter.execute_action(
        AdapterActionRequest(
            action_name="mcp.import.server_bundle",
            payload={
                "server_bundle": {
                    "server": {
                        "server_name": "security-gateway-server",
                        "server_version": "latest",
                        "trust_profile_id": "secure_code_review_primary",
                    },
                    "tools": [
                        {
                            "name": "dependency_lookup",
                            "metadata": {
                                "command_template": "python lookup_risk.py",
                                "can_access_network": False,
                                "can_write_files": False,
                                "timeout_seconds": 30,
                            },
                        }
                    ],
                }
            },
        )
    )
    assert not result.ok
    assert result.errors[0].code == "invalid_action_payload"
    assert "must be pinned" in result.errors[0].message


def test_model_context_protocol_import_rejects_local_startup_command() -> None:
    adapter = ModelContextProtocolCompatibilityAdapter()
    result = adapter.execute_action(
        AdapterActionRequest(
            action_name="mcp.import.server_bundle",
            payload={
                "server_bundle": {
                    "schema": "mcp_server_bundle_v1",
                    "server": {
                        "server_name": "security-gateway-server",
                        "server_version": "1.2.3",
                        "trust_profile_id": "secure_code_review_primary",
                        "startup_command": "python run_server.py",
                    },
                    "tools": [
                        {
                            "name": "dependency_lookup",
                            "metadata": {
                                "command_template": "python lookup_risk.py",
                                "can_access_network": False,
                                "can_write_files": False,
                                "timeout_seconds": 30,
                            },
                        }
                    ],
                }
            },
        )
    )
    assert not result.ok
    assert result.errors[0].code == "invalid_action_payload"
    assert "local startup command execution is blocked" in result.errors[0].message


def test_model_context_protocol_export_requires_explicit_trust_profile() -> None:
    adapter = ModelContextProtocolCompatibilityAdapter()
    payload = _sample_agent_spec()
    payload["live_data"] = {
        "enabled": False,
        "provider": "openrouter",
        "model": "openai/gpt-5.2:online",
        "max_results": 5,
        "min_citations": 2,
        "timeout_seconds": 45,
        "query": "",
        "trust_profile_id": "",
        "strict": True,
    }
    result = adapter.execute_action(
        AdapterActionRequest(
            action_name="mcp.export.agent_spec",
            payload={
                "agent_spec": payload,
                "server_name": "security-gateway-server",
                "server_version": "1.2.3",
            },
        )
    )
    assert not result.ok
    assert result.errors[0].code == "invalid_action_payload"
    assert "trust_profile_id is required" in result.errors[0].message


def test_model_context_protocol_rejects_unknown_action() -> None:
    adapter = ModelContextProtocolCompatibilityAdapter()
    result = adapter.execute_action(
        AdapterActionRequest(action_name="mcp.unknown", payload={})
    )
    assert not result.ok
    assert result.errors[0].code == "unknown_action"


def test_model_context_protocol_rejects_contract_version_mismatch() -> None:
    adapter = ModelContextProtocolCompatibilityAdapter()
    result = adapter.execute_action(
        AdapterActionRequest(
            action_name="mcp.module_status.list",
            payload={},
            contract_version="0.0.1",
        )
    )
    assert not result.ok
    assert result.errors[0].code == "contract_version_mismatch"
