from __future__ import annotations

from typing import Any

from .live_intelligence import LiveDataReport
from .policy_compiler import CompiledPolicy
from .spec_schema import AgentSpec
from .verification_pipeline import VerificationReport


class OutputContractError(ValueError):
    """Raised when a runtime node returns invalid output data."""


def validate_node_output_contract(node_name: str, output: dict[str, Any]) -> None:
    if not isinstance(output, dict):
        raise OutputContractError(f"Node '{node_name}' output must be a dictionary.")

    if node_name == "load_spec":
        _require_type(node_name, output, "spec", AgentSpec)
        return

    if node_name == "collect_live_intelligence":
        _require_type(node_name, output, "spec", AgentSpec)
        _require_optional_type(node_name, output, "live_data_report", LiveDataReport)
        _require_optional_type(node_name, output, "live_data_error", str)
        return

    if node_name == "compile_policy":
        _require_type(node_name, output, "spec", AgentSpec)
        _require_optional_type(node_name, output, "policy", CompiledPolicy)
        _require_optional_type(node_name, output, "policy_error", str)
        return

    if node_name == "policy_runtime_gate":
        _require_type(node_name, output, "spec", AgentSpec)
        _require_optional_type(node_name, output, "policy", CompiledPolicy)
        _require_optional_type(node_name, output, "tool_gate_passed", bool)
        _require_optional_sequence(node_name, output, "tool_gate_results")
        _require_optional_sequence(node_name, output, "blocked_tool_decisions")
        return

    if node_name == "execute_tools":
        _require_type(node_name, output, "spec", AgentSpec)
        _require_optional_type(node_name, output, "tool_execution_passed", bool)
        _require_optional_sequence(node_name, output, "tool_execution_results")
        _require_optional_type(node_name, output, "tool_execution_error", str)
        return

    if node_name == "threat_checks":
        _require_type(node_name, output, "spec", AgentSpec)
        _require_optional_type(node_name, output, "policy", CompiledPolicy)
        _require_optional_sequence(node_name, output, "threat_findings")
        return

    if node_name == "verification":
        _require_type(node_name, output, "spec", AgentSpec)
        _require_type(node_name, output, "verification_report", VerificationReport)
        return

    raise OutputContractError(f"Unknown output contract for node '{node_name}'.")


def _require_type(node_name: str, output: dict[str, Any], key: str, expected_type: type) -> None:
    value = output.get(key)
    if not isinstance(value, expected_type):
        raise OutputContractError(
            f"Node '{node_name}' key '{key}' must be {expected_type.__name__}."
        )


def _require_optional_type(
    node_name: str, output: dict[str, Any], key: str, expected_type: type
) -> None:
    if key not in output:
        return
    value = output.get(key)
    if value is None:
        return
    if not isinstance(value, expected_type):
        raise OutputContractError(
            f"Node '{node_name}' key '{key}' must be {expected_type.__name__} or null."
        )


def _require_optional_sequence(node_name: str, output: dict[str, Any], key: str) -> None:
    if key not in output:
        return
    value = output.get(key)
    if value is None:
        return
    if not isinstance(value, (list, tuple)):
        raise OutputContractError(
            f"Node '{node_name}' key '{key}' must be a list or tuple."
        )
