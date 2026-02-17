from __future__ import annotations

import pytest

from lifeguard.output_contracts import OutputContractError, validate_node_output_contract
from lifeguard.policy_compiler import compile_policy
from lifeguard.spec_schema import AgentSpec, DataScope, ToolSpec
from lifeguard.verification_pipeline import CheckResult, VerificationReport


def _spec() -> AgentSpec:
    return AgentSpec(
        name="output-contract-agent",
        description="Output contract checks.",
        risk_level="low",
        tools=(
            ToolSpec(
                name="review",
                command="python review.py",
                can_write_files=False,
                can_access_network=False,
                timeout_seconds=30,
            ),
        ),
        data_scope=DataScope(
            read_paths=("/workspace",),
            write_paths=("/workspace/out",),
            allowed_hosts=(),
        ),
        runtime_environment="container",
        budget_limit_usd=10.0,
        max_runtime_seconds=300,
    )


def test_output_contract_accepts_valid_verification_node_output(tmp_path) -> None:
    spec = _spec()
    report = VerificationReport(
        passed=True,
        results=(CheckResult(name="ok", passed=True, message="ok"),),
        policy=compile_policy(spec),
        evidence_path=tmp_path / "events.jsonl",
    )
    validate_node_output_contract(
        "verification",
        {
            "spec": spec,
            "verification_report": report,
        },
    )


def test_output_contract_rejects_invalid_type() -> None:
    with pytest.raises(OutputContractError):
        validate_node_output_contract("verification", {"spec": "not-a-spec"})


def test_output_contract_rejects_unknown_node() -> None:
    with pytest.raises(OutputContractError):
        validate_node_output_contract("unknown_node", {})
