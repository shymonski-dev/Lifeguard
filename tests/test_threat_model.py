from __future__ import annotations

from dataclasses import replace

from lifeguard.policy_compiler import compile_policy
from lifeguard.spec_schema import AgentSpec, DataScope, ToolSpec
from lifeguard.threat_model import controls_for_risk, validate_policy_against_threats


def _spec(risk_level: str = "low", *, can_access_network: bool = False) -> AgentSpec:
    return AgentSpec(
        name=f"threat-model-{risk_level}",
        description="Threat model test.",
        risk_level=risk_level,
        tools=(
            ToolSpec(
                name="review",
                command="python review.py",
                can_write_files=False,
                can_access_network=can_access_network,
                timeout_seconds=30,
            ),
        ),
        data_scope=DataScope(
            read_paths=("/workspace",),
            write_paths=("/workspace/out",),
            allowed_hosts=("example.com",) if can_access_network else (),
        ),
        runtime_environment="container",
        budget_limit_usd=50.0,
        max_runtime_seconds=600,
    )


def test_controls_for_risk_returns_expected_count() -> None:
    assert len(controls_for_risk("low")) == 2
    assert len(controls_for_risk("medium")) == 3
    assert len(controls_for_risk("high")) == 4


def test_validate_policy_against_threats_passes_for_valid_policy() -> None:
    spec = _spec(can_access_network=True)
    policy = compile_policy(spec)
    assert validate_policy_against_threats(spec, policy) == []


def test_validate_policy_against_threats_detects_missing_high_risk_approval_requirement() -> None:
    spec = _spec(risk_level="high")
    policy = compile_policy(spec)
    weakened = replace(policy, requires_human_approval=False)
    findings = validate_policy_against_threats(spec, weakened)
    assert findings
    assert "require human approval" in findings[0].lower()
