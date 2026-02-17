from __future__ import annotations

from lifeguard.adversarial_validation import evaluate_adversarial_pack
from lifeguard.policy_compiler import compile_policy
from lifeguard.spec_schema import AgentSpec, DataScope, SecurityRequirements, ToolSpec


def _safe_spec() -> AgentSpec:
    return AgentSpec(
        name="adversarial-safe",
        description="Adversarial pack safety test.",
        risk_level="medium",
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
            write_paths=("/workspace/reports",),
            allowed_hosts=(),
        ),
        runtime_environment="container",
        budget_limit_usd=40.0,
        max_runtime_seconds=600,
        security_requirements=SecurityRequirements(
            goals=("Validate security controls.", "Block adversarial command attempts."),
            threat_actors=("External attacker", "Malicious insider"),
            evidence_requirements=("Verification log", "Case level pass summary"),
        ),
    )


def _weak_network_spec() -> AgentSpec:
    return AgentSpec(
        name="adversarial-weak",
        description="Adversarial pack weak test.",
        risk_level="medium",
        tools=(
            ToolSpec(
                name="fetch",
                command="python fetch.py",
                can_write_files=False,
                can_access_network=True,
                timeout_seconds=30,
            ),
        ),
        data_scope=DataScope(
            read_paths=("/workspace",),
            write_paths=("/workspace/reports",),
            allowed_hosts=("attacker.example",),
        ),
        runtime_environment="container",
        budget_limit_usd=40.0,
        max_runtime_seconds=600,
        security_requirements=SecurityRequirements(
            goals=("Validate network controls.", "Detect weak allow list choices."),
            threat_actors=("External attacker", "Compromised dependency"),
            evidence_requirements=("Verification log", "Case level pass summary"),
        ),
    )


def test_adversarial_pack_passes_for_safe_spec() -> None:
    spec = _safe_spec()
    policy = compile_policy(spec)
    report = evaluate_adversarial_pack(spec=spec, policy=policy)
    assert report.passed is True
    assert report.pass_rate == 1.0
    assert report.failed_case_ids == ()


def test_adversarial_pack_can_fail_with_impossible_threshold() -> None:
    spec = _weak_network_spec()
    policy = compile_policy(spec)
    report = evaluate_adversarial_pack(spec=spec, policy=policy, threshold=1.01)
    assert report.passed is False
    assert report.pass_rate == 1.0
