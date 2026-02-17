from __future__ import annotations

from lifeguard.policy_compiler import compile_policy
from lifeguard.runtime_policy_middleware import PolicyExecutionMiddleware
from lifeguard.spec_schema import AgentSpec, DataScope, ToolSpec


def _spec_with_tools(
    tools: tuple[ToolSpec, ...],
    allowed_hosts: tuple[str, ...] = (),
    risk_level: str = "low",
) -> AgentSpec:
    return AgentSpec(
        name="middleware-agent",
        description="Policy middleware checks.",
        risk_level=risk_level,
        tools=tools,
        data_scope=DataScope(
            read_paths=("/workspace",),
            write_paths=("/workspace/out",),
            allowed_hosts=allowed_hosts,
        ),
        runtime_environment="container",
        budget_limit_usd=50.0,
        max_runtime_seconds=900,
    )


def test_policy_middleware_allows_safe_tool() -> None:
    spec = _spec_with_tools(
        (
            ToolSpec(
                name="review",
                command="python review.py",
                can_access_network=False,
                can_write_files=False,
                timeout_seconds=30,
            ),
        )
    )
    policy = compile_policy(spec)
    decisions = PolicyExecutionMiddleware().evaluate_spec_tools(spec, policy)
    assert len(decisions) == 1
    assert decisions[0].allowed is True


def test_policy_middleware_blocks_disallowed_host() -> None:
    spec = _spec_with_tools(
        (
            ToolSpec(
                name="fetch",
                command="curl https://bad.example.com/feed",
                can_access_network=True,
                can_write_files=False,
                timeout_seconds=30,
            ),
        ),
        allowed_hosts=("good.example.com",),
    )
    policy = compile_policy(spec)
    decisions = PolicyExecutionMiddleware().evaluate_spec_tools(spec, policy)
    assert decisions[0].allowed is False
    assert "disallowed hosts" in decisions[0].reason


def test_policy_middleware_blocks_disallowed_host_from_scheme_less_domain_token() -> None:
    spec = _spec_with_tools(
        (
            ToolSpec(
                name="fetch",
                command="python query_advisories.py --source osv.dev --input /workspace/dependencies.json",
                can_access_network=True,
                can_write_files=False,
                timeout_seconds=30,
            ),
        ),
        allowed_hosts=("api.github.com",),
    )
    policy = compile_policy(spec)
    decisions = PolicyExecutionMiddleware().evaluate_spec_tools(spec, policy)
    assert decisions[0].allowed is False
    assert "disallowed hosts" in decisions[0].reason


def test_policy_middleware_blocks_high_risk_network_tool_without_explicit_host_target() -> None:
    spec = _spec_with_tools(
        (
            ToolSpec(
                name="fetch",
                command="python query_advisories.py --input /workspace/dependencies.json",
                can_access_network=True,
                can_write_files=False,
                timeout_seconds=30,
            ),
        ),
        allowed_hosts=("api.github.com",),
        risk_level="high",
    )
    policy = compile_policy(spec)
    decisions = PolicyExecutionMiddleware().evaluate_spec_tools(spec, policy)
    assert decisions[0].allowed is False
    assert "explicit host targets" in decisions[0].reason.lower()


def test_policy_middleware_blocks_network_in_non_network_tool() -> None:
    spec = _spec_with_tools(
        (
            ToolSpec(
                name="review",
                command="python review.py https://example.com/data",
                can_access_network=False,
                timeout_seconds=30,
            ),
        )
    )
    policy = compile_policy(spec)
    decisions = PolicyExecutionMiddleware().evaluate_spec_tools(spec, policy)
    assert decisions[0].allowed is False
    assert "network" in decisions[0].reason.lower()


def test_policy_middleware_blocks_write_tool_without_write_paths() -> None:
    spec = AgentSpec(
        name="write-check",
        description="Checks write path requirement.",
        risk_level="low",
        tools=(
            ToolSpec(
                name="writer",
                command="python write.py",
                can_write_files=True,
                can_access_network=False,
                timeout_seconds=20,
            ),
        ),
        data_scope=DataScope(
            read_paths=("/workspace",),
            write_paths=(),
            allowed_hosts=(),
        ),
        runtime_environment="container",
        budget_limit_usd=50.0,
        max_runtime_seconds=900,
    )
    policy = compile_policy(spec)
    decisions = PolicyExecutionMiddleware().evaluate_spec_tools(spec, policy)
    assert decisions[0].allowed is False
    assert "write paths" in decisions[0].reason


def test_policy_middleware_blocks_command_chaining_when_prefix_matches() -> None:
    baseline = _spec_with_tools(
        (
            ToolSpec(
                name="review",
                command="python review.py",
                can_access_network=False,
                timeout_seconds=30,
            ),
        )
    )
    policy = compile_policy(baseline)
    chained = _spec_with_tools(
        (
            ToolSpec(
                name="review",
                command="python review.py && rm -rf /",
                can_access_network=False,
                timeout_seconds=30,
            ),
        )
    )
    decisions = PolicyExecutionMiddleware().evaluate_spec_tools(chained, policy)
    assert decisions[0].allowed is False
    assert "allow list" in decisions[0].reason.lower()


def test_policy_middleware_blocks_unapproved_extra_arguments() -> None:
    baseline = _spec_with_tools(
        (
            ToolSpec(
                name="review",
                command="python review.py",
                can_access_network=False,
                timeout_seconds=30,
            ),
        )
    )
    policy = compile_policy(baseline)
    with_extra_args = _spec_with_tools(
        (
            ToolSpec(
                name="review",
                command="python review.py --debug",
                can_access_network=False,
                timeout_seconds=30,
            ),
        )
    )
    decisions = PolicyExecutionMiddleware().evaluate_spec_tools(with_extra_args, policy)
    assert decisions[0].allowed is False
    assert "allow list" in decisions[0].reason.lower()
