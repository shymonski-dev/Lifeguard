import pytest

from lifeguard.policy_compiler import compile_policy
from lifeguard.spec_schema import AgentSpec, ConfigValidationError, DataScope, LiveDataSettings, ToolSpec


def _network_spec(allowed_hosts: tuple[str, ...]) -> AgentSpec:
    return AgentSpec(
        name="network-agent",
        description="Fetches dependency data from trusted hosts.",
        risk_level="medium",
        tools=(
            ToolSpec(
                name="fetch",
                command="curl https://example.com",
                can_access_network=True,
                timeout_seconds=20,
            ),
        ),
        data_scope=DataScope(
            read_paths=("/workspace",),
            write_paths=("/workspace/out",),
            allowed_hosts=allowed_hosts,
        ),
        runtime_environment="container",
        budget_limit_usd=50.0,
        max_runtime_seconds=900,
    )


def test_network_tools_require_allowed_hosts() -> None:
    with pytest.raises(ConfigValidationError):
        compile_policy(_network_spec(allowed_hosts=()))


def test_network_tools_compile_with_allow_list() -> None:
    policy = compile_policy(_network_spec(allowed_hosts=("example.com",)))
    assert policy.network_mode == "allow_list"


def test_rejects_evolutionary_command_terms() -> None:
    with pytest.raises(ConfigValidationError):
        compile_policy(
            AgentSpec(
                name="blocked-command-agent",
                description="Reads files and writes report.",
                risk_level="low",
                tools=(
                    ToolSpec(
                        name="run_blocked",
                        command="python evolve_plan.py",
                        can_access_network=False,
                        timeout_seconds=15,
                    ),
                ),
                data_scope=DataScope(
                    read_paths=("/workspace",),
                    write_paths=("/workspace/out",),
                    allowed_hosts=(),
                ),
                runtime_environment="container",
                budget_limit_usd=25.0,
                max_runtime_seconds=300,
            )
        )


def test_rejects_shell_command_chaining_tokens() -> None:
    with pytest.raises(ConfigValidationError):
        compile_policy(
            AgentSpec(
                name="blocked-shell-operator-agent",
                description="Reject shell chaining operators in tool commands.",
                risk_level="low",
                tools=(
                    ToolSpec(
                        name="review",
                        command="python review.py && rm -rf /",
                        can_access_network=False,
                        timeout_seconds=15,
                    ),
                ),
                data_scope=DataScope(
                    read_paths=("/workspace",),
                    write_paths=("/workspace/out",),
                    allowed_hosts=(),
                ),
                runtime_environment="container",
                budget_limit_usd=25.0,
                max_runtime_seconds=300,
            )
        )


def test_allows_literal_pipe_character_inside_quotes() -> None:
    policy = compile_policy(
        AgentSpec(
            name="quoted-pipe-agent",
            description="Allow quoted pipe characters in tool arguments.",
            risk_level="low",
            tools=(
                ToolSpec(
                    name="search",
                    command='rg "foo|bar" /workspace',
                    can_access_network=False,
                    timeout_seconds=15,
                ),
            ),
            data_scope=DataScope(
                read_paths=("/workspace",),
                write_paths=("/workspace/out",),
                allowed_hosts=(),
            ),
            runtime_environment="container",
            budget_limit_usd=25.0,
            max_runtime_seconds=300,
        )
    )
    assert policy.allowed_commands


def test_rejects_shell_executable() -> None:
    with pytest.raises(ConfigValidationError):
        compile_policy(
            AgentSpec(
                name="blocked-shell-agent",
                description="Reject shell executables in tool commands.",
                risk_level="low",
                tools=(
                    ToolSpec(
                        name="shell",
                        command='bash -lc "echo hi"',
                        can_access_network=False,
                        timeout_seconds=15,
                    ),
                ),
                data_scope=DataScope(
                    read_paths=("/workspace",),
                    write_paths=("/workspace/out",),
                    allowed_hosts=(),
                ),
                runtime_environment="container",
                budget_limit_usd=25.0,
                max_runtime_seconds=300,
            )
        )


def test_rejects_inline_interpreter_execution_flag() -> None:
    with pytest.raises(ConfigValidationError):
        compile_policy(
            AgentSpec(
                name="blocked-inline-exec-agent",
                description="Reject interpreter inline execution flags.",
                risk_level="low",
                tools=(
                    ToolSpec(
                        name="review",
                        command='python -c "import os; print(os.getcwd())"',
                        can_access_network=False,
                        timeout_seconds=15,
                    ),
                ),
                data_scope=DataScope(
                    read_paths=("/workspace",),
                    write_paths=("/workspace/out",),
                    allowed_hosts=(),
                ),
                runtime_environment="container",
                budget_limit_usd=25.0,
                max_runtime_seconds=300,
            )
        )


def test_rejects_non_deterministic_design_method() -> None:
    with pytest.raises(ConfigValidationError):
        AgentSpec(
            name="blocked-design-method-agent",
            description="Reads files and writes report.",
            risk_level="low",
            tools=(
                ToolSpec(
                    name="review",
                    command="python review.py",
                    can_access_network=False,
                    timeout_seconds=15,
                ),
            ),
            data_scope=DataScope(
                read_paths=("/workspace",),
                write_paths=("/workspace/out",),
                allowed_hosts=(),
            ),
            runtime_environment="container",
            budget_limit_usd=25.0,
            max_runtime_seconds=300,
            design_method="evolutionary",
        )


def test_rejects_invalid_live_data_provider() -> None:
    with pytest.raises(ConfigValidationError):
        AgentSpec(
            name="invalid-live-provider-agent",
            description="Reads files and writes report.",
            risk_level="low",
            tools=(
                ToolSpec(
                    name="review",
                    command="python review.py",
                    can_access_network=False,
                    timeout_seconds=15,
                ),
            ),
            data_scope=DataScope(
                read_paths=("/workspace",),
                write_paths=("/workspace/out",),
                allowed_hosts=(),
            ),
            runtime_environment="container",
            budget_limit_usd=25.0,
            max_runtime_seconds=300,
            live_data=LiveDataSettings(provider="unsupported"),
        )


def test_rejects_live_data_min_citations_above_max_results() -> None:
    with pytest.raises(ConfigValidationError):
        AgentSpec(
            name="invalid-live-citations-agent",
            description="Reads files and writes report.",
            risk_level="low",
            tools=(
                ToolSpec(
                    name="review",
                    command="python review.py",
                    can_access_network=False,
                    timeout_seconds=15,
                ),
            ),
            data_scope=DataScope(
                read_paths=("/workspace",),
                write_paths=("/workspace/out",),
                allowed_hosts=(),
            ),
            runtime_environment="container",
            budget_limit_usd=25.0,
            max_runtime_seconds=300,
            live_data=LiveDataSettings(
                enabled=True,
                provider="openrouter",
                max_results=1,
                min_citations=2,
            ),
        )
