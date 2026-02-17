from __future__ import annotations

from dataclasses import replace

import pytest

from lifeguard.docker_sandbox import DockerSandboxRequest, DockerSandboxResult
from lifeguard.policy_compiler import compile_policy
from lifeguard.spec_schema import AgentSpec, DataScope, ToolSpec
from lifeguard.tool_execution import ToolExecutionEngine


class _CapturingSandboxExecutor:
    def __init__(self) -> None:
        self.requests: list[DockerSandboxRequest] = []

    def run(self, request: DockerSandboxRequest) -> DockerSandboxResult:
        self.requests.append(request)
        return DockerSandboxResult(
            passed=True,
            exit_code=0,
            stdout="ok",
            stderr="",
            duration_seconds=0.01,
            command=("docker", "run"),
            policy_violations=(),
        )


class _ViolationSandboxExecutor(_CapturingSandboxExecutor):
    def run(self, request: DockerSandboxRequest) -> DockerSandboxResult:
        self.requests.append(request)
        return DockerSandboxResult(
            passed=True,
            exit_code=0,
            stdout="ok",
            stderr="",
            duration_seconds=0.01,
            command=("docker", "run"),
            policy_violations=("image_policy_override_enabled_for_unapproved_image",),
        )


def _spec(runtime_environment: str, *, network_enabled: bool = False, write_enabled: bool = False) -> AgentSpec:
    allowed_hosts = ("example.com",) if network_enabled else ()
    write_paths = ("/workspace/reports",) if write_enabled else ()
    return AgentSpec(
        name=f"tool-execution-{runtime_environment}",
        description="Tool execution sandbox test.",
        risk_level="low",
        tools=(
            ToolSpec(
                name="review",
                command="python review.py",
                can_write_files=write_enabled,
                can_access_network=network_enabled,
                timeout_seconds=30,
            ),
        ),
        data_scope=DataScope(
            read_paths=("/workspace",),
            write_paths=write_paths,
            allowed_hosts=allowed_hosts,
        ),
        runtime_environment=runtime_environment,
        budget_limit_usd=20.0,
        max_runtime_seconds=600,
    )


@pytest.mark.parametrize(
    "runtime_environment",
    ("local", "container", "continuous_integration"),
)
def test_tool_execution_routes_all_runtime_modes_through_hardened_sandbox(
    tmp_path,
    runtime_environment: str,
) -> None:
    spec = _spec(runtime_environment)
    policy = compile_policy(spec)
    sandbox = _CapturingSandboxExecutor()
    engine = ToolExecutionEngine(
        sandbox_executor=sandbox,  # type: ignore[arg-type]
        workspace_path=tmp_path,
        image="cgr.dev/chainguard/python:latest-dev",
    )
    results = engine.execute_spec_tools(spec=spec, policy=policy)

    assert len(results) == 1
    assert results[0].passed is True
    assert results[0].backend == "docker_hardened"
    assert results[0].policy_violations == ()
    assert len(sandbox.requests) == 1
    request = sandbox.requests[0]
    assert request.runtime_environment == runtime_environment
    assert request.network_enabled is False
    assert request.write_paths == ()


def test_tool_execution_passes_network_and_write_policy_to_sandbox(tmp_path) -> None:
    spec = _spec("container", network_enabled=True, write_enabled=True)
    policy = compile_policy(spec)
    sandbox = _CapturingSandboxExecutor()
    engine = ToolExecutionEngine(
        sandbox_executor=sandbox,  # type: ignore[arg-type]
        workspace_path=tmp_path,
        image="cgr.dev/chainguard/python:latest-dev",
    )
    results = engine.execute_spec_tools(spec=spec, policy=policy)

    assert len(results) == 1
    assert results[0].passed is True
    assert len(sandbox.requests) == 1
    request = sandbox.requests[0]
    assert request.network_enabled is True
    assert request.allowed_hosts == ("example.com",)
    assert request.write_paths == ("/workspace/reports",)


def test_tool_execution_blocks_command_not_in_allow_list_without_calling_sandbox(tmp_path) -> None:
    allowed_spec = _spec("container")
    policy = compile_policy(allowed_spec)
    disallowed_spec = replace(
        allowed_spec,
        tools=(
            ToolSpec(
                name="review",
                command="python not_allowed.py",
                can_write_files=False,
                can_access_network=False,
                timeout_seconds=30,
            ),
        ),
    )
    sandbox = _CapturingSandboxExecutor()
    engine = ToolExecutionEngine(
        sandbox_executor=sandbox,  # type: ignore[arg-type]
        workspace_path=tmp_path,
        image="cgr.dev/chainguard/python:latest-dev",
    )
    results = engine.execute_spec_tools(spec=disallowed_spec, policy=policy)

    assert len(results) == 1
    assert results[0].passed is False
    assert "allow list" in results[0].reason
    assert sandbox.requests == []


def test_tool_execution_surfaces_sandbox_policy_violations(tmp_path) -> None:
    spec = _spec("container")
    policy = compile_policy(spec)
    sandbox = _ViolationSandboxExecutor()
    engine = ToolExecutionEngine(
        sandbox_executor=sandbox,  # type: ignore[arg-type]
        workspace_path=tmp_path,
        image="cgr.dev/chainguard/python:latest-dev",
    )
    results = engine.execute_spec_tools(spec=spec, policy=policy)

    assert len(results) == 1
    assert results[0].passed is True
    assert results[0].policy_violations == ("image_policy_override_enabled_for_unapproved_image",)
    assert "image_policy_override_enabled_for_unapproved_image" in results[0].reason
