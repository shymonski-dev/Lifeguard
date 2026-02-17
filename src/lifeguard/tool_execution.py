from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .docker_sandbox import (
    DockerSandboxError,
    DockerSandboxExecutor,
    DockerSandboxPolicyError,
    DockerSandboxRequest,
)
from .policy_compiler import CompiledPolicy, is_command_allowed
from .spec_schema import AgentSpec, ToolSpec


class ToolExecutionError(RuntimeError):
    """Raised when tool execution cannot be completed."""


@dataclass(frozen=True)
class ToolExecutionResult:
    tool_name: str
    command: str
    runtime_environment: str
    backend: str
    image: str
    passed: bool
    exit_code: int
    stdout: str
    stderr: str
    reason: str = ""
    policy_violations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "tool_name": self.tool_name,
            "command": self.command,
            "runtime_environment": self.runtime_environment,
            "backend": self.backend,
            "image": self.image,
            "passed": self.passed,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "reason": self.reason,
            "policy_violations": list(self.policy_violations),
        }


class ToolExecutionEngine:
    """Executes approved tools inside a hardened container sandbox."""

    def __init__(
        self,
        *,
        sandbox_executor: DockerSandboxExecutor | None = None,
        workspace_path: Path | None = None,
        image: str | None = None,
    ) -> None:
        self._sandbox_executor = sandbox_executor or DockerSandboxExecutor()
        self._workspace_path = (workspace_path or Path.cwd()).resolve()
        self._image = image or os.getenv(
            "LIFEGUARD_RUNTIME_CONTAINER_IMAGE",
            "cgr.dev/chainguard/python:latest-dev",
        )

    def execute_spec_tools(
        self,
        *,
        spec: AgentSpec,
        policy: CompiledPolicy,
    ) -> tuple[ToolExecutionResult, ...]:
        results: list[ToolExecutionResult] = []
        for tool in spec.tools:
            results.append(
                self._execute_tool(
                    tool=tool,
                    spec=spec,
                    policy=policy,
                )
            )
        return tuple(results)

    def _execute_tool(
        self,
        *,
        tool: ToolSpec,
        spec: AgentSpec,
        policy: CompiledPolicy,
    ) -> ToolExecutionResult:
        if not is_command_allowed(policy, tool.command):
            return ToolExecutionResult(
                tool_name=tool.name,
                command=tool.command,
                runtime_environment=spec.runtime_environment,
                backend="docker_hardened",
                image=self._image,
                passed=False,
                exit_code=1,
                stdout="",
                stderr="",
                reason="Command is not in the compiled allow list.",
                policy_violations=(),
            )

        if tool.timeout_seconds > policy.max_tool_timeout_seconds:
            return ToolExecutionResult(
                tool_name=tool.name,
                command=tool.command,
                runtime_environment=spec.runtime_environment,
                backend="docker_hardened",
                image=self._image,
                passed=False,
                exit_code=1,
                stdout="",
                stderr="",
                reason="Tool timeout exceeds compiled policy timeout.",
                policy_violations=(),
            )

        write_paths = policy.write_paths if tool.can_write_files else ()
        allowed_hosts = policy.allowed_hosts if tool.can_access_network else ()
        request = DockerSandboxRequest(
            command=tool.command,
            workspace_path=self._workspace_path,
            runtime_environment=spec.runtime_environment,
            image=self._image,
            read_paths=policy.read_paths,
            write_paths=write_paths,
            network_enabled=tool.can_access_network,
            allowed_hosts=allowed_hosts,
            timeout_seconds=min(tool.timeout_seconds, policy.max_tool_timeout_seconds),
        )
        try:
            sandbox_result = self._sandbox_executor.run(request)
        except (DockerSandboxPolicyError, DockerSandboxError) as exc:
            return ToolExecutionResult(
                tool_name=tool.name,
                command=tool.command,
                runtime_environment=spec.runtime_environment,
                backend="docker_hardened",
                image=self._image,
                passed=False,
                exit_code=1,
                stdout="",
                stderr="",
                reason=str(exc),
                policy_violations=(),
            )

        reason = ""
        if sandbox_result.policy_violations:
            reason = "; ".join(sandbox_result.policy_violations)
        elif not sandbox_result.passed:
            reason = "Sandbox command exited with non-zero status."

        return ToolExecutionResult(
            tool_name=tool.name,
            command=tool.command,
            runtime_environment=spec.runtime_environment,
            backend="docker_hardened",
            image=self._image,
            passed=sandbox_result.passed,
            exit_code=sandbox_result.exit_code,
            stdout=sandbox_result.stdout,
            stderr=sandbox_result.stderr,
            reason=reason,
            policy_violations=sandbox_result.policy_violations,
        )
