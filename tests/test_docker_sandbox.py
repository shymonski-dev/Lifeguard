from __future__ import annotations

import pytest

from lifeguard.docker_sandbox import (
    DockerSandboxExecutor,
    DockerSandboxPolicyError,
    DockerSandboxRequest,
)


class _Result:
    def __init__(self, *, exit_code: int, stdout: str = "", stderr: str = "") -> None:
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


class _CapturingRunner:
    def __init__(self, *, tool_exit_code: int = 0) -> None:
        self.calls: list[tuple[list[str], int]] = []
        self._tool_exit_code = tool_exit_code

    def __call__(self, command: list[str], timeout_seconds: int) -> _Result:
        self.calls.append((list(command), timeout_seconds))
        if command[:3] == ["docker", "inspect", "-f"]:
            return _Result(exit_code=0, stdout="true\n", stderr="")
        if command[:2] == ["docker", "run"] and "-d" not in command:
            return _Result(
                exit_code=self._tool_exit_code,
                stdout="ok" if self._tool_exit_code == 0 else "",
                stderr="" if self._tool_exit_code == 0 else "tool failed",
            )
        return _Result(exit_code=0, stdout="", stderr="")


def test_hardened_sandbox_builds_strict_docker_command(tmp_path, monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_runner(command: list[str], timeout_seconds: int):
        captured["command"] = command
        captured["timeout_seconds"] = timeout_seconds
        return _Result(exit_code=0, stdout="ok", stderr="")

    monkeypatch.setattr("lifeguard.docker_sandbox.shutil.which", lambda name: "/usr/bin/docker")
    executor = DockerSandboxExecutor(runner=fake_runner)
    request = DockerSandboxRequest(
        command="python review.py",
        workspace_path=tmp_path,
        runtime_environment="container",
        image="cgr.dev/chainguard/python:latest-dev",
        read_paths=("/workspace",),
        write_paths=("/workspace/reports",),
        network_enabled=False,
        allowed_hosts=(),
    )
    result = executor.run(request)

    assert result.passed is True
    command = captured["command"]
    assert isinstance(command, list)
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "no-new-privileges:true" in command
    assert "--network" in command
    assert "none" in command
    assert any(item.endswith(":/workspace:ro") for item in command if isinstance(item, str))


def test_hardened_sandbox_uses_isolated_network_gateway_for_network_enabled_tools(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr("lifeguard.docker_sandbox.shutil.which", lambda name: "/usr/bin/docker")
    runner = _CapturingRunner(tool_exit_code=0)
    executor = DockerSandboxExecutor(runner=runner)
    request = DockerSandboxRequest(
        command="python review.py",
        workspace_path=tmp_path,
        runtime_environment="container",
        image="cgr.dev/chainguard/python:latest-dev",
        network_enabled=True,
        allowed_hosts=("example.com",),
    )
    result = executor.run(request)

    assert result.passed is True
    commands = [item[0] for item in runner.calls]

    create_internal = next(
        command
        for command in commands
        if command[:4] == ["docker", "network", "create", "--internal"]
    )
    internal_network_name = create_internal[-1]

    create_egress = next(
        command
        for command in commands
        if command[:4] == ["docker", "network", "create", "--driver"]
    )
    egress_network_name = create_egress[-1]

    run_gateway = next(
        command
        for command in commands
        if command[:2] == ["docker", "run"] and "-d" in command
    )
    gateway_name = run_gateway[run_gateway.index("--name") + 1]

    run_tool = next(
        command
        for command in commands
        if command[:2] == ["docker", "run"] and "-d" not in command
    )
    assert "--network" in run_tool
    assert internal_network_name in run_tool
    assert "HTTP_PROXY=http://lifeguard-egress-gateway:3128" in run_tool
    assert "HTTPS_PROXY=http://lifeguard-egress-gateway:3128" in run_tool

    assert [
        "docker",
        "network",
        "connect",
        "--alias",
        "lifeguard-egress-gateway",
        internal_network_name,
        gateway_name,
    ] in commands
    assert ["docker", "rm", "-f", gateway_name] in commands
    assert ["docker", "network", "rm", internal_network_name] in commands
    assert ["docker", "network", "rm", egress_network_name] in commands


def test_hardened_sandbox_cleans_up_gateway_resources_when_tool_fails(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr("lifeguard.docker_sandbox.shutil.which", lambda name: "/usr/bin/docker")
    runner = _CapturingRunner(tool_exit_code=1)
    executor = DockerSandboxExecutor(runner=runner)
    request = DockerSandboxRequest(
        command="python review.py",
        workspace_path=tmp_path,
        runtime_environment="container",
        image="cgr.dev/chainguard/python:latest-dev",
        network_enabled=True,
        allowed_hosts=("example.com",),
    )
    result = executor.run(request)

    assert result.passed is False
    commands = [item[0] for item in runner.calls]
    create_internal = next(
        command
        for command in commands
        if command[:4] == ["docker", "network", "create", "--internal"]
    )
    internal_network_name = create_internal[-1]
    create_egress = next(
        command
        for command in commands
        if command[:4] == ["docker", "network", "create", "--driver"]
    )
    egress_network_name = create_egress[-1]
    run_gateway = next(
        command
        for command in commands
        if command[:2] == ["docker", "run"] and "-d" in command
    )
    gateway_name = run_gateway[run_gateway.index("--name") + 1]

    assert ["docker", "rm", "-f", gateway_name] in commands
    assert ["docker", "network", "rm", internal_network_name] in commands
    assert ["docker", "network", "rm", egress_network_name] in commands


def test_hardened_sandbox_rejects_unapproved_image_prefix(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("lifeguard.docker_sandbox.shutil.which", lambda name: "/usr/bin/docker")
    executor = DockerSandboxExecutor(
        runner=lambda command, timeout_seconds: _Result(exit_code=0, stdout="", stderr="")
    )
    request = DockerSandboxRequest(
        command="python review.py",
        workspace_path=tmp_path,
        runtime_environment="container",
        image="python:3.11",
    )
    with pytest.raises(DockerSandboxPolicyError):
        executor.run(request)


def test_hardened_sandbox_requires_allowed_hosts_for_network_requests(tmp_path) -> None:
    with pytest.raises(DockerSandboxPolicyError):
        DockerSandboxRequest(
            command="python query.py",
            workspace_path=tmp_path,
            runtime_environment="container",
            network_enabled=True,
            allowed_hosts=(),
        )


def test_hardened_sandbox_blocks_host_network_mode(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("LIFEGUARD_SANDBOX_NETWORK", "host")
    monkeypatch.setattr("lifeguard.docker_sandbox.shutil.which", lambda name: "/usr/bin/docker")
    executor = DockerSandboxExecutor(
        runner=lambda command, timeout_seconds: _Result(exit_code=0, stdout="", stderr="")
    )
    request = DockerSandboxRequest(
        command="python review.py",
        workspace_path=tmp_path,
        runtime_environment="container",
        image="cgr.dev/chainguard/python:latest-dev",
        network_enabled=True,
        allowed_hosts=("example.com",),
    )
    with pytest.raises(DockerSandboxPolicyError):
        executor.run(request)


def test_hardened_sandbox_records_unapproved_image_override_violation(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr("lifeguard.docker_sandbox.shutil.which", lambda name: "/usr/bin/docker")
    monkeypatch.setenv("LIFEGUARD_ALLOW_UNHARDENED_IMAGE", "1")
    monkeypatch.setenv(
        "LIFEGUARD_ALLOW_UNHARDENED_IMAGE_ACK",
        "I_UNDERSTAND_UNHARDENED_IMAGE_RISK",
    )
    executor = DockerSandboxExecutor(
        runner=lambda command, timeout_seconds: _Result(exit_code=0, stdout="ok", stderr="")
    )
    request = DockerSandboxRequest(
        command="python review.py",
        workspace_path=tmp_path,
        runtime_environment="container",
        image="python:3.12-alpine",
    )
    result = executor.run(request)
    assert result.passed is True
    assert result.policy_violations == ("image_policy_override_enabled_for_unapproved_image",)


def test_hardened_sandbox_requires_override_ack_for_unapproved_image(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("lifeguard.docker_sandbox.shutil.which", lambda name: "/usr/bin/docker")
    monkeypatch.setenv("LIFEGUARD_ALLOW_UNHARDENED_IMAGE", "1")
    monkeypatch.delenv("LIFEGUARD_ALLOW_UNHARDENED_IMAGE_ACK", raising=False)
    executor = DockerSandboxExecutor(
        runner=lambda command, timeout_seconds: _Result(exit_code=0, stdout="ok", stderr="")
    )
    request = DockerSandboxRequest(
        command="python review.py",
        workspace_path=tmp_path,
        runtime_environment="container",
        image="python:3.12-alpine",
    )
    with pytest.raises(DockerSandboxPolicyError):
        executor.run(request)
