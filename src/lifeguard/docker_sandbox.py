from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable


class DockerSandboxError(RuntimeError):
    """Raised when hardened container execution fails."""


class DockerSandboxPolicyError(DockerSandboxError):
    """Raised when requested execution violates sandbox policy."""


@dataclass(frozen=True)
class DockerSandboxRequest:
    command: str
    workspace_path: Path
    runtime_environment: str
    image: str = "cgr.dev/chainguard/python:latest-dev"
    read_paths: tuple[str, ...] = ()
    write_paths: tuple[str, ...] = ()
    network_enabled: bool = False
    allowed_hosts: tuple[str, ...] = ()
    timeout_seconds: int = 60
    memory_limit_mb: int = 512
    cpu_limit: float = 1.0
    pids_limit: int = 128
    output_limit_bytes: int = 64_000
    user: str = "65532:65532"

    def __post_init__(self) -> None:
        if not self.command.strip():
            raise DockerSandboxPolicyError("Sandbox command must not be empty.")
        if self.timeout_seconds < 1 or self.timeout_seconds > 600:
            raise DockerSandboxPolicyError("Sandbox timeout_seconds must be between 1 and 600.")
        if self.memory_limit_mb < 64 or self.memory_limit_mb > 16_384:
            raise DockerSandboxPolicyError("Sandbox memory_limit_mb must be between 64 and 16384.")
        if self.cpu_limit <= 0.0 or self.cpu_limit > 8.0:
            raise DockerSandboxPolicyError("Sandbox cpu_limit must be greater than 0 and at most 8.")
        if self.pids_limit < 16 or self.pids_limit > 4096:
            raise DockerSandboxPolicyError("Sandbox pids_limit must be between 16 and 4096.")
        if self.output_limit_bytes < 1024 or self.output_limit_bytes > 5_000_000:
            raise DockerSandboxPolicyError(
                "Sandbox output_limit_bytes must be between 1024 and 5000000."
            )
        if self.network_enabled and not self.allowed_hosts:
            raise DockerSandboxPolicyError(
                "Network-enabled sandbox execution requires non-empty allowed_hosts."
            )


@dataclass(frozen=True)
class DockerSandboxResult:
    passed: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    command: tuple[str, ...]
    policy_violations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "passed": self.passed,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_seconds": self.duration_seconds,
            "command": list(self.command),
            "policy_violations": list(self.policy_violations),
        }


@dataclass(frozen=True)
class _RunnerResult:
    exit_code: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class _NetworkControlPlane:
    internal_network_name: str
    egress_network_name: str
    gateway_container_name: str
    proxy_url: str


RunnerCallable = Callable[[list[str], int], _RunnerResult]

_DEFAULT_HARDENED_IMAGE_PREFIXES = ("cgr.dev/chainguard/",)
_DEFAULT_SANDBOX_NETWORK = "bridge"
_ALLOWED_SANDBOX_NETWORKS = {"bridge"}
_BLOCKED_SANDBOX_NETWORKS = {"host"}
_DEFAULT_SANDBOX_GATEWAY_IMAGE = "cgr.dev/chainguard/python:latest-dev"
_DEFAULT_EGRESS_ALLOWED_PORTS = "80,443"
_GATEWAY_PROXY_ALIAS = "lifeguard-egress-gateway"
_GATEWAY_PROXY_PORT = 3128
_CONTROL_COMMAND_TIMEOUT_SECONDS = 30
_UNHARDENED_IMAGE_OVERRIDE_ACK_ENV = "LIFEGUARD_ALLOW_UNHARDENED_IMAGE_ACK"
_UNHARDENED_IMAGE_OVERRIDE_ACK_VALUE = "I_UNDERSTAND_UNHARDENED_IMAGE_RISK"


class DockerSandboxExecutor:
    """Hardened container executor for untrusted tool commands."""

    def __init__(self, *, runner: RunnerCallable | None = None) -> None:
        self._runner = runner or _run_subprocess

    def run(self, request: DockerSandboxRequest) -> DockerSandboxResult:
        policy_violations: list[str] = list(self._validate_image_policy(request.image))
        if shutil.which("docker") is None:
            raise DockerSandboxError("docker command is unavailable.")

        started = time.monotonic()
        control_plane: _NetworkControlPlane | None = None
        command: list[str] = []
        try:
            if request.network_enabled:
                gateway_image, gateway_policy_violations = self._resolve_gateway_image()
                policy_violations.extend(gateway_policy_violations)
                control_plane = self._start_network_control_plane(
                    request=request,
                    gateway_image=gateway_image,
                )
                command = self._build_command(
                    request=request,
                    network_name=control_plane.internal_network_name,
                    proxy_url=control_plane.proxy_url,
                )
            else:
                command = self._build_command(
                    request=request,
                    network_name="none",
                    proxy_url=None,
                )
            result = self._runner(command, request.timeout_seconds)
        finally:
            if control_plane is not None:
                self._teardown_network_control_plane(control_plane, ignore_errors=True)

        duration_seconds = round(time.monotonic() - started, 6)
        deduped_policy_violations = _dedupe_strings(policy_violations)

        return DockerSandboxResult(
            passed=result.exit_code == 0,
            exit_code=result.exit_code,
            stdout=_truncate_output(result.stdout, request.output_limit_bytes),
            stderr=_truncate_output(result.stderr, request.output_limit_bytes),
            duration_seconds=duration_seconds,
            command=tuple(command),
            policy_violations=deduped_policy_violations,
        )

    def _validate_image_policy(self, image: str) -> tuple[str, ...]:
        allow_unhardened = os.getenv("LIFEGUARD_ALLOW_UNHARDENED_IMAGE", "").strip() == "1"
        configured_prefixes = os.getenv(
            "LIFEGUARD_HARDENED_IMAGE_PREFIXES",
            ",".join(_DEFAULT_HARDENED_IMAGE_PREFIXES),
        ).strip()
        prefixes = tuple(item.strip() for item in configured_prefixes.split(",") if item.strip())
        if not prefixes:
            prefixes = _DEFAULT_HARDENED_IMAGE_PREFIXES
        cleaned_image = image.strip()
        if not cleaned_image:
            raise DockerSandboxPolicyError("Sandbox image must not be empty.")
        if any(cleaned_image.startswith(prefix) for prefix in prefixes):
            return ()
        if allow_unhardened:
            ack_value = os.getenv(_UNHARDENED_IMAGE_OVERRIDE_ACK_ENV, "").strip()
            if ack_value != _UNHARDENED_IMAGE_OVERRIDE_ACK_VALUE:
                raise DockerSandboxPolicyError(
                    "Unhardened image override requires explicit acknowledgment in "
                    f"{_UNHARDENED_IMAGE_OVERRIDE_ACK_ENV}."
                )
            return ("image_policy_override_enabled_for_unapproved_image",)
        raise DockerSandboxPolicyError(
            "Sandbox image must use an approved hardened prefix. "
            f"Allowed prefixes: {sorted(prefixes)}."
        )

    def _resolve_gateway_image(self) -> tuple[str, tuple[str, ...]]:
        image = os.getenv("LIFEGUARD_SANDBOX_GATEWAY_IMAGE", _DEFAULT_SANDBOX_GATEWAY_IMAGE).strip()
        if not image:
            raise DockerSandboxPolicyError("Gateway image must not be empty.")
        violations = self._validate_image_policy(image)
        return image, tuple(f"gateway_{item}" for item in violations)

    def _start_network_control_plane(
        self,
        *,
        request: DockerSandboxRequest,
        gateway_image: str,
    ) -> _NetworkControlPlane:
        network_driver = _resolve_sandbox_network_name(network_enabled=True)
        suffix = secrets.token_hex(6)
        internal_network_name = f"lifeguard_internal_{suffix}"
        egress_network_name = f"lifeguard_egress_{suffix}"
        gateway_container_name = f"lifeguard_gateway_{suffix}"
        control_plane = _NetworkControlPlane(
            internal_network_name=internal_network_name,
            egress_network_name=egress_network_name,
            gateway_container_name=gateway_container_name,
            proxy_url=f"http://{_GATEWAY_PROXY_ALIAS}:{_GATEWAY_PROXY_PORT}",
        )

        try:
            self._run_control_command(
                ["docker", "network", "create", "--internal", internal_network_name]
            )
            self._run_control_command(
                ["docker", "network", "create", "--driver", network_driver, egress_network_name]
            )

            gateway_proxy_script = Path(__file__).resolve().with_name("_network_gateway_proxy.py")
            if not gateway_proxy_script.exists():
                raise DockerSandboxError(
                    f"Gateway proxy script is missing: {gateway_proxy_script}"
                )
            gateway_proxy_script_mount = (
                f"{gateway_proxy_script}:/opt/lifeguard/network_gateway_proxy.py:ro"
            )
            allowed_hosts_value = ",".join(host.strip() for host in request.allowed_hosts if host.strip())
            allowed_ports_value = (
                os.getenv("LIFEGUARD_ALLOWED_EGRESS_PORTS", _DEFAULT_EGRESS_ALLOWED_PORTS).strip()
                or _DEFAULT_EGRESS_ALLOWED_PORTS
            )

            self._run_control_command(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    gateway_container_name,
                    "--network",
                    egress_network_name,
                    "--read-only",
                    "--cap-drop=ALL",
                    "--security-opt",
                    "no-new-privileges:true",
                    "--pids-limit",
                    "64",
                    "--memory",
                    "128m",
                    "--cpus",
                    "0.5",
                    "--user",
                    "65532:65532",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,size=16m",
                    "--entrypoint",
                    "python",
                    "-v",
                    gateway_proxy_script_mount,
                    "-e",
                    f"LIFEGUARD_ALLOWED_HOSTS={allowed_hosts_value}",
                    "-e",
                    f"LIFEGUARD_ALLOWED_EGRESS_PORTS={allowed_ports_value}",
                    "-e",
                    f"LIFEGUARD_PROXY_PORT={_GATEWAY_PROXY_PORT}",
                    gateway_image,
                    "/opt/lifeguard/network_gateway_proxy.py",
                ]
            )

            self._run_control_command(
                [
                    "docker",
                    "network",
                    "connect",
                    "--alias",
                    _GATEWAY_PROXY_ALIAS,
                    internal_network_name,
                    gateway_container_name,
                ]
            )

            gateway_status = self._run_control_command(
                ["docker", "inspect", "-f", "{{.State.Running}}", gateway_container_name]
            )
            if gateway_status.stdout.strip().lower() != "true":
                raise DockerSandboxError(
                    "Gateway container failed to start for restricted network execution."
                )
            return control_plane
        except Exception:
            self._teardown_network_control_plane(control_plane, ignore_errors=True)
            raise

    def _teardown_network_control_plane(
        self,
        control_plane: _NetworkControlPlane,
        *,
        ignore_errors: bool,
    ) -> None:
        commands = (
            ["docker", "rm", "-f", control_plane.gateway_container_name],
            ["docker", "network", "rm", control_plane.internal_network_name],
            ["docker", "network", "rm", control_plane.egress_network_name],
        )
        first_error: DockerSandboxError | None = None
        for command in commands:
            try:
                self._run_control_command(command)
            except DockerSandboxError as exc:
                if ignore_errors:
                    continue
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise first_error

    def _build_command(
        self,
        *,
        request: DockerSandboxRequest,
        network_name: str,
        proxy_url: str | None,
    ) -> list[str]:
        workspace_root = request.workspace_path.resolve()
        if not workspace_root.exists():
            raise DockerSandboxPolicyError(
                f"Sandbox workspace_path does not exist: {workspace_root}"
            )
        if not workspace_root.is_dir():
            raise DockerSandboxPolicyError(
                f"Sandbox workspace_path must be a directory: {workspace_root}"
            )

        mounts = _build_mounts(
            workspace_root=workspace_root,
            read_paths=request.read_paths,
            write_paths=request.write_paths,
        )

        command = [
            "docker",
            "run",
            "--rm",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            str(request.pids_limit),
            "--memory",
            f"{request.memory_limit_mb}m",
            "--cpus",
            str(request.cpu_limit),
            "--user",
            request.user,
            "--network",
            network_name,
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            "--entrypoint",
            "/bin/sh",
            *mounts,
            "-w",
            "/workspace",
        ]
        if proxy_url:
            command.extend(
                [
                    "-e",
                    f"HTTP_PROXY={proxy_url}",
                    "-e",
                    f"HTTPS_PROXY={proxy_url}",
                    "-e",
                    f"http_proxy={proxy_url}",
                    "-e",
                    f"https_proxy={proxy_url}",
                    "-e",
                    f"ALL_PROXY={proxy_url}",
                    "-e",
                    f"all_proxy={proxy_url}",
                    "-e",
                    "NO_PROXY=localhost,127.0.0.1",
                    "-e",
                    "no_proxy=localhost,127.0.0.1",
                ]
            )
        command.extend(
            [
                request.image,
                "-lc",
                request.command,
            ]
        )
        return command

    def _run_control_command(
        self,
        command: list[str],
        timeout_seconds: int = _CONTROL_COMMAND_TIMEOUT_SECONDS,
    ) -> _RunnerResult:
        result = self._runner(command, timeout_seconds)
        if result.exit_code != 0:
            joined_command = " ".join(command)
            stderr = result.stderr.strip()
            stdout = result.stdout.strip()
            detail = stderr or stdout or "no output"
            raise DockerSandboxError(
                f"Sandbox control command failed ({joined_command}): {detail}"
            )
        return result


def _resolve_sandbox_network_name(network_enabled: bool) -> str:
    if not network_enabled:
        return "none"

    configured_name = os.getenv("LIFEGUARD_SANDBOX_NETWORK", _DEFAULT_SANDBOX_NETWORK).strip().lower()
    network_name = configured_name or _DEFAULT_SANDBOX_NETWORK
    if network_name in _BLOCKED_SANDBOX_NETWORKS:
        raise DockerSandboxPolicyError(
            f"Sandbox network mode '{network_name}' is blocked by policy."
        )
    if network_name not in _ALLOWED_SANDBOX_NETWORKS:
        raise DockerSandboxPolicyError(
            "Sandbox network mode must be one of "
            f"{sorted(_ALLOWED_SANDBOX_NETWORKS)}."
        )
    return network_name


def _build_mounts(
    *,
    workspace_root: Path,
    read_paths: tuple[str, ...],
    write_paths: tuple[str, ...],
) -> list[str]:
    mounts: list[str] = ["-v", f"{workspace_root}:/workspace:ro"]
    normalized_read_paths = tuple(dict.fromkeys(path.strip() for path in read_paths if path.strip()))
    normalized_write_paths = tuple(dict.fromkeys(path.strip() for path in write_paths if path.strip()))

    for path in normalized_read_paths:
        _validate_container_workspace_path(path)

    for write_path in normalized_write_paths:
        _validate_container_workspace_path(write_path)
        host_path = _container_path_to_host(workspace_root, write_path)
        host_path.mkdir(parents=True, exist_ok=True)
        mounts.extend(["-v", f"{host_path}:{write_path}:rw"])
    return mounts


def _validate_container_workspace_path(container_path: str) -> None:
    parsed = PurePosixPath(container_path)
    if not str(parsed).startswith("/workspace"):
        raise DockerSandboxPolicyError(
            f"Sandbox path must be inside /workspace: {container_path}"
        )


def _container_path_to_host(workspace_root: Path, container_path: str) -> Path:
    parsed = PurePosixPath(container_path)
    relative = parsed.relative_to("/workspace")
    if not str(relative):
        return workspace_root
    return workspace_root / relative.as_posix()


def _truncate_output(value: str, max_bytes: int) -> str:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return value
    trimmed = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return trimmed + "\n[truncated]"


def _dedupe_strings(values: list[str]) -> tuple[str, ...]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        cleaned = value.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        deduped.append(cleaned)
    return tuple(deduped)


def _run_subprocess(command: list[str], timeout_seconds: int) -> _RunnerResult:
    try:
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise DockerSandboxError(
            f"Sandbox command timed out after {timeout_seconds} seconds."
        ) from exc
    except OSError as exc:
        raise DockerSandboxError(f"Sandbox command failed to start: {exc}") from exc
    return _RunnerResult(
        exit_code=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )
