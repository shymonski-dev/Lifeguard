from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from urllib.parse import urlparse

from .policy_compiler import CompiledPolicy, is_command_allowed
from .spec_schema import AgentSpec, ToolSpec

_SCHEMED_URL_PATTERN = re.compile(r"[a-z][a-z0-9+.-]*://[^\s'\"`]+", re.IGNORECASE)
_DOMAIN_PATTERN = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE,
)
_IPV4_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_BLOCKED_DOMAIN_TLDS = {
    "py",
    "js",
    "ts",
    "json",
    "yaml",
    "yml",
    "md",
    "txt",
    "csv",
    "log",
    "db",
    "sqlite",
    "toml",
    "ini",
    "conf",
    "cfg",
    "sh",
    "bash",
    "zsh",
}


@dataclass(frozen=True)
class ToolGateDecision:
    tool_name: str
    command: str
    allowed: bool
    reason: str

    def to_dict(self) -> dict[str, str | bool]:
        return {
            "tool_name": self.tool_name,
            "command": self.command,
            "allowed": self.allowed,
            "reason": self.reason,
        }


class PolicyExecutionMiddleware:
    """Runtime policy checks for each declared tool command."""

    def evaluate_spec_tools(
        self,
        spec: AgentSpec,
        policy: CompiledPolicy | None,
    ) -> tuple[ToolGateDecision, ...]:
        if policy is None:
            return (
                ToolGateDecision(
                    tool_name="policy",
                    command="",
                    allowed=False,
                    reason="Policy is unavailable.",
                ),
            )
        return tuple(
            self._evaluate_tool(policy, tool, risk_level=spec.risk_level)
            for tool in spec.tools
        )

    def _evaluate_tool(
        self,
        policy: CompiledPolicy,
        tool: ToolSpec,
        *,
        risk_level: str,
    ) -> ToolGateDecision:
        if not is_command_allowed(policy, tool.command):
            return ToolGateDecision(
                tool_name=tool.name,
                command=tool.command,
                allowed=False,
                reason="Command is not in the allow list.",
            )

        if tool.timeout_seconds > policy.max_tool_timeout_seconds:
            return ToolGateDecision(
                tool_name=tool.name,
                command=tool.command,
                allowed=False,
                reason="Tool timeout exceeds compiled policy timeout.",
            )

        command_hosts = _extract_hosts(tool.command)
        if command_hosts and not tool.can_access_network:
            return ToolGateDecision(
                tool_name=tool.name,
                command=tool.command,
                allowed=False,
                reason="Command includes network targets but tool network flag is disabled.",
            )

        if tool.can_access_network:
            if policy.network_mode != "allow_list":
                return ToolGateDecision(
                    tool_name=tool.name,
                    command=tool.command,
                    allowed=False,
                    reason="Network-enabled tool requires allow list mode.",
                )
            if not policy.allowed_hosts:
                return ToolGateDecision(
                    tool_name=tool.name,
                    command=tool.command,
                    allowed=False,
                    reason="Network-enabled tool missing allowed hosts policy.",
                )
            if risk_level == "high" and not command_hosts:
                return ToolGateDecision(
                    tool_name=tool.name,
                    command=tool.command,
                    allowed=False,
                    reason=(
                        "High-risk network-enabled tools must include explicit host targets "
                        "in command arguments for allow-list enforcement."
                    ),
                )
            disallowed_hosts = sorted(
                host for host in command_hosts if not _is_host_allowed(host, policy.allowed_hosts)
            )
            if disallowed_hosts:
                return ToolGateDecision(
                    tool_name=tool.name,
                    command=tool.command,
                    allowed=False,
                    reason=(
                        "Command targets disallowed hosts: "
                        + ", ".join(disallowed_hosts)
                    ),
                )
        elif command_hosts:
            return ToolGateDecision(
                tool_name=tool.name,
                command=tool.command,
                allowed=False,
                reason="Network host detected in command for non-network tool.",
            )

        if tool.can_write_files and not policy.write_paths:
            return ToolGateDecision(
                tool_name=tool.name,
                command=tool.command,
                allowed=False,
                reason="Write-enabled tool requires write paths policy.",
            )

        return ToolGateDecision(
            tool_name=tool.name,
            command=tool.command,
            allowed=True,
            reason="Allowed by runtime policy checks.",
        )


def _extract_hosts(command: str) -> tuple[str, ...]:
    hosts: list[str] = []

    for match in _SCHEMED_URL_PATTERN.findall(command):
        parsed = urlparse(match)
        host = (parsed.hostname or "").strip()
        if host:
            hosts.append(_normalize_host(host))

    for token in _split_command_tokens(command):
        host = _extract_host_from_token(token)
        if host:
            hosts.append(host)

    deduped: list[str] = []
    seen: set[str] = set()
    for host in hosts:
        if host in seen:
            continue
        seen.add(host)
        deduped.append(host)
    return tuple(deduped)


def _split_command_tokens(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def _normalize_host(host: str) -> str:
    cleaned = host.strip().lower()
    if cleaned.startswith("www."):
        cleaned = cleaned[4:]
    return cleaned


def _looks_like_ipv4(host: str) -> bool:
    if not _IPV4_PATTERN.match(host):
        return False
    parts = host.split(".")
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def _extract_host_from_token(token: str) -> str | None:
    candidate = token.strip()
    if not candidate:
        return None

    if candidate.startswith("-") and "=" in candidate:
        _, candidate = candidate.split("=", 1)
        candidate = candidate.strip()
        if not candidate:
            return None

    candidate = candidate.strip("\"'()[]{}<>.,;")
    if not candidate:
        return None

    # Ignore obvious local paths.
    if candidate.startswith(("/", "./", "../")):
        return None

    if "://" in candidate:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").strip()
        return _normalize_host(host) if host else None

    if "@" in candidate:
        _, candidate = candidate.split("@", 1)
        candidate = candidate.strip()
        if not candidate:
            return None

    # Trim any path component.
    if "/" in candidate:
        candidate = candidate.split("/", 1)[0]

    # Handle host:port and scp-style host:path.
    if ":" in candidate and candidate.count(":") == 1:
        left, right = candidate.split(":", 1)
        left = left.strip()
        right = right.strip()
        if right.isdigit():
            candidate = left
        elif left and ("." in left or _looks_like_ipv4(left)):
            # Treat git@host:path and host:path as a host reference.
            candidate = left

    candidate = candidate.strip(".,;:)]}")
    if not candidate:
        return None

    normalized = _normalize_host(candidate)
    if _looks_like_ipv4(normalized):
        return normalized
    if not _DOMAIN_PATTERN.match(normalized):
        return None
    tld = normalized.rsplit(".", 1)[-1]
    if tld in _BLOCKED_DOMAIN_TLDS:
        return None
    return normalized


def _is_host_allowed(host: str, allowed_hosts: tuple[str, ...]) -> bool:
    normalized_host = host.lower().strip()
    if normalized_host.startswith("www."):
        normalized_host = normalized_host[4:]

    for allowed in allowed_hosts:
        normalized_allowed = allowed.lower().strip()
        if normalized_allowed.startswith("www."):
            normalized_allowed = normalized_allowed[4:]
        if normalized_host == normalized_allowed:
            return True
        if normalized_host.endswith("." + normalized_allowed):
            return True
    return False
