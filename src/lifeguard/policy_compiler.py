from __future__ import annotations

import shlex
from dataclasses import dataclass

from .spec_schema import AgentSpec, ConfigValidationError

_BANNED_EVOLUTION_TERMS = (
    "evolution",
    "evolve",
    "genetic",
    "mutation",
    "population",
    "selection",
    "fitness",
)

_BANNED_APPLICATION_SECTORS = (
    "military",
    "healthcare",
    "health care",
)

_FORBIDDEN_SHELL_SUBSTRINGS_ALWAYS = (
    "$(",
    "`",
    "\n",
    "\r",
)

_FORBIDDEN_SHELL_TOKENS_OUTSIDE_QUOTES = (
    "&&",
    "||",
    ">>",
    "<<",
    ";",
    "|",
    ">",
    "<",
    "&",
)

_FORBIDDEN_SHELL_EXECUTABLES = {
    "sh",
    "bash",
    "zsh",
    "/bin/sh",
    "/bin/bash",
    "/bin/zsh",
}

_INTERPRETER_INLINE_EXECUTION_FLAGS = {
    "python": {"-c"},
    "python3": {"-c"},
    "node": {"-e", "--eval"},
    "ruby": {"-e"},
    "perl": {"-e"},
}


def _canonicalize_command(command: str) -> str:
    # Normalize whitespace so allow-lists are stable and comparisons are exact.
    return " ".join(command.strip().split())


def _find_forbidden_shell_syntax(command: str) -> str | None:
    for token in _FORBIDDEN_SHELL_SUBSTRINGS_ALWAYS:
        if token in command:
            return token

    # Only treat shell operators as forbidden when they appear outside of quotes.
    # This avoids false positives for strings like rg "foo|bar" while still
    # rejecting command chaining and redirection.
    in_single_quote = False
    in_double_quote = False
    escaped = False
    index = 0
    while index < len(command):
        ch = command[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if ch == "\\" and not in_single_quote:
            escaped = True
            index += 1
            continue
        if ch == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            index += 1
            continue
        if ch == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            index += 1
            continue

        if not in_single_quote and not in_double_quote:
            for token in _FORBIDDEN_SHELL_TOKENS_OUTSIDE_QUOTES:
                if command.startswith(token, index):
                    return token
        index += 1
    return None


def _first_executable_token(command: str) -> str:
    canonical = _canonicalize_command(command)
    if not canonical:
        return ""
    return canonical.split(" ", 1)[0]


def _split_command_tokens(command: str) -> tuple[str, ...]:
    canonical = _canonicalize_command(command)
    if not canonical:
        return ()
    try:
        return tuple(shlex.split(canonical))
    except ValueError:
        return tuple(canonical.split(" "))


def _normalized_executable_name(command: str) -> str:
    token = _first_executable_token(command)
    if not token:
        return ""
    return token.rsplit("/", 1)[-1].lower()


def _find_inline_execution_flag(command: str) -> str | None:
    executable_name = _normalized_executable_name(command)
    disallowed_flags = _INTERPRETER_INLINE_EXECUTION_FLAGS.get(executable_name)
    if not disallowed_flags:
        return None
    tokens = _split_command_tokens(command)
    if len(tokens) < 2:
        return None
    for token in tokens[1:]:
        if token in disallowed_flags:
            return token
    return None


def _find_banned_application_sector(spec: AgentSpec) -> str | None:
    parts = [
        spec.name,
        spec.description,
        spec.legal_context.intended_use,
        spec.legal_context.sector,
        spec.legal_context.compliance_target_date,
        *spec.legal_context.jurisdictions,
        *spec.legal_context.data_categories,
        *spec.security_requirements.goals,
        *spec.security_requirements.threat_actors,
        *spec.security_requirements.evidence_requirements,
    ]
    lowered = " ".join(item.strip().lower() for item in parts if item.strip())
    for term in _BANNED_APPLICATION_SECTORS:
        if term in lowered:
            return term
    return None


@dataclass(frozen=True)
class CompiledPolicy:
    allowed_commands: tuple[str, ...]
    read_paths: tuple[str, ...]
    write_paths: tuple[str, ...]
    allowed_hosts: tuple[str, ...]
    network_mode: str
    max_tool_timeout_seconds: int
    requires_human_approval: bool


def compile_policy(spec: AgentSpec) -> CompiledPolicy:
    banned_sector = _find_banned_application_sector(spec)
    if banned_sector is not None:
        raise ConfigValidationError(
            f"Agent specification includes forbidden sector term '{banned_sector}'."
        )

    for tool in spec.tools:
        executable = _first_executable_token(tool.command)
        if executable in _FORBIDDEN_SHELL_EXECUTABLES:
            raise ConfigValidationError(
                f"Tool '{tool.name}' command must not invoke a shell executable '{executable}'."
            )

        forbidden_token = _find_forbidden_shell_syntax(tool.command)
        if forbidden_token is not None:
            raise ConfigValidationError(
                f"Tool '{tool.name}' command includes forbidden shell token '{forbidden_token}'."
            )

        inline_flag = _find_inline_execution_flag(tool.command)
        if inline_flag is not None:
            raise ConfigValidationError(
                f"Tool '{tool.name}' command includes blocked inline execution flag '{inline_flag}'."
            )

        lowered_command = tool.command.lower()
        for term in _BANNED_EVOLUTION_TERMS:
            if term in lowered_command:
                raise ConfigValidationError(
                    f"Tool '{tool.name}' command includes forbidden term '{term}'."
                )

    uses_network = any(tool.can_access_network for tool in spec.tools)
    uses_write = any(tool.can_write_files for tool in spec.tools)

    if uses_network and not spec.data_scope.allowed_hosts:
        raise ConfigValidationError(
            "Network-enabled tools require explicit allowed_hosts."
        )

    if spec.risk_level == "high":
        for host in spec.data_scope.allowed_hosts:
            if host == "*" or host.startswith("*."):
                raise ConfigValidationError(
                    "High-risk agents must not use wildcard hosts."
                )

    network_mode = "allow_list" if uses_network else "deny_all"
    commands = tuple(tool.command for tool in spec.tools)
    max_timeout = max(tool.timeout_seconds for tool in spec.tools)
    requires_human_approval = spec.risk_level == "high" or uses_write

    return CompiledPolicy(
        allowed_commands=commands,
        read_paths=spec.data_scope.read_paths,
        write_paths=spec.data_scope.write_paths,
        allowed_hosts=spec.data_scope.allowed_hosts,
        network_mode=network_mode,
        max_tool_timeout_seconds=max_timeout,
        requires_human_approval=requires_human_approval,
    )


def is_command_allowed(policy: CompiledPolicy, command: str) -> bool:
    if _find_forbidden_shell_syntax(command) is not None:
        return False

    candidate_tokens = _split_command_tokens(command)
    if not candidate_tokens:
        return False

    for allowed in policy.allowed_commands:
        allowed_tokens = _split_command_tokens(allowed)
        if not allowed_tokens:
            continue
        if candidate_tokens == allowed_tokens:
            return True
    return False
