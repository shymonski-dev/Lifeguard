from __future__ import annotations

from dataclasses import dataclass

from .policy_compiler import CompiledPolicy
from .spec_schema import AgentSpec


@dataclass(frozen=True)
class ThreatControl:
    control_id: str
    description: str
    severity: str


BASE_CONTROLS: dict[str, tuple[ThreatControl, ...]] = {
    "low": (
        ThreatControl(
            control_id="SC-1",
            description="Tool commands must be explicitly allow-listed.",
            severity="medium",
        ),
        ThreatControl(
            control_id="SC-2",
            description="Execution timeout must be enforced for each tool.",
            severity="medium",
        ),
    ),
    "medium": (
        ThreatControl(
            control_id="SC-1",
            description="Tool commands must be explicitly allow-listed.",
            severity="high",
        ),
        ThreatControl(
            control_id="SC-2",
            description="Execution timeout must be enforced for each tool.",
            severity="high",
        ),
        ThreatControl(
            control_id="SC-3",
            description="Network access must be allow-list only.",
            severity="high",
        ),
    ),
    "high": (
        ThreatControl(
            control_id="SC-1",
            description="Tool commands must be explicitly allow-listed.",
            severity="critical",
        ),
        ThreatControl(
            control_id="SC-2",
            description="Execution timeout must be enforced for each tool.",
            severity="critical",
        ),
        ThreatControl(
            control_id="SC-3",
            description="Network access must be allow-list only.",
            severity="critical",
        ),
        ThreatControl(
            control_id="SC-4",
            description="Release requires human approval.",
            severity="critical",
        ),
    ),
}


def controls_for_risk(risk_level: str) -> tuple[ThreatControl, ...]:
    return BASE_CONTROLS[risk_level]


def validate_policy_against_threats(spec: AgentSpec, policy: CompiledPolicy) -> list[str]:
    findings: list[str] = []

    if not policy.allowed_commands:
        findings.append("Missing allowed_commands policy.")

    if policy.max_tool_timeout_seconds <= 0:
        findings.append("Tool timeout policy must be positive.")

    network_tools = any(tool.can_access_network for tool in spec.tools)
    if network_tools and policy.network_mode != "allow_list":
        findings.append("Network-enabled tools require allow_list mode.")

    if spec.risk_level == "high" and not policy.requires_human_approval:
        findings.append("High-risk agents require human approval before release.")

    return findings
