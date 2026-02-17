from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .live_intelligence import Citation, LiveDataAssessment, LiveDataAttempt, LiveDataReport
from .policy_compiler import CompiledPolicy
from .spec_schema import AgentSpec
from .verification_pipeline import CheckResult, VerificationReport

_SAFE_IDENTIFIER_PATTERN = re.compile(r"[^a-zA-Z0-9._-]")
_MAX_IDENTIFIER_LENGTH = 120


@dataclass(frozen=True)
class RuntimeCheckpoint:
    run_id: str
    node_name: str
    sequence: int
    saved_at: str
    path: Path
    state: dict[str, Any]


class RuntimeCheckpointStore:
    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def generate_run_id(self) -> str:
        now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        suffix = uuid.uuid4().hex[:8]
        return f"run-{now}-{suffix}"

    def save_checkpoint(
        self,
        run_id: str,
        node_name: str,
        sequence: int,
        state: dict[str, Any],
    ) -> RuntimeCheckpoint:
        safe_run_id = _sanitize_checkpoint_identifier(run_id, label="run_id")
        safe_node_name = _sanitize_checkpoint_identifier(node_name, label="node_name")
        timestamp = datetime.now(timezone.utc).isoformat()
        filename = f"{safe_run_id}--{sequence:03d}--{safe_node_name}.json"
        path = self.directory / filename
        serialized_state = _serialize_state(state)
        serialized_state["checkpoint_path"] = str(path)
        serialized_state["run_id"] = safe_run_id
        payload = {
            "version": 1,
            "run_id": safe_run_id,
            "node_name": safe_node_name,
            "sequence": sequence,
            "saved_at": timestamp,
            "state": serialized_state,
        }
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return RuntimeCheckpoint(
            run_id=safe_run_id,
            node_name=safe_node_name,
            sequence=sequence,
            saved_at=timestamp,
            path=path,
            state=_deserialize_state(serialized_state),
        )

    def load_checkpoint(self, checkpoint_path: str | Path) -> RuntimeCheckpoint:
        path = Path(checkpoint_path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Checkpoint file root must be an object.")
        state_payload = payload.get("state")
        if not isinstance(state_payload, dict):
            raise ValueError("Checkpoint missing state object.")
        return RuntimeCheckpoint(
            run_id=str(payload.get("run_id", "")).strip(),
            node_name=str(payload.get("node_name", "")).strip(),
            sequence=int(payload.get("sequence", 0)),
            saved_at=str(payload.get("saved_at", "")).strip(),
            path=path,
            state=_deserialize_state(state_payload),
        )


def _sanitize_checkpoint_identifier(value: str, *, label: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"Checkpoint {label} must not be empty.")
    cleaned = _SAFE_IDENTIFIER_PATTERN.sub("_", cleaned)
    cleaned = cleaned.strip("._-")
    if not cleaned:
        raise ValueError(f"Checkpoint {label} did not contain any safe characters.")
    return cleaned[:_MAX_IDENTIFIER_LENGTH]


def _serialize_state(state: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {}

    spec = state.get("spec")
    if isinstance(spec, AgentSpec):
        payload["spec"] = spec.to_dict()

    spec_path = state.get("spec_path")
    if isinstance(spec_path, str):
        payload["spec_path"] = spec_path

    policy = state.get("policy")
    if isinstance(policy, CompiledPolicy):
        payload["policy"] = {
            "allowed_commands": list(policy.allowed_commands),
            "read_paths": list(policy.read_paths),
            "write_paths": list(policy.write_paths),
            "allowed_hosts": list(policy.allowed_hosts),
            "network_mode": policy.network_mode,
            "max_tool_timeout_seconds": policy.max_tool_timeout_seconds,
            "requires_human_approval": policy.requires_human_approval,
        }
    elif policy is None and "policy" in state:
        payload["policy"] = None

    if "policy_error" in state:
        payload["policy_error"] = state.get("policy_error")

    live_data_report = state.get("live_data_report")
    if isinstance(live_data_report, LiveDataReport):
        payload["live_data_report"] = {
            "provider": live_data_report.provider,
            "model": live_data_report.model,
            "query": live_data_report.query,
            "summary": live_data_report.summary,
            "fetched_at": live_data_report.fetched_at,
            "attempts": [
                {
                    "attempt_number": item.attempt_number,
                    "model": item.model,
                    "query_variant": item.query_variant,
                    "citation_count": item.citation_count,
                    "assessment_passed": item.assessment_passed,
                    "failure": item.failure,
                }
                for item in live_data_report.attempts
            ],
            "assessment": live_data_report.assessment.to_dict(),
            "citations": [
                {
                    "url": citation.url,
                    "title": citation.title,
                    "domain": citation.domain,
                    "trust_tier": citation.trust_tier,
                    "source_type": citation.source_type,
                    "published_at": citation.published_at,
                    "freshness_window_days": citation.freshness_window_days,
                    "age_days": citation.age_days,
                    "is_fresh": citation.is_fresh,
                }
                for citation in live_data_report.citations
            ],
        }
    elif live_data_report is None and "live_data_report" in state:
        payload["live_data_report"] = None

    if "live_data_error" in state:
        payload["live_data_error"] = state.get("live_data_error")

    threat_findings = state.get("threat_findings")
    if isinstance(threat_findings, (list, tuple)):
        payload["threat_findings"] = [str(item) for item in threat_findings]

    if "tool_gate_passed" in state:
        payload["tool_gate_passed"] = bool(state.get("tool_gate_passed"))

    tool_gate_results = state.get("tool_gate_results")
    if isinstance(tool_gate_results, (list, tuple)):
        payload["tool_gate_results"] = [dict(item) for item in tool_gate_results]

    blocked_tool_decisions = state.get("blocked_tool_decisions")
    if isinstance(blocked_tool_decisions, (list, tuple)):
        payload["blocked_tool_decisions"] = [dict(item) for item in blocked_tool_decisions]

    if "tool_execution_passed" in state:
        payload["tool_execution_passed"] = bool(state.get("tool_execution_passed"))

    tool_execution_results = state.get("tool_execution_results")
    if isinstance(tool_execution_results, (list, tuple)):
        payload["tool_execution_results"] = [dict(item) for item in tool_execution_results]

    if "tool_execution_error" in state:
        tool_execution_error = state.get("tool_execution_error")
        payload["tool_execution_error"] = (
            str(tool_execution_error) if tool_execution_error is not None else None
        )

    verification_report = state.get("verification_report")
    if isinstance(verification_report, VerificationReport):
        payload["verification_report"] = {
            "passed": verification_report.passed,
            "results": [
                {
                    "name": result.name,
                    "passed": result.passed,
                    "message": result.message,
                }
                for result in verification_report.results
            ],
            "policy": (
                {
                    "allowed_commands": list(verification_report.policy.allowed_commands),
                    "read_paths": list(verification_report.policy.read_paths),
                    "write_paths": list(verification_report.policy.write_paths),
                    "allowed_hosts": list(verification_report.policy.allowed_hosts),
                    "network_mode": verification_report.policy.network_mode,
                    "max_tool_timeout_seconds": verification_report.policy.max_tool_timeout_seconds,
                    "requires_human_approval": verification_report.policy.requires_human_approval,
                }
                if verification_report.policy is not None
                else None
            ),
            "evidence_path": str(verification_report.evidence_path),
        }

    completed_nodes = state.get("completed_nodes")
    if isinstance(completed_nodes, (list, tuple)):
        payload["completed_nodes"] = [str(item) for item in completed_nodes]

    checkpoint_path = state.get("checkpoint_path")
    if isinstance(checkpoint_path, str):
        payload["checkpoint_path"] = checkpoint_path

    run_id = state.get("run_id")
    if isinstance(run_id, str):
        payload["run_id"] = run_id

    return payload


def _deserialize_state(payload: dict[str, Any]) -> dict[str, Any]:
    state: dict[str, Any] = {}

    spec_payload = payload.get("spec")
    if isinstance(spec_payload, dict):
        state["spec"] = AgentSpec.from_dict(spec_payload)

    spec_path = payload.get("spec_path")
    if isinstance(spec_path, str):
        state["spec_path"] = spec_path

    policy_payload = payload.get("policy")
    if isinstance(policy_payload, dict):
        state["policy"] = CompiledPolicy(
            allowed_commands=tuple(str(item) for item in policy_payload.get("allowed_commands", [])),
            read_paths=tuple(str(item) for item in policy_payload.get("read_paths", [])),
            write_paths=tuple(str(item) for item in policy_payload.get("write_paths", [])),
            allowed_hosts=tuple(str(item) for item in policy_payload.get("allowed_hosts", [])),
            network_mode=str(policy_payload.get("network_mode", "")).strip(),
            max_tool_timeout_seconds=int(policy_payload.get("max_tool_timeout_seconds", 0)),
            requires_human_approval=bool(policy_payload.get("requires_human_approval", False)),
        )
    elif "policy" in payload:
        state["policy"] = None

    if "policy_error" in payload:
        policy_error = payload.get("policy_error")
        state["policy_error"] = str(policy_error) if policy_error is not None else None

    live_data_payload = payload.get("live_data_report")
    if isinstance(live_data_payload, dict):
        citations_payload = live_data_payload.get("citations", [])
        citations: list[Citation] = []
        if isinstance(citations_payload, list):
            for item in citations_payload:
                if not isinstance(item, dict):
                    continue
                citations.append(
                    Citation(
                        url=str(item.get("url", "")).strip(),
                        title=str(item.get("title", "")).strip(),
                        domain=str(item.get("domain", "")).strip(),
                        trust_tier=str(item.get("trust_tier", "low")).strip(),
                        source_type=str(item.get("source_type", "general")).strip(),
                        published_at=(
                            str(item.get("published_at", "")).strip()
                            if item.get("published_at") is not None
                            else None
                        ),
                        freshness_window_days=(
                            int(item.get("freshness_window_days"))
                            if item.get("freshness_window_days") is not None
                            else None
                        ),
                        age_days=(
                            int(item.get("age_days"))
                            if item.get("age_days") is not None
                            else None
                        ),
                        is_fresh=(
                            bool(item.get("is_fresh"))
                            if item.get("is_fresh") is not None
                            else None
                        ),
                    )
                )
        assessment_payload = live_data_payload.get("assessment", {})
        attempts_payload = live_data_payload.get("attempts", [])
        attempts: list[LiveDataAttempt] = []
        if isinstance(attempts_payload, list):
            for item in attempts_payload:
                if not isinstance(item, dict):
                    continue
                attempts.append(
                    LiveDataAttempt(
                        attempt_number=int(item.get("attempt_number", 0)),
                        model=str(item.get("model", "")).strip(),
                        query_variant=str(item.get("query_variant", "")).strip(),
                        citation_count=int(item.get("citation_count", 0)),
                        assessment_passed=bool(item.get("assessment_passed", False)),
                        failure=str(item.get("failure", "")).strip(),
                    )
                )
        assessment = LiveDataAssessment(
            passed=bool(assessment_payload.get("passed", True))
            if isinstance(assessment_payload, dict)
            else True,
            trusted_citation_count=int(assessment_payload.get("trusted_citation_count", 0))
            if isinstance(assessment_payload, dict)
            else 0,
            required_trusted_citation_count=int(
                assessment_payload.get("required_trusted_citation_count", 0)
            )
            if isinstance(assessment_payload, dict)
            else 0,
            independent_trusted_domains=tuple(
                str(item)
                for item in assessment_payload.get("independent_trusted_domains", [])
            )
            if isinstance(assessment_payload, dict)
            else (),
            required_independent_trusted_domains=int(
                assessment_payload.get("required_independent_trusted_domains", 0)
            )
            if isinstance(assessment_payload, dict)
            else 0,
            stale_citation_count=int(assessment_payload.get("stale_citation_count", 0))
            if isinstance(assessment_payload, dict)
            else 0,
            unknown_freshness_count=int(assessment_payload.get("unknown_freshness_count", 0))
            if isinstance(assessment_payload, dict)
            else 0,
            freshness_enforced=bool(assessment_payload.get("freshness_enforced", False))
            if isinstance(assessment_payload, dict)
            else False,
            publication_dates_required=bool(
                assessment_payload.get("publication_dates_required", False)
            )
            if isinstance(assessment_payload, dict)
            else False,
            managed_profile=(
                {
                    str(key): str(value)
                    for key, value in dict(assessment_payload.get("managed_profile", {})).items()
                }
                if isinstance(assessment_payload, dict)
                and isinstance(assessment_payload.get("managed_profile"), dict)
                else None
            ),
            failures=tuple(str(item) for item in assessment_payload.get("failures", []))
            if isinstance(assessment_payload, dict)
            else (),
        )
        state["live_data_report"] = LiveDataReport(
            provider=str(live_data_payload.get("provider", "")).strip(),
            model=str(live_data_payload.get("model", "")).strip(),
            query=str(live_data_payload.get("query", "")).strip(),
            summary=str(live_data_payload.get("summary", "")).strip(),
            citations=tuple(citations),
            fetched_at=str(live_data_payload.get("fetched_at", "")).strip(),
            attempts=tuple(attempts),
            assessment=assessment,
        )
    elif "live_data_report" in payload:
        state["live_data_report"] = None

    if "live_data_error" in payload:
        live_data_error = payload.get("live_data_error")
        state["live_data_error"] = str(live_data_error) if live_data_error is not None else None

    threat_findings_payload = payload.get("threat_findings")
    if isinstance(threat_findings_payload, list):
        state["threat_findings"] = tuple(str(item) for item in threat_findings_payload)

    if "tool_gate_passed" in payload:
        state["tool_gate_passed"] = bool(payload.get("tool_gate_passed"))

    tool_gate_results_payload = payload.get("tool_gate_results")
    if isinstance(tool_gate_results_payload, list):
        state["tool_gate_results"] = tuple(
            dict(item) for item in tool_gate_results_payload if isinstance(item, dict)
        )

    blocked_tool_payload = payload.get("blocked_tool_decisions")
    if isinstance(blocked_tool_payload, list):
        state["blocked_tool_decisions"] = tuple(
            dict(item) for item in blocked_tool_payload if isinstance(item, dict)
        )

    if "tool_execution_passed" in payload:
        state["tool_execution_passed"] = bool(payload.get("tool_execution_passed"))

    tool_execution_payload = payload.get("tool_execution_results")
    if isinstance(tool_execution_payload, list):
        state["tool_execution_results"] = tuple(
            dict(item) for item in tool_execution_payload if isinstance(item, dict)
        )

    if "tool_execution_error" in payload:
        tool_execution_error = payload.get("tool_execution_error")
        state["tool_execution_error"] = (
            str(tool_execution_error) if tool_execution_error is not None else None
        )

    verification_payload = payload.get("verification_report")
    if isinstance(verification_payload, dict):
        check_payload = verification_payload.get("results", [])
        checks: list[CheckResult] = []
        if isinstance(check_payload, list):
            for item in check_payload:
                if not isinstance(item, dict):
                    continue
                checks.append(
                    CheckResult(
                        name=str(item.get("name", "")).strip(),
                        passed=bool(item.get("passed", False)),
                        message=str(item.get("message", "")).strip(),
                    )
                )
        report_policy_payload = verification_payload.get("policy")
        report_policy: CompiledPolicy | None = None
        if isinstance(report_policy_payload, dict):
            report_policy = CompiledPolicy(
                allowed_commands=tuple(
                    str(item) for item in report_policy_payload.get("allowed_commands", [])
                ),
                read_paths=tuple(str(item) for item in report_policy_payload.get("read_paths", [])),
                write_paths=tuple(str(item) for item in report_policy_payload.get("write_paths", [])),
                allowed_hosts=tuple(
                    str(item) for item in report_policy_payload.get("allowed_hosts", [])
                ),
                network_mode=str(report_policy_payload.get("network_mode", "")).strip(),
                max_tool_timeout_seconds=int(
                    report_policy_payload.get("max_tool_timeout_seconds", 0)
                ),
                requires_human_approval=bool(
                    report_policy_payload.get("requires_human_approval", False)
                ),
            )
        evidence_path = Path(str(verification_payload.get("evidence_path", "")).strip())
        state["verification_report"] = VerificationReport(
            passed=bool(verification_payload.get("passed", False)),
            results=tuple(checks),
            policy=report_policy,
            evidence_path=evidence_path,
        )

    completed_nodes_payload = payload.get("completed_nodes")
    if isinstance(completed_nodes_payload, list):
        state["completed_nodes"] = tuple(str(item) for item in completed_nodes_payload)

    checkpoint_path = payload.get("checkpoint_path")
    if isinstance(checkpoint_path, str):
        state["checkpoint_path"] = checkpoint_path

    run_id = payload.get("run_id")
    if isinstance(run_id, str):
        state["run_id"] = run_id

    return state
