from __future__ import annotations

from lifeguard.adversarial_reports import AdversarialReportStore, summarize_adversarial_history
from lifeguard.adversarial_validation import evaluate_adversarial_pack
from lifeguard.policy_compiler import compile_policy
from lifeguard.spec_schema import AgentSpec, DataScope, SecurityRequirements, ToolSpec


def _safe_spec() -> AgentSpec:
    return AgentSpec(
        name="adversarial-report-agent",
        description="Writes adversarial artifacts for trend tracking.",
        risk_level="medium",
        tools=(
            ToolSpec(
                name="review",
                command="python review.py",
                can_write_files=False,
                can_access_network=False,
                timeout_seconds=30,
            ),
        ),
        data_scope=DataScope(
            read_paths=("/workspace",),
            write_paths=("/workspace/reports",),
            allowed_hosts=(),
        ),
        runtime_environment="container",
        budget_limit_usd=35.0,
        max_runtime_seconds=600,
        security_requirements=SecurityRequirements(
            goals=("Track adversarial trends.", "Persist run artifacts."),
            threat_actors=("External attacker", "Malicious insider"),
            evidence_requirements=("Artifact file", "History summary"),
        ),
    )


def test_report_store_writes_artifact_and_history(tmp_path) -> None:
    evidence_path = tmp_path / "events.jsonl"
    store = AdversarialReportStore(evidence_path)
    spec = _safe_spec()
    policy = compile_policy(spec)

    first_report = evaluate_adversarial_pack(spec=spec, policy=policy)
    first_record = store.record(spec=spec, report=first_report)
    assert first_record.artifact_path.exists()
    assert first_record.history_path.exists()
    assert first_record.history_count == 1

    second_report = evaluate_adversarial_pack(spec=spec, policy=policy, threshold=1.10)
    second_record = store.record(spec=spec, report=second_report)
    assert second_record.history_count == 2
    assert second_record.pass_rate_delta_from_previous is not None


def test_history_summary_returns_latest_and_recent_records(tmp_path) -> None:
    evidence_path = tmp_path / "events.jsonl"
    store = AdversarialReportStore(evidence_path)
    spec = _safe_spec()
    policy = compile_policy(spec)
    store.record(spec=spec, report=evaluate_adversarial_pack(spec=spec, policy=policy))
    store.record(spec=spec, report=evaluate_adversarial_pack(spec=spec, policy=policy))

    summary = summarize_adversarial_history(evidence_path=evidence_path, limit=1)
    assert summary["count"] == 2
    assert summary["latest"] is not None
    assert len(summary["recent"]) == 1
