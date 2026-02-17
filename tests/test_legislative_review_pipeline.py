from __future__ import annotations

import json

from lifeguard.adapters import AdapterModuleStatus
from lifeguard.legislative_review import spec_sha256
from lifeguard.live_intelligence import Citation, LiveDataReport
from lifeguard.spec_schema import (
    AgentSpec,
    DataScope,
    LegalContext,
    LegislativeReviewSettings,
    LiveDataSettings,
    SecurityRequirements,
    ToolSpec,
)
from lifeguard.verification_pipeline import default_pipeline


class _FakeAdapterLayer:
    def list_module_status(self) -> tuple[AdapterModuleStatus, ...]:
        return (
            AdapterModuleStatus(
                adapter_name="json_parser",
                module_path="lifeguard.extracts.json_parser",
                available=True,
            ),
        )

    def run_security_preflight(self, repo_path):
        return None


class _FakeIntelligenceClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []

    def collect_latest(self, query, settings, risk_level="low"):
        del settings, risk_level
        query_text = str(query)
        self.calls.append({"query": query_text})
        jurisdiction = "United Kingdom" if "United Kingdom" in query_text else "European Union"
        domain = "legislation.gov.uk" if jurisdiction == "United Kingdom" else "eur-lex.europa.eu"
        return LiveDataReport(
            provider="openrouter",
            model="openai/gpt-5.2:online",
            query=query_text,
            summary=f"{jurisdiction} obligations summary.",
            citations=(
                Citation(
                    url=f"https://{domain}/example",
                    title=f"{jurisdiction} source",
                    domain=domain,
                ),
                Citation(
                    url=f"https://{domain}/example2",
                    title=f"{jurisdiction} source 2",
                    domain=domain,
                ),
            ),
            fetched_at="2026-02-17T00:00:00+00:00",
        )


def _spec(*, decision_file: str = "") -> AgentSpec:
    return AgentSpec(
        name="legislative-review-agent",
        description="Design and verify a secure agent.",
        risk_level="low",
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
        budget_limit_usd=30.0,
        max_runtime_seconds=600,
        security_requirements=SecurityRequirements(
            goals=("Review source for vulnerabilities.", "Produce deterministic evidence."),
            threat_actors=("External attacker", "Malicious insider"),
            evidence_requirements=("Signed summary", "Evidence log"),
        ),
        legal_context=LegalContext(
            jurisdictions=("United Kingdom", "European Union"),
            intended_use="tax administration assistant",
            sector="administrative",
            decision_impact_level="medium",
            compliance_target_date="2026-08-02",
            data_categories=("personal data",),
        ),
        legislative_review=LegislativeReviewSettings(
            enabled=True,
            provider="openrouter",
            model="openai/gpt-5.2:online",
            max_results=6,
            min_citations=2,
            timeout_seconds=60,
            strict=True,
            require_human_decision=True,
            decision_file=decision_file,
        ),
        live_data=LiveDataSettings(enabled=False),
    )


def test_pipeline_creates_legislative_decision_template_when_missing(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    intelligence = _FakeIntelligenceClient()
    pipeline = default_pipeline(
        evidence,
        adapter_layer=_FakeAdapterLayer(),
        intelligence_client=intelligence,  # type: ignore[arg-type]
    )
    report = pipeline.run(_spec())
    assert report.passed is False
    assert any(
        result.name == "legislative_review_gate" and not result.passed
        for result in report.results
    )
    decision_path = tmp_path / "legislative_review_decision.json"
    pack_path = tmp_path / "legislative_review_pack.json"
    assert decision_path.exists()
    assert pack_path.exists()

    decision_payload = json.loads(decision_path.read_text(encoding="utf-8"))
    assert decision_payload["spec_name"] == "legislative-review-agent"
    assert decision_payload["spec_sha256"] == spec_sha256(_spec())
    assert decision_payload["jurisdictions"] == ["United Kingdom", "European Union"]


def test_pipeline_passes_when_legislative_decision_accepts(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    decision_path = tmp_path / "legislative_review_decision.json"
    spec = _spec()
    decision_payload = {
        "version": 1,
        "decision": "accept",
        "reviewed_by": "compliance-reviewer",
        "review_id": "leg-approval-001",
        "reviewed_at": "2026-02-17T00:00:00+00:00",
        "notes": "Reviewed and approved for administrative use.",
        "spec_name": spec.name,
        "spec_sha256": spec_sha256(spec),
        "pack_sha256": "",
        "jurisdictions": ["United Kingdom", "European Union"],
    }
    decision_path.write_text(json.dumps(decision_payload, indent=2) + "\n", encoding="utf-8")

    intelligence = _FakeIntelligenceClient()
    pipeline = default_pipeline(
        evidence,
        adapter_layer=_FakeAdapterLayer(),
        intelligence_client=intelligence,  # type: ignore[arg-type]
    )
    report = pipeline.run(spec)
    assert report.passed is True
    assert any(
        result.name == "legislative_review_gate" and result.passed
        for result in report.results
    )

