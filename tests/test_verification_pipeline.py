import json

from lifeguard.adapters import (
    AdapterActionResult,
    AdapterError,
    AdapterModuleStatus,
    AdapterTrustMetadata,
)
from lifeguard.adversarial_validation import AdversarialValidationReport
from lifeguard.live_intelligence import Citation, LiveDataProviderError, LiveDataReport
from lifeguard.spec_schema import (
    AgentSpec,
    DataScope,
    LiveDataSettings,
    SecurityRequirements,
    ToolSpec,
)
from lifeguard.verification_pipeline import default_pipeline


def _base_spec(command: str) -> AgentSpec:
    return AgentSpec(
        name="local-review",
        description="Analyze source and create report.",
        risk_level="low",
        tools=(
            ToolSpec(
                name="review",
                command=command,
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
            goals=("Find security defects.", "Generate remediation guidance."),
            threat_actors=("External attacker", "Malicious insider"),
            evidence_requirements=("Signed summary", "File-level findings"),
        ),
    )


class _FakeAdapterLayer:
    def __init__(
        self,
        statuses: tuple[AdapterModuleStatus, ...],
        preflight_error: str | None = None,
    ) -> None:
        self._statuses = statuses
        self._preflight_error = preflight_error

    def list_module_status(self) -> tuple[AdapterModuleStatus, ...]:
        return self._statuses

    def run_security_preflight(self, repo_path):
        return self._preflight_error


class _FakeIntelligenceClient:
    def __init__(self, report: LiveDataReport | None = None, error: Exception | None = None) -> None:
        self._report = report
        self._error = error

    def collect_latest(self, query, settings, risk_level="low"):
        if self._error is not None:
            raise self._error
        if self._report is None:
            raise AssertionError("Fake intelligence client missing report.")
        return self._report


def _available_statuses() -> tuple[AdapterModuleStatus, ...]:
    return (
        AdapterModuleStatus(
            adapter_name="json_parser",
            module_path="lifeguard.extracts.json_parser",
            available=True,
        ),
    )


def test_pipeline_passes_for_safe_spec(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    pipeline = default_pipeline(evidence)
    report = pipeline.run(_base_spec("python review.py"))
    assert report.passed is True
    assert evidence.exists()
    lines = evidence.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) >= 1
    json.loads(lines[-1])
    adversarial_events = [
        json.loads(line)
        for line in lines
        if json.loads(line).get("event_type") == "adversarial_resilience"
    ]
    assert adversarial_events
    details = adversarial_events[-1]["details"]
    assert "artifact_path" in details
    assert "history_path" in details


def test_pipeline_fails_on_secret_marker(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    pipeline = default_pipeline(evidence)
    report = pipeline.run(_base_spec("python run.py --token=abcd"))
    assert report.passed is False
    assert any(result.name == "secret_hygiene" and not result.passed for result in report.results)


def test_pipeline_fails_high_risk_local_environment(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    pipeline = default_pipeline(evidence)
    spec = _base_spec("python review.py")
    spec = AgentSpec(
        name=spec.name,
        description=spec.description,
        risk_level="high",
        tools=spec.tools,
        data_scope=spec.data_scope,
        runtime_environment="local",
        budget_limit_usd=spec.budget_limit_usd,
        max_runtime_seconds=spec.max_runtime_seconds,
        profile_id=spec.profile_id,
        security_requirements=spec.security_requirements,
    )
    report = pipeline.run(spec)
    assert report.passed is False
    assert any(
        result.name == "runtime_environment_guardrail" and not result.passed
        for result in report.results
    )


def test_pipeline_fails_when_adapter_module_unavailable(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    adapter = _FakeAdapterLayer(
        statuses=(
            AdapterModuleStatus(
                adapter_name="json_parser",
                module_path="lifeguard.extracts.json_parser",
                available=False,
                detail="mock missing module",
            ),
        ),
    )
    pipeline = default_pipeline(evidence, adapter_layer=adapter)
    report = pipeline.run(_base_spec("python review.py"))
    assert report.passed is False
    assert any(
        result.name == "adapter_module_readiness" and not result.passed
        for result in report.results
    )


def test_pipeline_fails_on_adapter_preflight_error(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    adapter = _FakeAdapterLayer(
        statuses=_available_statuses(),
        preflight_error="preflight blocked by policy",
    )
    pipeline = default_pipeline(evidence, adapter_layer=adapter)
    report = pipeline.run(_base_spec("python review.py"))
    assert report.passed is False
    assert any(
        result.name == "adapter_security_preflight" and not result.passed
        for result in report.results
    )


def test_pipeline_fails_when_live_intelligence_is_strict(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    spec = _base_spec("python review.py")
    spec = AgentSpec(
        name=spec.name,
        description=spec.description,
        risk_level=spec.risk_level,
        tools=spec.tools,
        data_scope=spec.data_scope,
        runtime_environment=spec.runtime_environment,
        budget_limit_usd=spec.budget_limit_usd,
        max_runtime_seconds=spec.max_runtime_seconds,
        profile_id=spec.profile_id,
        security_requirements=spec.security_requirements,
        live_data=LiveDataSettings(
            enabled=True,
            provider="openrouter",
            model="openai/gpt-5.2:online",
            max_results=3,
            min_citations=1,
            timeout_seconds=15,
            strict=True,
        ),
    )
    pipeline = default_pipeline(
        evidence,
        adapter_layer=_FakeAdapterLayer(statuses=_available_statuses()),
        intelligence_client=_FakeIntelligenceClient(error=LiveDataProviderError("provider timeout")),
    )
    report = pipeline.run(spec)
    assert report.passed is False
    assert any(
        result.name == "live_intelligence_freshness" and not result.passed for result in report.results
    )


def test_pipeline_passes_when_live_intelligence_is_not_strict(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    spec = _base_spec("python review.py")
    spec = AgentSpec(
        name=spec.name,
        description=spec.description,
        risk_level=spec.risk_level,
        tools=spec.tools,
        data_scope=spec.data_scope,
        runtime_environment=spec.runtime_environment,
        budget_limit_usd=spec.budget_limit_usd,
        max_runtime_seconds=spec.max_runtime_seconds,
        profile_id=spec.profile_id,
        security_requirements=spec.security_requirements,
        live_data=LiveDataSettings(
            enabled=True,
            provider="openrouter",
            model="openai/gpt-5.2:online",
            max_results=3,
            min_citations=1,
            timeout_seconds=15,
            strict=False,
        ),
    )
    pipeline = default_pipeline(
        evidence,
        adapter_layer=_FakeAdapterLayer(statuses=_available_statuses()),
        intelligence_client=_FakeIntelligenceClient(error=LiveDataProviderError("provider timeout")),
    )
    report = pipeline.run(spec)
    assert report.passed is True
    assert any(
        result.name == "live_intelligence_freshness" and result.passed for result in report.results
    )


def test_pipeline_fails_when_live_intelligence_is_not_strict_for_medium_risk(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    spec = _base_spec("python review.py")
    spec = AgentSpec(
        name=spec.name,
        description=spec.description,
        risk_level="medium",
        tools=spec.tools,
        data_scope=spec.data_scope,
        runtime_environment=spec.runtime_environment,
        budget_limit_usd=spec.budget_limit_usd,
        max_runtime_seconds=spec.max_runtime_seconds,
        profile_id=spec.profile_id,
        security_requirements=spec.security_requirements,
        live_data=LiveDataSettings(
            enabled=True,
            provider="openrouter",
            model="openai/gpt-5.2:online",
            max_results=3,
            min_citations=1,
            timeout_seconds=15,
            strict=False,
        ),
    )
    pipeline = default_pipeline(
        evidence,
        adapter_layer=_FakeAdapterLayer(statuses=_available_statuses()),
        intelligence_client=_FakeIntelligenceClient(error=LiveDataProviderError("provider timeout")),
    )
    report = pipeline.run(spec)
    assert report.passed is False
    assert any(
        result.name == "live_intelligence_freshness" and not result.passed for result in report.results
    )


def test_pipeline_passes_when_live_intelligence_returns_citations(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    spec = _base_spec("python review.py")
    spec = AgentSpec(
        name=spec.name,
        description=spec.description,
        risk_level=spec.risk_level,
        tools=spec.tools,
        data_scope=spec.data_scope,
        runtime_environment=spec.runtime_environment,
        budget_limit_usd=spec.budget_limit_usd,
        max_runtime_seconds=spec.max_runtime_seconds,
        profile_id=spec.profile_id,
        security_requirements=spec.security_requirements,
        live_data=LiveDataSettings(
            enabled=True,
            provider="openrouter",
            model="openai/gpt-5.2:online",
            max_results=3,
            min_citations=1,
            timeout_seconds=15,
            strict=True,
        ),
    )
    report_payload = LiveDataReport(
        provider="openrouter",
        model="openai/gpt-5.2:online",
        query="latest secure design checks",
        summary="Latest controls include explicit citation tracking.",
        citations=(
            Citation(
                url="https://openrouter.ai/docs/use-cases/web-browsing",
                title="Open Router Web Browsing",
                domain="openrouter.ai",
            ),
        ),
        fetched_at="2026-02-14T20:00:00+00:00",
    )
    pipeline = default_pipeline(
        evidence,
        adapter_layer=_FakeAdapterLayer(statuses=_available_statuses()),
        intelligence_client=_FakeIntelligenceClient(report=report_payload),
    )
    report = pipeline.run(spec)
    assert report.passed is True
    assert any(
        result.name == "live_intelligence_freshness" and result.passed for result in report.results
    )


def test_pipeline_blocks_weak_spec_with_quality_gate(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    pipeline = default_pipeline(evidence, adapter_layer=_FakeAdapterLayer(statuses=_available_statuses()))
    weak_spec = AgentSpec(
        name="weak-quality-spec",
        description="Weak specification that should be blocked by quality gate.",
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
            write_paths=(),
            allowed_hosts=(),
        ),
        runtime_environment="container",
        budget_limit_usd=25.0,
        max_runtime_seconds=300,
    )
    report = pipeline.run(weak_spec)
    assert report.passed is False
    assert len(report.results) == 1
    assert report.results[0].name == "spec_quality_gate"


def test_pipeline_fails_when_adversarial_resilience_is_weak(tmp_path, monkeypatch) -> None:
    evidence = tmp_path / "events.jsonl"
    pipeline = default_pipeline(evidence, adapter_layer=_FakeAdapterLayer(statuses=_available_statuses()))
    spec = AgentSpec(
        name="weak-adversarial-resilience",
        description="Specification that should fail adversarial gate.",
        risk_level="medium",
        tools=(
            ToolSpec(
                name="fetch",
                command="python fetch.py",
                can_write_files=False,
                can_access_network=True,
                timeout_seconds=30,
            ),
        ),
        data_scope=DataScope(
            read_paths=("/workspace",),
            write_paths=("/workspace/reports",),
            allowed_hosts=("attacker.example",),
        ),
        runtime_environment="container",
        budget_limit_usd=30.0,
        max_runtime_seconds=600,
        security_requirements=SecurityRequirements(
            goals=("Collect remote data.", "Summarize findings."),
            threat_actors=("External attacker", "Compromised dependency"),
            evidence_requirements=("Verification log", "Risk summary"),
        ),
        live_data=LiveDataSettings(enabled=False),
    )

    def fake_evaluate_adversarial_pack(*, spec, policy, **kwargs):
        del spec, policy, kwargs
        return AdversarialValidationReport(
            passed=False,
            pass_rate=0.4,
            threshold=0.85,
            passed_cases=4,
            total_cases=10,
            failed_case_ids=("fetch:command_smuggling_chain",),
            results=(),
        )

    monkeypatch.setattr(
        "lifeguard.verification_pipeline.evaluate_adversarial_pack",
        fake_evaluate_adversarial_pack,
    )
    report = pipeline.run(spec)
    assert report.passed is False
    assert any(
        result.name == "adversarial_resilience" and not result.passed
        for result in report.results
    )


def test_pipeline_records_model_context_protocol_gating_events(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    pipeline = default_pipeline(evidence)
    report = pipeline.run(_base_spec("python review.py"))

    assert report.passed is True
    assert any(
        result.name == "model_context_protocol_gating" and result.passed
        for result in report.results
    )
    events = [json.loads(line) for line in evidence.read_text(encoding="utf-8").splitlines()]
    event_types = [item.get("event_type") for item in events]
    assert "model_context_protocol_gating.export" in event_types
    assert "model_context_protocol_gating.import" in event_types
    assert "model_context_protocol_gating.final" in event_types
    decision_events = [
        item
        for item in events
        if item.get("event_type") == "model_context_protocol_gating.decision"
    ]
    assert len(decision_events) >= 3


def test_pipeline_fails_when_model_context_protocol_export_gating_fails(
    tmp_path, monkeypatch
) -> None:
    evidence = tmp_path / "events.jsonl"

    class _FailingModelContextProtocolCompatibilityAdapter:
        def execute_action(self, request):
            return AdapterActionResult(
                action_name=request.action_name,
                ok=False,
                errors=(
                    AdapterError(
                        code="invalid_action_payload",
                        message="simulated export failure",
                        category="validation",
                    ),
                ),
                metadata={},
                trust=AdapterTrustMetadata(),
            )

    monkeypatch.setattr(
        "lifeguard.verification_pipeline.ModelContextProtocolCompatibilityAdapter",
        _FailingModelContextProtocolCompatibilityAdapter,
    )

    pipeline = default_pipeline(evidence)
    report = pipeline.run(_base_spec("python review.py"))
    assert report.passed is False
    assert any(
        result.name == "model_context_protocol_gating" and not result.passed
        for result in report.results
    )
    events = [json.loads(line) for line in evidence.read_text(encoding="utf-8").splitlines()]
    event_types = [item.get("event_type") for item in events]
    assert "model_context_protocol_gating.export" in event_types
    assert "model_context_protocol_gating.final" in event_types
