from __future__ import annotations

import json
from dataclasses import replace

import pytest

from lifeguard.adapters import AdapterModuleStatus
from lifeguard.langgraph_runtime import default_langgraph_runtime
from lifeguard.live_intelligence import Citation, LiveDataProviderError, LiveDataReport
from lifeguard.runtime_policy_middleware import ToolGateDecision
from lifeguard.spec_schema import (
    AgentSpec,
    DataScope,
    LiveDataSettings,
    SecurityRequirements,
    ToolSpec,
    write_spec,
)
from lifeguard.tool_execution import ToolExecutionResult


_GUARD_ENV_VARS = (
    "LANGSMITH_API_KEY",
    "LANGCHAIN_API_KEY",
    "LANGSMITH_ENDPOINT",
    "LANGCHAIN_ENDPOINT",
    "LANGCHAIN_TRACING_V2",
    "LANGSMITH_TRACING",
)


def _clear_guard_env(monkeypatch) -> None:
    for key in _GUARD_ENV_VARS:
        monkeypatch.delenv(key, raising=False)


def _base_spec(live_data: LiveDataSettings | None = None) -> AgentSpec:
    return AgentSpec(
        name="langgraph-review",
        description="Analyze repository security posture.",
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
        budget_limit_usd=50.0,
        max_runtime_seconds=600,
        security_requirements=SecurityRequirements(
            goals=("Assess repository security posture.", "Produce deterministic verification output."),
            threat_actors=("External attacker", "Malicious insider"),
            evidence_requirements=("Signed verification summary", "Evidence log entries"),
        ),
        live_data=live_data or LiveDataSettings(enabled=False),
    )


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
    def __init__(self, report: LiveDataReport | None = None, error: Exception | None = None) -> None:
        self._report = report
        self._error = error

    def collect_latest(self, query, settings, risk_level="low"):
        if self._error is not None:
            raise self._error
        if self._report is None:
            raise AssertionError("Missing report for fake intelligence client.")
        return self._report


class _BlockedPolicyMiddleware:
    def evaluate_spec_tools(self, spec, policy):
        return (
            ToolGateDecision(
                tool_name="review",
                command="python review.py",
                allowed=False,
                reason="Blocked by policy middleware test.",
            ),
        )


class _FakeToolExecutor:
    def __init__(self, *, passed: bool = True, policy_violations: tuple[str, ...] = ()) -> None:
        self._passed = passed
        self._policy_violations = policy_violations

    def execute_spec_tools(self, *, spec, policy):
        del policy
        results: list[ToolExecutionResult] = []
        for tool in spec.tools:
            results.append(
                ToolExecutionResult(
                    tool_name=tool.name,
                    command=tool.command,
                    runtime_environment=spec.runtime_environment,
                    backend="docker_hardened",
                    image="cgr.dev/chainguard/python:latest-dev",
                    passed=self._passed,
                    exit_code=0 if self._passed else 1,
                    stdout="ok" if self._passed else "",
                    stderr="" if self._passed else "tool failed",
                    reason=(
                        "; ".join(self._policy_violations)
                        if self._policy_violations
                        else ("" if self._passed else "tool failed")
                    ),
                    policy_violations=self._policy_violations,
                )
            )
        return tuple(results)


class _CapturingToolExecutor(_FakeToolExecutor):
    def __init__(self, *, passed: bool = True) -> None:
        super().__init__(passed=passed)
        self.runtime_environments: list[str] = []

    def execute_spec_tools(self, *, spec, policy):
        self.runtime_environments.append(spec.runtime_environment)
        return super().execute_spec_tools(spec=spec, policy=policy)


class _SequentialRunner:
    def __init__(self, nodes) -> None:
        self._nodes = nodes

    def invoke(self, input):
        state = dict(input)
        for _, node in self._nodes:
            update = node(state)
            if update:
                state.update(update)
        return state


def _sequential_graph_runner_factory(nodes):
    return _SequentialRunner(nodes)


class _ReplacingRunner:
    def __init__(self, nodes) -> None:
        self._nodes = nodes

    def invoke(self, input):
        state = dict(input)
        for _, node in self._nodes:
            update = node(state)
            if update:
                state = dict(update)
        return state


def _replacing_graph_runner_factory(nodes):
    return _ReplacingRunner(nodes)


def test_langgraph_runtime_passes_with_disabled_live_data(tmp_path, monkeypatch) -> None:
    _clear_guard_env(monkeypatch)
    evidence = tmp_path / "events.jsonl"
    runtime = default_langgraph_runtime(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
        graph_runner_factory=_sequential_graph_runner_factory,
        tool_executor=_FakeToolExecutor(),
    )
    report = runtime.run(spec=_base_spec())

    assert report.passed is True
    assert report.policy is not None
    assert report.threat_findings == ()

    lines = evidence.read_text(encoding="utf-8").strip().splitlines()
    events = [json.loads(line)["event_type"] for line in lines]
    assert "langgraph.runtime.load_spec" in events
    assert "langgraph.runtime.model_context_protocol_gating" in events
    assert "langgraph.runtime.verification" in events


def test_langgraph_runtime_fails_when_strict_live_data_fails(tmp_path, monkeypatch) -> None:
    _clear_guard_env(monkeypatch)
    evidence = tmp_path / "events.jsonl"
    settings = LiveDataSettings(
        enabled=True,
        provider="openrouter",
        model="openai/gpt-5.2:online",
        max_results=3,
        min_citations=1,
        timeout_seconds=15,
        strict=True,
    )
    runtime = default_langgraph_runtime(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
        intelligence_client=_FakeIntelligenceClient(error=LiveDataProviderError("provider down")),
        graph_runner_factory=_sequential_graph_runner_factory,
        tool_executor=_FakeToolExecutor(),
    )
    report = runtime.run(spec=_base_spec(live_data=settings))

    assert report.passed is False
    assert report.live_data_error == "provider down"
    assert report.verification_report.passed is False


def test_langgraph_runtime_loads_spec_from_path(tmp_path, monkeypatch) -> None:
    _clear_guard_env(monkeypatch)
    evidence = tmp_path / "events.jsonl"
    spec_path = tmp_path / "spec.json"
    settings = LiveDataSettings(
        enabled=True,
        provider="openrouter",
        model="openai/gpt-5.2:online",
        max_results=3,
        min_citations=1,
        timeout_seconds=15,
        strict=True,
    )
    spec = _base_spec(live_data=settings)
    write_spec(spec_path, spec)
    intelligence_report = LiveDataReport(
        provider="openrouter",
        model="openai/gpt-5.2:online",
        query="Analyze repository security posture.",
        summary="Use strict verification and signed release output.",
        citations=(
            Citation(
                url="https://openrouter.ai/docs/use-cases/web-browsing",
                title="Open Router Web Browsing",
                domain="openrouter.ai",
            ),
        ),
        fetched_at="2026-02-14T20:00:00+00:00",
    )
    runtime = default_langgraph_runtime(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
        intelligence_client=_FakeIntelligenceClient(report=intelligence_report),
        graph_runner_factory=_sequential_graph_runner_factory,
        tool_executor=_FakeToolExecutor(),
    )
    report = runtime.run(spec_path=spec_path)

    assert report.passed is True
    assert report.spec.name == "langgraph-review"
    assert report.live_data_report is not None
    assert report.live_data_report.citations[0].domain == "openrouter.ai"


def test_langgraph_runtime_checkpoint_resume_and_replay(tmp_path, monkeypatch) -> None:
    _clear_guard_env(monkeypatch)
    evidence = tmp_path / "events.jsonl"
    runtime = default_langgraph_runtime(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
        graph_runner_factory=_sequential_graph_runner_factory,
        tool_executor=_FakeToolExecutor(),
    )
    first_report = runtime.run(spec=_base_spec(), checkpoint_dir=tmp_path / "checkpoints")
    assert first_report.passed is True
    assert first_report.checkpoint_path is not None
    assert first_report.checkpoint_path.exists()

    resumed_report = runtime.resume(
        checkpoint_path=first_report.checkpoint_path,
        checkpoint_dir=tmp_path / "checkpoints",
    )
    assert resumed_report.passed is True
    assert resumed_report.resumed_from == first_report.checkpoint_path

    replay_report = runtime.replay(
        checkpoint_path=first_report.checkpoint_path,
        checkpoint_dir=tmp_path / "checkpoints",
    )
    assert replay_report.passed is True
    assert replay_report.replay_of == first_report.checkpoint_path
    assert replay_report.replay_match is True


def test_langgraph_runtime_resume_from_middle_checkpoint_with_replacing_runner(
    tmp_path, monkeypatch
) -> None:
    _clear_guard_env(monkeypatch)
    evidence = tmp_path / "events.jsonl"
    checkpoint_dir = tmp_path / "checkpoints"
    runtime = default_langgraph_runtime(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
        graph_runner_factory=_replacing_graph_runner_factory,
        tool_executor=_FakeToolExecutor(),
    )
    first_report = runtime.run(spec=_base_spec(), checkpoint_dir=checkpoint_dir)
    assert first_report.passed is True

    checkpoint_candidates = sorted(checkpoint_dir.glob("*--003--compile_policy.json"))
    assert checkpoint_candidates
    middle_checkpoint = checkpoint_candidates[0]

    resumed_report = runtime.resume(
        checkpoint_path=middle_checkpoint,
        checkpoint_dir=tmp_path / "resumed_checkpoints",
    )
    assert resumed_report.passed is True
    assert resumed_report.resumed_from == middle_checkpoint


def test_langgraph_runtime_fails_when_policy_runtime_gate_blocks(tmp_path, monkeypatch) -> None:
    _clear_guard_env(monkeypatch)
    evidence = tmp_path / "events.jsonl"
    runtime = default_langgraph_runtime(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
        graph_runner_factory=_sequential_graph_runner_factory,
        policy_middleware=_BlockedPolicyMiddleware(),
        tool_executor=_FakeToolExecutor(),
    )
    report = runtime.run(spec=_base_spec(), checkpoint_dir=tmp_path / "checkpoints")

    assert report.passed is False
    assert any(
        result.name == "policy_execution_gate" and not result.passed
        for result in report.verification_report.results
    )


def test_langgraph_runtime_fails_when_tool_execution_fails(tmp_path, monkeypatch) -> None:
    _clear_guard_env(monkeypatch)
    evidence = tmp_path / "events.jsonl"
    runtime = default_langgraph_runtime(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
        graph_runner_factory=_sequential_graph_runner_factory,
        tool_executor=_FakeToolExecutor(passed=False),
    )
    report = runtime.run(spec=_base_spec(), checkpoint_dir=tmp_path / "checkpoints")

    assert report.passed is False
    assert any(
        result.name == "tool_execution_gate" and not result.passed
        for result in report.verification_report.results
    )


def test_langgraph_runtime_fails_when_sandbox_policy_violation_detected(tmp_path, monkeypatch) -> None:
    _clear_guard_env(monkeypatch)
    evidence = tmp_path / "events.jsonl"
    runtime = default_langgraph_runtime(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
        graph_runner_factory=_sequential_graph_runner_factory,
        tool_executor=_FakeToolExecutor(
            passed=True,
            policy_violations=("image_policy_override_enabled_for_unapproved_image",),
        ),
    )
    report = runtime.run(spec=_base_spec(), checkpoint_dir=tmp_path / "checkpoints")

    assert report.passed is False
    assert any(
        result.name == "tool_execution_gate" and not result.passed
        for result in report.verification_report.results
    )
    event_text = evidence.read_text(encoding="utf-8")
    assert "langgraph.runtime.sandbox_policy_violation" in event_text


@pytest.mark.parametrize(
    "runtime_environment",
    ("local", "container", "continuous_integration"),
)
def test_langgraph_runtime_enforces_execution_path_across_runtime_environments(
    tmp_path,
    monkeypatch,
    runtime_environment: str,
) -> None:
    _clear_guard_env(monkeypatch)
    evidence = tmp_path / f"events-{runtime_environment}.jsonl"
    tool_executor = _CapturingToolExecutor()
    runtime = default_langgraph_runtime(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
        graph_runner_factory=_sequential_graph_runner_factory,
        tool_executor=tool_executor,
    )
    spec = replace(_base_spec(), runtime_environment=runtime_environment)
    report = runtime.run(spec=spec, checkpoint_dir=tmp_path / f"checkpoints-{runtime_environment}")

    assert report.passed is True
    assert tool_executor.runtime_environments == [runtime_environment]


class _RaisingToolExecutor:
    def execute_spec_tools(self, *, spec, policy):
        del spec, policy
        raise AssertionError("Tool executor should not be invoked when approval is missing.")


def test_langgraph_runtime_blocks_network_or_write_tools_without_approval(tmp_path, monkeypatch) -> None:
    _clear_guard_env(monkeypatch)
    evidence = tmp_path / "events.jsonl"
    runtime = default_langgraph_runtime(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
        graph_runner_factory=_sequential_graph_runner_factory,
        tool_executor=_RaisingToolExecutor(),  # type: ignore[arg-type]
    )
    spec = replace(
        _base_spec(),
        tools=(
            ToolSpec(
                name="write_report",
                command="python write_report.py",
                can_write_files=True,
                can_access_network=False,
                timeout_seconds=30,
            ),
        ),
        data_scope=DataScope(
            read_paths=("/workspace",),
            write_paths=("/workspace/reports",),
            allowed_hosts=(),
        ),
    )
    report = runtime.run(spec=spec, checkpoint_dir=tmp_path / "checkpoints")

    assert report.passed is False
    assert any(
        result.name == "tool_execution_gate" and not result.passed
        for result in report.verification_report.results
    )
    event_text = evidence.read_text(encoding="utf-8")
    assert "langgraph.runtime.tool_execution.approval_gate" in event_text
    assert "Human approval is required" in event_text


def test_langgraph_runtime_allows_network_or_write_tools_with_approval(tmp_path, monkeypatch) -> None:
    _clear_guard_env(monkeypatch)
    evidence = tmp_path / "events.jsonl"
    tool_executor = _CapturingToolExecutor()
    runtime = default_langgraph_runtime(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
        graph_runner_factory=_sequential_graph_runner_factory,
        tool_executor=tool_executor,
    )
    spec = replace(
        _base_spec(),
        tools=(
            ToolSpec(
                name="write_report",
                command="python write_report.py",
                can_write_files=True,
                can_access_network=False,
                timeout_seconds=30,
            ),
        ),
        data_scope=DataScope(
            read_paths=("/workspace",),
            write_paths=("/workspace/reports",),
            allowed_hosts=(),
        ),
    )
    report = runtime.run(
        spec=spec,
        checkpoint_dir=tmp_path / "checkpoints",
        approved_by="compliance-reviewer",
        approval_id="approval-001",
    )

    assert report.passed is True
    assert tool_executor.runtime_environments == ["container"]
    event_text = evidence.read_text(encoding="utf-8")
    assert "langgraph.runtime.tool_execution.approval_gate" in event_text
