from __future__ import annotations

from pathlib import Path

import pytest

from lifeguard.checkpoint_store import RuntimeCheckpointStore
from lifeguard.live_intelligence import Citation, LiveDataReport
from lifeguard.policy_compiler import compile_policy
from lifeguard.spec_schema import AgentSpec, DataScope, ToolSpec
from lifeguard.verification_pipeline import CheckResult, VerificationReport


def _spec() -> AgentSpec:
    return AgentSpec(
        name="checkpoint-agent",
        description="Checkpoint test spec.",
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
            write_paths=("/workspace/out",),
            allowed_hosts=(),
        ),
        runtime_environment="container",
        budget_limit_usd=30.0,
        max_runtime_seconds=600,
    )


def test_checkpoint_store_round_trip(tmp_path) -> None:
    store = RuntimeCheckpointStore(tmp_path / "checkpoints")
    spec = _spec()
    policy = compile_policy(spec)
    verification = VerificationReport(
        passed=True,
        results=(CheckResult(name="x", passed=True, message="ok"),),
        policy=policy,
        evidence_path=Path(tmp_path / "events.jsonl"),
    )
    live_report = LiveDataReport(
        provider="openrouter",
        model="openai/gpt-5.2:online",
        query="q",
        summary="s",
        citations=(Citation(url="https://example.com", title="t", domain="example.com"),),
        fetched_at="2026-02-14T00:00:00+00:00",
    )
    state = {
        "spec": spec,
        "spec_path": str(tmp_path / "spec.json"),
        "policy": policy,
        "policy_error": None,
        "live_data_report": live_report,
        "live_data_error": None,
        "threat_findings": ("none",),
        "tool_gate_passed": True,
        "tool_gate_results": (
            {
                "tool_name": "review",
                "command": "python review.py",
                "allowed": True,
                "reason": "ok",
            },
        ),
        "blocked_tool_decisions": (),
        "verification_report": verification,
        "completed_nodes": ("load_spec",),
        "run_id": "run-test",
    }
    checkpoint = store.save_checkpoint(
        run_id="run-test",
        node_name="load_spec",
        sequence=1,
        state=state,
    )
    loaded = store.load_checkpoint(checkpoint.path)
    assert loaded.run_id == "run-test"
    assert loaded.node_name == "load_spec"
    assert loaded.sequence == 1
    assert isinstance(loaded.state["spec"], AgentSpec)
    assert loaded.state["spec"].name == "checkpoint-agent"
    assert loaded.state["policy"] is not None
    assert loaded.state["verification_report"].passed is True
    assert loaded.state["checkpoint_path"] == str(checkpoint.path)


def test_checkpoint_store_sanitizes_run_id_and_node_name(tmp_path) -> None:
    store = RuntimeCheckpointStore(tmp_path / "checkpoints")
    spec = _spec()
    state = {"spec": spec, "run_id": "../unsafe-run"}

    checkpoint = store.save_checkpoint(
        run_id="../unsafe-run",
        node_name="../node/name",
        sequence=2,
        state=state,
    )

    assert ".." not in checkpoint.path.name
    assert "/" not in checkpoint.path.name
    assert checkpoint.run_id == "unsafe-run"
    assert checkpoint.node_name == "node_name"


def test_checkpoint_store_rejects_empty_or_unsafe_identifier(tmp_path) -> None:
    store = RuntimeCheckpointStore(tmp_path / "checkpoints")
    with pytest.raises(ValueError):
        store.save_checkpoint(
            run_id="///",
            node_name="load_spec",
            sequence=1,
            state={},
        )
