from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from lifeguard.adapters import (
    AdapterActionResult,
    AdapterError,
    AdapterModuleStatus,
    AdapterTrustMetadata,
)
from lifeguard.compliance_pack import verify_compliance_pack
from lifeguard.policy_compiler import compile_policy
from lifeguard.release_workflow import default_release_workflow
from lifeguard.signing import load_signing_key, verify_payload_signature
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
from lifeguard.verification_pipeline import CheckResult, VerificationReport


def _base_spec(command: str) -> AgentSpec:
    return AgentSpec(
        name="release-agent",
        description="Analyze source and produce a signed release package.",
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
            goals=("Review source for vulnerabilities.", "Produce signed release evidence."),
            threat_actors=("External attacker", "Malicious insider"),
            evidence_requirements=("Signed manifest", "Verification check log"),
        ),
    )


def _high_risk_spec(command: str) -> AgentSpec:
    return AgentSpec(
        name="release-agent-high",
        description="High risk release package for secure code review.",
        risk_level="high",
        tools=(
            ToolSpec(
                name="review",
                command=command,
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
        runtime_environment="container",
        budget_limit_usd=100.0,
        max_runtime_seconds=600,
        security_requirements=SecurityRequirements(
            goals=("Review high-risk changes.", "Approve only safe release output."),
            threat_actors=("External attacker", "Compromised maintainer"),
            evidence_requirements=("Approval record", "Signed manifest"),
        ),
    )


def _write_signing_key(tmp_path) -> str:
    path = tmp_path / "signing.key"
    path.write_text("lifeguard-signing-key-material-123456789", encoding="utf-8")
    return str(path)


def _fake_sigstore_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    if command[:2] == ["sigstore", "--version"]:
        return subprocess.CompletedProcess(command, 0, stdout="sigstore 3.0.0", stderr="")
    if command[:3] == ["sigstore", "sign", "--bundle"]:
        bundle_path = Path(command[3])
        bundle_path.parent.mkdir(parents=True, exist_ok=True)
        bundle_payload = {
            "verificationMaterial": {
                "tlogEntries": [
                    {
                        "logIndex": 9,
                        "integratedTime": 1_739_500_000,
                        "logId": {"keyId": "sigstore-log-key"},
                        "kindVersion": "0.0.1",
                    }
                ]
            }
        }
        bundle_path.write_text(json.dumps(bundle_payload), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="signed", stderr="")
    if command[:3] == ["sigstore", "verify", "github"]:
        return subprocess.CompletedProcess(command, 0, stdout="verified", stderr="")
    return subprocess.CompletedProcess(command, 1, stdout="", stderr="unexpected command")


class _FakeAdapterLayer:
    def __init__(self, preflight_error: str | None = None) -> None:
        self.preflight_error = preflight_error

    def list_module_status(self) -> tuple[AdapterModuleStatus, ...]:
        return (
            AdapterModuleStatus(
                adapter_name="json_parser",
                module_path="lifeguard.extracts.json_parser",
                available=True,
            ),
        )

    def run_security_preflight(self, repo_path):
        return self.preflight_error


class _FakeIntelligenceClient:
    def collect_latest(self, query, settings, risk_level="low"):
        del settings, risk_level
        query_text = str(query)
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


def _legislative_spec(command: str) -> AgentSpec:
    base = _base_spec(command)
    return AgentSpec(
        name=base.name,
        description=base.description,
        risk_level=base.risk_level,
        tools=base.tools,
        data_scope=base.data_scope,
        runtime_environment=base.runtime_environment,
        budget_limit_usd=base.budget_limit_usd,
        max_runtime_seconds=base.max_runtime_seconds,
        profile_id=base.profile_id,
        security_requirements=base.security_requirements,
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
            decision_file="",
        ),
        live_data=LiveDataSettings(enabled=False),
    )


def test_release_workflow_writes_signed_manifest(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    output_dir = tmp_path / "release"
    signing_key_file = _write_signing_key(tmp_path)
    workflow = default_release_workflow(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
    )
    report = workflow.run(
        spec=_base_spec("python review.py"),
        output_dir=output_dir,
        signing_key_file=signing_key_file,
    )
    assert report.passed is True
    assert report.manifest_path is not None
    assert report.manifest_path.exists()
    payload = json.loads(report.manifest_path.read_text(encoding="utf-8"))
    assert payload["signature"]["algorithm"] == "hmac-sha256"
    assert payload["verification"]["passed"] is True
    assert payload["owasp_control_matrix"]["passed"] is True
    badge_path = output_dir / "owasp_control_badge.json"
    assert badge_path.exists()
    signature_value = payload["signature"]["value"]
    manifest_without_signature = dict(payload)
    manifest_without_signature.pop("signature")
    assert verify_payload_signature(
        manifest_without_signature,
        signature_value,
        load_signing_key(signing_key_file),
    )

    anchor_path = output_dir / "release_anchor.json"
    assert anchor_path.exists()
    anchor_payload = json.loads(anchor_path.read_text(encoding="utf-8"))
    assert anchor_payload["manifest_path"] == "release_manifest.json"
    assert anchor_payload["evidence_path"] == payload["verification"]["evidence_path"]
    assert anchor_payload["evidence_last_hash"] == payload["verification"]["evidence_last_hash"]

    manifest_sha256 = hashlib.sha256(report.manifest_path.read_bytes()).hexdigest()
    assert anchor_payload["manifest_sha256"] == manifest_sha256

    manifest_body = dict(payload)
    manifest_body.pop("signature", None)
    manifest_body.pop("anchor", None)
    manifest_body_sha256 = hashlib.sha256(
        json.dumps(manifest_body, sort_keys=True).encode("utf-8")
    ).hexdigest()
    assert payload["anchor"]["manifest_body_sha256"] == manifest_body_sha256
    assert anchor_payload["manifest_body_sha256"] == manifest_body_sha256

    assert str(anchor_payload["evidence_path"]).startswith("/") is False

    pack_dir = output_dir / "compliance_pack"
    assert (pack_dir / "pack_manifest.json").exists()
    pack_report = verify_compliance_pack(pack_dir=pack_dir, signing_key_file=signing_key_file)
    assert pack_report.passed is True


def test_release_workflow_blocks_when_verification_fails(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    output_dir = tmp_path / "release"
    workflow = default_release_workflow(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(preflight_error="blocked"),
    )
    report = workflow.run(
        spec=_base_spec("python review.py"),
        output_dir=output_dir,
        signing_key_file=_write_signing_key(tmp_path),
    )
    assert report.passed is False
    assert report.manifest_path is None


def test_release_workflow_blocks_when_control_matrix_is_incomplete(tmp_path) -> None:
    matrix_path = tmp_path / "incomplete_control_matrix.json"
    matrix_path.write_text(
        json.dumps(
            {
                "framework_version": "test",
                "controls": [
                    {
                        "id": "LLM01",
                        "name": "Prompt Injection",
                        "mapped_by": ["runtime_policy_middleware"],
                        "tests": ["tests/test_runtime_policy_middleware.py"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    evidence = tmp_path / "events.jsonl"
    output_dir = tmp_path / "release"
    workflow = default_release_workflow(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
    )
    report = workflow.run(
        spec=_base_spec("python review.py"),
        output_dir=output_dir,
        signing_key_file=_write_signing_key(tmp_path),
        control_matrix_file=matrix_path,
    )
    assert report.passed is False
    assert report.failure_reason == "control_matrix_missing"


def test_release_workflow_blocks_high_risk_without_approval(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    output_dir = tmp_path / "release"
    workflow = default_release_workflow(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
    )
    report = workflow.run(
        spec=_high_risk_spec("python review.py"),
        output_dir=output_dir,
        signing_key_file=_write_signing_key(tmp_path),
    )
    assert report.passed is False
    assert report.failure_reason == "approval_missing"


def test_release_workflow_allows_high_risk_with_approval(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    output_dir = tmp_path / "release"
    workflow = default_release_workflow(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
    )
    report = workflow.run(
        spec=_high_risk_spec("python review.py"),
        output_dir=output_dir,
        approved_by="security-reviewer",
        approval_id="approval-001",
        signing_key_file=_write_signing_key(tmp_path),
    )
    assert report.passed is True
    assert report.manifest_path is not None


def test_release_workflow_blocks_high_risk_env_signing_key_material(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LIFEGUARD_SIGNING_KEY", "inline-signing-key-material-123456789")
    monkeypatch.delenv("LIFEGUARD_SIGNING_KEY_FILE", raising=False)
    evidence = tmp_path / "events.jsonl"
    output_dir = tmp_path / "release"
    workflow = default_release_workflow(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
    )
    report = workflow.run(
        spec=_high_risk_spec("python review.py"),
        output_dir=output_dir,
        approved_by="security-reviewer",
        approval_id="approval-001",
    )
    assert report.passed is False
    assert report.failure_reason == "signing_key_policy_blocked"


def test_release_workflow_blocks_when_signing_key_missing(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    output_dir = tmp_path / "release"
    workflow = default_release_workflow(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
    )
    report = workflow.run(
        spec=_base_spec("python review.py"),
        output_dir=output_dir,
    )
    assert report.passed is False
    assert report.failure_reason == "signing_key_missing"


def test_release_workflow_uses_sigstore_signing_mode(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    output_dir = tmp_path / "release"
    workflow = default_release_workflow(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
        sigstore_command_runner=_fake_sigstore_runner,
    )
    report = workflow.run(
        spec=_base_spec("python review.py"),
        output_dir=output_dir,
        signing_mode="sigstore",
        sigstore_repository="acme/lifeguard",
        sigstore_workflow=".github/workflows/release.yml",
    )
    assert report.passed is True
    payload = json.loads((output_dir / "release_manifest.json").read_text(encoding="utf-8"))
    signature = payload["signature"]
    assert signature["algorithm"] == "sigstore-bundle"
    assert signature["verified"] is True
    assert signature["repository"] == "acme/lifeguard"
    assert signature["workflow"] == ".github/workflows/release.yml"
    assert Path(output_dir / signature["bundle_path"]).exists()


def test_release_workflow_auto_falls_back_to_hmac_when_sigstore_config_is_missing(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    output_dir = tmp_path / "release"
    workflow = default_release_workflow(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
        sigstore_command_runner=_fake_sigstore_runner,
    )
    report = workflow.run(
        spec=_base_spec("python review.py"),
        output_dir=output_dir,
        signing_mode="auto",
        signing_key_file=_write_signing_key(tmp_path),
    )
    assert report.passed is True
    payload = json.loads((output_dir / "release_manifest.json").read_text(encoding="utf-8"))
    assert payload["signature"]["algorithm"] == "hmac-sha256"
    events_text = evidence.read_text(encoding="utf-8")
    assert "release.signing.fallback" in events_text


def test_release_workflow_blocks_when_compatibility_gate_fails(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("LIFEGUARD_COMPATIBILITY_GATE_ADAPTERS", "langchain,unknown_adapter")
    evidence = tmp_path / "events.jsonl"
    output_dir = tmp_path / "release"
    workflow = default_release_workflow(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
    )
    report = workflow.run(
        spec=_base_spec("python review.py"),
        output_dir=output_dir,
        signing_key_file=_write_signing_key(tmp_path),
    )
    assert report.passed is False
    assert report.failure_reason == "compatibility_gate_failed"
    assert report.manifest_path is None
    event_text = evidence.read_text(encoding="utf-8")
    assert "release.compatibility_gate.blocked" in event_text


def test_release_manifest_includes_runtime_metadata(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    output_dir = tmp_path / "release"
    workflow = default_release_workflow(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
    )
    report = workflow.run(
        spec=_base_spec("python review.py"),
        output_dir=output_dir,
        signing_key_file=_write_signing_key(tmp_path),
        runtime_metadata={
            "mode": "langgraph",
            "run_id": "run-test",
            "checkpoint_path": "/tmp/checkpoint.json",
            "resumed_from": None,
            "replay_of": None,
            "replay_match": None,
        },
    )
    assert report.passed is True
    payload = json.loads((output_dir / "release_manifest.json").read_text(encoding="utf-8"))
    assert payload["runtime"]["mode"] == "langgraph"
    assert payload["runtime"]["run_id"] == "run-test"


def test_release_manifest_includes_compatibility_gate(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("LIFEGUARD_COMPATIBILITY_GATE_ADAPTERS", "langchain,langgraph,mcp")
    evidence = tmp_path / "events.jsonl"
    output_dir = tmp_path / "release"
    workflow = default_release_workflow(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
    )
    report = workflow.run(
        spec=_base_spec("python review.py"),
        output_dir=output_dir,
        signing_key_file=_write_signing_key(tmp_path),
    )
    assert report.passed is True
    payload = json.loads((output_dir / "release_manifest.json").read_text(encoding="utf-8"))
    gate = payload["compatibility_gate"]
    assert gate["required"] is True
    assert gate["passed"] is True
    adapter_names = [entry["adapter_name"] for entry in gate["adapters"]]
    assert adapter_names == ["langchain", "langgraph", "mcp"]
    assert all(entry["passed"] is True for entry in gate["adapters"])


def test_release_workflow_blocks_when_mcp_enforcement_is_advisory(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("LIFEGUARD_COMPATIBILITY_GATE_ADAPTERS", "mcp")

    class _AdvisoryModelContextProtocolAdapter:
        def execute_action(self, request):
            if request.action_name == "mcp.export.agent_spec":
                return AdapterActionResult(
                    action_name=request.action_name,
                    ok=True,
                    output={
                        "policy_hints": {
                            "risk_level": "low",
                            "runtime_environment": "container",
                            "max_runtime_seconds": 600,
                            "budget_limit_usd": 30.0,
                            "read_paths": ["/workspace"],
                            "write_paths": ["/workspace/reports"],
                            "allowed_hosts": [],
                        },
                        "server_bundle": {
                            "schema": "mcp_server_bundle_v1",
                            "server": {
                                "server_name": "release-agent-server",
                                "server_version": "1.0.0",
                                "trust_profile_id": "profile_custom",
                            },
                            "tools": [],
                        },
                    },
                    errors=(),
                    metadata={},
                    trust=AdapterTrustMetadata(),
                )
            if request.action_name == "mcp.import.server_bundle":
                return AdapterActionResult(
                    action_name=request.action_name,
                    ok=True,
                    output={
                        "tools": [
                            {
                                "name": "review",
                                "command": "python review.py",
                                "can_write_files": False,
                                "can_access_network": False,
                                "timeout_seconds": 30,
                            }
                        ],
                        "data_scope_hints": {
                            "read_paths": ["/workspace"],
                            "write_paths": ["/workspace/reports"],
                            "allowed_hosts": [],
                        },
                        "gating": {
                            "version_pinned": True,
                            "trust_profile_required": True,
                            "default_deny": True,
                            "host_allow_list_required_for_network_tools": True,
                            "startup_commands_blocked": True,
                            "advisory_only": True,
                            "enforcement_mode": "advisory",
                        },
                    },
                    errors=(),
                    metadata={},
                    trust=AdapterTrustMetadata(),
                )
            return AdapterActionResult(
                action_name=request.action_name,
                ok=False,
                output={},
                errors=(
                    AdapterError(
                        code="unknown_action",
                        message="unexpected action",
                        category="validation",
                    ),
                ),
                metadata={},
                trust=AdapterTrustMetadata(),
            )

    monkeypatch.setattr(
        "lifeguard.release_workflow.ModelContextProtocolCompatibilityAdapter",
        _AdvisoryModelContextProtocolAdapter,
    )

    evidence = tmp_path / "events.jsonl"
    output_dir = tmp_path / "release"
    workflow = default_release_workflow(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
    )
    report = workflow.run(
        spec=_base_spec("python review.py"),
        output_dir=output_dir,
        signing_key_file=_write_signing_key(tmp_path),
    )
    assert report.passed is False
    assert report.failure_reason == "compatibility_gate_failed"


def test_release_workflow_blocks_when_adversarial_gate_below_threshold(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    output_dir = tmp_path / "release"
    spec = _high_risk_spec("python review.py")
    workflow = default_release_workflow(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
    )
    verification_override = VerificationReport(
        passed=True,
        results=(
            CheckResult(name="spec_quality_gate", passed=True, message="ok"),
            CheckResult(
                name="adversarial_resilience",
                passed=True,
                message="pass_rate=0.95 threshold=0.95 passed_cases=19 total_cases=20 failed_cases=review:command_smuggling_chain",
            ),
        ),
        policy=compile_policy(spec),
        evidence_path=Path(evidence),
    )
    report = workflow.run(
        spec=spec,
        output_dir=output_dir,
        signing_key_file=_write_signing_key(tmp_path),
        verification_report_override=verification_override,
        approved_by="security-reviewer",
        approval_id="approval-001",
    )
    assert report.passed is False
    assert report.failure_reason == "adversarial_gate_failed"


def test_release_workflow_allows_when_adversarial_gate_meets_threshold(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    output_dir = tmp_path / "release"
    spec = _high_risk_spec("python review.py")
    workflow = default_release_workflow(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
    )
    verification_override = VerificationReport(
        passed=True,
        results=(
            CheckResult(name="spec_quality_gate", passed=True, message="ok"),
            CheckResult(
                name="adversarial_resilience",
                passed=True,
                message="pass_rate=1.00 threshold=0.95 passed_cases=20 total_cases=20 failed_cases=none",
            ),
        ),
        policy=compile_policy(spec),
        evidence_path=Path(evidence),
    )
    report = workflow.run(
        spec=spec,
        output_dir=output_dir,
        signing_key_file=_write_signing_key(tmp_path),
        verification_report_override=verification_override,
        approved_by="security-reviewer",
        approval_id="approval-001",
    )
    assert report.passed is True
    payload = json.loads((output_dir / "release_manifest.json").read_text(encoding="utf-8"))
    assert payload["adversarial_gate"]["passed"] is True


def test_release_workflow_includes_legislative_review_pack_and_decision(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    output_dir = tmp_path / "release"
    signing_key_file = _write_signing_key(tmp_path)

    spec = _legislative_spec("python review.py")
    decision_path = tmp_path / "legislative_review_decision.json"
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

    workflow = default_release_workflow(
        evidence_path=evidence,
        adapter_layer=_FakeAdapterLayer(),
        intelligence_client=_FakeIntelligenceClient(),  # type: ignore[arg-type]
    )
    report = workflow.run(
        spec=spec,
        output_dir=output_dir,
        signing_key_file=signing_key_file,
    )
    assert report.passed is True

    payload = json.loads((output_dir / "release_manifest.json").read_text(encoding="utf-8"))
    legislative = payload["legislative_review"]
    assert legislative["enabled"] is True
    assert legislative["decision"]["decision"] == "accept"
    assert isinstance(legislative["pack"], dict)
    assert legislative["pack"]["spec_name"] == spec.name

    pack_dir = output_dir / "compliance_pack"
    assert (pack_dir / "legislative_review_pack.json").exists()
    assert (pack_dir / "legislative_review_decision.json").exists()
    pack_report = verify_compliance_pack(pack_dir=pack_dir, signing_key_file=signing_key_file)
    assert pack_report.passed is True
