from __future__ import annotations

import json

from lifeguard.compliance_pack import verify_compliance_pack
from lifeguard.release_workflow import default_release_workflow
from lifeguard.spec_schema import AgentSpec, DataScope, SecurityRequirements, ToolSpec


def _write_signing_key(tmp_path) -> str:
    path = tmp_path / "signing.key"
    path.write_text("lifeguard-signing-key-material-123456789", encoding="utf-8")
    return str(path)


def _base_spec() -> AgentSpec:
    return AgentSpec(
        name="compliance-pack-agent",
        description="Produce a signed release and compliance pack.",
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
            goals=("Review source for vulnerabilities.", "Produce signed release evidence."),
            threat_actors=("External attacker", "Malicious insider"),
            evidence_requirements=("Signed manifest", "Verification check log"),
        ),
    )


def test_verify_compliance_pack_fails_on_tamper(tmp_path) -> None:
    evidence = tmp_path / "events.jsonl"
    output_dir = tmp_path / "release"
    signing_key_file = _write_signing_key(tmp_path)
    workflow = default_release_workflow(evidence_path=evidence)
    report = workflow.run(
        spec=_base_spec(),
        output_dir=output_dir,
        signing_key_file=signing_key_file,
    )
    assert report.passed is True

    pack_dir = output_dir / "compliance_pack"
    spec_snapshot = pack_dir / "agent_spec.json"
    payload = json.loads(spec_snapshot.read_text(encoding="utf-8"))
    payload["name"] = "tampered-agent"
    spec_snapshot.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    verification = verify_compliance_pack(pack_dir=pack_dir, signing_key_file=signing_key_file)
    assert verification.passed is False
    assert any("Hash mismatch" in failure for failure in verification.failures)


def test_verify_compliance_pack_reports_invalid_manifest_json(tmp_path) -> None:
    pack_dir = tmp_path / "compliance_pack"
    pack_dir.mkdir(parents=True, exist_ok=True)
    (pack_dir / "pack_manifest.json").write_text("{not-json", encoding="utf-8")

    verification = verify_compliance_pack(pack_dir=pack_dir, signing_key_file=None)
    assert verification.passed is False
    assert any("pack_manifest.json could not be read as JSON" in failure for failure in verification.failures)

