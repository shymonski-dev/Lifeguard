from __future__ import annotations

import argparse
import json
from pathlib import Path

from .adapters import (
    AdapterActionRequest,
    LangChainCompatibilityAdapter,
    LangGraphCompatibilityAdapter,
    ModelContextProtocolCompatibilityAdapter,
)
from .adversarial_reports import summarize_adversarial_history
from .dashboard import write_dashboard
from .langgraph_runtime import (
    LangGraphRuntimeError,
    LangGraphRuntimeReport,
    default_langgraph_runtime,
)
from .live_intelligence import LiveDataError, LiveIntelligenceClient
from .open_source_guardrails import OpenSourceModeViolation, enforce_open_source_mode
from .release_workflow import compute_release_anchor_payload, default_release_workflow
from .spec_schema import (
    VALID_RISK_LEVELS,
    VALID_RUNTIME_ENVIRONMENTS,
    AgentSpec,
    create_spec_from_profile,
    evaluate_spec_quality,
    list_security_profiles,
    load_spec,
    write_spec,
)
from .trust_source_profiles import (
    default_trust_source_profile_path,
    list_managed_trust_source_profiles,
)
from .verification_pipeline import default_pipeline

_PROFILE_CHOICES = tuple(profile.profile_id for profile in list_security_profiles())
_COMPAT_ADAPTER_CHOICES = ("langchain", "langgraph", "mcp")


def _default_spec() -> AgentSpec:
    return create_spec_from_profile(
        "secure_code_review",
        name="secure-code-review-agent",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lifeguard",
        description="Design and verify secure tool-using agents.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Write a starter specification file.")
    init_parser.add_argument("--path", required=True, help="Target JSON file path.")
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the target if it already exists.",
    )
    init_parser.add_argument(
        "--profile",
        choices=_PROFILE_CHOICES,
        default="secure_code_review",
        help="Profile template used to generate the starter specification.",
    )
    init_parser.add_argument(
        "--name",
        help="Optional agent name override.",
    )
    init_parser.add_argument(
        "--description",
        help="Optional agent description override.",
    )
    init_parser.add_argument(
        "--risk-level",
        choices=tuple(sorted(VALID_RISK_LEVELS)),
        help="Optional risk level override for the selected profile.",
    )
    init_parser.add_argument(
        "--runtime-environment",
        choices=tuple(sorted(VALID_RUNTIME_ENVIRONMENTS)),
        help="Optional runtime environment override for the selected profile.",
    )

    subparsers.add_parser(
        "profiles",
        help="List starter security profile templates.",
    )

    quality_parser = subparsers.add_parser(
        "quality",
        help="Score specification quality and list missing required fields.",
    )
    quality_parser.add_argument("--spec", required=True, help="Path to the specification JSON.")

    adversarial_parser = subparsers.add_parser(
        "adversarial-report",
        help="Show adversarial validation history for an evidence log.",
    )
    adversarial_parser.add_argument(
        "--evidence",
        required=True,
        help="Path to append-only evidence log file.",
    )
    adversarial_parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Number of recent records to include.",
    )

    trust_parser = subparsers.add_parser(
        "trust-source-profiles",
        help="List managed trust source profiles and approval metadata.",
    )
    trust_parser.add_argument(
        "--profile-file",
        help="Optional path to managed trust source profile file.",
    )

    compat_export_parser = subparsers.add_parser(
        "compat-export",
        help="Export a Lifeguard specification to a compatibility adapter format.",
    )
    compat_export_parser.add_argument("--spec", required=True, help="Path to the specification JSON.")
    compat_export_parser.add_argument(
        "--adapter",
        required=True,
        choices=_COMPAT_ADAPTER_CHOICES,
        help="Compatibility adapter target format.",
    )
    compat_export_parser.add_argument(
        "--output",
        help="Optional output JSON file path for exported payload.",
    )
    compat_export_parser.add_argument(
        "--request-id",
        help="Optional request identifier attached to adapter metadata.",
    )

    compat_import_parser = subparsers.add_parser(
        "compat-import",
        help="Import a compatibility adapter payload into Lifeguard tool declarations.",
    )
    compat_import_parser.add_argument(
        "--adapter",
        required=True,
        choices=_COMPAT_ADAPTER_CHOICES,
        help="Compatibility adapter source format.",
    )
    compat_import_parser.add_argument(
        "--input",
        required=True,
        help="Input JSON file path containing compatibility payload.",
    )
    compat_import_parser.add_argument(
        "--output",
        help="Optional output JSON file path for normalized Lifeguard payload.",
    )
    compat_import_parser.add_argument(
        "--request-id",
        help="Optional request identifier attached to adapter metadata.",
    )

    verify_parser = subparsers.add_parser("verify", help="Run verification on a specification.")
    verify_parser.add_argument("--spec", required=True, help="Path to the specification JSON.")
    verify_parser.add_argument(
        "--evidence",
        required=True,
        help="Path to append-only evidence log file.",
    )
    verify_parser.add_argument(
        "--repo",
        help="Optional repository path for adapter-backed security preflight.",
    )
    verify_parser.add_argument(
        "--runtime",
        choices=("standard", "langgraph"),
        default="standard",
        help="Verification runtime implementation.",
    )
    verify_parser.add_argument(
        "--checkpoint-dir",
        help="Optional checkpoint directory for Lang Graph runtime.",
    )
    verify_parser.add_argument(
        "--resume-checkpoint",
        help="Optional checkpoint file path to resume from in Lang Graph runtime.",
    )

    resume_parser = subparsers.add_parser(
        "resume",
        help="Resume Lang Graph verification from a checkpoint.",
    )
    resume_parser.add_argument(
        "--checkpoint",
        required=True,
        help="Checkpoint file path to resume from.",
    )
    resume_parser.add_argument(
        "--evidence",
        required=True,
        help="Path to append-only evidence log file.",
    )
    resume_parser.add_argument(
        "--spec",
        help="Optional specification path override for resumed execution.",
    )
    resume_parser.add_argument(
        "--repo",
        help="Optional repository path for adapter-backed security preflight.",
    )
    resume_parser.add_argument(
        "--checkpoint-dir",
        help="Optional checkpoint directory for resumed run output.",
    )

    replay_parser = subparsers.add_parser(
        "replay",
        help="Replay and compare runtime output from a checkpoint.",
    )
    replay_parser.add_argument(
        "--checkpoint",
        required=True,
        help="Checkpoint file path used as replay baseline.",
    )
    replay_parser.add_argument(
        "--evidence",
        required=True,
        help="Path to append-only evidence log file.",
    )
    replay_parser.add_argument(
        "--spec",
        help="Optional specification path override for replay execution.",
    )
    replay_parser.add_argument(
        "--repo",
        help="Optional repository path for adapter-backed security preflight.",
    )
    replay_parser.add_argument(
        "--checkpoint-dir",
        help="Optional checkpoint directory for replay output.",
    )

    intelligence_parser = subparsers.add_parser(
        "intelligence",
        help="Run a live intelligence query and print cited results.",
    )
    intelligence_parser.add_argument("--spec", required=True, help="Path to the specification JSON.")
    intelligence_parser.add_argument(
        "--query",
        help="Optional query override. Defaults to live_data.query or specification description.",
    )

    release_parser = subparsers.add_parser(
        "release",
        help="Run verification and emit a signed release manifest.",
    )
    release_parser.add_argument("--spec", required=True, help="Path to the specification JSON.")
    release_parser.add_argument(
        "--evidence",
        required=True,
        help="Path to append-only evidence log file.",
    )
    release_parser.add_argument(
        "--output",
        required=True,
        help="Output directory for release artifacts.",
    )
    release_parser.add_argument(
        "--repo",
        help="Optional repository path for adapter-backed security preflight.",
    )
    release_parser.add_argument(
        "--runtime",
        choices=("standard", "langgraph"),
        default="standard",
        help="Verification runtime implementation used before packaging.",
    )
    release_parser.add_argument(
        "--checkpoint-dir",
        help="Optional checkpoint directory for Lang Graph runtime.",
    )
    release_parser.add_argument(
        "--resume-checkpoint",
        help="Optional checkpoint file path to resume from in Lang Graph runtime.",
    )
    release_parser.add_argument(
        "--replay-checkpoint",
        help="Optional checkpoint file path for replay and comparison in Lang Graph runtime.",
    )
    release_parser.add_argument(
        "--approved-by",
        help="Required for high-risk release publishing.",
    )
    release_parser.add_argument(
        "--approval-id",
        help="Required for high-risk release publishing.",
    )
    release_parser.add_argument(
        "--approval-notes",
        help="Optional approval notes for release metadata.",
    )
    release_parser.add_argument(
        "--signing-key-file",
        help="Path to the signing key file. If omitted, environment key settings are used.",
    )
    release_parser.add_argument(
        "--signing-mode",
        choices=("hmac", "sigstore", "auto"),
        help="Signing mode for release artifacts.",
    )
    release_parser.add_argument(
        "--sigstore-bundle-path",
        help="Optional output path for Sigstore bundle artifact.",
    )
    release_parser.add_argument(
        "--sigstore-repository",
        help="Repository identity binding for Sigstore verification (owner/repository).",
    )
    release_parser.add_argument(
        "--sigstore-workflow",
        help="Workflow identity binding for Sigstore verification.",
    )
    release_parser.add_argument(
        "--sigstore-certificate-oidc-issuer",
        help="Optional certificate issuer for Sigstore identity verification.",
    )
    release_parser.add_argument(
        "--control-matrix-file",
        help="Optional path to Open Worldwide Application Security Project control matrix JSON file.",
    )

    anchor_parser = subparsers.add_parser(
        "anchor",
        help="Generate an external anchor payload from a release manifest.",
    )
    anchor_parser.add_argument(
        "--manifest",
        required=True,
        help="Path to the release manifest JSON.",
    )
    anchor_parser.add_argument(
        "--output",
        help="Optional output JSON file path for the generated anchor payload.",
    )

    dashboard_parser = subparsers.add_parser(
        "dashboard",
        help="Build a read-only verification dashboard from artifacts.",
    )
    dashboard_parser.add_argument(
        "--validation-root",
        required=True,
        help="Root path containing release and evidence artifacts.",
    )
    dashboard_parser.add_argument(
        "--output",
        required=True,
        help="Output HTML file path for the dashboard.",
    )

    return parser


def _cmd_init(
    path: str,
    force: bool,
    profile: str,
    name: str | None,
    description: str | None,
    risk_level: str | None,
    runtime_environment: str | None,
) -> int:
    target = Path(path)
    if target.exists() and not force:
        print(f"Refusing to overwrite existing file: {target}")
        print("Use --force to overwrite.")
        return 1

    default_name = _default_spec().name if profile == "secure_code_review" else None
    spec = create_spec_from_profile(
        profile,
        name=name or default_name,
        description=description,
        risk_level=risk_level,
        runtime_environment=runtime_environment,
    )
    write_spec(target, spec)
    print(f"Wrote starter specification to {target}")
    print(json.dumps({"profile_id": spec.profile_id, "risk_level": spec.risk_level}, indent=2))
    return 0


def _cmd_profiles() -> int:
    profiles = list_security_profiles()
    payload = {
        "profiles": [
            {
                "profile_id": profile.profile_id,
                "display_name": profile.display_name,
                "description": profile.description,
                "risk_level": profile.risk_level,
                "runtime_environment": profile.runtime_environment,
                "trust_profile_id": profile.live_data.trust_profile_id,
                "goals": list(profile.security_requirements.goals),
                "threat_actors": list(profile.security_requirements.threat_actors),
                "evidence_requirements": list(profile.security_requirements.evidence_requirements),
            }
            for profile in profiles
        ]
    }
    print(json.dumps(payload, indent=2))
    return 0


def _cmd_quality(spec_path: str) -> int:
    spec = load_spec(spec_path)
    report = evaluate_spec_quality(spec)
    payload = report.to_dict()
    payload["profile_id"] = spec.profile_id
    print(json.dumps(payload, indent=2))
    return 0 if report.passed else 1


def _cmd_adversarial_report(evidence_path: str, limit: int) -> int:
    if limit < 0:
        print("limit must be non-negative.")
        return 1
    payload = summarize_adversarial_history(evidence_path=evidence_path, limit=limit)
    print(json.dumps(payload, indent=2))
    return 0


def _cmd_trust_source_profiles(profile_file: str | None) -> int:
    profiles = list_managed_trust_source_profiles(profile_file=profile_file)
    payload = {
        "profile_file": str(default_trust_source_profile_path() if profile_file is None else profile_file),
        "profiles": list(profiles),
    }
    print(json.dumps(payload, indent=2))
    return 0


def _compat_adapter(adapter_name: str):
    if adapter_name == "langchain":
        return LangChainCompatibilityAdapter()
    if adapter_name == "langgraph":
        return LangGraphCompatibilityAdapter()
    if adapter_name == "mcp":
        return ModelContextProtocolCompatibilityAdapter()
    raise ValueError(f"Unsupported compatibility adapter '{adapter_name}'.")


def _write_json_file(path: str, payload: object) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _load_json_file(path: str) -> object:
    target = Path(path)
    return json.loads(target.read_text(encoding="utf-8"))


def _cmd_compat_export(
    spec_path: str,
    adapter_name: str,
    output_path: str | None,
    request_id: str | None,
) -> int:
    spec = load_spec(spec_path)
    adapter = _compat_adapter(adapter_name)

    if adapter_name == "langchain":
        action_name = "langchain.export.agent_spec"
    elif adapter_name == "langgraph":
        action_name = "langgraph.export.agent_spec"
    elif adapter_name == "mcp":
        action_name = "mcp.export.agent_spec"
    else:  # pragma: no cover - parser choices enforce supported values
        print(json.dumps({"passed": False, "error": f"Unsupported adapter: {adapter_name}"}, indent=2))
        return 1

    result = adapter.execute_action(
        AdapterActionRequest(
            action_name=action_name,
            payload=(
                {
                    "agent_spec": spec.to_dict(),
                    "server_name": f"{spec.name}-server",
                    "server_version": "1.0.0",
                    "trust_profile_id": _default_protocol_trust_profile_id(spec),
                }
                if adapter_name == "mcp"
                else {"agent_spec": spec.to_dict()}
            ),
            request_id=request_id or "",
        )
    )
    if not result.ok:
        print(
            json.dumps(
                {
                    "passed": False,
                    "adapter": adapter_name,
                    "contract_version": result.contract_version,
                    "errors": [error.to_dict() for error in result.errors],
                },
                indent=2,
            )
        )
        return 1

    if output_path:
        _write_json_file(output_path, result.output)

    payload: dict[str, object] = {
        "passed": True,
        "adapter": adapter_name,
        "contract_version": result.contract_version,
        "output": result.output,
    }
    if output_path:
        payload["output_file"] = output_path
    print(json.dumps(payload, indent=2))
    return 0


def _cmd_compat_import(
    adapter_name: str,
    input_path: str,
    output_path: str | None,
    request_id: str | None,
) -> int:
    try:
        source_payload = _load_json_file(input_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(
            json.dumps(
                {"passed": False, "error": f"Failed to read compatibility payload: {exc}"},
                indent=2,
            )
        )
        return 1

    adapter = _compat_adapter(adapter_name)
    try:
        action_name, action_payload = _build_compat_import_request(adapter_name, source_payload)
    except ValueError as exc:
        print(json.dumps({"passed": False, "error": str(exc)}, indent=2))
        return 1

    result = adapter.execute_action(
        AdapterActionRequest(
            action_name=action_name,
            payload=action_payload,
            request_id=request_id or "",
        )
    )
    if not result.ok:
        print(
            json.dumps(
                {
                    "passed": False,
                    "adapter": adapter_name,
                    "contract_version": result.contract_version,
                    "errors": [error.to_dict() for error in result.errors],
                },
                indent=2,
            )
        )
        return 1

    if output_path:
        _write_json_file(output_path, result.output)

    payload: dict[str, object] = {
        "passed": True,
        "adapter": adapter_name,
        "contract_version": result.contract_version,
        "output": result.output,
    }
    if output_path:
        payload["output_file"] = output_path
    print(json.dumps(payload, indent=2))
    return 0


def _build_compat_import_request(
    adapter_name: str,
    source_payload: object,
) -> tuple[str, dict[str, object]]:
    if adapter_name == "langchain":
        tool_bundle = (
            source_payload.get("tool_bundle")
            if isinstance(source_payload, dict) and "tool_bundle" in source_payload
            else source_payload
        )
        if not isinstance(tool_bundle, list):
            raise ValueError(
                "LangChain import expects a 'tool_bundle' list or a JSON root list."
            )
        return "langchain.import.tool_bundle", {"tool_bundle": tool_bundle}

    if adapter_name == "langgraph":
        flow_definition = (
            source_payload.get("flow_definition")
            if isinstance(source_payload, dict) and "flow_definition" in source_payload
            else source_payload
        )
        if not isinstance(flow_definition, dict):
            raise ValueError(
                "LangGraph import expects a 'flow_definition' object or a JSON root object."
            )
        return "langgraph.import.flow_definition", {"flow_definition": flow_definition}

    if adapter_name == "mcp":
        server_bundle = (
            source_payload.get("server_bundle")
            if isinstance(source_payload, dict) and "server_bundle" in source_payload
            else source_payload
        )
        if not isinstance(server_bundle, dict):
            raise ValueError(
                "Model Context Protocol import expects a 'server_bundle' object or a JSON root object."
            )
        return "mcp.import.server_bundle", {"server_bundle": server_bundle}

    raise ValueError(f"Unsupported compatibility adapter '{adapter_name}'.")


def _print_verification_results(passed: bool, results: tuple, evidence_path: Path) -> None:
    print(json.dumps({"passed": passed}, indent=2))
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(f"[{status}] {result.name}: {result.message}")
    print(f"Evidence: {evidence_path}")


def _print_runtime_metadata(runtime_report: LangGraphRuntimeReport) -> None:
    payload: dict[str, object] = {
        "runtime": "langgraph",
        "run_id": runtime_report.run_id,
        "checkpoint_path": str(runtime_report.checkpoint_path) if runtime_report.checkpoint_path else None,
        "resumed_from": str(runtime_report.resumed_from) if runtime_report.resumed_from else None,
        "replay_of": str(runtime_report.replay_of) if runtime_report.replay_of else None,
        "replay_match": runtime_report.replay_match,
    }
    print(json.dumps(payload, indent=2))


def _runtime_metadata(runtime_report: LangGraphRuntimeReport | None, mode: str) -> dict[str, object]:
    if runtime_report is None:
        return {"mode": mode}
    return {
        "mode": mode,
        "run_id": runtime_report.run_id,
        "checkpoint_path": str(runtime_report.checkpoint_path) if runtime_report.checkpoint_path else None,
        "resumed_from": str(runtime_report.resumed_from) if runtime_report.resumed_from else None,
        "replay_of": str(runtime_report.replay_of) if runtime_report.replay_of else None,
        "replay_match": runtime_report.replay_match,
    }


def _default_protocol_trust_profile_id(spec: AgentSpec) -> str:
    explicit = spec.live_data.trust_profile_id.strip()
    if explicit:
        return explicit
    profile_id = (spec.profile_id or "custom").strip() or "custom"
    return f"profile_{profile_id}"


def _cmd_verify(
    spec_path: str,
    evidence_path: str,
    repo_path: str | None,
    runtime: str,
    checkpoint_dir: str | None,
    resume_checkpoint: str | None,
) -> int:
    spec = load_spec(spec_path)
    if runtime == "langgraph":
        runtime_adapter = default_langgraph_runtime(evidence_path, repo_path=repo_path)
        try:
            runtime_report = runtime_adapter.run(
                spec=spec,
                checkpoint_dir=checkpoint_dir,
                resume_from=resume_checkpoint,
            )
        except LangGraphRuntimeError as exc:
            print(json.dumps({"passed": False, "error": str(exc)}, indent=2))
            return 1
        _print_verification_results(
            runtime_report.verification_report.passed,
            runtime_report.verification_report.results,
            runtime_report.verification_report.evidence_path,
        )
        _print_runtime_metadata(runtime_report)
        return 0 if runtime_report.verification_report.passed else 1

    if resume_checkpoint:
        print("resume_checkpoint is supported only for runtime=langgraph.")
        return 1

    report = default_pipeline(evidence_path, repo_path=repo_path).run(spec)
    _print_verification_results(report.passed, report.results, report.evidence_path)
    print(json.dumps({"runtime": "standard"}, indent=2))
    return 0 if report.passed else 1


def _cmd_resume(
    checkpoint_path: str,
    evidence_path: str,
    spec_path: str | None,
    repo_path: str | None,
    checkpoint_dir: str | None,
) -> int:
    runtime_adapter = default_langgraph_runtime(evidence_path, repo_path=repo_path)
    spec = load_spec(spec_path) if spec_path is not None else None
    try:
        runtime_report = runtime_adapter.resume(
            checkpoint_path=checkpoint_path,
            spec=spec,
            checkpoint_dir=checkpoint_dir,
        )
    except LangGraphRuntimeError as exc:
        print(json.dumps({"passed": False, "error": str(exc)}, indent=2))
        return 1
    _print_verification_results(
        runtime_report.verification_report.passed,
        runtime_report.verification_report.results,
        runtime_report.verification_report.evidence_path,
    )
    _print_runtime_metadata(runtime_report)
    return 0 if runtime_report.verification_report.passed else 1


def _cmd_replay(
    checkpoint_path: str,
    evidence_path: str,
    spec_path: str | None,
    repo_path: str | None,
    checkpoint_dir: str | None,
) -> int:
    runtime_adapter = default_langgraph_runtime(evidence_path, repo_path=repo_path)
    spec = load_spec(spec_path) if spec_path is not None else None
    try:
        runtime_report = runtime_adapter.replay(
            checkpoint_path=checkpoint_path,
            spec=spec,
            checkpoint_dir=checkpoint_dir,
        )
    except LangGraphRuntimeError as exc:
        print(json.dumps({"passed": False, "error": str(exc)}, indent=2))
        return 1
    _print_verification_results(
        runtime_report.verification_report.passed,
        runtime_report.verification_report.results,
        runtime_report.verification_report.evidence_path,
    )
    _print_runtime_metadata(runtime_report)
    if runtime_report.replay_match is None:
        return 1
    return 0 if runtime_report.verification_report.passed and runtime_report.replay_match else 1


def _cmd_intelligence(spec_path: str, query_override: str | None) -> int:
    spec = load_spec(spec_path)
    query = query_override.strip() if query_override else (spec.live_data.query.strip() or spec.description)
    client = LiveIntelligenceClient()
    try:
        report = client.collect_latest(
            query=query,
            settings=spec.live_data,
            risk_level=spec.risk_level,
        )
    except LiveDataError as exc:
        print(
            json.dumps(
                {
                    "passed": False,
                    "provider": spec.live_data.provider,
                    "model": spec.live_data.model,
                    "error": str(exc),
                },
                indent=2,
            )
        )
        return 1

    print(
        json.dumps(
            {
                "passed": True,
                "provider": report.provider,
                "model": report.model,
                "query": report.query,
                "fetched_at": report.fetched_at,
                "summary": report.summary,
                "attempts": [item.to_dict() for item in report.attempts],
                "trust_assessment": report.assessment.to_dict(),
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
                    for citation in report.citations
                ],
            },
            indent=2,
        )
    )
    return 0


def _cmd_release(
    spec_path: str,
    evidence_path: str,
    output_path: str,
    repo_path: str | None,
    runtime: str,
    checkpoint_dir: str | None,
    resume_checkpoint: str | None,
    replay_checkpoint: str | None,
    approved_by: str | None,
    approval_id: str | None,
    approval_notes: str | None,
    signing_key_file: str | None,
    signing_mode: str | None,
    sigstore_bundle_path: str | None,
    sigstore_repository: str | None,
    sigstore_workflow: str | None,
    sigstore_certificate_oidc_issuer: str | None,
    control_matrix_file: str | None,
) -> int:
    spec = load_spec(spec_path)
    runtime_report: LangGraphRuntimeReport | None = None
    verification_override = None
    if runtime == "langgraph":
        runtime_adapter = default_langgraph_runtime(evidence_path, repo_path=repo_path)
        try:
            if replay_checkpoint:
                runtime_report = runtime_adapter.replay(
                    checkpoint_path=replay_checkpoint,
                    spec=spec,
                    checkpoint_dir=checkpoint_dir,
                )
            else:
                runtime_report = runtime_adapter.run(
                    spec=spec,
                    checkpoint_dir=checkpoint_dir,
                    resume_from=resume_checkpoint,
                )
        except LangGraphRuntimeError as exc:
            print(json.dumps({"passed": False, "error": str(exc)}, indent=2))
            return 1
        verification_override = runtime_report.verification_report
    elif resume_checkpoint or replay_checkpoint:
        print("resume_checkpoint and replay_checkpoint require runtime=langgraph.")
        return 1

    report = default_release_workflow(evidence_path).run(
        spec=spec,
        output_dir=output_path,
        repo_path=repo_path,
        approved_by=approved_by,
        approval_id=approval_id,
        approval_notes=approval_notes,
        signing_key_file=signing_key_file,
        signing_mode=signing_mode,
        sigstore_bundle_path=sigstore_bundle_path,
        sigstore_repository=sigstore_repository,
        sigstore_workflow=sigstore_workflow,
        sigstore_certificate_oidc_issuer=sigstore_certificate_oidc_issuer,
        control_matrix_file=control_matrix_file,
        verification_report_override=verification_override,
        runtime_metadata=_runtime_metadata(runtime_report, runtime),
    )
    _print_verification_results(
        report.verification_report.passed,
        report.verification_report.results,
        report.verification_report.evidence_path,
    )
    if runtime_report is not None:
        _print_runtime_metadata(runtime_report)
    if report.manifest_path is not None:
        print(f"Release manifest: {report.manifest_path}")
    if report.signature is not None:
        print(f"Release signature: {report.signature}")
    if report.failure_reason is not None:
        print(f"Release failure reason: {report.failure_reason}")
    return 0 if report.passed else 1


def _cmd_anchor(manifest_path: str, output_path: str | None) -> int:
    try:
        anchor_payload = compute_release_anchor_payload(manifest_path)
    except ValueError as exc:
        print(json.dumps({"passed": False, "error": str(exc)}, indent=2))
        return 1

    if output_path:
        _write_json_file(output_path, anchor_payload)

    payload: dict[str, object] = {
        "passed": True,
        "anchor": anchor_payload,
    }
    if output_path:
        payload["output_file"] = output_path
    print(json.dumps(payload, indent=2))
    return 0


def _cmd_dashboard(validation_root: str, output_path: str) -> int:
    try:
        dashboard_path = write_dashboard(validation_root=validation_root, output_path=output_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"passed": False, "error": str(exc)}, indent=2))
        return 1
    print(
        json.dumps(
            {
                "passed": True,
                "dashboard_path": str(dashboard_path),
            },
            indent=2,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        enforce_open_source_mode()
    except OpenSourceModeViolation as exc:
        print(str(exc))
        return 1

    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "init":
        return _cmd_init(
            path=args.path,
            force=args.force,
            profile=args.profile,
            name=args.name,
            description=args.description,
            risk_level=args.risk_level,
            runtime_environment=args.runtime_environment,
        )
    if args.command == "profiles":
        return _cmd_profiles()
    if args.command == "quality":
        return _cmd_quality(spec_path=args.spec)
    if args.command == "adversarial-report":
        return _cmd_adversarial_report(
            evidence_path=args.evidence,
            limit=args.limit,
        )
    if args.command == "trust-source-profiles":
        return _cmd_trust_source_profiles(profile_file=args.profile_file)
    if args.command == "compat-export":
        return _cmd_compat_export(
            spec_path=args.spec,
            adapter_name=args.adapter,
            output_path=args.output,
            request_id=args.request_id,
        )
    if args.command == "compat-import":
        return _cmd_compat_import(
            adapter_name=args.adapter,
            input_path=args.input,
            output_path=args.output,
            request_id=args.request_id,
        )
    if args.command == "verify":
        return _cmd_verify(
            spec_path=args.spec,
            evidence_path=args.evidence,
            repo_path=args.repo,
            runtime=args.runtime,
            checkpoint_dir=args.checkpoint_dir,
            resume_checkpoint=args.resume_checkpoint,
        )
    if args.command == "resume":
        return _cmd_resume(
            checkpoint_path=args.checkpoint,
            evidence_path=args.evidence,
            spec_path=args.spec,
            repo_path=args.repo,
            checkpoint_dir=args.checkpoint_dir,
        )
    if args.command == "replay":
        return _cmd_replay(
            checkpoint_path=args.checkpoint,
            evidence_path=args.evidence,
            spec_path=args.spec,
            repo_path=args.repo,
            checkpoint_dir=args.checkpoint_dir,
        )
    if args.command == "intelligence":
        return _cmd_intelligence(
            spec_path=args.spec,
            query_override=args.query,
        )
    if args.command == "release":
        return _cmd_release(
            spec_path=args.spec,
            evidence_path=args.evidence,
            output_path=args.output,
            repo_path=args.repo,
            runtime=args.runtime,
            checkpoint_dir=args.checkpoint_dir,
            resume_checkpoint=args.resume_checkpoint,
            replay_checkpoint=args.replay_checkpoint,
            approved_by=args.approved_by,
            approval_id=args.approval_id,
            approval_notes=args.approval_notes,
            signing_key_file=args.signing_key_file,
            signing_mode=args.signing_mode,
            sigstore_bundle_path=args.sigstore_bundle_path,
            sigstore_repository=args.sigstore_repository,
            sigstore_workflow=args.sigstore_workflow,
            sigstore_certificate_oidc_issuer=args.sigstore_certificate_oidc_issuer,
            control_matrix_file=args.control_matrix_file,
        )
    if args.command == "anchor":
        return _cmd_anchor(
            manifest_path=args.manifest,
            output_path=args.output,
        )
    if args.command == "dashboard":
        return _cmd_dashboard(
            validation_root=args.validation_root,
            output_path=args.output,
        )

    parser.print_help()
    return 1
