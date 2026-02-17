from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .adapters import (
    AdapterActionRequest,
    LifeguardExtractsAdapterLayer,
    LangChainCompatibilityAdapter,
    LangGraphCompatibilityAdapter,
    ModelContextProtocolCompatibilityAdapter,
)
from .evidence_store import EvidenceStore
from .legislative_review import (
    LegislativeReviewError,
    load_json_file,
    resolve_legislative_review_artifacts,
    validate_legislative_decision,
)
from .live_intelligence import LiveIntelligenceClient
from .owasp_controls import (
    ControlMatrixSummary,
    build_badge_material,
    evaluate_control_matrix_file,
)
from .sigstore_signing import (
    CommandRunner,
    SigstoreConfigurationError,
    SigstoreExecutionError,
    default_sigstore_command_runner,
    sign_and_verify_bundle,
    sigstore_available,
)
from .signing import SigningConfigurationError, SigningKey, load_signing_key, sign_payload
from .spec_schema import AgentSpec
from .verification_pipeline import VerificationPipeline, VerificationReport

_RELEASE_ADVERSARIAL_THRESHOLD_BY_RISK = {
    "low": 0.80,
    "medium": 0.90,
    "high": 1.00,
}
_DEFAULT_COMPATIBILITY_GATE_ADAPTERS = ("langchain", "langgraph")
_SIGNING_MODES = ("auto", "hmac", "sigstore")
_DEFAULT_SIGSTORE_OIDC_ISSUER = "https://token.actions.githubusercontent.com"

_PASS_RATE_PATTERN = re.compile(r"pass_rate=([0-9]+(?:\.[0-9]+)?)")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_json(payload: dict[str, Any]) -> str:
    return _sha256_hex(json.dumps(payload, sort_keys=True).encode("utf-8"))


def _sha256_file(path: Path) -> str:
    return _sha256_hex(path.read_bytes())


def compute_release_anchor_payload(manifest_path: str | Path) -> dict[str, Any]:
    """Compute the external anchor payload for a signed release manifest.

    This anchor can be stored outside the local machine (for example in a build log,
    a signed tag, or a separate evidence archive) to make local evidence tampering
    easier to detect.
    """
    target = Path(manifest_path)
    try:
        manifest = json.loads(target.read_text(encoding="utf-8"))
    except OSError as exc:  # pragma: no cover - depends on filesystem failures
        raise ValueError(f"Failed to read manifest: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Manifest is not valid JSON: {exc}") from exc

    if not isinstance(manifest, dict):
        raise ValueError("Release manifest must be a JSON object.")

    verification = manifest.get("verification", {})
    evidence_path = ""
    evidence_last_hash = ""
    if isinstance(verification, dict):
        evidence_path = str(verification.get("evidence_path", "") or "")
        evidence_last_hash = str(verification.get("evidence_last_hash", "") or "")

    anchor_block = manifest.get("anchor", {})
    expected_body_sha256 = ""
    repo_commit: str | None = None
    if isinstance(anchor_block, dict):
        expected_body_sha256 = str(anchor_block.get("manifest_body_sha256", "") or "")
        repo_commit_value = anchor_block.get("repo_commit")
        if isinstance(repo_commit_value, str) and repo_commit_value.strip():
            repo_commit = repo_commit_value.strip()

    manifest_without_signature = dict(manifest)
    manifest_without_signature.pop("signature", None)
    manifest_without_signature.pop("anchor", None)
    computed_body_sha256 = _sha256_json(manifest_without_signature)
    if expected_body_sha256 and expected_body_sha256 != computed_body_sha256:
        raise ValueError("Manifest anchor body hash does not match computed manifest payload.")

    return {
        "created_at": manifest.get("created_at"),
        "manifest_path": target.name,
        "manifest_sha256": _sha256_file(target),
        "manifest_body_sha256": expected_body_sha256 or computed_body_sha256,
        "evidence_last_hash": evidence_last_hash,
        "evidence_path": evidence_path,
        "repo_commit": repo_commit,
    }


def _try_git_head_commit(repo_path: Path | None) -> str | None:
    if repo_path is None:
        return None
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError:
        return None

    if completed.returncode != 0:
        return None
    candidate = completed.stdout.strip()
    if not candidate or " " in candidate or "\n" in candidate:
        return None
    return candidate


def _relpath_for_manifest(path: Path, *, base: Path) -> str:
    """Prefer relative paths in release manifests to avoid leaking workstation prefixes."""
    resolved_path = path
    resolved_base = base
    try:
        resolved_path = path.resolve()
    except OSError:
        pass
    try:
        resolved_base = base.resolve()
    except OSError:
        pass
    try:
        return os.path.relpath(str(resolved_path), start=str(resolved_base))
    except ValueError:
        return str(resolved_path)


@dataclass(frozen=True)
class ApprovalDecision:
    required: bool
    approved: bool
    approved_by: str | None
    approval_id: str | None
    approval_notes: str | None
    approved_at: str | None


@dataclass(frozen=True)
class ReleaseReport:
    passed: bool
    verification_report: VerificationReport
    manifest_path: Path | None
    signature: str | None
    failure_reason: str | None = None


@dataclass(frozen=True)
class AdversarialGateDecision:
    required: bool
    passed: bool
    pass_rate: float | None
    threshold: float
    check_present: bool


@dataclass(frozen=True)
class CompatibilityAdapterDecision:
    adapter_name: str
    passed: bool
    reason: str
    export_ok: bool
    import_ok: bool
    required_fields_preserved: bool
    enforcement_ok: bool
    details: dict[str, Any]


@dataclass(frozen=True)
class CompatibilityGateDecision:
    required: bool
    passed: bool
    adapter_decisions: tuple[CompatibilityAdapterDecision, ...]


class ReleaseWorkflow:
    def __init__(
        self,
        evidence_store: EvidenceStore,
        adapter_layer: LifeguardExtractsAdapterLayer | None = None,
        sigstore_command_runner: CommandRunner | None = None,
        intelligence_client: LiveIntelligenceClient | None = None,
    ) -> None:
        self.evidence_store = evidence_store
        self.adapter_layer = adapter_layer or LifeguardExtractsAdapterLayer()
        self.sigstore_command_runner = sigstore_command_runner
        self.intelligence_client = intelligence_client

    def run(
        self,
        spec: AgentSpec,
        output_dir: str | Path,
        repo_path: str | Path | None = None,
        approved_by: str | None = None,
        approval_id: str | None = None,
        approval_notes: str | None = None,
        signing_key_file: str | Path | None = None,
        signing_mode: str | None = None,
        sigstore_bundle_path: str | Path | None = None,
        sigstore_repository: str | None = None,
        sigstore_workflow: str | None = None,
        sigstore_certificate_oidc_issuer: str | None = None,
        control_matrix_file: str | Path | None = None,
        verification_report_override: VerificationReport | None = None,
        runtime_metadata: dict[str, Any] | None = None,
    ) -> ReleaseReport:
        if verification_report_override is None:
            verifier = VerificationPipeline(
                evidence_store=self.evidence_store,
                adapter_layer=self.adapter_layer,
                repo_path=Path(repo_path) if repo_path is not None else None,
                intelligence_client=self.intelligence_client,
            )
            verification_report = verifier.run(spec)
        else:
            verification_report = verification_report_override

        if not verification_report.passed:
            self.evidence_store.append(
                "release.package.blocked",
                "fail",
                {
                    "agent_name": spec.name,
                    "reason": "verification_failed",
                },
            )
            return ReleaseReport(
                passed=False,
                verification_report=verification_report,
                manifest_path=None,
                signature=None,
                failure_reason="verification_failed",
            )

        if spec.legislative_review.enabled:
            artifacts = resolve_legislative_review_artifacts(
                spec=spec,
                evidence_path=verification_report.evidence_path,
            )
            errors: list[str] = []
            decision_value: str | None = None
            if not artifacts.pack_path.exists():
                errors.append("Legislative review pack file is missing.")
            if spec.legislative_review.require_human_decision:
                if not artifacts.decision_path.exists():
                    errors.append("Legislative review decision file is missing.")
                else:
                    try:
                        raw_decision = load_json_file(artifacts.decision_path)
                        decision = validate_legislative_decision(
                            payload=raw_decision,
                            spec=spec,
                            required_jurisdictions=tuple(spec.legal_context.jurisdictions),
                        )
                        decision_value = str(decision.get("decision", "")).strip().lower()
                        if decision_value != "accept":
                            errors.append(
                                "Legislative review decision must be accept for release."
                            )
                    except LegislativeReviewError as exc:
                        errors.append(str(exc))

            if errors:
                self.evidence_store.append(
                    "release.legislative_review.blocked",
                    "fail",
                    {
                        "agent_name": spec.name,
                        "pack_path": artifacts.pack_path,
                        "decision_path": artifacts.decision_path,
                        "errors": errors,
                        "decision": decision_value,
                    },
                )
                return ReleaseReport(
                    passed=False,
                    verification_report=verification_report,
                    manifest_path=None,
                    signature=None,
                    failure_reason="legislative_review_blocked",
                )

            self.evidence_store.append(
                "release.legislative_review.checked",
                "pass",
                {
                    "agent_name": spec.name,
                    "pack_path": artifacts.pack_path,
                    "decision_path": artifacts.decision_path,
                    "decision": decision_value or "accept",
                },
            )

        compatibility_gate = self._evaluate_compatibility_gate(spec)
        if not compatibility_gate.passed:
            self.evidence_store.append(
                "release.compatibility_gate.blocked",
                "fail",
                {
                    "agent_name": spec.name,
                    "adapter_decisions": [
                        {
                            "adapter_name": decision.adapter_name,
                            "passed": decision.passed,
                            "reason": decision.reason,
                            "export_ok": decision.export_ok,
                            "import_ok": decision.import_ok,
                            "required_fields_preserved": decision.required_fields_preserved,
                            "enforcement_ok": decision.enforcement_ok,
                        }
                        for decision in compatibility_gate.adapter_decisions
                    ],
                },
            )
            return ReleaseReport(
                passed=False,
                verification_report=verification_report,
                manifest_path=None,
                signature=None,
                failure_reason="compatibility_gate_failed",
            )
        self.evidence_store.append(
            "release.compatibility_gate.checked",
            "pass",
            {
                "agent_name": spec.name,
                "adapter_decisions": [
                    {
                        "adapter_name": decision.adapter_name,
                        "passed": decision.passed,
                        "reason": decision.reason,
                        "export_ok": decision.export_ok,
                        "import_ok": decision.import_ok,
                        "required_fields_preserved": decision.required_fields_preserved,
                        "enforcement_ok": decision.enforcement_ok,
                    }
                    for decision in compatibility_gate.adapter_decisions
                ],
            },
        )

        adversarial_gate = self._evaluate_adversarial_gate(spec, verification_report)
        if not adversarial_gate.passed:
            self.evidence_store.append(
                "release.adversarial_gate.blocked",
                "fail",
                {
                    "agent_name": spec.name,
                    "risk_level": spec.risk_level,
                    "required": adversarial_gate.required,
                    "pass_rate": adversarial_gate.pass_rate,
                    "threshold": adversarial_gate.threshold,
                    "check_present": adversarial_gate.check_present,
                },
            )
            return ReleaseReport(
                passed=False,
                verification_report=verification_report,
                manifest_path=None,
                signature=None,
                failure_reason="adversarial_gate_failed",
            )
        self.evidence_store.append(
            "release.adversarial_gate.checked",
            "pass",
            {
                "agent_name": spec.name,
                "risk_level": spec.risk_level,
                "required": adversarial_gate.required,
                "pass_rate": adversarial_gate.pass_rate,
                "threshold": adversarial_gate.threshold,
            },
        )

        approval = self._evaluate_approval(
            spec=spec,
            approved_by=approved_by,
            approval_id=approval_id,
            approval_notes=approval_notes,
        )
        if not approval.approved:
            self.evidence_store.append(
                "release.approval.blocked",
                "fail",
                {
                    "agent_name": spec.name,
                    "risk_level": spec.risk_level,
                    "approval_required": approval.required,
                    "approved_by": approval.approved_by,
                    "approval_id": approval.approval_id,
                },
            )
            return ReleaseReport(
                passed=False,
                verification_report=verification_report,
                manifest_path=None,
                signature=None,
                failure_reason="approval_missing",
            )
        self.evidence_store.append(
            "release.approval.checked",
            "pass",
            {
                "agent_name": spec.name,
                "approval_required": approval.required,
                "approved_by": approval.approved_by,
                "approval_id": approval.approval_id,
            },
        )

        target_dir = Path(output_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = target_dir / "release_manifest.json"
        payload_path = target_dir / "release_manifest_payload.json"
        control_matrix_summary = evaluate_control_matrix_file(control_matrix_file)
        if not control_matrix_summary.passed:
            self.evidence_store.append(
                "release.control_matrix.blocked",
                "fail",
                {
                    "agent_name": spec.name,
                    "summary": control_matrix_summary.to_dict(),
                },
            )
            return ReleaseReport(
                passed=False,
                verification_report=verification_report,
                manifest_path=None,
                signature=None,
                failure_reason="control_matrix_missing",
            )
        self.evidence_store.append(
            "release.control_matrix.checked",
            "pass",
            {
                "agent_name": spec.name,
                "summary": control_matrix_summary.to_dict(),
            },
        )
        evidence_run_id = ""
        if runtime_metadata is not None and isinstance(runtime_metadata.get("run_id"), str):
            evidence_run_id = runtime_metadata.get("run_id", "").strip()
        if not evidence_run_id:
            evidence_run_id = self.evidence_store.get_last_hash()
        badge_payload = build_badge_material(
            summary=control_matrix_summary,
            evidence_run_id=evidence_run_id,
        )
        badge_path = target_dir / "owasp_control_badge.json"
        badge_path.write_text(json.dumps(badge_payload, indent=2) + "\n", encoding="utf-8")
        self.evidence_store.append(
            "release.control_matrix.badge.created",
            "pass",
            {
                "agent_name": spec.name,
                "badge_path": badge_path.name,
                "coverage_percent": control_matrix_summary.coverage_percent,
            },
        )

        resolved_signing_mode = self._resolve_signing_mode(signing_mode)
        if not resolved_signing_mode:
            self.evidence_store.append(
                "release.signing.blocked",
                "fail",
                {
                    "agent_name": spec.name,
                    "error": f"Unsupported signing mode '{signing_mode}'.",
                    "supported_modes": list(_SIGNING_MODES),
                },
            )
            return ReleaseReport(
                passed=False,
                verification_report=verification_report,
                manifest_path=None,
                signature=None,
                failure_reason="invalid_signing_mode",
            )

        manifest: dict[str, Any] | None = None
        signature: str | None = None
        signature_algorithm = ""
        signature_key_id = ""
        sigstore_errors: list[str] = []
        sigstore_used = False

        if resolved_signing_mode in {"sigstore", "auto"}:
            sigstore_configuration_error, sigstore_settings = self._resolve_sigstore_settings(
                output_dir=target_dir,
                bundle_path=sigstore_bundle_path,
                repository=sigstore_repository,
                workflow=sigstore_workflow,
                certificate_oidc_issuer=sigstore_certificate_oidc_issuer,
            )
            if sigstore_configuration_error:
                if resolved_signing_mode == "sigstore":
                    self.evidence_store.append(
                        "release.signing.blocked",
                        "fail",
                        {
                            "agent_name": spec.name,
                            "error": sigstore_configuration_error,
                            "signing_mode": resolved_signing_mode,
                        },
                    )
                    return ReleaseReport(
                        passed=False,
                        verification_report=verification_report,
                        manifest_path=None,
                        signature=None,
                        failure_reason="sigstore_configuration_missing",
                    )
                sigstore_errors.append(sigstore_configuration_error)
            elif not sigstore_available(command_runner=self._sigstore_command_runner()):
                unavailable_error = "Sigstore command is unavailable."
                if resolved_signing_mode == "sigstore":
                    self.evidence_store.append(
                        "release.signing.blocked",
                        "fail",
                        {
                            "agent_name": spec.name,
                            "error": unavailable_error,
                            "signing_mode": resolved_signing_mode,
                        },
                    )
                    return ReleaseReport(
                        passed=False,
                        verification_report=verification_report,
                        manifest_path=None,
                        signature=None,
                        failure_reason="sigstore_unavailable",
                    )
                sigstore_errors.append(unavailable_error)
            else:
                assert sigstore_settings is not None
                sigstore_signing_metadata = {
                    "algorithm": "sigstore-bundle",
                    "key_id": "sigstore-keyless",
                    "mode": "sigstore",
                    "repository": sigstore_settings["repository"],
                    "workflow": sigstore_settings["workflow"],
                }
                candidate_manifest = self._build_manifest(
                    spec=spec,
                    verification_report=verification_report,
                    repo_path=Path(repo_path) if repo_path is not None else None,
                    approval=approval,
                    signing_metadata=sigstore_signing_metadata,
                    runtime_metadata=runtime_metadata,
                    compatibility_gate=compatibility_gate,
                    adversarial_gate=adversarial_gate,
                    control_matrix_summary=control_matrix_summary,
                    output_dir=target_dir,
                )
                manifest_body_sha256 = _sha256_json(candidate_manifest)
                repo_commit = _try_git_head_commit(Path(repo_path) if repo_path is not None else None)
                candidate_manifest["anchor"] = {
                    "manifest_body_sha256": manifest_body_sha256,
                    "evidence_last_hash": candidate_manifest.get("verification", {}).get(
                        "evidence_last_hash", ""
                    ),
                    "repo_commit": repo_commit,
                }
                payload_path.write_text(
                    json.dumps(candidate_manifest, indent=2) + "\n",
                    encoding="utf-8",
                )
                try:
                    sigstore_report = sign_and_verify_bundle(
                        artifact_path=payload_path,
                        bundle_path=sigstore_settings["bundle_path"],
                        repository=sigstore_settings["repository"],
                        workflow=sigstore_settings["workflow"],
                        certificate_oidc_issuer=sigstore_settings["certificate_oidc_issuer"],
                        command_runner=self._sigstore_command_runner(),
                    )
                except (SigstoreConfigurationError, SigstoreExecutionError) as exc:
                    if resolved_signing_mode == "sigstore":
                        self.evidence_store.append(
                            "release.signing.blocked",
                            "fail",
                            {
                                "agent_name": spec.name,
                                "error": str(exc),
                                "signing_mode": resolved_signing_mode,
                            },
                        )
                        return ReleaseReport(
                            passed=False,
                            verification_report=verification_report,
                            manifest_path=None,
                            signature=None,
                            failure_reason="sigstore_signing_failed",
                        )
                    sigstore_errors.append(str(exc))
                else:
                    candidate_manifest["signature"] = {
                        "algorithm": "sigstore-bundle",
                        "key_id": "sigstore-keyless",
                        "bundle_path": _relpath_for_manifest(sigstore_report.bundle_path, base=target_dir),
                        "bundle_sha256": sigstore_report.bundle_sha256,
                        "payload_path": payload_path.name,
                        "payload_sha256": _sha256_file(payload_path),
                        "verified": True,
                        "workflow_identity_name": sigstore_report.identity_policy.workflow_name,
                        "certificate_oidc_issuer": sigstore_report.identity_policy.certificate_oidc_issuer,
                        "repository": sigstore_report.identity_policy.repository,
                        "workflow": sigstore_report.identity_policy.workflow,
                        "transparency_log_entries": list(sigstore_report.transparency_log_entries),
                    }
                    manifest = candidate_manifest
                    signature = sigstore_report.bundle_sha256
                    signature_algorithm = "sigstore-bundle"
                    signature_key_id = "sigstore-keyless"
                    sigstore_used = True

        if manifest is None:
            signing_source_error = self._validate_signing_key_source_policy(
                spec=spec,
                signing_key_file=signing_key_file,
                signing_mode="hmac",
            )
            if signing_source_error:
                self.evidence_store.append(
                    "release.signing.blocked",
                    "fail",
                    {
                        "agent_name": spec.name,
                        "error": signing_source_error,
                    },
                )
                return ReleaseReport(
                    passed=False,
                    verification_report=verification_report,
                    manifest_path=None,
                    signature=None,
                    failure_reason="signing_key_policy_blocked",
                )

            signing_key: SigningKey
            try:
                signing_key = load_signing_key(signing_key_file)
            except SigningConfigurationError as exc:
                self.evidence_store.append(
                    "release.signing.blocked",
                    "fail",
                    {
                        "agent_name": spec.name,
                        "error": str(exc),
                    },
                )
                return ReleaseReport(
                    passed=False,
                    verification_report=verification_report,
                    manifest_path=None,
                    signature=None,
                    failure_reason="signing_key_missing",
                )

            hmac_signing_metadata = {
                "algorithm": signing_key.algorithm,
                "key_id": signing_key.key_id,
                "mode": "hmac",
            }
            manifest = self._build_manifest(
                spec=spec,
                verification_report=verification_report,
                repo_path=Path(repo_path) if repo_path is not None else None,
                approval=approval,
                signing_metadata=hmac_signing_metadata,
                runtime_metadata=runtime_metadata,
                compatibility_gate=compatibility_gate,
                adversarial_gate=adversarial_gate,
                control_matrix_summary=control_matrix_summary,
                output_dir=target_dir,
            )
            manifest_body_sha256 = _sha256_json(manifest)
            repo_commit = _try_git_head_commit(Path(repo_path) if repo_path is not None else None)
            manifest["anchor"] = {
                "manifest_body_sha256": manifest_body_sha256,
                "evidence_last_hash": manifest.get("verification", {}).get("evidence_last_hash", ""),
                "repo_commit": repo_commit,
            }
            signature = sign_payload(manifest, key=signing_key)
            manifest["signature"] = {
                "algorithm": signing_key.algorithm,
                "key_id": signing_key.key_id,
                "value": signature,
            }
            signature_algorithm = signing_key.algorithm
            signature_key_id = signing_key.key_id

        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        anchor_path = target_dir / "release_anchor.json"
        anchor_payload = compute_release_anchor_payload(manifest_path)
        anchor_path.write_text(json.dumps(anchor_payload, indent=2) + "\n", encoding="utf-8")

        if sigstore_errors and not sigstore_used:
            self.evidence_store.append(
                "release.signing.fallback",
                "pass",
                {
                    "agent_name": spec.name,
                    "from_mode": resolved_signing_mode,
                    "to_mode": "hmac",
                    "errors": sigstore_errors,
                },
            )

        self.evidence_store.append(
            "release.anchor.created",
            "pass",
            {
                "agent_name": spec.name,
                "anchor_path": anchor_path.name,
                "manifest_path": manifest_path.name,
                "manifest_sha256": anchor_payload.get("manifest_sha256", ""),
            },
        )

        self.evidence_store.append(
            "release.package.created",
            "pass",
            {
                "agent_name": spec.name,
                "manifest_path": str(manifest_path),
                "signature_algorithm": signature_algorithm,
                "signature_key_id": signature_key_id,
                "signature": signature,
                "signing_mode": "sigstore" if sigstore_used else "hmac",
            },
        )
        return ReleaseReport(
            passed=True,
            verification_report=verification_report,
            manifest_path=manifest_path,
            signature=signature,
        )

    def _build_manifest(
        self,
        spec: AgentSpec,
        verification_report: VerificationReport,
        repo_path: Path | None,
        approval: ApprovalDecision,
        signing_metadata: dict[str, Any],
        runtime_metadata: dict[str, Any] | None,
        compatibility_gate: CompatibilityGateDecision,
        adversarial_gate: AdversarialGateDecision,
        control_matrix_summary: ControlMatrixSummary,
        output_dir: Path,
    ) -> dict[str, Any]:
        policy = verification_report.policy
        policy_payload: dict[str, Any] | None = None
        if policy is not None:
            policy_payload = {
                "allowed_commands": list(policy.allowed_commands),
                "read_paths": list(policy.read_paths),
                "write_paths": list(policy.write_paths),
                "allowed_hosts": list(policy.allowed_hosts),
                "network_mode": policy.network_mode,
                "max_tool_timeout_seconds": policy.max_tool_timeout_seconds,
                "requires_human_approval": policy.requires_human_approval,
            }

        adapter_status = [
            {
                "adapter_name": status.adapter_name,
                "module_path": status.module_path,
                "available": status.available,
                "detail": status.detail,
            }
            for status in self.adapter_layer.list_module_status()
        ]

        legislative_review_payload: dict[str, Any] = {"enabled": False}
        if spec.legislative_review.enabled:
            artifacts = resolve_legislative_review_artifacts(
                spec=spec,
                evidence_path=verification_report.evidence_path,
            )
            pack_payload: object | None = None
            pack_error = ""
            if artifacts.pack_path.exists():
                try:
                    pack_payload = load_json_file(artifacts.pack_path)
                except LegislativeReviewError as exc:
                    pack_error = str(exc)
            else:
                pack_error = "Legislative review pack file missing."

            decision_payload: dict[str, Any] | None = None
            decision_error = ""
            if artifacts.decision_path.exists():
                try:
                    raw_decision = load_json_file(artifacts.decision_path)
                    decision_payload = validate_legislative_decision(
                        payload=raw_decision,
                        spec=spec,
                        required_jurisdictions=tuple(spec.legal_context.jurisdictions),
                    )
                except LegislativeReviewError as exc:
                    decision_error = str(exc)
            else:
                decision_error = "Legislative decision file missing."

            legislative_review_payload = {
                "enabled": True,
                "strict": spec.legislative_review.strict,
                "require_human_decision": spec.legislative_review.require_human_decision,
                "jurisdictions": list(spec.legal_context.jurisdictions),
                "pack": pack_payload if isinstance(pack_payload, dict) else None,
                "pack_error": pack_error or None,
                "decision": decision_payload,
                "decision_error": decision_error or None,
            }

        return {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "agent_spec": spec.to_dict(),
            "runtime": runtime_metadata or {"mode": "standard"},
            "verification": {
                "passed": verification_report.passed,
                "checks": [
                    {
                        "name": result.name,
                        "passed": result.passed,
                        "message": result.message,
                    }
                    for result in verification_report.results
                ],
                "policy": policy_payload,
                "evidence_path": _relpath_for_manifest(verification_report.evidence_path, base=output_dir),
                "evidence_last_hash": self.evidence_store.get_last_hash(),
            },
            "legislative_review": legislative_review_payload,
            "compatibility_gate": {
                "required": compatibility_gate.required,
                "passed": compatibility_gate.passed,
                "adapters": [
                    {
                        "adapter_name": decision.adapter_name,
                        "passed": decision.passed,
                        "reason": decision.reason,
                        "export_ok": decision.export_ok,
                        "import_ok": decision.import_ok,
                        "required_fields_preserved": decision.required_fields_preserved,
                        "enforcement_ok": decision.enforcement_ok,
                        "details": decision.details,
                    }
                    for decision in compatibility_gate.adapter_decisions
                ],
            },
            "adversarial_gate": {
                "required": adversarial_gate.required,
                "passed": adversarial_gate.passed,
                "pass_rate": adversarial_gate.pass_rate,
                "threshold": adversarial_gate.threshold,
                "check_present": adversarial_gate.check_present,
            },
            "owasp_control_matrix": control_matrix_summary.to_dict(),
            "adapter_modules": adapter_status,
            "repo_path": _relpath_for_manifest(repo_path, base=output_dir) if repo_path else None,
            "approval": {
                "required": approval.required,
                "approved": approval.approved,
                "approved_by": approval.approved_by,
                "approval_id": approval.approval_id,
                "approval_notes": approval.approval_notes,
                "approved_at": approval.approved_at,
            },
            "signing": {
                "algorithm": str(signing_metadata.get("algorithm", "")).strip(),
                "key_id": str(signing_metadata.get("key_id", "")).strip(),
                "mode": str(signing_metadata.get("mode", "")).strip(),
                "repository": signing_metadata.get("repository"),
                "workflow": signing_metadata.get("workflow"),
            },
        }

    def _evaluate_approval(
        self,
        spec: AgentSpec,
        approved_by: str | None,
        approval_id: str | None,
        approval_notes: str | None,
    ) -> ApprovalDecision:
        required = spec.risk_level == "high"
        approved_by_clean = approved_by.strip() if approved_by else None
        approval_id_clean = approval_id.strip() if approval_id else None
        approval_notes_clean = approval_notes.strip() if approval_notes else None

        if not required:
            approved = True
        else:
            approved = bool(approved_by_clean and approval_id_clean)

        approved_at = datetime.now(timezone.utc).isoformat() if approved else None
        return ApprovalDecision(
            required=required,
            approved=approved,
            approved_by=approved_by_clean,
            approval_id=approval_id_clean,
            approval_notes=approval_notes_clean,
            approved_at=approved_at,
        )

    def _validate_signing_key_source_policy(
        self,
        *,
        spec: AgentSpec,
        signing_key_file: str | Path | None,
        signing_mode: str,
    ) -> str:
        if signing_mode != "hmac":
            return ""
        if spec.risk_level != "high":
            return ""
        explicit_key_file = str(signing_key_file).strip() if signing_key_file is not None else ""
        env_key_file = os.getenv("LIFEGUARD_SIGNING_KEY_FILE", "").strip()
        if explicit_key_file or env_key_file:
            return ""
        if os.getenv("LIFEGUARD_SIGNING_KEY", "").strip():
            return (
                "High-risk release requires a file-based signing key source. "
                "Environment key material is blocked."
            )
        return "High-risk release requires --signing-key-file or LIFEGUARD_SIGNING_KEY_FILE."

    def _resolve_signing_mode(self, signing_mode: str | None) -> str:
        raw_mode = (
            str(signing_mode).strip().lower()
            if signing_mode is not None
            else os.getenv("LIFEGUARD_SIGNING_MODE", "hmac").strip().lower()
        )
        if raw_mode not in _SIGNING_MODES:
            return ""
        return raw_mode

    def _resolve_sigstore_settings(
        self,
        *,
        output_dir: Path,
        bundle_path: str | Path | None,
        repository: str | None,
        workflow: str | None,
        certificate_oidc_issuer: str | None,
    ) -> tuple[str, dict[str, Any] | None]:
        repo = (
            str(repository).strip()
            if repository is not None
            else os.getenv("LIFEGUARD_SIGSTORE_REPOSITORY", "").strip()
        )
        flow = (
            str(workflow).strip()
            if workflow is not None
            else os.getenv("LIFEGUARD_SIGSTORE_WORKFLOW", "").strip()
        )
        if not repo or not flow:
            return (
                "Sigstore signing requires repository and workflow identity settings.",
                None,
            )

        bundle = Path(bundle_path) if bundle_path is not None else None
        if bundle is None:
            env_bundle = os.getenv("LIFEGUARD_SIGSTORE_BUNDLE_PATH", "").strip()
            if env_bundle:
                bundle = Path(env_bundle)
            else:
                bundle = output_dir / "release_manifest.sigstore.bundle.json"
        if not bundle.is_absolute():
            bundle = output_dir / bundle

        issuer = (
            str(certificate_oidc_issuer).strip()
            if certificate_oidc_issuer is not None
            else os.getenv(
                "LIFEGUARD_SIGSTORE_CERTIFICATE_OIDC_ISSUER",
                _DEFAULT_SIGSTORE_OIDC_ISSUER,
            ).strip()
        )
        if not issuer:
            issuer = _DEFAULT_SIGSTORE_OIDC_ISSUER
        return (
            "",
            {
                "repository": repo,
                "workflow": flow,
                "bundle_path": bundle,
                "certificate_oidc_issuer": issuer,
            },
        )

    def _sigstore_command_runner(self) -> CommandRunner:
        if self.sigstore_command_runner is not None:
            return self.sigstore_command_runner
        return default_sigstore_command_runner

    def _evaluate_compatibility_gate(self, spec: AgentSpec) -> CompatibilityGateDecision:
        adapter_names = self._required_compatibility_gate_adapters()
        if not adapter_names:
            return CompatibilityGateDecision(
                required=False,
                passed=True,
                adapter_decisions=(),
            )

        decisions = tuple(
            self._evaluate_compatibility_adapter(spec, adapter_name)
            for adapter_name in adapter_names
        )
        passed = bool(decisions) and all(item.passed for item in decisions)
        return CompatibilityGateDecision(
            required=True,
            passed=passed,
            adapter_decisions=decisions,
        )

    def _required_compatibility_gate_adapters(self) -> tuple[str, ...]:
        raw_value = os.getenv(
            "LIFEGUARD_COMPATIBILITY_GATE_ADAPTERS",
            ",".join(_DEFAULT_COMPATIBILITY_GATE_ADAPTERS),
        )
        candidates = [item.strip().lower() for item in raw_value.split(",")]
        deduped: list[str] = []
        for candidate in candidates:
            if not candidate:
                continue
            if candidate in deduped:
                continue
            deduped.append(candidate)
        return tuple(deduped)

    def _evaluate_compatibility_adapter(
        self, spec: AgentSpec, adapter_name: str
    ) -> CompatibilityAdapterDecision:
        if adapter_name == "langchain":
            adapter = LangChainCompatibilityAdapter()
            export_action = "langchain.export.agent_spec"
            import_action = "langchain.import.tool_bundle"
            import_payload_key = "tool_bundle"
            export_payload_key = "tool_bundle"
        elif adapter_name == "langgraph":
            adapter = LangGraphCompatibilityAdapter()
            export_action = "langgraph.export.agent_spec"
            import_action = "langgraph.import.flow_definition"
            import_payload_key = "flow_definition"
            export_payload_key = "flow_definition"
        elif adapter_name == "mcp":
            adapter = ModelContextProtocolCompatibilityAdapter()
            export_action = "mcp.export.agent_spec"
            import_action = "mcp.import.server_bundle"
            import_payload_key = "server_bundle"
            export_payload_key = "server_bundle"
        else:
            return CompatibilityAdapterDecision(
                adapter_name=adapter_name,
                passed=False,
                reason=f"Unknown compatibility adapter '{adapter_name}'.",
                export_ok=False,
                import_ok=False,
                required_fields_preserved=False,
                enforcement_ok=False,
                details={},
            )

        export_payload: dict[str, Any] = {"agent_spec": spec.to_dict()}
        if adapter_name == "mcp":
            export_payload.update(
                {
                    "server_name": f"{spec.name}-server",
                    "server_version": "1.0.0",
                    "trust_profile_id": self._default_protocol_trust_profile_id(spec),
                }
            )

        export_result = adapter.execute_action(
            AdapterActionRequest(
                action_name=export_action,
                payload=export_payload,
            )
        )
        if not export_result.ok:
            return CompatibilityAdapterDecision(
                adapter_name=adapter_name,
                passed=False,
                reason="Export action failed.",
                export_ok=False,
                import_ok=False,
                required_fields_preserved=False,
                enforcement_ok=False,
                details={
                    "export_errors": [item.to_dict() for item in export_result.errors],
                },
            )

        export_payload = export_result.output.get(export_payload_key)
        import_result = adapter.execute_action(
            AdapterActionRequest(
                action_name=import_action,
                payload={import_payload_key: export_payload},
            )
        )
        if not import_result.ok:
            return CompatibilityAdapterDecision(
                adapter_name=adapter_name,
                passed=False,
                reason="Import action failed.",
                export_ok=True,
                import_ok=False,
                required_fields_preserved=False,
                enforcement_ok=False,
                details={
                    "import_errors": [item.to_dict() for item in import_result.errors],
                },
            )

        required_fields_preserved, field_details = self._compatibility_fields_preserved(
            spec=spec,
            export_output=export_result.output,
            import_output=import_result.output,
        )
        enforcement_ok = True
        enforcement_details: dict[str, Any] = {}
        if adapter_name == "mcp":
            enforcement_ok, enforcement_details = self._mcp_enforcement_preserved(
                import_output=import_result.output
            )
        details = dict(field_details)
        if enforcement_details:
            details["enforcement"] = enforcement_details
        if not required_fields_preserved:
            reason = "Required fields changed in adapter round trip."
        elif not enforcement_ok:
            reason = "Protocol adapter enforcement checks are advisory or incomplete."
        else:
            reason = ""
        return CompatibilityAdapterDecision(
            adapter_name=adapter_name,
            passed=required_fields_preserved and enforcement_ok,
            reason=reason,
            export_ok=True,
            import_ok=True,
            required_fields_preserved=required_fields_preserved,
            enforcement_ok=enforcement_ok,
            details=details,
        )

    def _compatibility_fields_preserved(
        self,
        spec: AgentSpec,
        export_output: dict[str, Any],
        import_output: dict[str, Any],
    ) -> tuple[bool, dict[str, Any]]:
        policy_hints = export_output.get("policy_hints")
        imported_tools = import_output.get("tools")
        data_scope_hints = import_output.get("data_scope_hints")

        policy_ok = isinstance(policy_hints, dict) and self._policy_hints_match_spec(
            spec=spec,
            policy_hints=policy_hints,
        )
        tools_ok = isinstance(imported_tools, list) and self._tools_match_spec(
            spec=spec,
            imported_tools=imported_tools,
        )
        scope_ok = isinstance(data_scope_hints, dict) and self._data_scope_hints_match_spec(
            spec=spec,
            data_scope_hints=data_scope_hints,
        )
        details = {
            "policy_hints_ok": policy_ok,
            "tools_ok": tools_ok,
            "data_scope_hints_ok": scope_ok,
            "expected_tool_count": len(spec.tools),
            "received_tool_count": len(imported_tools) if isinstance(imported_tools, list) else None,
        }
        return policy_ok and tools_ok and scope_ok, details

    def _policy_hints_match_spec(self, spec: AgentSpec, policy_hints: dict[str, Any]) -> bool:
        expected = {
            "risk_level": spec.risk_level,
            "runtime_environment": spec.runtime_environment,
            "max_runtime_seconds": spec.max_runtime_seconds,
            "budget_limit_usd": spec.budget_limit_usd,
            "read_paths": list(spec.data_scope.read_paths),
            "write_paths": list(spec.data_scope.write_paths),
            "allowed_hosts": list(spec.data_scope.allowed_hosts),
        }
        for key, value in expected.items():
            if policy_hints.get(key) != value:
                return False
        return True

    def _tools_match_spec(self, spec: AgentSpec, imported_tools: list[Any]) -> bool:
        if len(imported_tools) != len(spec.tools):
            return False
        for tool, imported in zip(spec.tools, imported_tools):
            if not isinstance(imported, dict):
                return False
            if imported.get("name") != tool.name:
                return False
            if imported.get("command") != tool.command:
                return False
            if bool(imported.get("can_write_files")) != tool.can_write_files:
                return False
            if bool(imported.get("can_access_network")) != tool.can_access_network:
                return False
            if int(imported.get("timeout_seconds", 0)) != tool.timeout_seconds:
                return False
        return True

    def _data_scope_hints_match_spec(
        self, spec: AgentSpec, data_scope_hints: dict[str, Any]
    ) -> bool:
        read_paths = data_scope_hints.get("read_paths")
        write_paths = data_scope_hints.get("write_paths")
        allowed_hosts = data_scope_hints.get("allowed_hosts")
        if not isinstance(read_paths, list) or not isinstance(write_paths, list):
            return False
        if not isinstance(allowed_hosts, list):
            return False
        return (
            sorted(str(item) for item in read_paths) == sorted(spec.data_scope.read_paths)
            and sorted(str(item) for item in write_paths) == sorted(spec.data_scope.write_paths)
            and sorted(str(item) for item in allowed_hosts) == sorted(spec.data_scope.allowed_hosts)
        )

    def _mcp_enforcement_preserved(
        self,
        *,
        import_output: dict[str, Any],
    ) -> tuple[bool, dict[str, Any]]:
        gating_payload = import_output.get("gating")
        if not isinstance(gating_payload, dict):
            return False, {
                "present": False,
                "reason": "missing gating payload",
            }

        required_true_fields = (
            "version_pinned",
            "trust_profile_required",
            "default_deny",
            "host_allow_list_required_for_network_tools",
            "startup_commands_blocked",
        )
        checks = {field: bool(gating_payload.get(field, False)) for field in required_true_fields}
        advisory_only = bool(gating_payload.get("advisory_only", True))
        enforcement_mode = str(gating_payload.get("enforcement_mode", "")).strip().lower()

        checks_pass = all(checks.values()) and (not advisory_only) and enforcement_mode == "enforced"
        return checks_pass, {
            "present": True,
            "checks": checks,
            "advisory_only": advisory_only,
            "enforcement_mode": enforcement_mode,
        }

    def _default_protocol_trust_profile_id(self, spec: AgentSpec) -> str:
        explicit = spec.live_data.trust_profile_id.strip()
        if explicit:
            return explicit
        profile_id = (spec.profile_id or "custom").strip() or "custom"
        return f"profile_{profile_id}"

    def _evaluate_adversarial_gate(
        self,
        spec: AgentSpec,
        verification_report: VerificationReport,
    ) -> AdversarialGateDecision:
        threshold = _RELEASE_ADVERSARIAL_THRESHOLD_BY_RISK[spec.risk_level]
        check = next(
            (item for item in verification_report.results if item.name == "adversarial_resilience"),
            None,
        )
        if check is None:
            return AdversarialGateDecision(
                required=True,
                passed=False,
                pass_rate=None,
                threshold=threshold,
                check_present=False,
            )

        match = _PASS_RATE_PATTERN.search(check.message)
        pass_rate = float(match.group(1)) if match else None
        passed = bool(check.passed and pass_rate is not None and pass_rate >= threshold)
        return AdversarialGateDecision(
            required=True,
            passed=passed,
            pass_rate=pass_rate,
            threshold=threshold,
            check_present=True,
        )


def default_release_workflow(
    evidence_path: str | Path,
    adapter_layer: LifeguardExtractsAdapterLayer | None = None,
    sigstore_command_runner: CommandRunner | None = None,
    intelligence_client: LiveIntelligenceClient | None = None,
) -> ReleaseWorkflow:
    return ReleaseWorkflow(
        evidence_store=EvidenceStore(evidence_path),
        adapter_layer=adapter_layer,
        sigstore_command_runner=sigstore_command_runner,
        intelligence_client=intelligence_client,
    )
