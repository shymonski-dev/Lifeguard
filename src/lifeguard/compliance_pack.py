from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .evidence_store import EvidenceStore
from .legislative_review import (
    LegislativeReviewError,
    load_json_file,
    resolve_legislative_review_artifacts,
    validate_legislative_decision,
)
from .owasp_controls import evaluate_control_matrix_file
from .release_anchor import compute_release_anchor_payload, sha256_file, sha256_json
from .sigstore_signing import (
    SigstoreConfigurationError,
    SigstoreExecutionError,
    default_sigstore_command_runner,
    sigstore_available,
    verify_bundle,
)
from .signing import SigningConfigurationError, load_signing_key, verify_payload_signature
from .spec_schema import AgentSpec
from .trust_source_profiles import default_trust_source_profile_path


class CompliancePackError(ValueError):
    """Raised when compliance pack creation or verification fails."""


@dataclass(frozen=True)
class CompliancePackBuildReport:
    pack_dir: Path
    manifest_path: Path
    artifact_count: int


@dataclass(frozen=True)
class CompliancePackVerificationReport:
    passed: bool
    checked_files: int
    failures: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "checked_files": self.checked_files,
            "failures": list(self.failures),
        }


def build_compliance_pack(
    *,
    spec: AgentSpec,
    release_dir: str | Path,
    evidence_path: str | Path,
    control_matrix_path: str | Path,
) -> CompliancePackBuildReport:
    output_dir = Path(release_dir)
    if not output_dir.exists():
        raise CompliancePackError(f"Release output directory does not exist: {output_dir}")

    release_manifest_source = output_dir / "release_manifest.json"
    release_anchor_source = output_dir / "release_anchor.json"
    badge_source = output_dir / "owasp_control_badge.json"
    if not release_manifest_source.exists():
        raise CompliancePackError(f"Release manifest file is missing: {release_manifest_source}")
    if not release_anchor_source.exists():
        raise CompliancePackError(f"Release anchor file is missing: {release_anchor_source}")
    if not badge_source.exists():
        raise CompliancePackError(f"Control badge file is missing: {badge_source}")

    try:
        manifest_payload = json.loads(release_manifest_source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CompliancePackError(f"Release manifest is not valid JSON: {exc}") from exc
    if not isinstance(manifest_payload, dict):
        raise CompliancePackError("Release manifest payload must be an object.")

    verification_block = manifest_payload.get("verification", {})
    evidence_last_hash = ""
    if isinstance(verification_block, dict):
        evidence_last_hash = str(verification_block.get("evidence_last_hash", "")).strip()

    pack_dir = output_dir / "compliance_pack"
    pack_dir.mkdir(parents=True, exist_ok=True)
    pack_manifest_path = pack_dir / "pack_manifest.json"

    artifacts: list[dict[str, Any]] = []

    def add_copy(*, src: Path, dst_rel: str) -> None:
        dst = pack_dir / dst_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())
        artifacts.append(
            {
                "path": dst_rel,
                "sha256": sha256_file(dst),
                "size_bytes": dst.stat().st_size,
            }
        )

    add_copy(src=release_manifest_source, dst_rel="release_manifest.json")
    add_copy(src=release_anchor_source, dst_rel="release_anchor.json")
    add_copy(src=badge_source, dst_rel="owasp_control_badge.json")

    matrix_source = Path(control_matrix_path)
    if not matrix_source.exists():
        raise CompliancePackError(f"Control matrix file is missing: {matrix_source}")
    add_copy(src=matrix_source, dst_rel="owasp_control_matrix.json")

    # Optional Sigstore artifacts, resolved from the manifest signature block when present.
    signature_block = manifest_payload.get("signature", {})
    if isinstance(signature_block, dict) and str(signature_block.get("algorithm", "")).strip() == "sigstore-bundle":
        payload_name = str(signature_block.get("payload_path", "")).strip() or "release_manifest_payload.json"
        bundle_name = str(signature_block.get("bundle_path", "")).strip() or "release_manifest.sigstore.bundle.json"

        payload_source = output_dir / Path(payload_name).name
        if payload_source.exists():
            add_copy(src=payload_source, dst_rel=payload_source.name)
        else:
            raise CompliancePackError(f"Sigstore payload file is missing: {payload_source}")

        bundle_source = Path(bundle_name)
        if not bundle_source.is_absolute():
            bundle_source = output_dir / bundle_source
        if bundle_source.exists():
            add_copy(src=bundle_source, dst_rel=Path(bundle_name).name)
        else:
            raise CompliancePackError(f"Sigstore bundle file is missing: {bundle_source}")

    # Spec snapshot.
    spec_path = pack_dir / "agent_spec.json"
    spec_path.write_text(json.dumps(spec.to_dict(), indent=2) + "\n", encoding="utf-8")
    artifacts.append(
        {
            "path": spec_path.name,
            "sha256": sha256_file(spec_path),
            "size_bytes": spec_path.stat().st_size,
        }
    )

    # Evidence snapshot: copy only up to the anchored evidence hash so the pack can be verified offline.
    evidence_source = Path(evidence_path)
    if not evidence_source.exists():
        raise CompliancePackError(f"Evidence log file is missing: {evidence_source}")
    pack_evidence_path = pack_dir / "evidence.jsonl"
    _write_evidence_snapshot(
        source_path=evidence_source,
        destination_path=pack_evidence_path,
        anchored_last_hash=evidence_last_hash,
    )
    artifacts.append(
        {
            "path": pack_evidence_path.name,
            "sha256": sha256_file(pack_evidence_path),
            "size_bytes": pack_evidence_path.stat().st_size,
        }
    )

    evidence_store = EvidenceStore(pack_evidence_path)
    chain_report = evidence_store.verify_chain()
    computed_last_hash = ""
    computed_last_hash_error = ""
    try:
        computed_last_hash = evidence_store.get_last_hash()
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        computed_last_hash_error = str(exc)
    chain_payload = {
        "passed": chain_report.passed,
        "record_count": chain_report.record_count,
        "failure_index": chain_report.failure_index,
        "failure_reason": chain_report.failure_reason,
        "anchored_last_hash": evidence_last_hash,
        "computed_last_hash": computed_last_hash,
        "computed_last_hash_error": computed_last_hash_error,
    }
    chain_path = pack_dir / "evidence_chain_verification.json"
    chain_path.write_text(json.dumps(chain_payload, indent=2) + "\n", encoding="utf-8")
    artifacts.append(
        {
            "path": chain_path.name,
            "sha256": sha256_file(chain_path),
            "size_bytes": chain_path.stat().st_size,
        }
    )
    if not chain_report.passed:
        raise CompliancePackError(
            "Evidence hash chain verification failed while building compliance pack."
        )
    if computed_last_hash_error:
        raise CompliancePackError(
            "Evidence last hash could not be computed while building compliance pack."
        )
    if evidence_last_hash and evidence_last_hash != computed_last_hash:
        raise CompliancePackError(
            "Evidence snapshot last hash does not match release anchor evidence hash."
        )

    # Trust profile snapshots.
    trust_dir = pack_dir / "trust_profiles"
    trust_dir.mkdir(parents=True, exist_ok=True)

    baseline_trust_profiles = default_trust_source_profile_path()
    trust_sources: list[tuple[str, Path]] = [("managed_trust_profiles.json", baseline_trust_profiles)]

    live_trust_used = bool(spec.live_data.enabled and spec.live_data.trust_profile_id.strip())
    legislative_trust_used = bool(spec.legislative_review.enabled)

    used_live_profiles = _resolve_trust_profile_path(spec.live_data.trust_profile_file or None) if live_trust_used else None
    if used_live_profiles is not None and used_live_profiles != baseline_trust_profiles:
        trust_sources.append(("live_data_trust_profiles.json", used_live_profiles))

    used_legislative_profiles = (
        _resolve_trust_profile_path(spec.legislative_review.trust_profile_file or None)
        if legislative_trust_used
        else None
    )
    if used_legislative_profiles is not None and used_legislative_profiles != baseline_trust_profiles:
        trust_sources.append(("legislative_review_trust_profiles.json", used_legislative_profiles))

    copied_trust_sources: set[str] = set()
    for dst_name, src_path in trust_sources:
        key = str(src_path)
        if key in copied_trust_sources:
            continue
        copied_trust_sources.add(key)
        if not src_path.exists():
            raise CompliancePackError(f"Trust profile file is missing: {src_path}")
        add_copy(src=src_path, dst_rel=str(Path("trust_profiles") / dst_name))

    # Legislative review artifacts are stored next to evidence.
    if spec.legislative_review.enabled:
        artifacts_paths = resolve_legislative_review_artifacts(spec=spec, evidence_path=evidence_source)
        if not artifacts_paths.pack_path.exists():
            raise CompliancePackError(
                f"Legislative review pack file is missing: {artifacts_paths.pack_path}"
            )
        add_copy(src=artifacts_paths.pack_path, dst_rel="legislative_review_pack.json")
        if spec.legislative_review.require_human_decision:
            if not artifacts_paths.decision_path.exists():
                raise CompliancePackError(
                    f"Legislative review decision file is missing: {artifacts_paths.decision_path}"
                )
            add_copy(src=artifacts_paths.decision_path, dst_rel="legislative_review_decision.json")

    manifest_metadata = {
        "version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "agent_name": spec.name,
        "spec_sha256": sha256_json(spec.to_dict()),
        "release_manifest_sha256": sha256_file(release_manifest_source),
        "release_anchor_sha256": sha256_file(release_anchor_source),
        "evidence_last_hash": evidence_last_hash,
        "artifacts": sorted(artifacts, key=lambda item: str(item.get("path", ""))),
    }
    pack_manifest_path.write_text(
        json.dumps(manifest_metadata, indent=2) + "\n", encoding="utf-8"
    )

    return CompliancePackBuildReport(
        pack_dir=pack_dir,
        manifest_path=pack_manifest_path,
        artifact_count=len(artifacts),
    )


def verify_compliance_pack(
    *,
    pack_dir: str | Path,
    signing_key_file: str | Path | None = None,
    sigstore_command_runner=default_sigstore_command_runner,
) -> CompliancePackVerificationReport:
    root = Path(pack_dir)
    failures: list[str] = []

    manifest_path = root / "pack_manifest.json"
    if not manifest_path.exists():
        return CompliancePackVerificationReport(
            passed=False,
            checked_files=0,
            failures=(f"pack_manifest.json is missing in {root}",),
        )

    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return CompliancePackVerificationReport(
            passed=False,
            checked_files=0,
            failures=(f"pack_manifest.json could not be read as JSON: {exc}",),
        )
    if not isinstance(payload, dict):
        return CompliancePackVerificationReport(
            passed=False,
            checked_files=0,
            failures=("pack_manifest.json must contain an object.",),
        )
    if int(payload.get("version", 0) or 0) != 1:
        return CompliancePackVerificationReport(
            passed=False,
            checked_files=0,
            failures=("Unsupported pack manifest version.",),
        )

    artifacts_payload = payload.get("artifacts", [])
    if not isinstance(artifacts_payload, list):
        return CompliancePackVerificationReport(
            passed=False,
            checked_files=0,
            failures=("pack_manifest.json artifacts must be a list.",),
        )

    checked_files = 0
    for item in artifacts_payload:
        if not isinstance(item, dict):
            failures.append("pack manifest artifact entry must be an object.")
            continue
        rel_path = str(item.get("path", "")).strip()
        expected_sha256 = str(item.get("sha256", "")).strip()
        if not rel_path:
            failures.append("pack manifest artifact path must not be empty.")
            continue
        target = root / rel_path
        if not target.exists():
            failures.append(f"Missing pack file: {rel_path}")
            continue
        checked_files += 1
        actual_sha256 = sha256_file(target)
        if expected_sha256 and actual_sha256 != expected_sha256:
            failures.append(f"Hash mismatch for {rel_path}")

    release_manifest_path = root / "release_manifest.json"
    release_anchor_path = root / "release_anchor.json"
    if not release_manifest_path.exists():
        failures.append("release_manifest.json is missing.")
    if not release_anchor_path.exists():
        failures.append("release_anchor.json is missing.")

    manifest: dict[str, Any] = {}
    if release_manifest_path.exists():
        try:
            raw_manifest = json.loads(release_manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            failures.append("release_manifest.json is not valid JSON.")
        else:
            if isinstance(raw_manifest, dict):
                manifest = raw_manifest
            else:
                failures.append("release_manifest.json must contain an object.")

    if release_anchor_path.exists() and release_manifest_path.exists() and manifest:
        try:
            computed_anchor = compute_release_anchor_payload(release_manifest_path)
            anchor_payload = json.loads(release_anchor_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            failures.append(f"Release anchor verification failed: {exc}")
        else:
            if not isinstance(anchor_payload, dict):
                failures.append("release_anchor.json must contain an object.")
            else:
                for key in (
                    "manifest_sha256",
                    "manifest_body_sha256",
                    "evidence_last_hash",
                    "evidence_path",
                    "repo_commit",
                ):
                    if anchor_payload.get(key) != computed_anchor.get(key):
                        failures.append(f"Release anchor mismatch for {key}")

    evidence_path = root / "evidence.jsonl"
    if evidence_path.exists() and manifest:
        evidence_store = EvidenceStore(evidence_path)
        chain_report = evidence_store.verify_chain()
        if not chain_report.passed:
            failures.append("Evidence hash chain verification failed.")
        anchored_hash = ""
        verification_block = manifest.get("verification", {})
        if isinstance(verification_block, dict):
            anchored_hash = str(verification_block.get("evidence_last_hash", "")).strip()
        last_hash = ""
        try:
            last_hash = evidence_store.get_last_hash()
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            failures.append(f"Evidence last hash could not be computed: {exc}")
        else:
            if anchored_hash and last_hash != anchored_hash:
                failures.append("Evidence last hash does not match release manifest evidence_last_hash.")
    elif not evidence_path.exists():
        failures.append("evidence.jsonl is missing.")

    if manifest:
        failures.extend(
            _verify_release_signature(
                root=root,
                manifest=manifest,
                signing_key_file=signing_key_file,
                sigstore_command_runner=sigstore_command_runner,
            )
        )
        failures.extend(_verify_control_matrix(root=root, manifest=manifest))
        failures.extend(_verify_legislative_review(root=root, manifest=manifest))

    return CompliancePackVerificationReport(
        passed=not failures,
        checked_files=checked_files,
        failures=tuple(failures),
    )


def _resolve_trust_profile_path(profile_file: str | Path | None) -> Path:
    raw_value = str(profile_file).strip() if profile_file is not None else ""
    if raw_value:
        resolved = Path(raw_value).expanduser()
    else:
        env_path = os.getenv("LIFEGUARD_TRUST_SOURCE_PROFILE_FILE", "").strip()
        if env_path:
            resolved = Path(env_path).expanduser()
        else:
            resolved = default_trust_source_profile_path()
    return resolved


def _write_evidence_snapshot(
    *,
    source_path: Path,
    destination_path: Path,
    anchored_last_hash: str,
) -> None:
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    if not anchored_last_hash or anchored_last_hash == "GENESIS":
        destination_path.write_text("", encoding="utf-8")
        return

    found = False
    with source_path.open("r", encoding="utf-8") as src, destination_path.open(
        "w", encoding="utf-8"
    ) as dst:
        for line in src:
            cleaned = line.strip()
            if not cleaned:
                continue
            dst.write(cleaned + "\n")
            try:
                record = json.loads(cleaned)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            record_hash = str(record.get("record_hash", "")).strip()
            if record_hash and record_hash == anchored_last_hash:
                found = True
                break
    if not found:
        raise CompliancePackError(
            "Anchored evidence hash was not found in the evidence log while building compliance pack."
        )


def _verify_release_signature(
    *,
    root: Path,
    manifest: dict[str, Any],
    signing_key_file: str | Path | None,
    sigstore_command_runner,
) -> list[str]:
    failures: list[str] = []
    signature_block = manifest.get("signature", {})
    if not isinstance(signature_block, dict):
        return ["Release manifest signature block is missing or invalid."]

    algorithm = str(signature_block.get("algorithm", "")).strip()
    if algorithm == "hmac-sha256":
        signature_value = str(signature_block.get("value", "")).strip()
        if not signature_value:
            return ["Key-based signature value is missing."]
        try:
            key = load_signing_key(signing_key_file)
        except SigningConfigurationError as exc:
            return [str(exc)]
        manifest_without_signature = dict(manifest)
        manifest_without_signature.pop("signature", None)
        if not verify_payload_signature(manifest_without_signature, signature_value, key):
            failures.append("Key-based release signature verification failed.")
        return failures

    if algorithm == "sigstore-bundle":
        payload_name = str(signature_block.get("payload_path", "")).strip() or "release_manifest_payload.json"
        bundle_name = str(signature_block.get("bundle_path", "")).strip() or "release_manifest.sigstore.bundle.json"
        repository = str(signature_block.get("repository", "")).strip()
        workflow = str(signature_block.get("workflow", "")).strip()
        workflow_name = str(signature_block.get("workflow_identity_name", "")).strip()
        issuer = str(signature_block.get("certificate_oidc_issuer", "")).strip()

        artifact_path = root / Path(payload_name).name
        bundle_path = root / Path(bundle_name).name
        if not artifact_path.exists():
            return [f"Sigstore payload file is missing: {artifact_path.name}"]
        if not bundle_path.exists():
            return [f"Sigstore bundle file is missing: {bundle_path.name}"]
        if not sigstore_available(command_runner=sigstore_command_runner):
            return ["Sigstore command is unavailable for verification."]
        try:
            verify_bundle(
                artifact_path=artifact_path,
                bundle_path=bundle_path,
                repository=repository,
                workflow=workflow,
                workflow_name=workflow_name,
                certificate_oidc_issuer=issuer,
                command_runner=sigstore_command_runner,
            )
        except (SigstoreConfigurationError, SigstoreExecutionError) as exc:
            failures.append(f"Sigstore release verification failed: {exc}")
        return failures

    return [f"Unsupported release signature algorithm: {algorithm!r}"]


def _verify_control_matrix(*, root: Path, manifest: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    matrix_path = root / "owasp_control_matrix.json"
    if not matrix_path.exists():
        return ["Control matrix file is missing."]

    summary = evaluate_control_matrix_file(matrix_path)
    expected = manifest.get("owasp_control_matrix", {})
    if not isinstance(expected, dict):
        failures.append("Release manifest control matrix block is missing or invalid.")
        return failures
    for key in ("passed", "coverage_percent", "required_count", "mapped_count", "framework_version"):
        if expected.get(key) != summary.to_dict().get(key):
            failures.append(f"Control matrix mismatch for {key}")
    return failures


def _verify_legislative_review(*, root: Path, manifest: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    legislative = manifest.get("legislative_review", {})
    if not isinstance(legislative, dict):
        return []
    if not bool(legislative.get("enabled", False)):
        return []

    pack_path = root / "legislative_review_pack.json"
    if not pack_path.exists():
        failures.append("Legislative review pack file is missing.")
    require_decision = bool(legislative.get("require_human_decision", False))
    if not require_decision:
        return failures

    decision_path = root / "legislative_review_decision.json"
    if not decision_path.exists():
        failures.append("Legislative review decision file is missing.")
        return failures

    agent_spec_payload = manifest.get("agent_spec", {})
    if not isinstance(agent_spec_payload, dict):
        failures.append("Release manifest agent_spec is missing or invalid.")
        return failures
    try:
        spec = AgentSpec.from_dict(agent_spec_payload)
    except ValueError as exc:
        failures.append(f"Release manifest agent_spec is invalid: {exc}")
        return failures

    try:
        raw_decision = load_json_file(decision_path)
        decision = validate_legislative_decision(
            payload=raw_decision,
            spec=spec,
            required_jurisdictions=tuple(spec.legal_context.jurisdictions),
        )
    except LegislativeReviewError as exc:
        failures.append(str(exc))
        return failures

    if decision.get("decision") != "accept":
        failures.append("Legislative review decision is not accept.")
    return failures
