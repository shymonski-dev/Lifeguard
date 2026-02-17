from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


class SigstoreConfigurationError(ValueError):
    """Raised when Sigstore settings are missing or invalid."""


class SigstoreExecutionError(RuntimeError):
    """Raised when Sigstore command execution fails."""


@dataclass(frozen=True)
class SigstoreIdentityPolicy:
    repository: str
    workflow: str
    workflow_name: str
    certificate_oidc_issuer: str


@dataclass(frozen=True)
class SigstoreBundleReport:
    bundle_path: Path
    bundle_sha256: str
    transparency_log_entries: tuple[dict[str, Any], ...]
    identity_policy: SigstoreIdentityPolicy


CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def default_sigstore_command_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=False,
    )


def sigstore_available(
    *,
    command_runner: CommandRunner = default_sigstore_command_runner,
) -> bool:
    completed = command_runner(["sigstore", "--version"])
    return completed.returncode == 0


def sign_and_verify_bundle(
    *,
    artifact_path: str | Path,
    bundle_path: str | Path,
    repository: str,
    workflow: str,
    certificate_oidc_issuer: str = "https://token.actions.githubusercontent.com",
    command_runner: CommandRunner = default_sigstore_command_runner,
) -> SigstoreBundleReport:
    artifact = Path(artifact_path)
    if not artifact.exists():
        raise SigstoreConfigurationError(f"Sigstore artifact does not exist: {artifact}")

    bundle = Path(bundle_path)
    bundle.parent.mkdir(parents=True, exist_ok=True)

    policy = _build_identity_policy(
        repository=repository,
        workflow=workflow,
        certificate_oidc_issuer=certificate_oidc_issuer,
    )

    sign_command = ["sigstore", "sign", "--bundle", str(bundle), str(artifact)]
    signed = command_runner(sign_command)
    if signed.returncode != 0:
        raise SigstoreExecutionError(
            "Sigstore sign command failed. "
            f"exit_code={signed.returncode} stderr={signed.stderr.strip()}"
        )

    verify_command = [
        "sigstore",
        "verify",
        "github",
        "--bundle",
        str(bundle),
        "--repository",
        policy.repository,
        "--name",
        policy.workflow_name,
        str(artifact),
    ]
    verified = command_runner(verify_command)
    if verified.returncode != 0:
        raise SigstoreExecutionError(
            "Sigstore verify command failed. "
            f"exit_code={verified.returncode} stderr={verified.stderr.strip()}"
        )

    bundle_payload = _load_bundle_payload(bundle)
    entries = _extract_transparency_log_entries(bundle_payload)
    return SigstoreBundleReport(
        bundle_path=bundle,
        bundle_sha256=hashlib.sha256(bundle.read_bytes()).hexdigest(),
        transparency_log_entries=tuple(entries),
        identity_policy=policy,
    )


def verify_bundle(
    *,
    artifact_path: str | Path,
    bundle_path: str | Path,
    repository: str,
    workflow: str,
    workflow_name: str,
    certificate_oidc_issuer: str = "https://token.actions.githubusercontent.com",
    command_runner: CommandRunner = default_sigstore_command_runner,
) -> SigstoreBundleReport:
    artifact = Path(artifact_path)
    if not artifact.exists():
        raise SigstoreConfigurationError(f"Sigstore artifact does not exist: {artifact}")

    bundle = Path(bundle_path)
    if not bundle.exists():
        raise SigstoreConfigurationError(f"Sigstore bundle does not exist: {bundle}")

    policy = SigstoreIdentityPolicy(
        repository=repository.strip().strip("/"),
        workflow=str(workflow).strip(),
        workflow_name=str(workflow_name).strip(),
        certificate_oidc_issuer=str(certificate_oidc_issuer).strip()
        or "https://token.actions.githubusercontent.com",
    )
    if not policy.repository:
        raise SigstoreConfigurationError("Sigstore repository must not be empty.")
    if not policy.workflow_name:
        raise SigstoreConfigurationError("Sigstore workflow name must not be empty.")

    verify_command = [
        "sigstore",
        "verify",
        "github",
        "--bundle",
        str(bundle),
        "--repository",
        policy.repository,
        "--name",
        policy.workflow_name,
        str(artifact),
    ]
    verified = command_runner(verify_command)
    if verified.returncode != 0:
        raise SigstoreExecutionError(
            "Sigstore verify command failed. "
            f"exit_code={verified.returncode} stderr={verified.stderr.strip()}"
        )

    bundle_payload = _load_bundle_payload(bundle)
    entries = _extract_transparency_log_entries(bundle_payload)
    return SigstoreBundleReport(
        bundle_path=bundle,
        bundle_sha256=hashlib.sha256(bundle.read_bytes()).hexdigest(),
        transparency_log_entries=tuple(entries),
        identity_policy=policy,
    )


def _build_identity_policy(
    *,
    repository: str,
    workflow: str,
    certificate_oidc_issuer: str,
) -> SigstoreIdentityPolicy:
    repo = repository.strip().strip("/")
    flow = workflow.strip().strip("/")
    if not repo:
        raise SigstoreConfigurationError("Sigstore repository must not be empty.")
    if not flow:
        raise SigstoreConfigurationError("Sigstore workflow must not be empty.")
    if flow.endswith(".yml") or flow.endswith(".yaml"):
        workflow_path = flow
    elif "/" in flow:
        workflow_path = f"{flow}.yml"
    else:
        workflow_path = f".github/workflows/{flow}.yml"
    workflow_name = _workflow_name_from_file(workflow_path)
    if not workflow_name:
        workflow_name = Path(workflow_path).stem
    return SigstoreIdentityPolicy(
        repository=repo,
        workflow=workflow_path,
        workflow_name=workflow_name,
        certificate_oidc_issuer=certificate_oidc_issuer.strip()
        or "https://token.actions.githubusercontent.com",
    )


def _load_bundle_payload(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SigstoreExecutionError(f"Sigstore bundle file is missing: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SigstoreExecutionError(f"Sigstore bundle is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SigstoreExecutionError("Sigstore bundle payload must be an object.")
    return payload


def _extract_transparency_log_entries(bundle_payload: dict[str, Any]) -> list[dict[str, Any]]:
    verification_material = bundle_payload.get("verificationMaterial")
    if not isinstance(verification_material, dict):
        return []
    raw_entries = verification_material.get("tlogEntries")
    if not isinstance(raw_entries, list):
        return []

    entries: list[dict[str, Any]] = []
    for item in raw_entries:
        if not isinstance(item, dict):
            continue
        log_id = item.get("logId")
        log_key_id = ""
        if isinstance(log_id, dict):
            log_key_id = str(log_id.get("keyId", "")).strip()
        entries.append(
            {
                "log_index": item.get("logIndex"),
                "integrated_time": item.get("integratedTime"),
                "log_id_key_id": log_key_id,
                "kind_version": item.get("kindVersion"),
            }
        )
    return entries


def _workflow_name_from_file(workflow_path: str) -> str:
    path = Path(workflow_path)
    if not path.exists():
        return ""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return ""
    for line in text.splitlines():
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#"):
            continue
        if cleaned.lower().startswith("name:"):
            _, _, value = cleaned.partition(":")
            return value.strip().strip("'\"")
    return ""
