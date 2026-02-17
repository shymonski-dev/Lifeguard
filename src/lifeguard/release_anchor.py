from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_json(payload: dict[str, Any]) -> str:
    return sha256_hex(json.dumps(payload, sort_keys=True).encode("utf-8"))


def sha256_file(path: Path) -> str:
    return sha256_hex(path.read_bytes())


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
    computed_body_sha256 = sha256_json(manifest_without_signature)
    if expected_body_sha256 and expected_body_sha256 != computed_body_sha256:
        raise ValueError("Manifest anchor body hash does not match computed manifest payload.")

    return {
        "created_at": manifest.get("created_at"),
        "manifest_path": target.name,
        "manifest_sha256": sha256_file(target),
        "manifest_body_sha256": expected_body_sha256 or computed_body_sha256,
        "evidence_last_hash": evidence_last_hash,
        "evidence_path": evidence_path,
        "repo_commit": repo_commit,
    }

