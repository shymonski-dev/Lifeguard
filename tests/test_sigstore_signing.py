from __future__ import annotations

import json
import subprocess

import pytest

from lifeguard.sigstore_signing import (
    SigstoreConfigurationError,
    sign_and_verify_bundle,
    sigstore_available,
    verify_bundle,
)


def test_sigstore_sign_and_verify_bundle(tmp_path) -> None:
    artifact = tmp_path / "payload.json"
    artifact.write_text("{\"name\":\"lifeguard\"}\n", encoding="utf-8")
    bundle = tmp_path / "payload.sigstore.json"

    def _runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        if command[:3] == ["sigstore", "sign", "--bundle"]:
            bundle_payload = {
                "verificationMaterial": {
                    "tlogEntries": [
                        {
                            "logIndex": 7,
                            "integratedTime": 1_739_000_000,
                            "logId": {"keyId": "abc123"},
                            "kindVersion": "0.0.1",
                        }
                    ]
                }
            }
            bundle.write_text(json.dumps(bundle_payload), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="signed", stderr="")
        if command[:3] == ["sigstore", "verify", "github"]:
            return subprocess.CompletedProcess(command, 0, stdout="verified", stderr="")
        if command[:2] == ["sigstore", "--version"]:
            return subprocess.CompletedProcess(command, 0, stdout="sigstore 3.0.0", stderr="")
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="unexpected command")

    report = sign_and_verify_bundle(
        artifact_path=artifact,
        bundle_path=bundle,
        repository="acme/lifeguard",
        workflow=".github/workflows/release.yml",
        command_runner=_runner,
    )
    assert report.bundle_path == bundle
    assert len(report.bundle_sha256) == 64
    assert report.identity_policy.repository == "acme/lifeguard"
    assert report.identity_policy.workflow == ".github/workflows/release.yml"
    assert report.identity_policy.workflow_name == "release"
    assert report.transparency_log_entries[0]["log_index"] == 7


def test_sigstore_rejects_empty_identity_configuration(tmp_path) -> None:
    artifact = tmp_path / "payload.json"
    artifact.write_text("{\"name\":\"lifeguard\"}\n", encoding="utf-8")
    bundle = tmp_path / "payload.sigstore.json"

    with pytest.raises(SigstoreConfigurationError):
        sign_and_verify_bundle(
            artifact_path=artifact,
            bundle_path=bundle,
            repository="",
            workflow="release.yml",
            command_runner=lambda command: subprocess.CompletedProcess(command, 0, "", ""),
        )


def test_sigstore_available_uses_version_command() -> None:
    available = sigstore_available(
        command_runner=lambda command: subprocess.CompletedProcess(command, 0, "ok", "")
    )
    assert available is True
    unavailable = sigstore_available(
        command_runner=lambda command: subprocess.CompletedProcess(command, 1, "", "missing")
    )
    assert unavailable is False


def test_sigstore_verify_bundle(tmp_path) -> None:
    artifact = tmp_path / "payload.json"
    artifact.write_text("{\"name\":\"lifeguard\"}\n", encoding="utf-8")
    bundle = tmp_path / "payload.sigstore.json"
    bundle_payload = {
        "verificationMaterial": {
            "tlogEntries": [
                {
                    "logIndex": 11,
                    "integratedTime": 1_739_900_000,
                    "logId": {"keyId": "abc123"},
                    "kindVersion": "0.0.1",
                }
            ]
        }
    }
    bundle.write_text(json.dumps(bundle_payload), encoding="utf-8")

    def _runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        if command[:3] == ["sigstore", "verify", "github"]:
            return subprocess.CompletedProcess(command, 0, stdout="verified", stderr="")
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="unexpected command")

    report = verify_bundle(
        artifact_path=artifact,
        bundle_path=bundle,
        repository="acme/lifeguard",
        workflow=".github/workflows/release.yml",
        workflow_name="release",
        command_runner=_runner,
    )
    assert report.bundle_path == bundle
    assert len(report.bundle_sha256) == 64
    assert report.identity_policy.workflow_name == "release"
    assert report.transparency_log_entries[0]["log_index"] == 11
