from __future__ import annotations

import pytest

from lifeguard.signing import (
    SigningConfigurationError,
    load_signing_key,
    sign_payload,
    verify_payload_signature,
)


def test_load_signing_key_from_file(tmp_path) -> None:
    key_file = tmp_path / "signing.key"
    key_file.write_text("lifeguard-signing-key-material-123456789", encoding="utf-8")
    key = load_signing_key(key_file)
    assert key.algorithm == "hmac-sha256"
    assert key.key_id == "signing.key"
    assert len(key.material) >= 16


def test_sign_and_verify_payload(tmp_path) -> None:
    key_file = tmp_path / "signing.key"
    key_file.write_text("lifeguard-signing-key-material-123456789", encoding="utf-8")
    key = load_signing_key(key_file)
    payload = {"agent": "secure-review", "result": "pass"}
    signature = sign_payload(payload, key)
    assert verify_payload_signature(payload, signature, key) is True


def test_load_signing_key_raises_for_missing_configuration(monkeypatch) -> None:
    monkeypatch.delenv("LIFEGUARD_SIGNING_KEY", raising=False)
    monkeypatch.delenv("LIFEGUARD_SIGNING_KEY_FILE", raising=False)
    with pytest.raises(SigningConfigurationError):
        load_signing_key()


def test_load_signing_key_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("LIFEGUARD_SIGNING_KEY", "lifeguard-environment-key-123456")
    monkeypatch.setenv("LIFEGUARD_SIGNING_KEY_ID", "environment-key")
    key = load_signing_key()
    assert key.key_id == "environment-key"
    assert key.algorithm == "hmac-sha256"
    monkeypatch.delenv("LIFEGUARD_SIGNING_KEY", raising=False)
    monkeypatch.delenv("LIFEGUARD_SIGNING_KEY_ID", raising=False)
