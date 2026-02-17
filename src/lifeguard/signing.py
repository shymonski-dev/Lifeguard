from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class SigningConfigurationError(ValueError):
    """Raised when signing key material is missing or invalid."""


@dataclass(frozen=True)
class SigningKey:
    key_id: str
    algorithm: str
    material: bytes


def load_signing_key(signing_key_file: str | Path | None = None) -> SigningKey:
    env_key = os.getenv("LIFEGUARD_SIGNING_KEY", "").strip()
    env_key_file = os.getenv("LIFEGUARD_SIGNING_KEY_FILE", "").strip()
    env_key_id = os.getenv("LIFEGUARD_SIGNING_KEY_ID", "").strip()

    key_file_path = Path(signing_key_file) if signing_key_file is not None else None
    if key_file_path is None and env_key_file:
        key_file_path = Path(env_key_file)

    if key_file_path is not None:
        if not key_file_path.exists():
            raise SigningConfigurationError(f"Signing key file not found: {key_file_path}")
        key_material = key_file_path.read_bytes().strip()
        if not key_material:
            raise SigningConfigurationError("Signing key file is empty.")
        key_id = env_key_id or key_file_path.name
    elif env_key:
        key_material = env_key.encode("utf-8")
        key_id = env_key_id or "env-lifeguard-signing-key"
    else:
        raise SigningConfigurationError(
            "No signing key configured. Set LIFEGUARD_SIGNING_KEY, "
            "set LIFEGUARD_SIGNING_KEY_FILE, or pass --signing-key-file."
        )

    if len(key_material) < 16:
        raise SigningConfigurationError("Signing key material must be at least 16 bytes.")

    return SigningKey(
        key_id=key_id,
        algorithm="hmac-sha256",
        material=key_material,
    )


def sign_payload(payload: dict[str, Any], key: SigningKey) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key.material, encoded, hashlib.sha256).hexdigest()


def verify_payload_signature(payload: dict[str, Any], signature: str, key: SigningKey) -> bool:
    expected = sign_payload(payload, key)
    return hmac.compare_digest(signature, expected)
