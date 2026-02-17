"""Security preflight checks for running tools in a workspace."""

from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Optional


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _is_path_under(path: Path, base: Path) -> bool:
    try:
        path.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def _is_ephemeral_path(path: Path) -> bool:
    if _env_bool("LIFEGUARD_EPHEMERAL", False) or _env_bool("LIFEGUARD_EPHEMERAL_OK", False):
        return True

    temp_root = Path(tempfile.gettempdir())
    if _is_path_under(path, temp_root):
        return True

    ephemeral_markers = {"tmp", "temp", "worktree", "worktrees", "ephemeral", "sandbox", "workspaces"}
    for part in path.parts:
        if part.lower() in ephemeral_markers:
            return True
    return False


def _enforce_ephemeral_repo(repo_path: Path) -> Optional[str]:
    if _env_bool("LIFEGUARD_ALLOW_NON_EPHEMERAL", False):
        return None
    if not _env_bool("LIFEGUARD_REQUIRE_EPHEMERAL", True):
        return None
    if _is_ephemeral_path(repo_path):
        return None
    return (
        "Refusing to run on a non-ephemeral repo. Use a disposable clone or worktree "
        "or set LIFEGUARD_ALLOW_NON_EPHEMERAL=1 to override."
    )


def _build_secret_scan_cmd(repo_path: Path) -> list[str]:
    tool = os.getenv("LIFEGUARD_SECRET_SCAN_TOOL", "git-secrets").strip()
    args = os.getenv("LIFEGUARD_SECRET_SCAN_ARGS", "").strip()
    if args:
        formatted = args.replace("{repo}", str(repo_path))
        return [tool] + shlex.split(formatted)
    if tool == "git-secrets":
        return [tool, "--scan", "-r", str(repo_path)]
    if tool == "trufflehog":
        return [tool, "filesystem", "--directory", str(repo_path), "--fail"]
    return [tool, str(repo_path)]


def _run_secret_scan(repo_path: Path) -> Optional[str]:
    if not _env_bool("LIFEGUARD_SECRET_SCAN", True):
        return None

    cmd = _build_secret_scan_cmd(repo_path)
    try:
        result = subprocess.run(
            cmd,
            cwd=str(repo_path),
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        if _env_bool("LIFEGUARD_SECRET_SCAN_ALLOW_MISSING", True):
            return None
        return f"Secret scan tool not found: {cmd[0]}"
    except Exception as exc:  # pragma: no cover
        return f"Secret scan failed to start: {exc}"

    if result.returncode == 0:
        return None

    output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
    output = output.strip()
    if len(output) > 1200:
        output = output[:1200] + "... (truncated)"
    return (
        f"Secret scan failed (tool={cmd[0]}, exit={result.returncode}). "
        f"Potential secrets detected or scan error.\n{output}"
    )


def run_preflight(repo_path: Optional[Path]) -> Optional[str]:
    """Run preflight checks. Return an error string if blocked."""
    if repo_path is None:
        return None

    error = _enforce_ephemeral_repo(repo_path)
    if error:
        return error

    error = _run_secret_scan(repo_path)
    if error:
        return error

    return None

