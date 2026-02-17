#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

STAGES = tuple(f"stage-{index}" for index in range(0, 7))
OPEN_SOURCE_GUARD_ENV_VARS = (
    "LANGSMITH_API_KEY",
    "LANGCHAIN_API_KEY",
    "LANGSMITH_ENDPOINT",
    "LANGCHAIN_ENDPOINT",
    "LANGCHAIN_TRACING_V2",
    "LANGSMITH_TRACING",
)
PROVIDER_KEY_BY_NAME = {
    "openrouter": "OPENROUTER_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}
DEFAULT_MODEL_BY_PROVIDER = {
    "openrouter": "openai/gpt-5.2:online",
    "openai": "gpt-4.1",
    "anthropic": "claude-3-5-sonnet-latest",
}
BUDGET_CAP_BY_RISK = {"low": 500.0, "medium": 250.0, "high": 100.0}
CONTAINER_IMAGE = os.getenv(
    "LIFEGUARD_STAGE1_CONTAINER_IMAGE",
    "cgr.dev/chainguard/python:latest-dev",
)
DEFAULT_HARDENED_IMAGE_PREFIXES = ("cgr.dev/chainguard/",)


@dataclass(frozen=True)
class CommandResult:
    command: list[str]
    return_code: int
    stdout: str
    stderr: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "return_code": self.return_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


def run_command(command: list[str], cwd: Path, env: dict[str, str] | None = None) -> CommandResult:
    completed = subprocess.run(
        command,
        cwd=str(cwd),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    return CommandResult(
        command=command,
        return_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _sanitize_text(text: str, roots: tuple[Path, ...]) -> str:
    sanitized = text
    resolved_roots = sorted(
        (root.resolve() for root in roots),
        key=lambda item: len(str(item)),
        reverse=True,
    )
    for root in resolved_roots:
        root_str = str(root)
        root_with_sep = root_str + os.sep
        if root_with_sep in sanitized:
            sanitized = sanitized.replace(root_with_sep, "")
        if root_str in sanitized:
            sanitized = sanitized.replace(root_str, "<repo>")
    return sanitized


def _sanitize_payload(value: Any, roots: tuple[Path, ...]) -> Any:
    if isinstance(value, dict):
        return {str(k): _sanitize_payload(v, roots) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_payload(v, roots) for v in value]
    if isinstance(value, tuple):
        return [_sanitize_payload(v, roots) for v in value]
    if isinstance(value, Path):
        return _sanitize_text(str(value), roots)
    if isinstance(value, str):
        return _sanitize_text(value, roots)
    return value


def _lifeguard_env(project_root: Path) -> dict[str, str]:
    env = dict(os.environ)
    python_path = str(project_root / "src")
    existing_python_path = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        f"{python_path}{os.pathsep}{existing_python_path}" if existing_python_path else python_path
    )
    for key in OPEN_SOURCE_GUARD_ENV_VARS:
        env.pop(key, None)
    return env


def _container_env_args(env: dict[str, str]) -> list[str]:
    passthrough_keys = (
        "OPENROUTER_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "LIFEGUARD_OPENROUTER_BASE_URL",
        "LIFEGUARD_OPENAI_BASE_URL",
        "LIFEGUARD_ANTHROPIC_BASE_URL",
        "LIFEGUARD_OPENAI_WEB_TOOL_TYPE",
        "LIFEGUARD_ANTHROPIC_WEB_TOOL_TYPE",
        "LIFEGUARD_OPENAI_SEARCH_CONTEXT_SIZE",
    )
    args: list[str] = []
    for key in passthrough_keys:
        value = env.get(key, "")
        if value:
            # Use pass-through form so secret values are not recorded in command logs.
            args.extend(["-e", key])
    return args


def _stage_one_provider_settings(env: dict[str, str]) -> dict[str, Any]:
    provider = os.getenv("LIFEGUARD_STAGE1_PROVIDER", "openrouter").strip().lower()
    if provider not in PROVIDER_KEY_BY_NAME:
        return {
            "provider": provider,
            "model": "",
            "key_name": "",
            "key_present": False,
            "error": (
                "LIFEGUARD_STAGE1_PROVIDER must be one of "
                f"{sorted(PROVIDER_KEY_BY_NAME.keys())}."
            ),
        }
    key_name = PROVIDER_KEY_BY_NAME[provider]
    key_present = bool(env.get(key_name, "").strip())
    model = os.getenv("LIFEGUARD_STAGE1_MODEL", "").strip() or DEFAULT_MODEL_BY_PROVIDER[provider]
    if not key_present:
        return {
            "provider": provider,
            "model": model,
            "key_name": key_name,
            "key_present": False,
            "error": f"{key_name} is required for stage one live intelligence validation.",
        }
    return {
        "provider": provider,
        "model": model,
        "key_name": key_name,
        "key_present": True,
        "error": "",
    }


def _update_spec_live_data_provider(spec_path: Path, provider: str, model: str, risk_level: str) -> None:
    payload = json.loads(spec_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Specification root must be an object.")
    live_data_payload = payload.get("live_data")
    if not isinstance(live_data_payload, dict):
        raise ValueError("Specification live_data must be an object.")

    live_data_payload["enabled"] = True
    live_data_payload["provider"] = provider
    live_data_payload["model"] = model
    if not str(live_data_payload.get("query", "")).strip():
        live_data_payload["query"] = "latest secure agent design patterns and risk controls"

    payload["live_data"] = live_data_payload
    budget_cap = BUDGET_CAP_BY_RISK.get(risk_level)
    if budget_cap is not None:
        current_budget = float(payload.get("budget_limit_usd", budget_cap))
        payload["budget_limit_usd"] = min(current_budget, budget_cap)
    spec_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            cleaned = line.strip()
            if not cleaned:
                continue
            try:
                parsed = json.loads(cleaned)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                records.append(parsed)
    return records


def _live_intelligence_event_summary(evidence_path: Path) -> dict[str, Any]:
    records = _read_jsonl(evidence_path)
    candidate: dict[str, Any] | None = None
    for record in records:
        if record.get("event_type") == "live_intelligence_freshness":
            candidate = record
    if candidate is None:
        return {
            "found": False,
            "passed": False,
            "citation_count": 0,
            "trust_assessment_present": False,
            "details": {},
            "reason": "live_intelligence_freshness event is missing.",
        }

    details = candidate.get("details")
    if not isinstance(details, dict):
        details = {}
    attempts_payload = details.get("attempts")
    attempts: list[dict[str, Any]] = []
    if isinstance(attempts_payload, list):
        for item in attempts_payload:
            if not isinstance(item, dict):
                continue
            attempts.append(
                {
                    "attempt_number": _coerce_int(item.get("attempt_number")),
                    "model": str(item.get("model", "")),
                    "query_variant": str(item.get("query_variant", "")),
                    "citation_count": _coerce_int(item.get("citation_count")),
                    "assessment_passed": bool(item.get("assessment_passed", False)),
                    "failure": str(item.get("failure", "")),
                }
            )

    citation_count = _coerce_int(details.get("citation_count", 0))
    if citation_count < 1 and attempts:
        citation_count = _coerce_int(attempts[-1].get("citation_count", 0))
    trust_assessment_present = isinstance(details.get("trust_assessment"), dict)
    passed = str(candidate.get("status", "")).lower() == "pass"
    reason = ""
    if not passed:
        reason = "Live intelligence event status is not pass."
    elif citation_count < 1:
        reason = "Live intelligence citation_count is less than 1."
    elif not trust_assessment_present:
        reason = "Live intelligence trust_assessment is missing."
    return {
        "found": True,
        "passed": passed and citation_count > 0 and trust_assessment_present,
        "citation_count": citation_count,
        "trust_assessment_present": trust_assessment_present,
        "attempt_count": len(attempts),
        "attempts": attempts,
        "details": details,
        "reason": reason,
    }


def _release_manifest_summary(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"exists": False, "verification_passed": False, "runtime_mode": "", "reason": "missing"}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return {
            "exists": True,
            "verification_passed": False,
            "runtime_mode": "",
            "reason": "invalid release manifest payload type",
        }
    verification = payload.get("verification")
    runtime = payload.get("runtime")
    verification_passed = bool(verification.get("passed")) if isinstance(verification, dict) else False
    runtime_mode = str(runtime.get("mode", "")) if isinstance(runtime, dict) else ""
    return {
        "exists": True,
        "verification_passed": verification_passed,
        "runtime_mode": runtime_mode,
        "reason": "",
    }


def _coerce_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _docker_available(project_root: Path) -> tuple[bool, str]:
    docker_version = run_command(["docker", "--version"], cwd=project_root)
    if docker_version.return_code != 0:
        return False, "docker command is unavailable."
    docker_info = run_command(["docker", "info"], cwd=project_root)
    if docker_info.return_code != 0:
        return False, "docker daemon is unavailable."
    return True, ""


def _container_image_policy(image_name: str) -> dict[str, Any]:
    allow_non_hardened = os.getenv("LIFEGUARD_ALLOW_UNHARDENED_IMAGE", "").strip() == "1"
    configured_prefixes = os.getenv(
        "LIFEGUARD_HARDENED_IMAGE_PREFIXES",
        ",".join(DEFAULT_HARDENED_IMAGE_PREFIXES),
    ).strip()
    prefixes = tuple(
        item.strip()
        for item in configured_prefixes.split(",")
        if item.strip()
    )
    if not prefixes:
        prefixes = DEFAULT_HARDENED_IMAGE_PREFIXES

    cleaned_image_name = image_name.strip()
    matched_prefix = next(
        (prefix for prefix in prefixes if cleaned_image_name.startswith(prefix)),
        "",
    )
    if allow_non_hardened:
        return {
            "passed": True,
            "image": cleaned_image_name,
            "matched_prefix": matched_prefix,
            "allowed_prefixes": list(prefixes),
            "override_enabled": True,
            "reason": "Container image policy override is enabled.",
        }
    if not cleaned_image_name:
        return {
            "passed": False,
            "image": cleaned_image_name,
            "matched_prefix": "",
            "allowed_prefixes": list(prefixes),
            "override_enabled": False,
            "reason": "Container image is empty.",
        }
    if matched_prefix:
        return {
            "passed": True,
            "image": cleaned_image_name,
            "matched_prefix": matched_prefix,
            "allowed_prefixes": list(prefixes),
            "override_enabled": False,
            "reason": "",
        }
    return {
        "passed": False,
        "image": cleaned_image_name,
        "matched_prefix": "",
        "allowed_prefixes": list(prefixes),
        "override_enabled": False,
        "reason": (
            "Container image policy failed. Configure a hardened minimal image with one of "
            f"the allowed prefixes: {sorted(prefixes)}."
        ),
    }


def _parse_json_stdout(result: CommandResult) -> dict[str, Any] | None:
    stdout = result.stdout.strip()
    if not stdout:
        return None
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _event_exists(evidence_path: Path, event_type: str) -> bool:
    records = _read_jsonl(evidence_path)
    return any(record.get("event_type") == event_type for record in records)


def _run_stage_one_combination(
    *,
    project_root: Path,
    base_env: dict[str, str],
    environment_item: dict[str, Any],
    risk: str,
    spec_path: Path,
    signing_key_path: Path,
    runs_path: Path,
    attempt_label: str = "primary",
) -> dict[str, Any]:
    environment_name = str(environment_item["name"])
    run_dir = runs_path / environment_name / risk
    if attempt_label != "primary":
        run_dir = run_dir / attempt_label
    run_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = run_dir / "evidence.jsonl"
    release_output = run_dir / "release"
    verify_result: CommandResult
    release_result: CommandResult
    approval_id = f"stage1-{environment_name}-{risk}"
    if attempt_label != "primary":
        approval_id = f"{approval_id}-{attempt_label}"

    if environment_item["kind"] == "host":
        env = dict(base_env)
        env.update({str(key): str(value) for key, value in environment_item["extra_env"].items()})

        verify_command = [
            sys.executable,
            "-m",
            "lifeguard",
            "verify",
            "--spec",
            str(spec_path),
            "--evidence",
            str(evidence_path),
        ]
        release_command = [
            sys.executable,
            "-m",
            "lifeguard",
            "release",
            "--spec",
            str(spec_path),
            "--evidence",
            str(evidence_path),
            "--output",
            str(release_output),
            "--approved-by",
            "stage-one-validator",
            "--approval-id",
            approval_id,
            "--signing-key-file",
            str(signing_key_path),
        ]
        verify_result = run_command(verify_command, cwd=project_root, env=env)
        if verify_result.return_code == 0:
            release_result = run_command(release_command, cwd=project_root, env=env)
        else:
            release_result = CommandResult(
                command=release_command,
                return_code=1,
                stdout="",
                stderr="release skipped because verify failed",
            )
    else:
        workspace_root = project_root.parent
        container_spec = f"/workspace/lifeguard/{spec_path.relative_to(project_root)}"
        container_evidence = f"/workspace/lifeguard/{evidence_path.relative_to(project_root)}"
        container_release_output = f"/workspace/lifeguard/{release_output.relative_to(project_root)}"
        container_signing_key = f"/workspace/lifeguard/{signing_key_path.relative_to(project_root)}"
        docker_env_args = _container_env_args(base_env)
        verify_command = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{workspace_root}:/workspace",
            "-w",
            "/workspace/lifeguard",
            *docker_env_args,
            "-e",
            "PYTHONPATH=/workspace/lifeguard/src",
            CONTAINER_IMAGE,
            "-m",
            "lifeguard",
            "verify",
            "--spec",
            container_spec,
            "--evidence",
            container_evidence,
        ]
        release_command = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{workspace_root}:/workspace",
            "-w",
            "/workspace/lifeguard",
            *docker_env_args,
            "-e",
            "PYTHONPATH=/workspace/lifeguard/src",
            CONTAINER_IMAGE,
            "-m",
            "lifeguard",
            "release",
            "--spec",
            container_spec,
            "--evidence",
            container_evidence,
            "--output",
            container_release_output,
            "--approved-by",
            "stage-one-validator",
            "--approval-id",
            approval_id,
            "--signing-key-file",
            container_signing_key,
        ]
        verify_result = run_command(verify_command, cwd=project_root, env=base_env)
        if verify_result.return_code == 0:
            release_result = run_command(release_command, cwd=project_root, env=base_env)
        else:
            release_result = CommandResult(
                command=release_command,
                return_code=1,
                stdout="",
                stderr="release skipped because verify failed",
            )

    live_summary = _live_intelligence_event_summary(evidence_path)
    manifest_summary = _release_manifest_summary(release_output / "release_manifest.json")
    run_passed = (
        verify_result.return_code == 0
        and release_result.return_code == 0
        and live_summary["passed"]
        and manifest_summary["verification_passed"]
    )
    payload = {
        "environment": environment_name,
        "risk": risk,
        "status": "pass" if run_passed else "fail",
        "reason": "" if run_passed else "One or more checks failed.",
        "spec_path": str(spec_path),
        "evidence_path": str(evidence_path),
        "release_manifest_path": str(release_output / "release_manifest.json"),
        "verify_command": verify_result.to_dict(),
        "release_command": release_result.to_dict(),
        "live_intelligence": live_summary,
        "release_manifest": manifest_summary,
    }
    if attempt_label != "primary":
        payload["attempt_label"] = attempt_label
    return payload


def _stage_one_transient_zero_citation_candidate(run_results: list[dict[str, Any]]) -> int | None:
    failed_indices = [
        index for index, result in enumerate(run_results) if str(result.get("status", "")) != "pass"
    ]
    if len(failed_indices) != 1:
        return None
    candidate_index = failed_indices[0]
    candidate = run_results[candidate_index]
    if str(candidate.get("environment", "")) != "container":
        return None
    if str(candidate.get("risk", "")) != "high":
        return None
    live_intelligence = candidate.get("live_intelligence")
    if not isinstance(live_intelligence, dict):
        return None
    if not bool(live_intelligence.get("found", False)):
        return None
    if _coerce_int(live_intelligence.get("citation_count", 0)) != 0:
        return None
    return candidate_index


def _required_stage_two_fields_match(
    spec_payload: dict[str, Any],
    export_payload: dict[str, Any],
    import_payload: dict[str, Any],
) -> tuple[bool, dict[str, bool]]:
    data_scope = spec_payload.get("data_scope", {})
    expected_policy_fields = {
        "risk_level": spec_payload.get("risk_level"),
        "runtime_environment": spec_payload.get("runtime_environment"),
        "read_paths": data_scope.get("read_paths", []),
        "write_paths": data_scope.get("write_paths", []),
        "allowed_hosts": data_scope.get("allowed_hosts", []),
        "max_runtime_seconds": spec_payload.get("max_runtime_seconds"),
        "budget_limit_usd": spec_payload.get("budget_limit_usd"),
    }
    policy_hints = export_payload.get("policy_hints", {})
    policy_fields_match = isinstance(policy_hints, dict) and all(
        policy_hints.get(field_name) == expected_value
        for field_name, expected_value in expected_policy_fields.items()
    )

    expected_tools = spec_payload.get("tools", [])
    imported_tools = import_payload.get("tools", [])
    imported_tools_match = isinstance(imported_tools, list) and imported_tools == expected_tools

    expected_scope = {
        "read_paths": sorted(str(item) for item in data_scope.get("read_paths", [])),
        "write_paths": sorted(str(item) for item in data_scope.get("write_paths", [])),
        "allowed_hosts": sorted(str(item) for item in data_scope.get("allowed_hosts", [])),
    }
    imported_scope = import_payload.get("data_scope_hints", {})
    imported_scope_match = (
        isinstance(imported_scope, dict)
        and sorted(str(item) for item in imported_scope.get("read_paths", []))
        == expected_scope["read_paths"]
        and sorted(str(item) for item in imported_scope.get("write_paths", []))
        == expected_scope["write_paths"]
        and sorted(str(item) for item in imported_scope.get("allowed_hosts", []))
        == expected_scope["allowed_hosts"]
    )

    details = {
        "policy_fields_match": policy_fields_match,
        "imported_tools_match": imported_tools_match,
        "imported_scope_match": imported_scope_match,
    }
    return all(details.values()), details


def _latest_event(evidence_path: Path, event_type: str) -> dict[str, Any] | None:
    records = _read_jsonl(evidence_path)
    candidate: dict[str, Any] | None = None
    for record in records:
        if record.get("event_type") == event_type:
            candidate = record
    return candidate


def _adversarial_event_summary(evidence_path: Path) -> dict[str, Any]:
    candidate = _latest_event(evidence_path=evidence_path, event_type="adversarial_resilience")
    if candidate is None:
        return {
            "found": False,
            "passed": False,
            "pass_rate": None,
            "threshold": None,
            "reason": "adversarial_resilience event is missing.",
        }
    details = candidate.get("details")
    if not isinstance(details, dict):
        details = {}
    status_pass = str(candidate.get("status", "")).lower() == "pass"
    pass_rate = details.get("pass_rate")
    threshold = details.get("threshold")
    parsed_pass_rate = float(pass_rate) if pass_rate is not None else None
    parsed_threshold = float(threshold) if threshold is not None else None
    computed_pass = bool(
        status_pass
        and parsed_pass_rate is not None
        and parsed_threshold is not None
        and parsed_pass_rate >= parsed_threshold
    )
    reason = ""
    if not status_pass:
        reason = "adversarial_resilience status is not pass."
    elif parsed_pass_rate is None or parsed_threshold is None:
        reason = "adversarial_resilience details missing pass_rate or threshold."
    elif parsed_pass_rate < parsed_threshold:
        reason = "adversarial_resilience pass_rate is below threshold."
    return {
        "found": True,
        "passed": computed_pass,
        "pass_rate": parsed_pass_rate,
        "threshold": parsed_threshold,
        "reason": reason,
    }

def stage_directory_map(validation_root: Path) -> dict[str, Path]:
    return {stage: validation_root / stage for stage in STAGES}


def ensure_stage_directories(validation_root: Path) -> dict[str, Path]:
    mapping = stage_directory_map(validation_root)
    validation_root.mkdir(parents=True, exist_ok=True)
    for directory in mapping.values():
        directory.mkdir(parents=True, exist_ok=True)
    return mapping


def git_info(project_root: Path) -> dict[str, Any]:
    commit = run_command(["git", "rev-parse", "HEAD"], cwd=project_root)
    branch = run_command(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=project_root)
    # Limit output to this project folder to avoid leaking sibling project paths.
    status = run_command(["git", "status", "--short", "--", "."], cwd=project_root)
    return {
        "commit": commit.stdout.strip(),
        "branch": branch.stdout.strip(),
        "dirty": bool(status.stdout.strip()),
        "status_short": status.stdout.strip().splitlines(),
        "commands": {
            "commit": commit.to_dict(),
            "branch": branch.to_dict(),
            "status": status.to_dict(),
        },
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def write_report_json(path: Path, payload: dict[str, Any], roots: tuple[Path, ...]) -> None:
    write_json(path, dict(_sanitize_payload(payload, roots)))


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_report_text(path: Path, text: str, roots: tuple[Path, ...]) -> None:
    write_text(path, _sanitize_text(text, roots))


def stage_zero(project_root: Path, validation_root: Path) -> dict[str, Any]:
    stage_path = validation_root / "stage-0"
    stage_started = now_iso()
    roots = (project_root, project_root.parent)

    base_env = _lifeguard_env(project_root)

    test_result = run_command([sys.executable, "-m", "pytest", "-q", "tests"], cwd=project_root, env=base_env)
    profiles_result = run_command([sys.executable, "-m", "lifeguard", "profiles"], cwd=project_root, env=base_env)

    baseline_payload: dict[str, Any] = {
        "stage": "stage-0",
        "created_at": now_iso(),
        "project_root": str(project_root),
        "python_version": sys.version,
        "git": git_info(project_root),
        "checks": {
            "tests": test_result.to_dict(),
            "profiles_command": profiles_result.to_dict(),
        },
    }
    write_report_json(stage_path / "baseline_report.json", baseline_payload, roots)

    passed = test_result.return_code == 0 and profiles_result.return_code == 0
    summary_lines = [
        "Stage zero summary",
        f"started_at: {stage_started}",
        f"finished_at: {now_iso()}",
        f"tests_passed: {test_result.return_code == 0}",
        f"profiles_command_passed: {profiles_result.return_code == 0}",
        f"baseline_report: {stage_path / 'baseline_report.json'}",
    ]
    write_report_text(stage_path / "summary.txt", "\n".join(summary_lines) + "\n", roots)

    signoff_payload = {
        "stage": "stage-0",
        "signed_at": now_iso(),
        "passed": passed,
        "criteria": {
            "tests_passed": test_result.return_code == 0,
            "baseline_report_exists": (stage_path / "baseline_report.json").exists(),
            "summary_exists": (stage_path / "summary.txt").exists(),
            "stage_folders_exist": all((validation_root / stage).exists() for stage in STAGES),
        },
    }
    write_report_json(stage_path / "stage_signoff.json", signoff_payload, roots)

    status = "pass" if passed and all(signoff_payload["criteria"].values()) else "fail"
    return {
        "stage": "stage-0",
        "status": status,
        "stage_path": str(stage_path),
        "baseline_report": str(stage_path / "baseline_report.json"),
        "summary_file": str(stage_path / "summary.txt"),
        "signoff_file": str(stage_path / "stage_signoff.json"),
    }


def stage_one(project_root: Path, validation_root: Path) -> dict[str, Any]:
    stage_path = validation_root / "stage-1"
    stage_started = now_iso()
    roots = (project_root, project_root.parent)
    base_env = _lifeguard_env(project_root)
    provider_settings = _stage_one_provider_settings(base_env)

    specs_path = stage_path / "specs"
    runs_path = stage_path / "runs"
    specs_path.mkdir(parents=True, exist_ok=True)
    runs_path.mkdir(parents=True, exist_ok=True)

    profile_matrix = (
        {"risk": "low", "profile": "secure_code_review", "name": "stage1-low-risk-agent", "risk_level": "low"},
        {
            "risk": "medium",
            "profile": "dependency_audit",
            "name": "stage1-medium-risk-agent",
            "risk_level": "medium",
        },
        {
            "risk": "high",
            "profile": "runtime_threat_hunting",
            "name": "stage1-high-risk-agent",
            "risk_level": "high",
        },
    )

    spec_build_results: list[dict[str, Any]] = []
    spec_paths_by_risk: dict[str, Path] = {}
    for item in profile_matrix:
        target = specs_path / f"{item['risk']}_{item['profile']}.json"
        init_command = [
            sys.executable,
            "-m",
            "lifeguard",
            "init",
            "--path",
            str(target),
            "--force",
            "--profile",
            item["profile"],
            "--name",
            item["name"],
            "--risk-level",
            item["risk_level"],
            "--runtime-environment",
            "container",
        ]
        init_result = run_command(init_command, cwd=project_root, env=base_env)
        update_error = ""
        provider_for_spec = str(provider_settings.get("provider", "openrouter")).strip().lower()
        if provider_for_spec not in PROVIDER_KEY_BY_NAME:
            provider_for_spec = "openrouter"
        model_for_spec = str(provider_settings.get("model", "")).strip() or DEFAULT_MODEL_BY_PROVIDER[
            provider_for_spec
        ]
        if init_result.return_code == 0:
            try:
                _update_spec_live_data_provider(
                    target,
                    provider=provider_for_spec,
                    model=model_for_spec,
                    risk_level=str(item["risk_level"]),
                )
            except Exception as exc:  # pragma: no cover - defensive safeguard
                update_error = str(exc)
        if init_result.return_code == 0 and not update_error:
            spec_paths_by_risk[item["risk"]] = target
        spec_build_results.append(
            {
                "risk": item["risk"],
                "profile": item["profile"],
                "target": str(target),
                "init_command": init_result.to_dict(),
                "provider_update_error": update_error,
            }
        )

    signing_key_path = stage_path / "stage1_signing.key"
    write_text(signing_key_path, "stage-one-signing-key-material-abcdefghijklmnopqrstuvwxyz\n")

    docker_available, docker_reason = _docker_available(project_root)
    container_image_policy = _container_image_policy(CONTAINER_IMAGE)
    environment_matrix = (
        {"name": "local", "kind": "host", "extra_env": {}},
        {
            "name": "continuous_integration",
            "kind": "host",
            "extra_env": {"CI": "true", "GITHUB_ACTIONS": "true"},
        },
        {"name": "container", "kind": "container", "extra_env": {}},
    )

    run_results: list[dict[str, Any]] = []
    for environment_item in environment_matrix:
        environment_name = str(environment_item["name"])
        if environment_item["kind"] == "container" and not bool(container_image_policy.get("passed", False)):
            image_policy_reason = str(container_image_policy.get("reason", "Container image policy failed."))
            for risk in ("low", "medium", "high"):
                run_results.append(
                    {
                        "environment": environment_name,
                        "risk": risk,
                        "status": "fail",
                        "reason": image_policy_reason,
                        "verify_command": None,
                        "release_command": None,
                    }
                )
            continue
        if environment_item["kind"] == "container" and not docker_available:
            for risk in ("low", "medium", "high"):
                run_results.append(
                    {
                        "environment": environment_name,
                        "risk": risk,
                        "status": "fail",
                        "reason": docker_reason,
                        "verify_command": None,
                        "release_command": None,
                    }
                )
            continue

        for risk in ("low", "medium", "high"):
            spec_path = spec_paths_by_risk.get(risk)
            if spec_path is None:
                run_results.append(
                    {
                        "environment": environment_name,
                        "risk": risk,
                        "status": "fail",
                        "reason": "Missing canonical specification for risk level.",
                        "verify_command": None,
                        "release_command": None,
                    }
                )
                continue

            run_results.append(
                _run_stage_one_combination(
                    project_root=project_root,
                    base_env=base_env,
                    environment_item=environment_item,
                    risk=risk,
                    spec_path=spec_path,
                    signing_key_path=signing_key_path,
                    runs_path=runs_path,
                    attempt_label="primary",
                )
            )

    targeted_rerun = {
        "triggered": False,
        "trigger_reason": "",
        "rerun_status": "",
        "environment": "",
        "risk": "",
        "initial_result": None,
        "rerun_result": None,
    }
    rerun_candidate_index = _stage_one_transient_zero_citation_candidate(run_results)
    if rerun_candidate_index is not None:
        targeted_rerun["triggered"] = True
        targeted_rerun["trigger_reason"] = (
            "Only failure was high risk container run with zero live intelligence citations."
        )
        initial_result = dict(run_results[rerun_candidate_index])
        targeted_rerun["initial_result"] = initial_result
        targeted_rerun["environment"] = str(initial_result.get("environment", ""))
        targeted_rerun["risk"] = str(initial_result.get("risk", ""))
        rerun_environment = next(
            (
                item
                for item in environment_matrix
                if str(item.get("name", "")) == str(initial_result.get("environment", ""))
            ),
            None,
        )
        rerun_spec_path = spec_paths_by_risk.get("high")
        if rerun_environment is not None and rerun_spec_path is not None:
            rerun_result = _run_stage_one_combination(
                project_root=project_root,
                base_env=base_env,
                environment_item=rerun_environment,
                risk="high",
                spec_path=rerun_spec_path,
                signing_key_path=signing_key_path,
                runs_path=runs_path,
                attempt_label="rerun-1",
            )
            targeted_rerun["rerun_status"] = str(rerun_result.get("status", ""))
            targeted_rerun["rerun_result"] = rerun_result
            run_results[rerun_candidate_index] = {
                **rerun_result,
                "initial_failure": initial_result,
                "rerun_applied": True,
            }
        else:
            targeted_rerun["rerun_status"] = "skipped"
            targeted_rerun["rerun_result"] = {
                "status": "skip",
                "reason": "Rerun skipped because stage one rerun context was incomplete.",
            }

    check_all_runs_passed = all(item.get("status") == "pass" for item in run_results)
    check_live_intelligence = all(
        bool(item.get("live_intelligence", {}).get("passed")) for item in run_results if "live_intelligence" in item
    ) and bool([item for item in run_results if "live_intelligence" in item])

    runtime_mode_consistent = True
    consistency_failures: list[str] = []
    for risk in ("low", "medium", "high"):
        risk_runs = [item for item in run_results if item.get("risk") == risk and "release_manifest" in item]
        if not risk_runs:
            runtime_mode_consistent = False
            consistency_failures.append(f"Missing release runs for risk level {risk}.")
            continue
        runtime_modes = {
            str(item.get("release_manifest", {}).get("runtime_mode", ""))
            for item in risk_runs
        }
        if len(runtime_modes) != 1:
            runtime_mode_consistent = False
            consistency_failures.append(
                f"Runtime mode mismatch for risk level {risk}: {sorted(runtime_modes)}."
            )

    high_risk_container_zero_citation_failures = [
        item
        for item in run_results
        if str(item.get("environment", "")) == "container"
        and str(item.get("risk", "")) == "high"
        and str(item.get("status", "")) != "pass"
        and _coerce_int(
            dict(item.get("live_intelligence", {})).get("citation_count", 0)
            if isinstance(item.get("live_intelligence", {}), dict)
            else 0
        )
        == 0
    ]
    no_high_risk_container_zero_citation_failures = (
        len(high_risk_container_zero_citation_failures) == 0
    )

    summary_payload = {
        "stage": "stage-1",
        "created_at": now_iso(),
        "provider_settings": {
            "provider": provider_settings.get("provider", ""),
            "model": provider_settings.get("model", ""),
            "key_name": provider_settings.get("key_name", ""),
            "key_present": provider_settings.get("key_present", False),
            "error": provider_settings.get("error", ""),
        },
        "docker_available": docker_available,
        "docker_reason": docker_reason,
        "container_image_policy": container_image_policy,
        "spec_build_results": spec_build_results,
        "run_results": run_results,
        "targeted_rerun": targeted_rerun,
        "checks": {
            "all_runs_passed": check_all_runs_passed,
            "live_intelligence_present": check_live_intelligence,
            "runtime_release_consistency": runtime_mode_consistent,
            "no_high_risk_container_zero_citation_failures": no_high_risk_container_zero_citation_failures,
            "container_image_policy_passed": bool(container_image_policy.get("passed", False)),
            "consistency_failures": consistency_failures,
            "high_risk_container_zero_citation_failures": high_risk_container_zero_citation_failures,
        },
    }
    write_report_json(stage_path / "stage_summary.json", summary_payload, roots)

    summary_lines = [
        "Stage one summary",
        f"started_at: {stage_started}",
        f"finished_at: {now_iso()}",
        f"provider: {provider_settings.get('provider', '')}",
        f"provider_key_present: {provider_settings.get('key_present', False)}",
        f"docker_available: {docker_available}",
        (
            "container_image_policy_passed: "
            f"{bool(container_image_policy.get('passed', False))}"
        ),
        f"container_image: {container_image_policy.get('image', '')}",
        f"all_runs_passed: {check_all_runs_passed}",
        f"live_intelligence_present: {check_live_intelligence}",
        f"runtime_release_consistency: {runtime_mode_consistent}",
        (
            "no_high_risk_container_zero_citation_failures: "
            f"{no_high_risk_container_zero_citation_failures}"
        ),
        f"targeted_rerun_triggered: {targeted_rerun['triggered']}",
        f"targeted_rerun_status: {targeted_rerun['rerun_status']}",
        f"stage_summary: {stage_path / 'stage_summary.json'}",
    ]
    write_report_text(stage_path / "summary.txt", "\n".join(summary_lines) + "\n", roots)

    criteria = {
        "provider_ready": provider_settings.get("error", "") == "",
        "docker_available": docker_available,
        "container_image_policy_passed": bool(container_image_policy.get("passed", False)),
        "all_runs_passed": check_all_runs_passed,
        "live_intelligence_present": check_live_intelligence,
        "runtime_release_consistency": runtime_mode_consistent,
        "no_high_risk_container_zero_citation_failures": no_high_risk_container_zero_citation_failures,
        "stage_summary_exists": (stage_path / "stage_summary.json").exists(),
        "summary_exists": (stage_path / "summary.txt").exists(),
    }
    stage_passed = all(criteria.values())
    signoff_payload = {
        "stage": "stage-1",
        "signed_at": now_iso(),
        "passed": stage_passed,
        "criteria": criteria,
        "provider_error": provider_settings.get("error", ""),
        "docker_reason": docker_reason,
        "consistency_failures": consistency_failures,
    }
    write_report_json(stage_path / "stage_signoff.json", signoff_payload, roots)

    status = "pass" if stage_passed else "fail"
    return {
        "stage": "stage-1",
        "status": status,
        "stage_path": str(stage_path),
        "summary_file": str(stage_path / "summary.txt"),
        "signoff_file": str(stage_path / "stage_signoff.json"),
        "stage_summary": str(stage_path / "stage_summary.json"),
    }


def stage_two(project_root: Path, validation_root: Path) -> dict[str, Any]:
    stage_path = validation_root / "stage-2"
    stage_started = now_iso()
    roots = (project_root, project_root.parent)
    base_env = _lifeguard_env(project_root)

    compatibility_path = stage_path / "compatibility"
    compatibility_path.mkdir(parents=True, exist_ok=True)
    spec_path = stage_path / "stage2_compatibility_spec.json"

    init_command = [
        sys.executable,
        "-m",
        "lifeguard",
        "init",
        "--path",
        str(spec_path),
        "--force",
        "--profile",
        "secure_code_review_local",
        "--name",
        "stage2-compatibility-agent",
        "--risk-level",
        "low",
        "--runtime-environment",
        "local",
    ]
    init_result = run_command(init_command, cwd=project_root, env=base_env)

    spec_payload: dict[str, Any] = {}
    if init_result.return_code == 0 and spec_path.exists():
        parsed = json.loads(spec_path.read_text(encoding="utf-8"))
        if isinstance(parsed, dict):
            spec_payload = parsed

    adapter_matrix = (
        {
            "adapter": "langchain",
            "negative_payload": {"not_tool_bundle": True},
        },
        {
            "adapter": "langgraph",
            "negative_payload": {"not_flow_definition": True},
        },
    )

    round_trip_results: list[dict[str, Any]] = []
    negative_results: list[dict[str, Any]] = []

    for item in adapter_matrix:
        adapter_name = str(item["adapter"])
        export_path = compatibility_path / f"{adapter_name}_export.json"
        import_path = compatibility_path / f"{adapter_name}_import.json"
        negative_path = compatibility_path / f"{adapter_name}_negative.json"

        write_json(negative_path, item["negative_payload"])

        export_command = [
            sys.executable,
            "-m",
            "lifeguard",
            "compat-export",
            "--spec",
            str(spec_path),
            "--adapter",
            adapter_name,
            "--output",
            str(export_path),
            "--request-id",
            f"stage2-{adapter_name}-export",
        ]
        export_result = run_command(export_command, cwd=project_root, env=base_env)

        import_command = [
            sys.executable,
            "-m",
            "lifeguard",
            "compat-import",
            "--adapter",
            adapter_name,
            "--input",
            str(export_path),
            "--output",
            str(import_path),
            "--request-id",
            f"stage2-{adapter_name}-import",
        ]
        import_result = run_command(import_command, cwd=project_root, env=base_env)

        export_payload = (
            json.loads(export_path.read_text(encoding="utf-8"))
            if export_result.return_code == 0 and export_path.exists()
            else {}
        )
        import_payload = (
            json.loads(import_path.read_text(encoding="utf-8"))
            if import_result.return_code == 0 and import_path.exists()
            else {}
        )
        required_fields_unchanged, required_field_details = (False, {})
        if spec_payload and isinstance(export_payload, dict) and isinstance(import_payload, dict):
            required_fields_unchanged, required_field_details = _required_stage_two_fields_match(
                spec_payload=spec_payload,
                export_payload=export_payload,
                import_payload=import_payload,
            )

        export_stdout_payload = _parse_json_stdout(export_result)
        import_stdout_payload = _parse_json_stdout(import_result)
        round_trip_passed = (
            init_result.return_code == 0
            and export_result.return_code == 0
            and import_result.return_code == 0
            and bool(export_stdout_payload and export_stdout_payload.get("passed") is True)
            and bool(import_stdout_payload and import_stdout_payload.get("passed") is True)
            and required_fields_unchanged
        )
        round_trip_results.append(
            {
                "adapter": adapter_name,
                "status": "pass" if round_trip_passed else "fail",
                "spec_path": str(spec_path),
                "export_path": str(export_path),
                "import_path": str(import_path),
                "required_fields_unchanged": required_fields_unchanged,
                "required_field_details": required_field_details,
                "export_command": export_result.to_dict(),
                "import_command": import_result.to_dict(),
            }
        )

        negative_command = [
            sys.executable,
            "-m",
            "lifeguard",
            "compat-import",
            "--adapter",
            adapter_name,
            "--input",
            str(negative_path),
            "--request-id",
            f"stage2-{adapter_name}-negative",
        ]
        negative_result = run_command(negative_command, cwd=project_root, env=base_env)
        negative_payload = _parse_json_stdout(negative_result)
        negative_passed = (
            negative_result.return_code != 0
            and bool(negative_payload and negative_payload.get("passed") is False)
        )
        negative_results.append(
            {
                "adapter": adapter_name,
                "status": "pass" if negative_passed else "fail",
                "negative_payload_path": str(negative_path),
                "command": negative_result.to_dict(),
            }
        )

    check_round_trip = bool(round_trip_results) and all(
        item["status"] == "pass" for item in round_trip_results
    )
    check_required_fields = bool(round_trip_results) and all(
        bool(item.get("required_fields_unchanged")) for item in round_trip_results
    )
    check_negative = bool(negative_results) and all(
        item["status"] == "pass" for item in negative_results
    )

    summary_payload = {
        "stage": "stage-2",
        "created_at": now_iso(),
        "init_command": init_result.to_dict(),
        "round_trip_results": round_trip_results,
        "negative_results": negative_results,
        "checks": {
            "round_trip_checks_pass": check_round_trip,
            "required_fields_unchanged": check_required_fields,
            "negative_payload_tests_fail": check_negative,
        },
    }
    write_report_json(stage_path / "stage_summary.json", summary_payload, roots)

    summary_lines = [
        "Stage two summary",
        f"started_at: {stage_started}",
        f"finished_at: {now_iso()}",
        f"round_trip_checks_pass: {check_round_trip}",
        f"required_fields_unchanged: {check_required_fields}",
        f"negative_payload_tests_fail: {check_negative}",
        f"stage_summary: {stage_path / 'stage_summary.json'}",
    ]
    write_report_text(stage_path / "summary.txt", "\n".join(summary_lines) + "\n", roots)

    criteria = {
        "round_trip_checks_pass": check_round_trip,
        "required_fields_unchanged": check_required_fields,
        "negative_payload_tests_fail": check_negative,
        "stage_summary_exists": (stage_path / "stage_summary.json").exists(),
        "summary_exists": (stage_path / "summary.txt").exists(),
    }
    stage_passed = all(criteria.values())
    signoff_payload = {
        "stage": "stage-2",
        "signed_at": now_iso(),
        "passed": stage_passed,
        "criteria": criteria,
    }
    write_report_json(stage_path / "stage_signoff.json", signoff_payload, roots)

    return {
        "stage": "stage-2",
        "status": "pass" if stage_passed else "fail",
        "stage_path": str(stage_path),
        "summary_file": str(stage_path / "summary.txt"),
        "signoff_file": str(stage_path / "stage_signoff.json"),
        "stage_summary": str(stage_path / "stage_summary.json"),
    }


def stage_three(project_root: Path, validation_root: Path) -> dict[str, Any]:
    stage_path = validation_root / "stage-3"
    stage_started = now_iso()
    roots = (project_root, project_root.parent)
    base_env = _lifeguard_env(project_root)

    stage_path.mkdir(parents=True, exist_ok=True)
    signing_key_path = stage_path / "stage3_signing.key"
    write_text(signing_key_path, "stage-three-signing-key-material-abcdefghijklmnopqrstuvwxyz\n")

    spec_path = stage_path / "stage3_release_spec.json"
    spec_payload = {
        "name": "stage3-compatibility-gate-agent",
        "description": "Validate compatibility gate release controls.",
        "risk_level": "low",
        "tools": [
            {
                "name": "review",
                "command": "python review.py",
                "can_write_files": False,
                "can_access_network": False,
                "timeout_seconds": 30,
            }
        ],
        "data_scope": {
            "read_paths": ["/workspace"],
            "write_paths": ["/workspace/reports"],
            "allowed_hosts": [],
        },
        "runtime_environment": "container",
        "budget_limit_usd": 30.0,
        "max_runtime_seconds": 600,
        "design_method": "deterministic",
        "profile_id": "custom",
        "security_requirements": {
            "goals": [
                "Validate compatibility gate behavior in release flow.",
                "Produce signed release output for passing compatibility checks.",
            ],
            "threat_actors": [
                "External attacker",
                "Malicious insider",
            ],
            "evidence_requirements": [
                "Compatibility gate decision events.",
                "Signed release manifest.",
            ],
        },
        "live_data": {
            "enabled": False,
            "provider": "openrouter",
            "model": "openai/gpt-5.2:online",
            "max_results": 5,
            "min_citations": 2,
            "timeout_seconds": 45,
            "query": "",
            "strict": False,
        },
    }
    write_json(spec_path, spec_payload)

    failure_case_evidence = stage_path / "failure_case_events.jsonl"
    failure_case_output = stage_path / "failure_case_release"
    failure_env = dict(base_env)
    failure_env["LIFEGUARD_COMPATIBILITY_GATE_ADAPTERS"] = "langchain,unknown_adapter"

    failure_command = [
        sys.executable,
        "-m",
        "lifeguard",
        "release",
        "--spec",
        str(spec_path),
        "--evidence",
        str(failure_case_evidence),
        "--output",
        str(failure_case_output),
        "--signing-key-file",
        str(signing_key_path),
    ]
    failure_result = run_command(failure_command, cwd=project_root, env=failure_env)
    failure_manifest = failure_case_output / "release_manifest.json"
    failure_blocked = (
        failure_result.return_code != 0
        and not failure_manifest.exists()
        and "compatibility_gate_failed" in f"{failure_result.stdout}\n{failure_result.stderr}"
    )
    failure_event_present = _event_exists(
        evidence_path=failure_case_evidence,
        event_type="release.compatibility_gate.blocked",
    )

    passing_case_evidence = stage_path / "passing_case_events.jsonl"
    passing_case_output = stage_path / "passing_case_release"
    passing_env = dict(base_env)
    passing_env["LIFEGUARD_COMPATIBILITY_GATE_ADAPTERS"] = "langchain,langgraph"

    passing_command = [
        sys.executable,
        "-m",
        "lifeguard",
        "release",
        "--spec",
        str(spec_path),
        "--evidence",
        str(passing_case_evidence),
        "--output",
        str(passing_case_output),
        "--signing-key-file",
        str(signing_key_path),
    ]
    passing_result = run_command(passing_command, cwd=project_root, env=passing_env)
    passing_manifest = passing_case_output / "release_manifest.json"

    passing_manifest_payload: dict[str, Any] = {}
    if passing_manifest.exists():
        parsed_manifest = json.loads(passing_manifest.read_text(encoding="utf-8"))
        if isinstance(parsed_manifest, dict):
            passing_manifest_payload = parsed_manifest
    signature_payload = passing_manifest_payload.get("signature", {})
    compatibility_payload = passing_manifest_payload.get("compatibility_gate", {})
    control_matrix_payload = passing_manifest_payload.get("owasp_control_matrix", {})
    passing_emits_signed_release = (
        passing_result.return_code == 0
        and passing_manifest.exists()
        and isinstance(signature_payload, dict)
        and signature_payload.get("algorithm") in {"hmac-sha256", "sigstore-bundle"}
        and bool(passing_manifest_payload.get("verification", {}).get("passed"))
        and isinstance(compatibility_payload, dict)
        and compatibility_payload.get("passed") is True
        and isinstance(control_matrix_payload, dict)
        and control_matrix_payload.get("passed") is True
    )
    passing_event_present = _event_exists(
        evidence_path=passing_case_evidence,
        event_type="release.compatibility_gate.checked",
    )

    check_evidence_gate_decision = failure_event_present and passing_event_present

    summary_payload = {
        "stage": "stage-3",
        "created_at": now_iso(),
        "failure_case": {
            "blocked": failure_blocked,
            "event_present": failure_event_present,
            "evidence_path": str(failure_case_evidence),
            "manifest_path": str(failure_manifest),
            "command": failure_result.to_dict(),
        },
        "passing_case": {
            "passed": passing_emits_signed_release,
            "event_present": passing_event_present,
            "evidence_path": str(passing_case_evidence),
            "manifest_path": str(passing_manifest),
            "command": passing_result.to_dict(),
            "manifest_summary": {
                "exists": passing_manifest.exists(),
                "signature_algorithm": signature_payload.get("algorithm")
                if isinstance(signature_payload, dict)
                else None,
                "compatibility_gate_passed": compatibility_payload.get("passed")
                if isinstance(compatibility_payload, dict)
                else None,
                "control_matrix_passed": control_matrix_payload.get("passed")
                if isinstance(control_matrix_payload, dict)
                else None,
            },
        },
        "checks": {
            "failing_case_blocks_release_artifacts": failure_blocked,
            "passing_case_emits_signed_release_output": passing_emits_signed_release,
            "evidence_includes_compatibility_gate_decision": check_evidence_gate_decision,
        },
    }
    write_report_json(stage_path / "stage_summary.json", summary_payload, roots)

    summary_lines = [
        "Stage three summary",
        f"started_at: {stage_started}",
        f"finished_at: {now_iso()}",
        f"failing_case_blocks_release_artifacts: {failure_blocked}",
        f"passing_case_emits_signed_release_output: {passing_emits_signed_release}",
        f"evidence_includes_compatibility_gate_decision: {check_evidence_gate_decision}",
        f"stage_summary: {stage_path / 'stage_summary.json'}",
    ]
    write_report_text(stage_path / "summary.txt", "\n".join(summary_lines) + "\n", roots)

    criteria = {
        "failing_case_blocks_release_artifacts": failure_blocked,
        "passing_case_emits_signed_release_output": passing_emits_signed_release,
        "evidence_includes_compatibility_gate_decision": check_evidence_gate_decision,
        "stage_summary_exists": (stage_path / "stage_summary.json").exists(),
        "summary_exists": (stage_path / "summary.txt").exists(),
    }
    stage_passed = all(criteria.values())
    signoff_payload = {
        "stage": "stage-3",
        "signed_at": now_iso(),
        "passed": stage_passed,
        "criteria": criteria,
    }
    write_report_json(stage_path / "stage_signoff.json", signoff_payload, roots)

    return {
        "stage": "stage-3",
        "status": "pass" if stage_passed else "fail",
        "stage_path": str(stage_path),
        "summary_file": str(stage_path / "summary.txt"),
        "signoff_file": str(stage_path / "stage_signoff.json"),
        "stage_summary": str(stage_path / "stage_summary.json"),
    }


def stage_four(project_root: Path, validation_root: Path) -> dict[str, Any]:
    stage_path = validation_root / "stage-4"
    stage_started = now_iso()
    roots = (project_root, project_root.parent)
    base_env = _lifeguard_env(project_root)

    stage_path.mkdir(parents=True, exist_ok=True)
    spec_path = stage_path / "stage4_high_risk_spec.json"
    init_command = [
        sys.executable,
        "-m",
        "lifeguard",
        "init",
        "--path",
        str(spec_path),
        "--force",
        "--profile",
        "secure_code_review_local",
        "--name",
        "stage4-high-risk-adversarial-agent",
        "--risk-level",
        "high",
        "--runtime-environment",
        "container",
    ]
    init_result = run_command(init_command, cwd=project_root, env=base_env)

    run_count = int(os.getenv("LIFEGUARD_STAGE4_RUN_COUNT", "3"))
    campaign_results: list[dict[str, Any]] = []
    for index in range(run_count):
        run_id = index + 1
        evidence_path = stage_path / f"campaign_run_{run_id}.jsonl"
        verify_command = [
            sys.executable,
            "-m",
            "lifeguard",
            "verify",
            "--spec",
            str(spec_path),
            "--evidence",
            str(evidence_path),
        ]
        verify_result = run_command(verify_command, cwd=project_root, env=base_env)
        adversarial_summary = _adversarial_event_summary(evidence_path=evidence_path)
        run_passed = verify_result.return_code == 0 and adversarial_summary["passed"]
        campaign_results.append(
            {
                "run_id": run_id,
                "status": "pass" if run_passed else "fail",
                "evidence_path": str(evidence_path),
                "verify_command": verify_result.to_dict(),
                "adversarial_summary": adversarial_summary,
            }
        )

    pass_rates = [
        float(item["adversarial_summary"]["pass_rate"])
        for item in campaign_results
        if item.get("adversarial_summary", {}).get("pass_rate") is not None
    ]
    campaign_pass = bool(campaign_results) and all(item["status"] == "pass" for item in campaign_results)
    stable_pass_rates = bool(pass_rates) and len({round(value, 6) for value in pass_rates}) == 1
    high_risk_target_met = campaign_pass and stable_pass_rates

    regression_command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "tests/test_adversarial_validation.py",
        "tests/test_adversarial_reports.py",
        "tests/test_release_workflow.py",
    ]
    regression_result = run_command(regression_command, cwd=project_root, env=base_env)
    regression_tests_pass = regression_result.return_code == 0

    summary_payload = {
        "stage": "stage-4",
        "created_at": now_iso(),
        "init_command": init_result.to_dict(),
        "campaign_results": campaign_results,
        "checks": {
            "high_risk_campaign_meets_target": high_risk_target_met,
            "regression_tests_pass": regression_tests_pass,
        },
        "pass_rate_values": pass_rates,
    }
    write_report_json(stage_path / "stage_summary.json", summary_payload, roots)

    summary_lines = [
        "Stage four summary",
        f"started_at: {stage_started}",
        f"finished_at: {now_iso()}",
        f"campaign_runs: {run_count}",
        f"high_risk_campaign_meets_target: {high_risk_target_met}",
        f"regression_tests_pass: {regression_tests_pass}",
        f"stage_summary: {stage_path / 'stage_summary.json'}",
    ]
    write_report_text(stage_path / "summary.txt", "\n".join(summary_lines) + "\n", roots)

    criteria = {
        "high_risk_campaign_meets_target": high_risk_target_met,
        "regression_tests_pass": regression_tests_pass,
        "stage_summary_exists": (stage_path / "stage_summary.json").exists(),
        "summary_exists": (stage_path / "summary.txt").exists(),
    }
    stage_passed = all(criteria.values())
    signoff_payload = {
        "stage": "stage-4",
        "signed_at": now_iso(),
        "passed": stage_passed,
        "criteria": criteria,
    }
    write_report_json(stage_path / "stage_signoff.json", signoff_payload, roots)

    return {
        "stage": "stage-4",
        "status": "pass" if stage_passed else "fail",
        "stage_path": str(stage_path),
        "summary_file": str(stage_path / "summary.txt"),
        "signoff_file": str(stage_path / "stage_signoff.json"),
        "stage_summary": str(stage_path / "stage_summary.json"),
    }


def stage_five(project_root: Path, validation_root: Path) -> dict[str, Any]:
    stage_path = validation_root / "stage-5"
    stage_started = now_iso()
    roots = (project_root, project_root.parent)
    base_env = _lifeguard_env(project_root)

    runbook_path = project_root / "docs" / "OPERATIONS_RUNBOOK.md"
    runbook_text = runbook_path.read_text(encoding="utf-8") if runbook_path.exists() else ""
    expected_runbook_fragments = (
        "python3 -m lifeguard init",
        "python3 -m lifeguard verify",
        "python3 -m lifeguard adversarial-report",
        "python3 -m lifeguard release",
        "python3 -m lifeguard resume",
        "python3 -m lifeguard replay",
        "python3 -m lifeguard trust-source-profiles",
    )
    runbook_commands_documented = runbook_path.exists() and all(
        fragment in runbook_text for fragment in expected_runbook_fragments
    )

    runtime_root = stage_path / "runbook_runtime"
    runtime_root.mkdir(parents=True, exist_ok=True)
    spec_path = runtime_root / "spec_local.json"
    evidence_local = runtime_root / "evidence_local.jsonl"
    evidence_graph = runtime_root / "evidence_graph.jsonl"
    evidence_resume = runtime_root / "evidence_resume.jsonl"
    evidence_replay = runtime_root / "evidence_replay.jsonl"
    checkpoint_dir = runtime_root / "checkpoints"
    checkpoint_resume_dir = runtime_root / "checkpoints_resume"
    checkpoint_replay_dir = runtime_root / "checkpoints_replay"
    signing_key_path = runtime_root / "signing.key"
    write_text(signing_key_path, "lifeguard-runbook-signing-key-material-123456789\n")

    runthrough_results: list[dict[str, Any]] = []

    def _record_step(
        step_name: str,
        command: list[str],
        env: dict[str, str] | None = None,
        allowed_skip_markers: tuple[str, ...] = (),
    ) -> CommandResult:
        result = run_command(command, cwd=project_root, env=env or base_env)
        combined_output = f"{result.stdout}\n{result.stderr}".lower()
        status = "pass" if result.return_code == 0 else "fail"
        skip_reason = ""
        if result.return_code != 0:
            for marker in allowed_skip_markers:
                if marker.lower() in combined_output:
                    status = "skip"
                    skip_reason = marker
                    break
        runthrough_results.append(
            {
                "step": step_name,
                "status": status,
                "command": result.to_dict(),
                "skip_reason": skip_reason,
            }
        )
        return result

    _record_step(
        "init_spec",
        [
            sys.executable,
            "-m",
            "lifeguard",
            "init",
            "--path",
            str(spec_path),
            "--force",
            "--profile",
            "secure_code_review_local",
        ],
    )
    _record_step(
        "verify_standard",
        [
            sys.executable,
            "-m",
            "lifeguard",
            "verify",
            "--spec",
            str(spec_path),
            "--evidence",
            str(evidence_local),
        ],
    )
    _record_step(
        "adversarial_report",
        [
            sys.executable,
            "-m",
            "lifeguard",
            "adversarial-report",
            "--evidence",
            str(evidence_local),
            "--limit",
            "5",
        ],
    )
    _record_step(
        "release_signed",
        [
            sys.executable,
            "-m",
            "lifeguard",
            "release",
            "--spec",
            str(spec_path),
            "--evidence",
            str(evidence_local),
            "--output",
            str(runtime_root / "release"),
            "--signing-key-file",
            str(signing_key_path),
        ],
    )
    verify_langgraph_result = _record_step(
        "verify_langgraph",
        [
            sys.executable,
            "-m",
            "lifeguard",
            "verify",
            "--spec",
            str(spec_path),
            "--evidence",
            str(evidence_graph),
            "--runtime",
            "langgraph",
            "--checkpoint-dir",
            str(checkpoint_dir),
        ],
        allowed_skip_markers=("lang graph runtime unavailable",),
    )

    checkpoint_path: Path | None = None
    if verify_langgraph_result.return_code == 0:
        checkpoint_candidates = sorted(checkpoint_dir.glob("*--006--verification.json"))
        if not checkpoint_candidates:
            checkpoint_candidates = sorted(checkpoint_dir.glob("*.json"))
        checkpoint_path = checkpoint_candidates[0] if checkpoint_candidates else None

    if checkpoint_path is not None:
        _record_step(
            "resume_checkpoint",
            [
                sys.executable,
                "-m",
                "lifeguard",
                "resume",
                "--checkpoint",
                str(checkpoint_path),
                "--evidence",
                str(evidence_resume),
                "--checkpoint-dir",
                str(checkpoint_resume_dir),
            ],
        )
        _record_step(
            "replay_checkpoint",
            [
                sys.executable,
                "-m",
                "lifeguard",
                "replay",
                "--checkpoint",
                str(checkpoint_path),
                "--evidence",
                str(evidence_replay),
                "--checkpoint-dir",
                str(checkpoint_replay_dir),
            ],
        )
    elif verify_langgraph_result.return_code != 0:
        runthrough_results.append(
            {
                "step": "checkpoint_recovery",
                "status": "skip",
                "reason": "Lang Graph runtime is unavailable in this environment.",
            }
        )
    else:
        runthrough_results.append(
            {
                "step": "checkpoint_discovery",
                "status": "fail",
                "reason": "No checkpoint file was generated by langgraph verification.",
            }
        )

    _record_step(
        "trust_source_profiles",
        [
            sys.executable,
            "-m",
            "lifeguard",
            "trust-source-profiles",
        ],
    )

    runthrough_passed = bool(runthrough_results) and all(
        item.get("status") in {"pass", "skip"} for item in runthrough_results
    )
    documented_commands_verified = runbook_commands_documented and runthrough_passed

    summary_payload = {
        "stage": "stage-5",
        "created_at": now_iso(),
        "runbook_path": str(runbook_path),
        "runbook_exists": runbook_path.exists(),
        "runbook_commands_documented": runbook_commands_documented,
        "runthrough_results": runthrough_results,
        "checks": {
            "documentation_operator_runthrough_succeeds": runthrough_passed,
            "documented_commands_verified": documented_commands_verified,
        },
    }
    write_report_json(stage_path / "stage_summary.json", summary_payload, roots)

    summary_lines = [
        "Stage five summary",
        f"started_at: {stage_started}",
        f"finished_at: {now_iso()}",
        f"runbook_exists: {runbook_path.exists()}",
        f"runbook_commands_documented: {runbook_commands_documented}",
        f"documentation_operator_runthrough_succeeds: {runthrough_passed}",
        f"documented_commands_verified: {documented_commands_verified}",
        f"stage_summary: {stage_path / 'stage_summary.json'}",
    ]
    write_report_text(stage_path / "summary.txt", "\n".join(summary_lines) + "\n", roots)

    criteria = {
        "documentation_operator_runthrough_succeeds": runthrough_passed,
        "documented_commands_verified": documented_commands_verified,
        "stage_summary_exists": (stage_path / "stage_summary.json").exists(),
        "summary_exists": (stage_path / "summary.txt").exists(),
    }
    stage_passed = all(criteria.values())
    signoff_payload = {
        "stage": "stage-5",
        "signed_at": now_iso(),
        "passed": stage_passed,
        "criteria": criteria,
    }
    write_report_json(stage_path / "stage_signoff.json", signoff_payload, roots)

    return {
        "stage": "stage-5",
        "status": "pass" if stage_passed else "fail",
        "stage_path": str(stage_path),
        "summary_file": str(stage_path / "summary.txt"),
        "signoff_file": str(stage_path / "stage_signoff.json"),
        "stage_summary": str(stage_path / "stage_summary.json"),
    }


def stage_six(project_root: Path, validation_root: Path) -> dict[str, Any]:
    stage_path = validation_root / "stage-6"
    stage_started = now_iso()
    roots = (project_root, project_root.parent)
    base_env = _lifeguard_env(project_root)

    migration_policy_path = project_root / "docs" / "ADAPTER_MIGRATION_POLICY.md"
    fixture_request_path = project_root / "tests" / "fixtures" / "adapter_contract" / "v1" / "request.json"
    fixture_result_path = project_root / "tests" / "fixtures" / "adapter_contract" / "v1" / "result.json"
    version_policy_path = project_root / "tests" / "fixtures" / "adapter_contract" / "version_policy.json"

    backward_fixture_command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "tests/test_adapter_contract_policy.py::test_adapter_contract_backward_compatibility_fixtures_round_trip",
    ]
    backward_fixture_result = run_command(backward_fixture_command, cwd=project_root, env=base_env)

    version_policy_command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "tests/test_adapter_contract_policy.py::test_adapter_contract_version_policy_fixture_is_current",
        "tests/test_adapter_contract_policy.py::test_adapter_migration_policy_document_mentions_current_contract_version",
    ]
    version_policy_result = run_command(version_policy_command, cwd=project_root, env=base_env)

    backward_compatibility_fixtures_pass = (
        fixture_request_path.exists()
        and fixture_result_path.exists()
        and backward_fixture_result.return_code == 0
    )
    migration_policy_published = migration_policy_path.exists()
    version_policy_checks_pass = version_policy_path.exists() and version_policy_result.return_code == 0

    summary_payload = {
        "stage": "stage-6",
        "created_at": now_iso(),
        "migration_policy_path": str(migration_policy_path),
        "fixture_paths": {
            "request": str(fixture_request_path),
            "result": str(fixture_result_path),
            "version_policy": str(version_policy_path),
        },
        "commands": {
            "backward_fixture_check": backward_fixture_result.to_dict(),
            "version_policy_check": version_policy_result.to_dict(),
        },
        "checks": {
            "backward_compatibility_fixtures_pass": backward_compatibility_fixtures_pass,
            "migration_policy_document_published": migration_policy_published,
            "version_policy_checks_pass": version_policy_checks_pass,
        },
    }
    write_report_json(stage_path / "stage_summary.json", summary_payload, roots)

    summary_lines = [
        "Stage six summary",
        f"started_at: {stage_started}",
        f"finished_at: {now_iso()}",
        f"backward_compatibility_fixtures_pass: {backward_compatibility_fixtures_pass}",
        f"migration_policy_document_published: {migration_policy_published}",
        f"version_policy_checks_pass: {version_policy_checks_pass}",
        f"stage_summary: {stage_path / 'stage_summary.json'}",
    ]
    write_report_text(stage_path / "summary.txt", "\n".join(summary_lines) + "\n", roots)

    criteria = {
        "backward_compatibility_fixtures_pass": backward_compatibility_fixtures_pass,
        "migration_policy_document_published": migration_policy_published,
        "version_policy_checks_pass": version_policy_checks_pass,
        "stage_summary_exists": (stage_path / "stage_summary.json").exists(),
        "summary_exists": (stage_path / "summary.txt").exists(),
    }
    stage_passed = all(criteria.values())
    signoff_payload = {
        "stage": "stage-6",
        "signed_at": now_iso(),
        "passed": stage_passed,
        "criteria": criteria,
    }
    write_report_json(stage_path / "stage_signoff.json", signoff_payload, roots)

    return {
        "stage": "stage-6",
        "status": "pass" if stage_passed else "fail",
        "stage_path": str(stage_path),
        "summary_file": str(stage_path / "summary.txt"),
        "signoff_file": str(stage_path / "stage_signoff.json"),
        "stage_summary": str(stage_path / "stage_summary.json"),
    }


def stage_not_implemented(stage: str, validation_root: Path) -> dict[str, Any]:
    stage_path = validation_root / stage
    payload = {
        "stage": stage,
        "status": "not_implemented",
        "checked_at": now_iso(),
        "message": "Validation logic for this stage is not implemented yet.",
    }
    roots = (validation_root.parent, validation_root.parent.parent)
    write_report_json(stage_path / "stage_status.json", payload, roots)
    return payload


def run_selected_stages(project_root: Path, validation_root: Path, stage: str) -> dict[str, Any]:
    roots = (project_root, project_root.parent)
    ensure_stage_directories(validation_root)
    selected = STAGES if stage == "all" else (stage,)
    stage_results: list[dict[str, Any]] = []

    for stage_name in selected:
        if stage_name == "stage-0":
            stage_results.append(stage_zero(project_root=project_root, validation_root=validation_root))
            continue
        if stage_name == "stage-1":
            stage_results.append(stage_one(project_root=project_root, validation_root=validation_root))
            continue
        if stage_name == "stage-2":
            stage_results.append(stage_two(project_root=project_root, validation_root=validation_root))
            continue
        if stage_name == "stage-3":
            stage_results.append(stage_three(project_root=project_root, validation_root=validation_root))
            continue
        if stage_name == "stage-4":
            stage_results.append(stage_four(project_root=project_root, validation_root=validation_root))
            continue
        if stage_name == "stage-5":
            stage_results.append(stage_five(project_root=project_root, validation_root=validation_root))
            continue
        if stage_name == "stage-6":
            stage_results.append(stage_six(project_root=project_root, validation_root=validation_root))
            continue
        stage_results.append(stage_not_implemented(stage_name, validation_root=validation_root))

    status = "pass" if all(item.get("status") == "pass" for item in stage_results) else "fail"
    result = {
        "started_at": now_iso(),
        "project_root": str(project_root),
        "validation_root": str(validation_root),
        "selected_stage": stage,
        "status": status,
        "results": stage_results,
        "finished_at": now_iso(),
    }
    write_report_json(validation_root / "latest_run.json", result, roots)
    write_report_text(
        validation_root / "latest_run_summary.txt",
        "\n".join(
            [
                "Completion validation summary",
                f"selected_stage: {stage}",
                f"overall_status: {status}",
                "stage_results:",
                *[f"- {item['stage']}: {item['status']}" for item in stage_results],
            ]
        )
        + "\n",
        roots,
    )
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Runs completion validation stages and writes machine readable and human readable reports."
        ),
    )
    parser.add_argument(
        "--stage",
        choices=(*STAGES, "all"),
        default="stage-0",
        help="Validation stage to run.",
    )
    parser.add_argument(
        "--validation-root",
        default="validation",
        help="Validation output root directory.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    project_root = Path(__file__).resolve().parents[1]
    validation_root = project_root / args.validation_root
    result = run_selected_stages(
        project_root=project_root,
        validation_root=validation_root,
        stage=args.stage,
    )
    roots = (project_root, project_root.parent)
    print(json.dumps(_sanitize_payload(result, roots), indent=2))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
