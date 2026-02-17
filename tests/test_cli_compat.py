from __future__ import annotations

import json

from lifeguard.cli import main

_GUARD_ENV_VARS = (
    "LANGSMITH_API_KEY",
    "LANGCHAIN_API_KEY",
    "LANGSMITH_ENDPOINT",
    "LANGCHAIN_ENDPOINT",
    "LANGCHAIN_TRACING_V2",
    "LANGSMITH_TRACING",
)


def _clear_guard_env(monkeypatch) -> None:
    for key in _GUARD_ENV_VARS:
        monkeypatch.delenv(key, raising=False)


def test_cli_compat_export_and_import_langchain(tmp_path, monkeypatch, capsys) -> None:
    _clear_guard_env(monkeypatch)
    spec_path = tmp_path / "spec_local.json"
    export_path = tmp_path / "langchain_export.json"
    import_path = tmp_path / "langchain_import.json"

    init_code = main(
        [
            "init",
            "--path",
            str(spec_path),
            "--profile",
            "secure_code_review_local",
        ]
    )
    assert init_code == 0
    capsys.readouterr()

    export_code = main(
        [
            "compat-export",
            "--spec",
            str(spec_path),
            "--adapter",
            "langchain",
            "--output",
            str(export_path),
            "--request-id",
            "test-langchain-export",
        ]
    )
    assert export_code == 0
    export_payload = json.loads(capsys.readouterr().out)
    assert export_payload["passed"] is True
    assert export_payload["adapter"] == "langchain"
    assert "tool_bundle" in json.loads(export_path.read_text(encoding="utf-8"))

    import_code = main(
        [
            "compat-import",
            "--adapter",
            "langchain",
            "--input",
            str(export_path),
            "--output",
            str(import_path),
        ]
    )
    assert import_code == 0
    import_payload = json.loads(capsys.readouterr().out)
    assert import_payload["passed"] is True
    normalized = json.loads(import_path.read_text(encoding="utf-8"))
    assert "tools" in normalized
    assert len(normalized["tools"]) > 0


def test_cli_compat_export_and_import_langgraph(tmp_path, monkeypatch, capsys) -> None:
    _clear_guard_env(monkeypatch)
    spec_path = tmp_path / "spec_local.json"
    export_path = tmp_path / "langgraph_export.json"
    import_path = tmp_path / "langgraph_import.json"

    init_code = main(
        [
            "init",
            "--path",
            str(spec_path),
            "--profile",
            "secure_code_review_local",
        ]
    )
    assert init_code == 0
    capsys.readouterr()

    export_code = main(
        [
            "compat-export",
            "--spec",
            str(spec_path),
            "--adapter",
            "langgraph",
            "--output",
            str(export_path),
        ]
    )
    assert export_code == 0
    export_payload = json.loads(capsys.readouterr().out)
    assert export_payload["passed"] is True
    assert export_payload["adapter"] == "langgraph"
    exported = json.loads(export_path.read_text(encoding="utf-8"))
    assert "flow_definition" in exported

    import_code = main(
        [
            "compat-import",
            "--adapter",
            "langgraph",
            "--input",
            str(export_path),
            "--output",
            str(import_path),
        ]
    )
    assert import_code == 0
    import_payload = json.loads(capsys.readouterr().out)
    assert import_payload["passed"] is True
    normalized = json.loads(import_path.read_text(encoding="utf-8"))
    assert "tools" in normalized
    assert len(normalized["tools"]) > 0


def test_cli_compat_import_rejects_invalid_payload(tmp_path, monkeypatch, capsys) -> None:
    _clear_guard_env(monkeypatch)
    invalid_payload = tmp_path / "invalid_langchain.json"
    invalid_payload.write_text(json.dumps({"not_tool_bundle": True}), encoding="utf-8")

    exit_code = main(
        [
            "compat-import",
            "--adapter",
            "langchain",
            "--input",
            str(invalid_payload),
        ]
    )
    assert exit_code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is False
    assert "tool_bundle" in payload["error"]


def test_cli_compat_export_and_import_model_context_protocol(
    tmp_path, monkeypatch, capsys
) -> None:
    _clear_guard_env(monkeypatch)
    spec_path = tmp_path / "spec_local.json"
    export_path = tmp_path / "mcp_export.json"
    import_path = tmp_path / "mcp_import.json"

    init_code = main(
        [
            "init",
            "--path",
            str(spec_path),
            "--profile",
            "secure_code_review_local",
        ]
    )
    assert init_code == 0
    capsys.readouterr()

    export_code = main(
        [
            "compat-export",
            "--spec",
            str(spec_path),
            "--adapter",
            "mcp",
            "--output",
            str(export_path),
        ]
    )
    assert export_code == 0
    export_payload = json.loads(capsys.readouterr().out)
    assert export_payload["passed"] is True
    assert export_payload["adapter"] == "mcp"
    exported = json.loads(export_path.read_text(encoding="utf-8"))
    assert "server_bundle" in exported

    import_code = main(
        [
            "compat-import",
            "--adapter",
            "mcp",
            "--input",
            str(export_path),
            "--output",
            str(import_path),
        ]
    )
    assert import_code == 0
    import_payload = json.loads(capsys.readouterr().out)
    assert import_payload["passed"] is True
    normalized = json.loads(import_path.read_text(encoding="utf-8"))
    assert "tools" in normalized
    assert "gating" in normalized
