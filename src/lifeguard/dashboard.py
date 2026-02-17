from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def build_dashboard_data(validation_root: str | Path) -> dict[str, Any]:
    root = Path(validation_root)
    release_manifests = sorted(root.rglob("release_manifest.json"))
    evidence_logs = sorted(root.rglob("*.jsonl"))

    signature_algorithms: Counter[str] = Counter()
    risk_levels: Counter[str] = Counter()
    release_total = 0
    release_verified = 0
    verification_failures: Counter[str] = Counter()
    manifests_index: list[dict[str, Any]] = []

    for manifest_path in release_manifests:
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        release_total += 1
        verification_payload = payload.get("verification", {})
        if isinstance(verification_payload, dict) and bool(verification_payload.get("passed")):
            release_verified += 1
        checks = verification_payload.get("checks", [])
        if isinstance(checks, list):
            for item in checks:
                if not isinstance(item, dict):
                    continue
                if not bool(item.get("passed")):
                    verification_failures[str(item.get("name", "unknown"))] += 1
        signature_payload = payload.get("signature", {})
        if isinstance(signature_payload, dict):
            signature_algorithms[str(signature_payload.get("algorithm", "unknown"))] += 1
        agent_spec = payload.get("agent_spec", {})
        if isinstance(agent_spec, dict):
            risk_levels[str(agent_spec.get("risk_level", "unknown"))] += 1
        manifests_index.append(
            {
                "path": _relative_path(manifest_path, root),
                "verification_passed": bool(verification_payload.get("passed"))
                if isinstance(verification_payload, dict)
                else False,
                "signature_algorithm": str(signature_payload.get("algorithm", ""))
                if isinstance(signature_payload, dict)
                else "",
                "risk_level": str(agent_spec.get("risk_level", ""))
                if isinstance(agent_spec, dict)
                else "",
            }
        )

    event_counts: Counter[str] = Counter()
    event_status_counts: Counter[str] = Counter()
    model_context_protocol_final: Counter[str] = Counter()
    live_intelligence_counts: Counter[str] = Counter()
    live_intelligence_citation_total = 0
    live_intelligence_records = 0

    for evidence_path in evidence_logs:
        try:
            lines = evidence_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            cleaned = line.strip()
            if not cleaned:
                continue
            try:
                record = json.loads(cleaned)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            event_type = str(record.get("event_type", "")).strip()
            status = str(record.get("status", "")).strip().lower()
            details = record.get("details", {})
            event_counts[event_type] += 1
            event_status_counts[f"{event_type}:{status}"] += 1
            if event_type == "model_context_protocol_gating.final":
                model_context_protocol_final[status or "unknown"] += 1
            if event_type == "live_intelligence_freshness":
                live_intelligence_counts[status or "unknown"] += 1
                if isinstance(details, dict):
                    raw_citations = details.get("citation_count")
                    try:
                        citation_count = int(raw_citations)
                    except (TypeError, ValueError):
                        citation_count = 0
                    live_intelligence_citation_total += citation_count
                    live_intelligence_records += 1

    average_citations = (
        round(live_intelligence_citation_total / live_intelligence_records, 2)
        if live_intelligence_records > 0
        else 0.0
    )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "validation_root": str(root),
        "release": {
            "manifest_count": release_total,
            "verification_passed_count": release_verified,
            "signature_algorithms": dict(signature_algorithms),
            "risk_levels": dict(risk_levels),
            "verification_failures": dict(verification_failures),
            "manifests": manifests_index,
        },
        "evidence": {
            "log_count": len(evidence_logs),
            "event_counts": dict(event_counts),
            "model_context_protocol_final": dict(model_context_protocol_final),
            "live_intelligence": {
                "status_counts": dict(live_intelligence_counts),
                "average_citation_count": average_citations,
                "record_count": live_intelligence_records,
            },
        },
    }


def write_dashboard(validation_root: str | Path, output_path: str | Path) -> Path:
    data = build_dashboard_data(validation_root)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(_render_dashboard_html(data), encoding="utf-8")
    return output


def _render_dashboard_html(data: dict[str, Any]) -> str:
    release = data.get("release", {})
    evidence = data.get("evidence", {})
    manifests = release.get("manifests", []) if isinstance(release, dict) else []
    signature_algorithms = (
        release.get("signature_algorithms", {}) if isinstance(release, dict) else {}
    )
    risk_levels = release.get("risk_levels", {}) if isinstance(release, dict) else {}
    model_context_protocol_final = (
        evidence.get("model_context_protocol_final", {}) if isinstance(evidence, dict) else {}
    )
    live_intelligence = evidence.get("live_intelligence", {}) if isinstance(evidence, dict) else {}

    def _rows_from_map(mapping: dict[str, Any]) -> str:
        rows = []
        for key in sorted(mapping):
            rows.append(f"<tr><td>{_escape_html(str(key))}</td><td>{_escape_html(str(mapping[key]))}</td></tr>")
        return "".join(rows) if rows else "<tr><td colspan='2'>None</td></tr>"

    manifest_rows = ""
    if isinstance(manifests, list) and manifests:
        row_parts: list[str] = []
        for item in manifests:
            if not isinstance(item, dict):
                continue
            row_parts.append(
                "<tr>"
                + f"<td>{_escape_html(str(item.get('path', '')))}</td>"
                + f"<td>{_escape_html(str(item.get('risk_level', '')))}</td>"
                + f"<td>{_escape_html(str(item.get('signature_algorithm', '')))}</td>"
                + f"<td>{_escape_html(str(item.get('verification_passed', False)))}</td>"
                + "</tr>"
            )
        manifest_rows = "".join(row_parts) if row_parts else "<tr><td colspan='4'>None</td></tr>"
    else:
        manifest_rows = "<tr><td colspan='4'>None</td></tr>"

    dashboard_json = _escape_html(json.dumps(data, indent=2))
    return (
        "<!doctype html>\n"
        "<html lang='en'>\n"
        "<head>\n"
        "  <meta charset='utf-8'>\n"
        "  <meta name='viewport' content='width=device-width, initial-scale=1'>\n"
        "  <title>Lifeguard Verification Dashboard</title>\n"
        "  <style>\n"
        "    :root { color-scheme: light; --bg:#f5f6f8; --fg:#0f172a; --card:#ffffff; --line:#d1d5db; --accent:#0b4f6c; }\n"
        "    body { margin:0; font-family: 'IBM Plex Sans', 'Segoe UI', sans-serif; background:var(--bg); color:var(--fg); }\n"
        "    main { max-width:1200px; margin:0 auto; padding:24px; }\n"
        "    h1 { margin:0 0 8px 0; font-size:28px; }\n"
        "    p.meta { margin:0 0 24px 0; color:#334155; }\n"
        "    section { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px; margin-bottom:16px; }\n"
        "    table { width:100%; border-collapse:collapse; }\n"
        "    th, td { text-align:left; padding:8px; border-bottom:1px solid var(--line); }\n"
        "    th { color:#0b4f6c; }\n"
        "    pre { background:#0b1020; color:#e2e8f0; padding:12px; border-radius:8px; overflow:auto; }\n"
        "    .grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(260px, 1fr)); gap:16px; }\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        "<main>\n"
        "  <h1>Lifeguard Verification Dashboard</h1>\n"
        f"  <p class='meta'>Generated at {_escape_html(str(data.get('generated_at', '')))} from {_escape_html(str(data.get('validation_root', '')))}</p>\n"
        "  <section>\n"
        "    <h2>Release Summary</h2>\n"
        "    <div class='grid'>\n"
        f"      <div><strong>Manifest count</strong><div>{_escape_html(str(release.get('manifest_count', 0)))}</div></div>\n"
        f"      <div><strong>Verification passed count</strong><div>{_escape_html(str(release.get('verification_passed_count', 0)))}</div></div>\n"
        f"      <div><strong>Evidence logs</strong><div>{_escape_html(str(evidence.get('log_count', 0)))}</div></div>\n"
        "    </div>\n"
        "  </section>\n"
        "  <section>\n"
        "    <h2>Signature Algorithms</h2>\n"
        "    <table><thead><tr><th>Algorithm</th><th>Count</th></tr></thead><tbody>"
        + _rows_from_map(signature_algorithms if isinstance(signature_algorithms, dict) else {})
        + "</tbody></table>\n"
        "  </section>\n"
        "  <section>\n"
        "    <h2>Risk Distribution</h2>\n"
        "    <table><thead><tr><th>Risk level</th><th>Count</th></tr></thead><tbody>"
        + _rows_from_map(risk_levels if isinstance(risk_levels, dict) else {})
        + "</tbody></table>\n"
        "  </section>\n"
        "  <section>\n"
        "    <h2>Model Context Protocol Gating Outcomes</h2>\n"
        "    <table><thead><tr><th>Status</th><th>Count</th></tr></thead><tbody>"
        + _rows_from_map(model_context_protocol_final if isinstance(model_context_protocol_final, dict) else {})
        + "</tbody></table>\n"
        "  </section>\n"
        "  <section>\n"
        "    <h2>Live Intelligence Summary</h2>\n"
        "    <div class='grid'>\n"
        f"      <div><strong>Record count</strong><div>{_escape_html(str(live_intelligence.get('record_count', 0)))}</div></div>\n"
        f"      <div><strong>Average citation count</strong><div>{_escape_html(str(live_intelligence.get('average_citation_count', 0.0)))}</div></div>\n"
        "    </div>\n"
        "    <table><thead><tr><th>Status</th><th>Count</th></tr></thead><tbody>"
        + _rows_from_map(
            live_intelligence.get("status_counts", {})
            if isinstance(live_intelligence, dict)
            else {}
        )
        + "</tbody></table>\n"
        "  </section>\n"
        "  <section>\n"
        "    <h2>Release Manifests</h2>\n"
        "    <table><thead><tr><th>Path</th><th>Risk</th><th>Signature</th><th>Verification Passed</th></tr></thead><tbody>"
        + manifest_rows
        + "</tbody></table>\n"
        "  </section>\n"
        "  <section>\n"
        "    <h2>Raw Data</h2>\n"
        f"    <pre>{dashboard_json}</pre>\n"
        "  </section>\n"
        "</main>\n"
        "</body>\n"
        "</html>\n"
    )


def _relative_path(path: Path, base: Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve()))
    except ValueError:
        return str(path)


def _escape_html(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )
