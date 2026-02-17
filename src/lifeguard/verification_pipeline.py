from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .adapters import (
    AdapterActionRequest,
    LifeguardExtractsAdapterLayer,
    ModelContextProtocolCompatibilityAdapter,
)
from .adversarial_validation import evaluate_adversarial_pack
from .adversarial_reports import AdversarialReportStore
from .evidence_store import EvidenceStore
from .legislative_review import (
    LegislativeReviewError,
    build_legislative_decision_template,
    build_legislative_review_pack,
    load_json_file,
    payload_sha256,
    resolve_legislative_review_artifacts,
    validate_legislative_decision,
)
from .live_intelligence import (
    LiveDataConfigurationError,
    LiveDataError,
    LiveDataValidationError,
    LiveIntelligenceClient,
)
from .policy_compiler import CompiledPolicy, compile_policy
from .spec_schema import AgentSpec, ConfigValidationError, LiveDataSettings, evaluate_spec_quality
from .threat_model import validate_policy_against_threats

_SECRET_MARKERS = ("secret=", "token=", "password=", "-----begin")
_BUDGET_CAP_USD = {"low": 500.0, "medium": 250.0, "high": 100.0}


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    message: str


@dataclass(frozen=True)
class VerificationReport:
    passed: bool
    results: tuple[CheckResult, ...]
    policy: CompiledPolicy | None
    evidence_path: Path


class VerificationPipeline:
    def __init__(
        self,
        evidence_store: EvidenceStore,
        adapter_layer: LifeguardExtractsAdapterLayer | None = None,
        repo_path: Path | None = None,
        intelligence_client: LiveIntelligenceClient | None = None,
    ) -> None:
        self.evidence_store = evidence_store
        self.adapter_layer = adapter_layer or LifeguardExtractsAdapterLayer()
        self.repo_path = repo_path
        self.intelligence_client = intelligence_client or LiveIntelligenceClient()
        self.adversarial_report_store = AdversarialReportStore(self.evidence_store.path)

    def run(self, spec: AgentSpec) -> VerificationReport:
        results: list[CheckResult] = []
        policy: CompiledPolicy | None = None

        quality_result = self._check_spec_quality(spec)
        results.append(quality_result)
        if not quality_result.passed:
            self.evidence_store.append(
                "verification.run.complete",
                "fail",
                {
                    "agent_name": spec.name,
                    "result_count": len(results),
                    "blocked_by": quality_result.name,
                },
            )
            return VerificationReport(
                passed=False,
                results=tuple(results),
                policy=None,
                evidence_path=self.evidence_store.path,
            )

        policy_result, policy = self._check_policy_compilation(spec)
        results.append(policy_result)

        adapter_result = self._check_adapter_module_readiness()
        results.append(adapter_result)

        model_context_protocol_result = self._check_model_context_protocol_gating(spec)
        results.append(model_context_protocol_result)

        secret_result = self._check_secret_hygiene(spec)
        results.append(secret_result)

        threat_result = self._check_threat_controls(spec, policy)
        results.append(threat_result)

        live_data_result = self._check_live_intelligence(spec)
        results.append(live_data_result)

        legislative_result = self._check_legislative_review(spec)
        results.append(legislative_result)

        environment_result = self._check_runtime_environment(spec)
        results.append(environment_result)

        preflight_result = self._check_adapter_security_preflight()
        results.append(preflight_result)

        budget_result = self._check_budget(spec)
        results.append(budget_result)

        runtime_result = self._check_runtime(spec)
        results.append(runtime_result)

        adversarial_result = self._check_adversarial_resilience(spec, policy)
        results.append(adversarial_result)

        overall_pass = all(result.passed for result in results)
        self.evidence_store.append(
            "verification.run.complete",
            "pass" if overall_pass else "fail",
            {"agent_name": spec.name, "result_count": len(results)},
        )
        return VerificationReport(
            passed=overall_pass,
            results=tuple(results),
            policy=policy,
            evidence_path=self.evidence_store.path,
        )

    def run_legislative_review(self, spec: AgentSpec) -> CheckResult:
        """Run legislative review only.

        This is used by the command line interface convenience command.
        """

        return self._check_legislative_review(spec)

    def _check_policy_compilation(
        self, spec: AgentSpec
    ) -> tuple[CheckResult, CompiledPolicy | None]:
        try:
            policy = compile_policy(spec)
        except ConfigValidationError as exc:
            result = CheckResult(
                name="policy_compilation",
                passed=False,
                message=str(exc),
            )
            self.evidence_store.append(result.name, "fail", {"message": result.message})
            return result, None

        result = CheckResult(
            name="policy_compilation",
            passed=True,
            message="Policy compiled successfully.",
        )
        self.evidence_store.append(
            result.name,
            "pass",
            {
                "network_mode": policy.network_mode,
                "requires_human_approval": policy.requires_human_approval,
            },
        )
        return result, policy

    def _check_spec_quality(self, spec: AgentSpec) -> CheckResult:
        report = evaluate_spec_quality(spec)
        if not report.passed:
            message_parts: list[str] = [f"score {report.score}/{report.threshold}"]
            if report.missing_requirements:
                message_parts.append(
                    "missing required fields: " + ", ".join(report.missing_requirements)
                )
            if report.findings:
                message_parts.append("findings: " + "; ".join(report.findings))
            result = CheckResult(
                name="spec_quality_gate",
                passed=False,
                message="Specification quality gate failed: " + " | ".join(message_parts),
            )
            self.evidence_store.append(
                result.name,
                "fail",
                {
                    "profile_id": spec.profile_id,
                    "score": report.score,
                    "threshold": report.threshold,
                    "missing_requirements": list(report.missing_requirements),
                    "findings": list(report.findings),
                },
            )
            return result

        result = CheckResult(
            name="spec_quality_gate",
            passed=True,
            message=f"Specification quality score {report.score}/{report.threshold}.",
        )
        self.evidence_store.append(
            result.name,
            "pass",
            {
                "profile_id": spec.profile_id,
                "score": report.score,
                "threshold": report.threshold,
                "findings": list(report.findings),
            },
        )
        return result

    def _check_secret_hygiene(self, spec: AgentSpec) -> CheckResult:
        lowered_text = " ".join(
            [spec.description.lower(), *(tool.command.lower() for tool in spec.tools)]
        )
        marker = next((candidate for candidate in _SECRET_MARKERS if candidate in lowered_text), None)
        if marker:
            result = CheckResult(
                name="secret_hygiene",
                passed=False,
                message=f"Potential secret marker detected: '{marker}'.",
            )
            self.evidence_store.append(result.name, "fail", {"marker": marker})
            return result

        result = CheckResult(
            name="secret_hygiene",
            passed=True,
            message="No obvious secret markers detected.",
        )
        self.evidence_store.append(result.name, "pass", {})
        return result

    def _check_threat_controls(
        self, spec: AgentSpec, policy: CompiledPolicy | None
    ) -> CheckResult:
        if policy is None:
            result = CheckResult(
                name="threat_controls",
                passed=False,
                message="Threat controls skipped because policy compilation failed.",
            )
            self.evidence_store.append(result.name, "fail", {"reason": "missing_policy"})
            return result

        findings = validate_policy_against_threats(spec, policy)
        if findings:
            result = CheckResult(
                name="threat_controls",
                passed=False,
                message="; ".join(findings),
            )
            self.evidence_store.append(result.name, "fail", {"findings": findings})
            return result

        result = CheckResult(
            name="threat_controls",
            passed=True,
            message="Threat controls satisfied.",
        )
        self.evidence_store.append(result.name, "pass", {})
        return result

    def _check_live_intelligence(self, spec: AgentSpec) -> CheckResult:
        settings = spec.live_data
        if not settings.enabled:
            result = CheckResult(
                name="live_intelligence_freshness",
                passed=True,
                message="Live intelligence is disabled.",
            )
            self.evidence_store.append(result.name, "pass", {"enabled": False})
            return result

        query = settings.query.strip() or spec.description
        reused = self._reuse_live_intelligence_event(
            provider=settings.provider,
            model=settings.model,
            query=query,
        )
        if reused is not None:
            citation_count = int(reused.get("citation_count", 0))
            result = CheckResult(
                name="live_intelligence_freshness",
                passed=True,
                message=(
                    "Live intelligence reused from evidence with "
                    f"{citation_count} cited sources."
                ),
            )
            self.evidence_store.append(
                result.name,
                "pass",
                dict(reused, reused=True),
            )
            return result

        try:
            report = self.intelligence_client.collect_latest(
                query=query,
                settings=settings,
                risk_level=spec.risk_level,
            )
        except LiveDataError as exc:
            attempt_details = _live_data_attempt_details(exc)
            latest_citation_count = _last_attempt_citation_count(attempt_details)
            if isinstance(exc, LiveDataConfigurationError):
                result = CheckResult(
                    name="live_intelligence_freshness",
                    passed=False,
                    message=str(exc),
                )
                self.evidence_store.append(
                    result.name,
                    "fail",
                    {
                        "provider": settings.provider,
                        "model": settings.model,
                        "strict": settings.strict,
                        "error": str(exc),
                        "error_type": "configuration",
                        "attempts": attempt_details,
                        "citation_count": latest_citation_count,
                    },
                )
                return result
            if settings.strict:
                result = CheckResult(
                    name="live_intelligence_freshness",
                    passed=False,
                    message=str(exc),
                )
                self.evidence_store.append(
                    result.name,
                    "fail",
                    {
                        "provider": settings.provider,
                        "model": settings.model,
                        "strict": settings.strict,
                        "error": str(exc),
                        "attempts": attempt_details,
                        "citation_count": latest_citation_count,
                    },
                )
                return result

            if spec.risk_level in {"medium", "high"}:
                result = CheckResult(
                    name="live_intelligence_freshness",
                    passed=False,
                    message=(
                        "Live intelligence failed and non-strict mode is not allowed for "
                        f"risk level '{spec.risk_level}': {exc}"
                    ),
                )
                self.evidence_store.append(
                    result.name,
                    "fail",
                    {
                        "provider": settings.provider,
                        "model": settings.model,
                        "strict": settings.strict,
                        "strict_required_by_risk": True,
                        "error": str(exc),
                        "attempts": attempt_details,
                        "citation_count": latest_citation_count,
                    },
                )
                return result

            result = CheckResult(
                name="live_intelligence_freshness",
                passed=True,
                message=f"Live intelligence failed but strict mode is disabled: {exc}",
            )
            self.evidence_store.append(
                result.name,
                "pass",
                {
                    "provider": settings.provider,
                    "model": settings.model,
                    "strict": settings.strict,
                    "strict_required_by_risk": False,
                    "warning": str(exc),
                    "attempts": attempt_details,
                    "citation_count": latest_citation_count,
                },
            )
            return result

        result = CheckResult(
            name="live_intelligence_freshness",
            passed=True,
            message=(
                "Live intelligence succeeded with "
                f"{len(report.citations)} cited sources from provider {report.provider}."
            ),
        )
        self.evidence_store.append(
            result.name,
            "pass",
            {
                "provider": report.provider,
                "model": report.model,
                "query": report.query,
                "fetched_at": report.fetched_at,
                "citation_count": len(report.citations),
                "attempts": [item.to_dict() for item in report.attempts],
                "trust_assessment": report.assessment.to_dict(),
                "citations": [
                    {
                        "url": citation.url,
                        "title": citation.title,
                        "domain": citation.domain,
                        "trust_tier": citation.trust_tier,
                        "source_type": citation.source_type,
                        "published_at": citation.published_at,
                        "freshness_window_days": citation.freshness_window_days,
                        "age_days": citation.age_days,
                        "is_fresh": citation.is_fresh,
                    }
                    for citation in report.citations
                ],
            },
        )
        return result

    def _check_legislative_review(self, spec: AgentSpec) -> CheckResult:
        settings = spec.legislative_review
        if not settings.enabled:
            result = CheckResult(
                name="legislative_review_gate",
                passed=True,
                message="Legislative review is disabled.",
            )
            self.evidence_store.append(result.name, "pass", {"enabled": False})
            return result

        jurisdictions = tuple(item.strip() for item in spec.legal_context.jurisdictions if item.strip())
        if not jurisdictions:
            result = CheckResult(
                name="legislative_review_gate",
                passed=False,
                message="Legislative review jurisdictions must not be empty.",
            )
            self.evidence_store.append(result.name, "fail", {"enabled": True, "reason": "missing_jurisdictions"})
            return result

        jurisdiction_reports: list[tuple[str, LiveDataReport]] = []
        jurisdiction_errors: list[dict[str, str]] = []

        for jurisdiction in jurisdictions:
            normalized = jurisdiction.lower()
            trust_profile_id = ""
            if normalized in {"united kingdom", "uk"}:
                trust_profile_id = settings.united_kingdom_trust_profile_id.strip()
            elif normalized in {"european union", "eu"}:
                trust_profile_id = settings.european_union_trust_profile_id.strip()

            if not trust_profile_id:
                error = f"Unsupported legislative jurisdiction '{jurisdiction}'."
                jurisdiction_errors.append({"jurisdiction": jurisdiction, "error": error})
                self.evidence_store.append(
                    "legislative_review.intelligence",
                    "fail",
                    {
                        "jurisdiction": jurisdiction,
                        "error": error,
                        "error_type": "configuration",
                    },
                )
                continue

            target_date = spec.legal_context.compliance_target_date.strip() or "2026-08-02"
            use_statement = spec.legal_context.intended_use.strip() or spec.description.strip()
            query_parts = [
                f"{jurisdiction} legal and regulatory obligations",
                f"intended use: {use_statement}",
                f"compliance target date: {target_date}",
            ]
            if spec.legal_context.sector.strip():
                query_parts.append(f"sector: {spec.legal_context.sector.strip()}")
            if spec.legal_context.data_categories:
                query_parts.append("data categories: " + ", ".join(spec.legal_context.data_categories))
            query = " | ".join(query_parts)

            live_settings = LiveDataSettings(
                enabled=True,
                provider=settings.provider,
                model=settings.model,
                max_results=settings.max_results,
                min_citations=settings.min_citations,
                timeout_seconds=settings.timeout_seconds,
                strict=settings.strict,
                trust_profile_id=trust_profile_id,
                trust_profile_file=settings.trust_profile_file,
            )

            try:
                report = self.intelligence_client.collect_latest(
                    query=query,
                    settings=live_settings,
                    risk_level=spec.risk_level,
                )
            except LiveDataError as exc:
                attempt_details = _live_data_attempt_details(exc)
                latest_citation_count = _last_attempt_citation_count(attempt_details)
                error_type = "provider"
                if isinstance(exc, LiveDataConfigurationError):
                    error_type = "configuration"
                jurisdiction_errors.append({"jurisdiction": jurisdiction, "error": str(exc)})
                self.evidence_store.append(
                    "legislative_review.intelligence",
                    "fail",
                    {
                        "jurisdiction": jurisdiction,
                        "provider": settings.provider,
                        "model": settings.model,
                        "query": query,
                        "strict": settings.strict,
                        "error": str(exc),
                        "error_type": error_type,
                        "attempts": attempt_details,
                        "citation_count": latest_citation_count,
                    },
                )
                continue

            jurisdiction_reports.append((jurisdiction, report))
            self.evidence_store.append(
                "legislative_review.intelligence",
                "pass",
                {
                    "jurisdiction": jurisdiction,
                    "provider": report.provider,
                    "model": report.model,
                    "query": report.query,
                    "fetched_at": report.fetched_at,
                    "citation_count": len(report.citations),
                    "attempts": [item.to_dict() for item in report.attempts],
                    "trust_assessment": report.assessment.to_dict(),
                    "citations": [
                        {
                            "url": citation.url,
                            "title": citation.title,
                            "domain": citation.domain,
                            "trust_tier": citation.trust_tier,
                            "source_type": citation.source_type,
                            "published_at": citation.published_at,
                            "freshness_window_days": citation.freshness_window_days,
                            "age_days": citation.age_days,
                            "is_fresh": citation.is_fresh,
                        }
                        for citation in report.citations
                    ],
                },
            )

        artifacts = resolve_legislative_review_artifacts(
            spec=spec,
            evidence_path=self.evidence_store.path,
        )
        pack = build_legislative_review_pack(
            spec=spec,
            jurisdiction_reports=tuple(jurisdiction_reports),
        )
        if jurisdiction_errors:
            pack["jurisdiction_errors"] = jurisdiction_errors
        pack_sha256 = payload_sha256(pack)

        artifacts.pack_path.parent.mkdir(parents=True, exist_ok=True)
        artifacts.pack_path.write_text(json.dumps(pack, indent=2) + "\n", encoding="utf-8")
        self.evidence_store.append(
            "legislative_review.pack.created",
            "pass",
            {
                "pack_path": artifacts.pack_path,
                "pack_sha256": pack_sha256,
                "jurisdiction_count": len(jurisdictions),
                "report_count": len(jurisdiction_reports),
            },
        )

        if settings.require_human_decision:
            if not artifacts.decision_path.exists():
                template = build_legislative_decision_template(
                    spec=spec,
                    pack_sha256=pack_sha256,
                    jurisdictions=jurisdictions,
                )
                artifacts.decision_path.parent.mkdir(parents=True, exist_ok=True)
                artifacts.decision_path.write_text(
                    json.dumps(template, indent=2) + "\n",
                    encoding="utf-8",
                )
                self.evidence_store.append(
                    "legislative_review.decision.checked",
                    "fail",
                    {
                        "decision_path": artifacts.decision_path,
                        "reason": "missing_decision_file",
                        "template_created": True,
                    },
                )
                result = CheckResult(
                    name="legislative_review_gate",
                    passed=False,
                    message=f"Legislative decision file is required: {artifacts.decision_path}",
                )
                self.evidence_store.append(
                    result.name,
                    "fail",
                    {
                        "enabled": True,
                        "decision_path": artifacts.decision_path,
                        "pack_path": artifacts.pack_path,
                        "pack_sha256": pack_sha256,
                    },
                )
                return result

            try:
                decision_payload = load_json_file(artifacts.decision_path)
                decision = validate_legislative_decision(
                    payload=decision_payload,
                    spec=spec,
                    required_jurisdictions=jurisdictions,
                )
            except LegislativeReviewError as exc:
                self.evidence_store.append(
                    "legislative_review.decision.checked",
                    "fail",
                    {
                        "decision_path": artifacts.decision_path,
                        "error": str(exc),
                    },
                )
                result = CheckResult(
                    name="legislative_review_gate",
                    passed=False,
                    message=str(exc),
                )
                self.evidence_store.append(result.name, "fail", {"enabled": True, "error": str(exc)})
                return result

            if decision.get("decision") != "accept":
                message = (
                    "Legislative decision must be accept to pass verification. "
                    f"Found decision={decision.get('decision')!r}."
                )
                self.evidence_store.append(
                    "legislative_review.decision.checked",
                    "fail",
                    {
                        "decision_path": artifacts.decision_path,
                        "decision": decision.get("decision"),
                        "reviewed_by": decision.get("reviewed_by"),
                        "review_id": decision.get("review_id"),
                        "reviewed_at": decision.get("reviewed_at"),
                    },
                )
                result = CheckResult(
                    name="legislative_review_gate",
                    passed=False,
                    message=message,
                )
                self.evidence_store.append(result.name, "fail", {"enabled": True, "decision": decision.get("decision")})
                return result

            self.evidence_store.append(
                "legislative_review.decision.checked",
                "pass",
                {
                    "decision_path": artifacts.decision_path,
                    "decision": decision.get("decision"),
                    "reviewed_by": decision.get("reviewed_by"),
                    "review_id": decision.get("review_id"),
                    "reviewed_at": decision.get("reviewed_at"),
                },
            )

        intelligence_ok = not jurisdiction_errors and len(jurisdiction_reports) == len(jurisdictions)
        if not intelligence_ok:
            if settings.strict:
                message = "Legislative intelligence failed: " + "; ".join(
                    item.get("error", "") for item in jurisdiction_errors if item.get("error")
                )
                result = CheckResult(
                    name="legislative_review_gate",
                    passed=False,
                    message=message.strip(),
                )
                self.evidence_store.append(
                    result.name,
                    "fail",
                    {
                        "enabled": True,
                        "strict": settings.strict,
                        "jurisdiction_errors": jurisdiction_errors,
                    },
                )
                return result

            if spec.risk_level in {"medium", "high"}:
                message = (
                    "Legislative intelligence failed and non-strict mode is not allowed for "
                    f"risk level '{spec.risk_level}'."
                )
                result = CheckResult(
                    name="legislative_review_gate",
                    passed=False,
                    message=message,
                )
                self.evidence_store.append(
                    result.name,
                    "fail",
                    {
                        "enabled": True,
                        "strict": settings.strict,
                        "strict_required_by_risk": True,
                        "jurisdiction_errors": jurisdiction_errors,
                    },
                )
                return result

            warning = "; ".join(item.get("error", "") for item in jurisdiction_errors if item.get("error"))
            result = CheckResult(
                name="legislative_review_gate",
                passed=True,
                message=(
                    "Legislative intelligence failed but strict mode is disabled: "
                    + warning
                ).strip(),
            )
            self.evidence_store.append(
                result.name,
                "pass",
                {
                    "enabled": True,
                    "strict": settings.strict,
                    "strict_required_by_risk": False,
                    "warning": warning,
                    "jurisdiction_errors": jurisdiction_errors,
                },
            )
            return result

        result = CheckResult(
            name="legislative_review_gate",
            passed=True,
            message="Legislative intelligence and decision gate satisfied.",
        )
        self.evidence_store.append(
            result.name,
            "pass",
            {
                "enabled": True,
                "strict": settings.strict,
                "jurisdiction_count": len(jurisdictions),
                "report_count": len(jurisdiction_reports),
                "pack_path": artifacts.pack_path,
                "decision_required": settings.require_human_decision,
            },
        )
        return result

    def _reuse_live_intelligence_event(
        self,
        *,
        provider: str,
        model: str,
        query: str,
        max_age: timedelta = timedelta(hours=1),
    ) -> dict[str, object] | None:
        path = self.evidence_store.path
        if not path.exists():
            return None

        now = datetime.now(timezone.utc)
        candidate: dict[str, object] | None = None

        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                cleaned = line.strip()
                if not cleaned:
                    continue
                try:
                    record = json.loads(cleaned)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                if record.get("event_type") != "live_intelligence_freshness":
                    continue
                if str(record.get("status", "")).lower() != "pass":
                    continue

                details = record.get("details")
                if not isinstance(details, dict):
                    continue
                if details.get("provider") != provider:
                    continue
                if details.get("model") != model:
                    continue
                if details.get("query") != query:
                    continue
                if not isinstance(details.get("trust_assessment"), dict):
                    continue

                fetched_at = details.get("fetched_at")
                if isinstance(fetched_at, str) and fetched_at.strip():
                    try:
                        fetched_time = datetime.fromisoformat(fetched_at.strip())
                    except ValueError:
                        fetched_time = None
                    if fetched_time is not None:
                        if fetched_time.tzinfo is None:
                            fetched_time = fetched_time.replace(tzinfo=timezone.utc)
                        if now - fetched_time > max_age:
                            continue

                candidate = details

        return candidate

    def _check_adapter_module_readiness(self) -> CheckResult:
        statuses = self.adapter_layer.list_module_status()
        unavailable = [status for status in statuses if not status.available]
        if unavailable:
            message = (
                "Adapter modules unavailable: "
                + ", ".join(f"{status.adapter_name} ({status.detail})" for status in unavailable)
            )
            result = CheckResult(
                name="adapter_module_readiness",
                passed=False,
                message=message,
            )
            self.evidence_store.append(
                result.name,
                "fail",
                {
                    "unavailable": [
                        {
                            "adapter_name": status.adapter_name,
                            "module_path": status.module_path,
                            "detail": status.detail,
                        }
                        for status in unavailable
                    ]
                },
            )
            return result

        result = CheckResult(
            name="adapter_module_readiness",
            passed=True,
            message="Adapter module readiness satisfied.",
        )
        self.evidence_store.append(
            result.name,
            "pass",
            {
                "available_modules": [status.adapter_name for status in statuses],
            },
        )
        return result

    def _check_model_context_protocol_gating(self, spec: AgentSpec) -> CheckResult:
        adapter = ModelContextProtocolCompatibilityAdapter()
        export_action_name = "mcp.export.agent_spec"
        export_result = adapter.execute_action(
            AdapterActionRequest(
                action_name=export_action_name,
                payload={
                    "agent_spec": spec.to_dict(),
                    "server_name": f"{spec.name}-server",
                    "server_version": "1.0.0",
                    "trust_profile_id": _default_protocol_trust_profile_id(spec),
                },
            )
        )
        if not export_result.ok:
            export_errors = [error.to_dict() for error in export_result.errors]
            self.evidence_store.append(
                "model_context_protocol_gating.export",
                "fail",
                {
                    "action_name": export_action_name,
                    "contract_version": export_result.contract_version,
                    "errors": export_errors,
                },
            )
            self.evidence_store.append(
                "model_context_protocol_gating.final",
                "fail",
                {
                    "reason": "export_action_failed",
                    "errors": export_errors,
                },
            )
            return CheckResult(
                name="model_context_protocol_gating",
                passed=False,
                message="Model Context Protocol export gating action failed.",
            )

        server_bundle = export_result.output.get("server_bundle")
        if not isinstance(server_bundle, dict):
            self.evidence_store.append(
                "model_context_protocol_gating.export",
                "fail",
                {
                    "action_name": export_action_name,
                    "reason": "missing_server_bundle",
                },
            )
            self.evidence_store.append(
                "model_context_protocol_gating.final",
                "fail",
                {
                    "reason": "missing_server_bundle",
                },
            )
            return CheckResult(
                name="model_context_protocol_gating",
                passed=False,
                message="Model Context Protocol export did not return server bundle.",
            )

        server_payload = server_bundle.get("server")
        server_name = ""
        server_version = ""
        trust_profile_id = ""
        if isinstance(server_payload, dict):
            server_name = str(server_payload.get("server_name", "")).strip()
            server_version = str(server_payload.get("server_version", "")).strip()
            trust_profile_id = str(server_payload.get("trust_profile_id", "")).strip()

        self.evidence_store.append(
            "model_context_protocol_gating.export",
            "pass",
            {
                "action_name": export_action_name,
                "contract_version": export_result.contract_version,
                "server_name": server_name,
                "server_version": server_version,
                "trust_profile_id": trust_profile_id,
            },
        )

        import_action_name = "mcp.import.server_bundle"
        import_result = adapter.execute_action(
            AdapterActionRequest(
                action_name=import_action_name,
                payload={"server_bundle": server_bundle},
            )
        )
        if not import_result.ok:
            import_errors = [error.to_dict() for error in import_result.errors]
            self.evidence_store.append(
                "model_context_protocol_gating.import",
                "fail",
                {
                    "action_name": import_action_name,
                    "contract_version": import_result.contract_version,
                    "errors": import_errors,
                },
            )
            self.evidence_store.append(
                "model_context_protocol_gating.final",
                "fail",
                {
                    "reason": "import_action_failed",
                    "errors": import_errors,
                },
            )
            return CheckResult(
                name="model_context_protocol_gating",
                passed=False,
                message="Model Context Protocol import gating action failed.",
            )

        gating_payload = import_result.output.get("gating")
        if not isinstance(gating_payload, dict):
            self.evidence_store.append(
                "model_context_protocol_gating.import",
                "fail",
                {
                    "action_name": import_action_name,
                    "reason": "missing_gating_payload",
                },
            )
            self.evidence_store.append(
                "model_context_protocol_gating.final",
                "fail",
                {"reason": "missing_gating_payload"},
            )
            return CheckResult(
                name="model_context_protocol_gating",
                passed=False,
                message="Model Context Protocol import did not return gating metadata.",
            )

        imported_tools = import_result.output.get("tools")
        imported_tool_count = len(imported_tools) if isinstance(imported_tools, list) else 0
        self.evidence_store.append(
            "model_context_protocol_gating.import",
            "pass",
            {
                "action_name": import_action_name,
                "contract_version": import_result.contract_version,
                "imported_tool_count": imported_tool_count,
            },
        )

        decision_records = (
            (
                "version_pinned",
                bool(gating_payload.get("version_pinned", False)),
                "Server version must be pinned.",
            ),
            (
                "trust_profile_required",
                bool(gating_payload.get("trust_profile_required", False)),
                "Trust profile must be required.",
            ),
            (
                "default_deny",
                bool(gating_payload.get("default_deny", False)),
                "Protocol adapter must enforce default deny behavior.",
            ),
            (
                "host_allow_list_required_for_network_tools",
                bool(gating_payload.get("host_allow_list_required_for_network_tools", False)),
                "Network tools must require host allow list metadata.",
            ),
            (
                "startup_commands_blocked",
                bool(gating_payload.get("startup_commands_blocked", False)),
                "Local startup command execution must be blocked.",
            ),
            (
                "advisory_only_rejected",
                not bool(gating_payload.get("advisory_only", True)),
                "Advisory-only protocol checks are not allowed.",
            ),
            (
                "tool_count_preserved",
                imported_tool_count == len(spec.tools),
                "Imported tool count must match specification tool count.",
            ),
        )
        failed_decisions = [item for item in decision_records if not item[1]]
        for decision_name, decision_passed, decision_requirement in decision_records:
            self.evidence_store.append(
                "model_context_protocol_gating.decision",
                "pass" if decision_passed else "fail",
                {
                    "decision_name": decision_name,
                    "requirement": decision_requirement,
                    "decision_value": decision_passed,
                    "server_name": str(gating_payload.get("server_name", "")).strip(),
                    "server_version": str(gating_payload.get("server_version", "")).strip(),
                    "trust_profile_id": str(gating_payload.get("trust_profile_id", "")).strip(),
                },
            )

        overall_pass = not failed_decisions
        self.evidence_store.append(
            "model_context_protocol_gating.final",
            "pass" if overall_pass else "fail",
            {
                "failed_decisions": [item[0] for item in failed_decisions],
                "server_name": str(gating_payload.get("server_name", "")).strip(),
                "server_version": str(gating_payload.get("server_version", "")).strip(),
                "trust_profile_id": str(gating_payload.get("trust_profile_id", "")).strip(),
            },
        )
        if not overall_pass:
            return CheckResult(
                name="model_context_protocol_gating",
                passed=False,
                message=(
                    "Model Context Protocol gating decisions failed: "
                    + ", ".join(item[0] for item in failed_decisions)
                ),
            )

        return CheckResult(
            name="model_context_protocol_gating",
            passed=True,
            message="Model Context Protocol gating decisions satisfied.",
        )

    def _check_adapter_security_preflight(self) -> CheckResult:
        error = self.adapter_layer.run_security_preflight(self.repo_path)
        if error:
            result = CheckResult(
                name="adapter_security_preflight",
                passed=False,
                message=error,
            )
            self.evidence_store.append(
                result.name,
                "fail",
                {
                    "repo_path": str(self.repo_path) if self.repo_path else None,
                    "error": error,
                },
            )
            return result

        result = CheckResult(
            name="adapter_security_preflight",
            passed=True,
            message="Security preflight satisfied.",
        )
        self.evidence_store.append(
            result.name,
            "pass",
            {"repo_path": str(self.repo_path) if self.repo_path else None},
        )
        return result

    def _check_runtime_environment(self, spec: AgentSpec) -> CheckResult:
        network_tools = any(tool.can_access_network for tool in spec.tools)
        if network_tools and spec.runtime_environment != "container":
            result = CheckResult(
                name="runtime_environment_guardrail",
                passed=False,
                message="Network-enabled tools must run in container environment.",
            )
            self.evidence_store.append(
                result.name,
                "fail",
                {
                    "runtime_environment": spec.runtime_environment,
                    "network_tools_present": True,
                },
            )
            return result

        if spec.risk_level == "high" and spec.runtime_environment != "container":
            result = CheckResult(
                name="runtime_environment_guardrail",
                passed=False,
                message="High-risk agents must run in container environment.",
            )
            self.evidence_store.append(
                result.name,
                "fail",
                {"runtime_environment": spec.runtime_environment},
            )
            return result

        result = CheckResult(
            name="runtime_environment_guardrail",
            passed=True,
            message="Runtime environment guardrail satisfied.",
        )
        self.evidence_store.append(
            result.name,
            "pass",
            {
                "runtime_environment": spec.runtime_environment,
                "network_tools_present": network_tools,
            },
        )
        return result

    def _check_budget(self, spec: AgentSpec) -> CheckResult:
        cap = _BUDGET_CAP_USD[spec.risk_level]
        if spec.budget_limit_usd > cap:
            result = CheckResult(
                name="budget_guardrail",
                passed=False,
                message=(
                    f"budget_limit_usd={spec.budget_limit_usd} exceeds "
                    f"risk cap {cap} for {spec.risk_level}."
                ),
            )
            self.evidence_store.append(
                result.name,
                "fail",
                {"budget_limit_usd": spec.budget_limit_usd, "risk_cap_usd": cap},
            )
            return result

        result = CheckResult(
            name="budget_guardrail",
            passed=True,
            message="Budget cap satisfied.",
        )
        self.evidence_store.append(result.name, "pass", {"risk_cap_usd": cap})
        return result

    def _check_runtime(self, spec: AgentSpec) -> CheckResult:
        if spec.max_runtime_seconds > 7_200:
            result = CheckResult(
                name="runtime_guardrail",
                passed=False,
                message="max_runtime_seconds exceeds 7200-second guardrail.",
            )
            self.evidence_store.append(
                result.name,
                "fail",
                {"max_runtime_seconds": spec.max_runtime_seconds},
            )
            return result

        result = CheckResult(
            name="runtime_guardrail",
            passed=True,
            message="Runtime guardrail satisfied.",
        )
        self.evidence_store.append(
            result.name,
            "pass",
            {"max_runtime_seconds": spec.max_runtime_seconds},
        )
        return result

    def _check_adversarial_resilience(
        self, spec: AgentSpec, policy: CompiledPolicy | None
    ) -> CheckResult:
        if policy is None:
            result = CheckResult(
                name="adversarial_resilience",
                passed=False,
                message="Adversarial pack skipped because policy compilation failed.",
            )
            self.evidence_store.append(
                result.name,
                "fail",
                {"reason": "missing_policy"},
            )
            return result

        report = evaluate_adversarial_pack(spec=spec, policy=policy)
        run_record = self.adversarial_report_store.record(spec=spec, report=report)
        result = CheckResult(
            name="adversarial_resilience",
            passed=report.passed,
            message=(
                f"{report.to_message()} "
                f"history_count={run_record.history_count} "
                f"rolling_last_10={run_record.rolling_pass_rate_last_10:.2f}"
            ),
        )
        self.evidence_store.append(
            result.name,
            "pass" if result.passed else "fail",
            {
                "pass_rate": report.pass_rate,
                "threshold": report.threshold,
                "passed_cases": report.passed_cases,
                "total_cases": report.total_cases,
                "failed_case_ids": list(report.failed_case_ids),
                "artifact_path": str(run_record.artifact_path),
                "history_path": str(run_record.history_path),
                "history_count": run_record.history_count,
                "rolling_pass_rate_last_10": run_record.rolling_pass_rate_last_10,
                "pass_rate_delta_from_previous": run_record.pass_rate_delta_from_previous,
                "failing_streak": run_record.failing_streak,
            },
        )
        return result


def _live_data_attempt_details(exc: LiveDataError) -> list[dict[str, object]]:
    if not isinstance(exc, LiveDataValidationError):
        return []
    raw_attempts = getattr(exc, "attempts", ())
    if not isinstance(raw_attempts, tuple):
        return []
    payload: list[dict[str, object]] = []
    for item in raw_attempts:
        to_dict = getattr(item, "to_dict", None)
        if not callable(to_dict):
            continue
        item_payload = to_dict()
        if isinstance(item_payload, dict):
            payload.append(dict(item_payload))
    return payload


def _last_attempt_citation_count(attempts: list[dict[str, object]]) -> int:
    if not attempts:
        return 0
    raw_value = attempts[-1].get("citation_count")
    try:
        return int(raw_value)
    except (TypeError, ValueError):
        return 0


def default_pipeline(
    evidence_path: str | Path,
    repo_path: str | Path | None = None,
    adapter_layer: LifeguardExtractsAdapterLayer | None = None,
    intelligence_client: LiveIntelligenceClient | None = None,
) -> VerificationPipeline:
    resolved_repo_path = Path(repo_path) if repo_path is not None else None
    return VerificationPipeline(
        EvidenceStore(evidence_path),
        adapter_layer=adapter_layer,
        repo_path=resolved_repo_path,
        intelligence_client=intelligence_client,
    )


def _default_protocol_trust_profile_id(spec: AgentSpec) -> str:
    explicit = spec.live_data.trust_profile_id.strip()
    if explicit:
        return explicit
    profile_id = (spec.profile_id or "custom").strip() or "custom"
    return f"profile_{profile_id}"
