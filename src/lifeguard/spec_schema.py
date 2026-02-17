from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class ConfigValidationError(ValueError):
    """Raised when the agent specification is invalid."""


VALID_RISK_LEVELS = {"low", "medium", "high"}
VALID_RUNTIME_ENVIRONMENTS = {"local", "container", "continuous_integration"}
VALID_DESIGN_METHODS = {"deterministic"}
VALID_LIVE_DATA_PROVIDERS = {"openrouter", "openai", "anthropic"}
VALID_PROFILE_IDS = {"custom"}
VALID_DECISION_IMPACT_LEVELS = {"low", "medium", "high"}

_QUALITY_THRESHOLD_BY_RISK = {"low": 70, "medium": 80, "high": 90}


@dataclass(frozen=True)
class ToolSpec:
    name: str
    command: str
    can_write_files: bool = False
    can_access_network: bool = False
    timeout_seconds: int = 30

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ConfigValidationError("Tool name must not be empty.")
        if not self.command.strip():
            raise ConfigValidationError(f"Tool '{self.name}' command must not be empty.")
        if "\n" in self.command:
            raise ConfigValidationError(f"Tool '{self.name}' command must be single-line.")
        if self.timeout_seconds <= 0:
            raise ConfigValidationError(f"Tool '{self.name}' timeout must be positive.")
        if self.timeout_seconds > 600:
            raise ConfigValidationError(
                f"Tool '{self.name}' timeout exceeds 600 seconds security ceiling."
            )


@dataclass(frozen=True)
class DataScope:
    read_paths: tuple[str, ...] = ()
    write_paths: tuple[str, ...] = ()
    allowed_hosts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for path in (*self.read_paths, *self.write_paths):
            if not path.startswith("/"):
                raise ConfigValidationError(
                    f"Path '{path}' must be absolute for explicit security scoping."
                )
        for host in self.allowed_hosts:
            cleaned = host.strip()
            if not cleaned:
                raise ConfigValidationError("Allowed hosts must not be empty.")
            if " " in cleaned:
                raise ConfigValidationError(
                    f"Allowed host '{host}' must not contain whitespace."
                )


@dataclass(frozen=True)
class SecurityRequirements:
    goals: tuple[str, ...] = ()
    threat_actors: tuple[str, ...] = ()
    evidence_requirements: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_line_entries(self.goals, "security_requirements.goals")
        _validate_line_entries(self.threat_actors, "security_requirements.threat_actors")
        _validate_line_entries(
            self.evidence_requirements,
            "security_requirements.evidence_requirements",
        )


@dataclass(frozen=True)
class LegalContext:
    jurisdictions: tuple[str, ...] = ("United Kingdom", "European Union")
    intended_use: str = ""
    sector: str = ""
    decision_impact_level: str = "medium"
    compliance_target_date: str = ""
    data_categories: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.jurisdictions:
            raise ConfigValidationError("legal_context.jurisdictions must not be empty.")
        _validate_line_entries(self.jurisdictions, "legal_context.jurisdictions")
        _validate_line_entries(self.data_categories, "legal_context.data_categories")

        for value, name in (
            (self.intended_use, "legal_context.intended_use"),
            (self.sector, "legal_context.sector"),
            (self.decision_impact_level, "legal_context.decision_impact_level"),
            (self.compliance_target_date, "legal_context.compliance_target_date"),
        ):
            if "\n" in value:
                raise ConfigValidationError(f"{name} must be a single line.")

        impact = self.decision_impact_level.strip().lower()
        if impact and impact not in VALID_DECISION_IMPACT_LEVELS:
            raise ConfigValidationError(
                "legal_context.decision_impact_level must be one of "
                f"{sorted(VALID_DECISION_IMPACT_LEVELS)}."
            )

        if self.compliance_target_date.strip():
            cleaned = self.compliance_target_date.strip()
            # ISO date only (YYYY-MM-DD) keeps this strict and deterministic.
            if len(cleaned) != 10 or cleaned[4] != "-" or cleaned[7] != "-":
                raise ConfigValidationError(
                    "legal_context.compliance_target_date must be an ISO date (YYYY-MM-DD)."
                )


@dataclass(frozen=True)
class LiveDataSettings:
    enabled: bool = False
    provider: str = "openrouter"
    model: str = "openai/gpt-5.2:online"
    max_results: int = 5
    min_citations: int = 2
    timeout_seconds: int = 45
    query: str = ""
    trust_profile_id: str = ""
    trust_profile_file: str = ""
    allowed_domains: tuple[str, ...] = ()
    high_trust_domains: tuple[str, ...] = ()
    medium_trust_domains: tuple[str, ...] = ()
    min_trusted_citations: int = 0
    min_independent_trusted_domains: int = 0
    enforce_freshness: bool = True
    require_publication_dates: bool = False
    freshness_days_news: int = 30
    freshness_days_official_docs: int = 365
    freshness_days_security_advisory: int = 180
    freshness_days_general: int = 120
    strict: bool = True

    def __post_init__(self) -> None:
        if self.provider not in VALID_LIVE_DATA_PROVIDERS:
            raise ConfigValidationError(
                "live_data.provider must be one of "
                f"{sorted(VALID_LIVE_DATA_PROVIDERS)}."
            )
        if not self.model.strip():
            raise ConfigValidationError("live_data.model must not be empty.")
        if self.max_results < 1 or self.max_results > 10:
            raise ConfigValidationError("live_data.max_results must be between 1 and 10.")
        if self.min_citations < 1:
            raise ConfigValidationError("live_data.min_citations must be at least 1.")
        if self.min_citations > self.max_results:
            raise ConfigValidationError(
                "live_data.min_citations must be less than or equal to live_data.max_results."
            )
        if self.min_trusted_citations < 0:
            raise ConfigValidationError("live_data.min_trusted_citations must be at least 0.")
        if self.min_trusted_citations > self.max_results:
            raise ConfigValidationError(
                "live_data.min_trusted_citations must be less than or equal to live_data.max_results."
            )
        if self.min_independent_trusted_domains < 0:
            raise ConfigValidationError(
                "live_data.min_independent_trusted_domains must be at least 0."
            )
        if self.min_independent_trusted_domains > self.max_results:
            raise ConfigValidationError(
                "live_data.min_independent_trusted_domains must be less than or equal to live_data.max_results."
            )
        if self.timeout_seconds < 5 or self.timeout_seconds > 120:
            raise ConfigValidationError("live_data.timeout_seconds must be between 5 and 120.")
        if "\n" in self.query:
            raise ConfigValidationError("live_data.query must be a single line.")
        if "\n" in self.trust_profile_id:
            raise ConfigValidationError("live_data.trust_profile_id must be a single line.")
        if "\n" in self.trust_profile_file:
            raise ConfigValidationError("live_data.trust_profile_file must be a single line.")
        for host in (*self.allowed_domains, *self.high_trust_domains, *self.medium_trust_domains):
            cleaned = host.strip()
            if not cleaned:
                raise ConfigValidationError("live_data trust source domains must not be empty.")
            if " " in cleaned:
                raise ConfigValidationError(
                    f"live_data.allowed_domain '{host}' must not contain whitespace."
                )
        overlap = set(self.high_trust_domains) & set(self.medium_trust_domains)
        if overlap:
            raise ConfigValidationError(
                "live_data.high_trust_domains and live_data.medium_trust_domains must not overlap."
            )
        freshness_windows = (
            self.freshness_days_news,
            self.freshness_days_official_docs,
            self.freshness_days_security_advisory,
            self.freshness_days_general,
        )
        for value in freshness_windows:
            if value < 1 or value > 3650:
                raise ConfigValidationError(
                    "live_data freshness windows must be between 1 and 3650 days."
                )


@dataclass(frozen=True)
class LegislativeReviewSettings:
    enabled: bool = False
    provider: str = "openrouter"
    model: str = "openai/gpt-5.2:online"
    max_results: int = 6
    min_citations: int = 2
    timeout_seconds: int = 60
    trust_profile_file: str = ""
    united_kingdom_trust_profile_id: str = "legislation_united_kingdom_primary"
    european_union_trust_profile_id: str = "legislation_european_union_primary"
    strict: bool = True
    require_human_decision: bool = True
    decision_file: str = ""

    def __post_init__(self) -> None:
        if self.provider not in VALID_LIVE_DATA_PROVIDERS:
            raise ConfigValidationError(
                "legislative_review.provider must be one of "
                f"{sorted(VALID_LIVE_DATA_PROVIDERS)}."
            )
        if not self.model.strip():
            raise ConfigValidationError("legislative_review.model must not be empty.")
        if self.max_results < 1 or self.max_results > 10:
            raise ConfigValidationError(
                "legislative_review.max_results must be between 1 and 10."
            )
        if self.min_citations < 1:
            raise ConfigValidationError(
                "legislative_review.min_citations must be at least 1."
            )
        if self.min_citations > self.max_results:
            raise ConfigValidationError(
                "legislative_review.min_citations must be less than or equal to legislative_review.max_results."
            )
        if self.timeout_seconds < 5 or self.timeout_seconds > 180:
            raise ConfigValidationError(
                "legislative_review.timeout_seconds must be between 5 and 180."
            )
        for value, name in (
            (self.trust_profile_file, "legislative_review.trust_profile_file"),
            (
                self.united_kingdom_trust_profile_id,
                "legislative_review.united_kingdom_trust_profile_id",
            ),
            (
                self.european_union_trust_profile_id,
                "legislative_review.european_union_trust_profile_id",
            ),
            (self.decision_file, "legislative_review.decision_file"),
        ):
            if "\n" in value:
                raise ConfigValidationError(f"{name} must be a single line.")


@dataclass(frozen=True)
class AgentSpec:
    name: str
    description: str
    risk_level: str
    tools: tuple[ToolSpec, ...]
    data_scope: DataScope
    runtime_environment: str
    budget_limit_usd: float
    max_runtime_seconds: int
    design_method: str = "deterministic"
    profile_id: str = "custom"
    security_requirements: SecurityRequirements = field(default_factory=SecurityRequirements)
    legal_context: LegalContext = field(default_factory=LegalContext)
    legislative_review: LegislativeReviewSettings = field(default_factory=LegislativeReviewSettings)
    live_data: LiveDataSettings = field(default_factory=LiveDataSettings)

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ConfigValidationError("Agent name must not be empty.")
        if not self.description.strip():
            raise ConfigValidationError("Agent description must not be empty.")
        if self.risk_level not in VALID_RISK_LEVELS:
            raise ConfigValidationError(
                f"risk_level must be one of {sorted(VALID_RISK_LEVELS)}."
            )
        if self.runtime_environment not in VALID_RUNTIME_ENVIRONMENTS:
            raise ConfigValidationError(
                "runtime_environment must be one of "
                f"{sorted(VALID_RUNTIME_ENVIRONMENTS)}."
            )
        if self.design_method not in VALID_DESIGN_METHODS:
            raise ConfigValidationError(
                f"design_method must be one of {sorted(VALID_DESIGN_METHODS)}."
            )
        if self.profile_id not in VALID_PROFILE_IDS:
            raise ConfigValidationError(
                f"profile_id must be one of {sorted(VALID_PROFILE_IDS)}."
            )
        if not self.tools:
            raise ConfigValidationError("At least one tool must be declared.")
        if self.budget_limit_usd <= 0:
            raise ConfigValidationError("budget_limit_usd must be positive.")
        if self.budget_limit_usd > 10_000:
            raise ConfigValidationError("budget_limit_usd exceeds 10,000 cap.")
        if self.max_runtime_seconds <= 0:
            raise ConfigValidationError("max_runtime_seconds must be positive.")
        if self.max_runtime_seconds > 86_400:
            raise ConfigValidationError("max_runtime_seconds exceeds 24-hour cap.")

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> AgentSpec:
        tools_payload = payload.get("tools")
        if not isinstance(tools_payload, list):
            raise ConfigValidationError("'tools' must be a list.")

        tools: list[ToolSpec] = []
        for tool_payload in tools_payload:
            if not isinstance(tool_payload, dict):
                raise ConfigValidationError("Each tool entry must be an object.")
            tools.append(
                ToolSpec(
                    name=str(tool_payload.get("name", "")).strip(),
                    command=str(tool_payload.get("command", "")).strip(),
                    can_write_files=bool(tool_payload.get("can_write_files", False)),
                    can_access_network=bool(tool_payload.get("can_access_network", False)),
                    timeout_seconds=int(tool_payload.get("timeout_seconds", 30)),
                )
            )

        data_scope_payload = payload.get("data_scope", {})
        if not isinstance(data_scope_payload, dict):
            raise ConfigValidationError("'data_scope' must be an object.")

        data_scope = DataScope(
            read_paths=tuple(str(p) for p in data_scope_payload.get("read_paths", [])),
            write_paths=tuple(str(p) for p in data_scope_payload.get("write_paths", [])),
            allowed_hosts=tuple(str(h) for h in data_scope_payload.get("allowed_hosts", [])),
        )

        legal_payload = payload.get("legal_context", {})
        if not isinstance(legal_payload, dict):
            raise ConfigValidationError("'legal_context' must be an object.")
        jurisdictions_raw = tuple(str(item).strip() for item in legal_payload.get("jurisdictions", []))
        legal_context = LegalContext(
            jurisdictions=jurisdictions_raw or LegalContext().jurisdictions,
            intended_use=str(legal_payload.get("intended_use", "")).strip(),
            sector=str(legal_payload.get("sector", "")).strip(),
            decision_impact_level=str(legal_payload.get("decision_impact_level", "medium")).strip(),
            compliance_target_date=str(legal_payload.get("compliance_target_date", "")).strip(),
            data_categories=tuple(
                str(item).strip()
                for item in legal_payload.get("data_categories", [])
            ),
        )

        legislative_payload = payload.get("legislative_review", {})
        if not isinstance(legislative_payload, dict):
            raise ConfigValidationError("'legislative_review' must be an object.")
        legislative_review = LegislativeReviewSettings(
            enabled=bool(legislative_payload.get("enabled", False)),
            provider=str(legislative_payload.get("provider", "openrouter")).strip(),
            model=str(legislative_payload.get("model", "openai/gpt-5.2:online")).strip(),
            max_results=int(legislative_payload.get("max_results", 6)),
            min_citations=int(legislative_payload.get("min_citations", 2)),
            timeout_seconds=int(legislative_payload.get("timeout_seconds", 60)),
            trust_profile_file=str(legislative_payload.get("trust_profile_file", "")).strip(),
            united_kingdom_trust_profile_id=str(
                legislative_payload.get(
                    "united_kingdom_trust_profile_id",
                    "legislation_united_kingdom_primary",
                )
            ).strip(),
            european_union_trust_profile_id=str(
                legislative_payload.get(
                    "european_union_trust_profile_id",
                    "legislation_european_union_primary",
                )
            ).strip(),
            strict=bool(legislative_payload.get("strict", True)),
            require_human_decision=bool(legislative_payload.get("require_human_decision", True)),
            decision_file=str(legislative_payload.get("decision_file", "")).strip(),
        )

        live_data_payload = payload.get("live_data", {})
        if not isinstance(live_data_payload, dict):
            raise ConfigValidationError("'live_data' must be an object.")
        live_data = LiveDataSettings(
            enabled=bool(live_data_payload.get("enabled", False)),
            provider=str(live_data_payload.get("provider", "openrouter")).strip(),
            model=str(live_data_payload.get("model", "openai/gpt-5.2:online")).strip(),
            max_results=int(live_data_payload.get("max_results", 5)),
            min_citations=int(live_data_payload.get("min_citations", 2)),
            timeout_seconds=int(live_data_payload.get("timeout_seconds", 45)),
            query=str(live_data_payload.get("query", "")).strip(),
            trust_profile_id=str(live_data_payload.get("trust_profile_id", "")).strip(),
            trust_profile_file=str(live_data_payload.get("trust_profile_file", "")).strip(),
            allowed_domains=tuple(str(h) for h in live_data_payload.get("allowed_domains", [])),
            high_trust_domains=tuple(
                str(h) for h in live_data_payload.get("high_trust_domains", [])
            ),
            medium_trust_domains=tuple(
                str(h) for h in live_data_payload.get("medium_trust_domains", [])
            ),
            min_trusted_citations=int(live_data_payload.get("min_trusted_citations", 0)),
            min_independent_trusted_domains=int(
                live_data_payload.get("min_independent_trusted_domains", 0)
            ),
            enforce_freshness=bool(live_data_payload.get("enforce_freshness", True)),
            require_publication_dates=bool(
                live_data_payload.get("require_publication_dates", False)
            ),
            freshness_days_news=int(live_data_payload.get("freshness_days_news", 30)),
            freshness_days_official_docs=int(
                live_data_payload.get("freshness_days_official_docs", 365)
            ),
            freshness_days_security_advisory=int(
                live_data_payload.get("freshness_days_security_advisory", 180)
            ),
            freshness_days_general=int(live_data_payload.get("freshness_days_general", 120)),
            strict=bool(live_data_payload.get("strict", True)),
        )

        security_payload = payload.get("security_requirements", {})
        if not isinstance(security_payload, dict):
            raise ConfigValidationError("'security_requirements' must be an object.")
        security_requirements = SecurityRequirements(
            goals=tuple(str(item).strip() for item in security_payload.get("goals", [])),
            threat_actors=tuple(
                str(item).strip() for item in security_payload.get("threat_actors", [])
            ),
            evidence_requirements=tuple(
                str(item).strip() for item in security_payload.get("evidence_requirements", [])
            ),
        )

        return cls(
            name=str(payload.get("name", "")).strip(),
            description=str(payload.get("description", "")).strip(),
            risk_level=str(payload.get("risk_level", "")).strip(),
            tools=tuple(tools),
            data_scope=data_scope,
            runtime_environment=str(payload.get("runtime_environment", "container")).strip(),
            budget_limit_usd=float(payload.get("budget_limit_usd", 0)),
            max_runtime_seconds=int(payload.get("max_runtime_seconds", 0)),
            design_method=str(payload.get("design_method", "deterministic")).strip(),
            profile_id=str(payload.get("profile_id", payload.get("profile", "custom"))).strip(),
            security_requirements=security_requirements,
            legal_context=legal_context,
            legislative_review=legislative_review,
            live_data=live_data,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "risk_level": self.risk_level,
            "tools": [
                {
                    "name": tool.name,
                    "command": tool.command,
                    "can_write_files": tool.can_write_files,
                    "can_access_network": tool.can_access_network,
                    "timeout_seconds": tool.timeout_seconds,
                }
                for tool in self.tools
            ],
            "data_scope": {
                "read_paths": list(self.data_scope.read_paths),
                "write_paths": list(self.data_scope.write_paths),
                "allowed_hosts": list(self.data_scope.allowed_hosts),
            },
            "runtime_environment": self.runtime_environment,
            "budget_limit_usd": self.budget_limit_usd,
            "max_runtime_seconds": self.max_runtime_seconds,
            "design_method": self.design_method,
            "profile_id": self.profile_id,
            "security_requirements": {
                "goals": list(self.security_requirements.goals),
                "threat_actors": list(self.security_requirements.threat_actors),
                "evidence_requirements": list(self.security_requirements.evidence_requirements),
            },
            "legal_context": {
                "jurisdictions": list(self.legal_context.jurisdictions),
                "intended_use": self.legal_context.intended_use,
                "sector": self.legal_context.sector,
                "decision_impact_level": self.legal_context.decision_impact_level,
                "compliance_target_date": self.legal_context.compliance_target_date,
                "data_categories": list(self.legal_context.data_categories),
            },
            "legislative_review": {
                "enabled": self.legislative_review.enabled,
                "provider": self.legislative_review.provider,
                "model": self.legislative_review.model,
                "max_results": self.legislative_review.max_results,
                "min_citations": self.legislative_review.min_citations,
                "timeout_seconds": self.legislative_review.timeout_seconds,
                "trust_profile_file": self.legislative_review.trust_profile_file,
                "united_kingdom_trust_profile_id": self.legislative_review.united_kingdom_trust_profile_id,
                "european_union_trust_profile_id": self.legislative_review.european_union_trust_profile_id,
                "strict": self.legislative_review.strict,
                "require_human_decision": self.legislative_review.require_human_decision,
                "decision_file": self.legislative_review.decision_file,
            },
            "live_data": {
                "enabled": self.live_data.enabled,
                "provider": self.live_data.provider,
                "model": self.live_data.model,
                "max_results": self.live_data.max_results,
                "min_citations": self.live_data.min_citations,
                "timeout_seconds": self.live_data.timeout_seconds,
                "query": self.live_data.query,
                "trust_profile_id": self.live_data.trust_profile_id,
                "trust_profile_file": self.live_data.trust_profile_file,
                "allowed_domains": list(self.live_data.allowed_domains),
                "high_trust_domains": list(self.live_data.high_trust_domains),
                "medium_trust_domains": list(self.live_data.medium_trust_domains),
                "min_trusted_citations": self.live_data.min_trusted_citations,
                "min_independent_trusted_domains": self.live_data.min_independent_trusted_domains,
                "enforce_freshness": self.live_data.enforce_freshness,
                "require_publication_dates": self.live_data.require_publication_dates,
                "freshness_days_news": self.live_data.freshness_days_news,
                "freshness_days_official_docs": self.live_data.freshness_days_official_docs,
                "freshness_days_security_advisory": self.live_data.freshness_days_security_advisory,
                "freshness_days_general": self.live_data.freshness_days_general,
                "strict": self.live_data.strict,
            },
        }


@dataclass(frozen=True)
class SpecificationQualityReport:
    score: int
    threshold: int
    passed: bool
    missing_requirements: tuple[str, ...]
    findings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "threshold": self.threshold,
            "passed": self.passed,
            "missing_requirements": list(self.missing_requirements),
            "findings": list(self.findings),
        }


@dataclass(frozen=True)
class SecurityProfileTemplate:
    profile_id: str
    display_name: str
    description: str
    risk_level: str
    runtime_environment: str
    budget_limit_usd: float
    max_runtime_seconds: int
    tools: tuple[ToolSpec, ...]
    data_scope: DataScope
    security_requirements: SecurityRequirements
    live_data: LiveDataSettings

    def build_spec(
        self,
        *,
        name: str | None = None,
        description: str | None = None,
        risk_level: str | None = None,
        runtime_environment: str | None = None,
    ) -> AgentSpec:
        return AgentSpec(
            name=name or f"{self.profile_id}-agent",
            description=description or self.description,
            risk_level=risk_level or self.risk_level,
            tools=self.tools,
            data_scope=self.data_scope,
            runtime_environment=runtime_environment or self.runtime_environment,
            budget_limit_usd=self.budget_limit_usd,
            max_runtime_seconds=self.max_runtime_seconds,
            design_method="deterministic",
            profile_id=self.profile_id,
            security_requirements=self.security_requirements,
            live_data=self.live_data,
        )


def evaluate_spec_quality(spec: AgentSpec) -> SpecificationQualityReport:
    findings: list[str] = []
    missing: list[str] = []
    score = 100

    requirements = spec.security_requirements
    if not requirements.goals:
        missing.append("goals")
        findings.append("Missing security goals.")
        score -= 25
    elif len(requirements.goals) < 2:
        findings.append("Add at least two security goals for better coverage.")
        score -= 5

    if not requirements.threat_actors:
        missing.append("threat_actors")
        findings.append("Missing threat actors.")
        score -= 20
    elif len(requirements.threat_actors) < 2:
        findings.append("Add at least two threat actors for stronger threat modeling.")
        score -= 5

    if not spec.data_scope.read_paths:
        missing.append("data_boundaries.read_paths")
        findings.append("Missing read data boundaries.")
        score -= 20

    writes_enabled = any(tool.can_write_files for tool in spec.tools)
    if writes_enabled and not spec.data_scope.write_paths:
        missing.append("data_boundaries.write_paths")
        findings.append("Write-enabled tools require explicit write data boundaries.")
        score -= 15

    network_enabled = any(tool.can_access_network for tool in spec.tools)
    if network_enabled and not spec.data_scope.allowed_hosts:
        missing.append("data_boundaries.allowed_hosts")
        findings.append("Network-enabled tools require allowed hosts boundaries.")
        score -= 20

    if not spec.tools:
        missing.append("tool_permissions")
        findings.append("Missing tool permissions.")
        score -= 20
    else:
        if all(tool.can_write_files for tool in spec.tools):
            findings.append("All tools can write files; include at least one read-only tool.")
            score -= 5
        if any(tool.timeout_seconds > 300 for tool in spec.tools):
            findings.append("One or more tools exceed 300 seconds timeout target.")
            score -= 5

    if not requirements.evidence_requirements:
        missing.append("evidence_requirements")
        findings.append("Missing evidence requirements.")
        score -= 20
    elif len(requirements.evidence_requirements) < 2:
        findings.append("Add at least two evidence requirements for release confidence.")
        score -= 5

    if spec.live_data.enabled and not spec.live_data.query.strip():
        findings.append("Live data query is empty and falls back to description.")
        score -= 5
    if spec.live_data.enabled and not spec.live_data.trust_profile_id.strip():
        findings.append("Live data does not reference a managed trust source profile.")
        score -= 5
    if spec.live_data.enabled and not (
        spec.live_data.high_trust_domains
        or spec.live_data.medium_trust_domains
        or spec.live_data.allowed_domains
    ):
        findings.append("Live data has no trusted domain configuration.")
        score -= 10
    if (
        spec.live_data.enabled
        and spec.risk_level == "high"
        and spec.live_data.min_independent_trusted_domains < 2
    ):
        findings.append(
            "High-risk live data should require at least two independent trusted domains."
        )
        score -= 5

    if spec.legislative_review.enabled:
        if not spec.legal_context.intended_use.strip():
            missing.append("legal_context.intended_use")
            findings.append("Legislative review requires an intended_use statement.")
            score -= 20
        if not spec.legal_context.jurisdictions:
            missing.append("legal_context.jurisdictions")
            findings.append("Legislative review requires jurisdictions.")
            score -= 15
        if not spec.legislative_review.united_kingdom_trust_profile_id.strip():
            missing.append("legislative_review.united_kingdom_trust_profile_id")
            findings.append("Legislative review requires a United Kingdom trust profile id.")
            score -= 10
        if not spec.legislative_review.european_union_trust_profile_id.strip():
            missing.append("legislative_review.european_union_trust_profile_id")
            findings.append("Legislative review requires a European Union trust profile id.")
            score -= 10
        if spec.risk_level in {"medium", "high"} and not spec.legislative_review.strict:
            missing.append("legislative_review.strict")
            findings.append(
                f"Legislative review strict mode is required for risk level '{spec.risk_level}'."
            )
            score -= 10
        if (
            spec.risk_level in {"medium", "high"}
            and not spec.legislative_review.require_human_decision
        ):
            missing.append("legislative_review.require_human_decision")
            findings.append(
                f"Legislative review requires human decision for risk level '{spec.risk_level}'."
            )
            score -= 10

    normalized_score = max(0, min(100, score))
    threshold = _QUALITY_THRESHOLD_BY_RISK[spec.risk_level]
    passed = normalized_score >= threshold and not missing
    return SpecificationQualityReport(
        score=normalized_score,
        threshold=threshold,
        passed=passed,
        missing_requirements=tuple(missing),
        findings=tuple(findings),
    )


def list_security_profiles() -> tuple[SecurityProfileTemplate, ...]:
    return tuple(_SECURITY_PROFILE_LIBRARY.values())


def get_security_profile(profile_id: str) -> SecurityProfileTemplate:
    candidate = profile_id.strip()
    profile = _SECURITY_PROFILE_LIBRARY.get(candidate)
    if profile is None:
        raise ConfigValidationError(
            f"Unknown profile_id '{profile_id}'. Valid values: {sorted(_SECURITY_PROFILE_LIBRARY)}."
        )
    return profile


def create_spec_from_profile(
    profile_id: str,
    *,
    name: str | None = None,
    description: str | None = None,
    risk_level: str | None = None,
    runtime_environment: str | None = None,
) -> AgentSpec:
    profile = get_security_profile(profile_id)
    return profile.build_spec(
        name=name,
        description=description,
        risk_level=risk_level,
        runtime_environment=runtime_environment,
    )


def load_spec(path: str | Path) -> AgentSpec:
    target = Path(path)
    payload = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ConfigValidationError("Specification root must be an object.")
    return AgentSpec.from_dict(payload)


def write_spec(path: str | Path, spec: AgentSpec) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(spec.to_dict(), indent=2) + "\n", encoding="utf-8")


def _validate_line_entries(values: tuple[str, ...], field_name: str) -> None:
    for value in values:
        cleaned = value.strip()
        if not cleaned:
            raise ConfigValidationError(f"{field_name} must not include empty entries.")
        if "\n" in cleaned:
            raise ConfigValidationError(f"{field_name} must be single-line values.")


def _build_security_profile_library() -> dict[str, SecurityProfileTemplate]:
    secure_code_review = SecurityProfileTemplate(
        profile_id="secure_code_review",
        display_name="Secure Code Review",
        description="Analyze source code for security issues and produce signed evidence.",
        risk_level="high",
        runtime_environment="container",
        budget_limit_usd=100.0,
        max_runtime_seconds=1800,
        tools=(
            ToolSpec(
                name="read_source",
                command="rg --files /workspace",
                can_write_files=False,
                can_access_network=False,
                timeout_seconds=30,
            ),
            ToolSpec(
                name="write_report",
                command="python write_report.py",
                can_write_files=True,
                can_access_network=False,
                timeout_seconds=60,
            ),
        ),
        data_scope=DataScope(
            read_paths=("/workspace",),
            write_paths=("/workspace/reports",),
            allowed_hosts=(),
        ),
        security_requirements=SecurityRequirements(
            goals=(
                "Identify high-impact code vulnerabilities with deterministic checks.",
                "Generate remediation guidance tied to file-level evidence.",
            ),
            threat_actors=(
                "External attacker exploiting code defects.",
                "Malicious insider introducing unsafe changes.",
            ),
            evidence_requirements=(
                "Signed verification summary with pass and fail checks.",
                "Traceable evidence log linking findings to source files.",
            ),
        ),
        live_data=LiveDataSettings(
            enabled=True,
            provider="openrouter",
            model="openai/gpt-5.2:online",
            max_results=5,
            min_citations=2,
            timeout_seconds=45,
            query="latest secure code review agent design best practices",
            trust_profile_id="secure_code_review_primary",
            high_trust_domains=("openai.com", "docs.anthropic.com", "owasp.org"),
            medium_trust_domains=("openrouter.ai", "github.com"),
            min_trusted_citations=2,
            min_independent_trusted_domains=2,
            enforce_freshness=True,
            require_publication_dates=False,
            freshness_days_news=45,
            freshness_days_official_docs=365,
            freshness_days_security_advisory=180,
            freshness_days_general=120,
            strict=True,
        ),
    )

    dependency_audit = SecurityProfileTemplate(
        profile_id="dependency_audit",
        display_name="Dependency Security Audit",
        description="Audit dependencies and third-party packages for security exposure.",
        risk_level="medium",
        runtime_environment="container",
        budget_limit_usd=75.0,
        max_runtime_seconds=1200,
        tools=(
            ToolSpec(
                name="collect_dependencies",
                command="python collect_dependencies.py /workspace",
                can_write_files=False,
                can_access_network=False,
                timeout_seconds=45,
            ),
            ToolSpec(
                name="query_advisories",
                command="python query_advisories.py --source osv.dev --input /workspace/dependencies.json",
                can_write_files=False,
                can_access_network=True,
                timeout_seconds=60,
            ),
            ToolSpec(
                name="write_audit_report",
                command="python write_audit_report.py",
                can_write_files=True,
                can_access_network=False,
                timeout_seconds=60,
            ),
        ),
        data_scope=DataScope(
            read_paths=("/workspace",),
            write_paths=("/workspace/reports",),
            allowed_hosts=("osv.dev", "api.github.com"),
        ),
        security_requirements=SecurityRequirements(
            goals=(
                "Detect vulnerable dependencies with prioritized severity context.",
                "Recommend safe upgrade paths with compatibility notes.",
            ),
            threat_actors=(
                "Supply chain attacker publishing malicious package versions.",
                "Automated exploit systems targeting known dependency vulnerabilities.",
            ),
            evidence_requirements=(
                "Advisory citation list per vulnerable package.",
                "Signed summary of dependency risk and recommended actions.",
            ),
        ),
        live_data=LiveDataSettings(
            enabled=True,
            provider="openrouter",
            model="openai/gpt-5.2:online",
            max_results=5,
            min_citations=2,
            timeout_seconds=45,
            query="latest dependency supply chain security guidance and advisories",
            trust_profile_id="dependency_security_primary",
            high_trust_domains=("osv.dev", "nvd.nist.gov", "cve.mitre.org"),
            medium_trust_domains=("github.com", "pypi.org"),
            min_trusted_citations=2,
            min_independent_trusted_domains=2,
            enforce_freshness=True,
            require_publication_dates=False,
            freshness_days_news=30,
            freshness_days_official_docs=365,
            freshness_days_security_advisory=180,
            freshness_days_general=90,
            strict=True,
        ),
    )

    runtime_threat_hunting = SecurityProfileTemplate(
        profile_id="runtime_threat_hunting",
        display_name="Runtime Threat Hunting",
        description="Inspect runtime telemetry and identify suspicious activity patterns.",
        risk_level="high",
        runtime_environment="container",
        budget_limit_usd=120.0,
        max_runtime_seconds=2400,
        tools=(
            ToolSpec(
                name="collect_logs",
                command="python collect_logs.py /workspace/logs",
                can_write_files=False,
                can_access_network=False,
                timeout_seconds=45,
            ),
            ToolSpec(
                name="query_threat_intelligence",
                command="python query_threat_intelligence.py --provider abuseipdb --input /workspace/indicators.json",
                can_write_files=False,
                can_access_network=True,
                timeout_seconds=60,
            ),
            ToolSpec(
                name="write_hunting_report",
                command="python write_hunting_report.py",
                can_write_files=True,
                can_access_network=False,
                timeout_seconds=90,
            ),
        ),
        data_scope=DataScope(
            read_paths=("/workspace/logs", "/workspace/indicators"),
            write_paths=("/workspace/reports",),
            allowed_hosts=("abuseipdb.com", "otx.alienvault.com"),
        ),
        security_requirements=SecurityRequirements(
            goals=(
                "Identify indicators of compromise from runtime telemetry.",
                "Escalate high-confidence threats with containment actions.",
            ),
            threat_actors=(
                "Credential theft attacker moving laterally in production systems.",
                "Automated botnet probing exposed services.",
            ),
            evidence_requirements=(
                "Indicator timeline with source references and confidence levels.",
                "Signed incident recommendation package for security responders.",
            ),
        ),
        live_data=LiveDataSettings(
            enabled=True,
            provider="openrouter",
            model="openai/gpt-5.2:online",
            max_results=5,
            min_citations=2,
            timeout_seconds=45,
            query="latest runtime threat hunting techniques and incident response guidance",
            trust_profile_id="runtime_incident_response_primary",
            high_trust_domains=("nvd.nist.gov", "cisa.gov", "otx.alienvault.com"),
            medium_trust_domains=("abuseipdb.com", "github.com"),
            min_trusted_citations=2,
            min_independent_trusted_domains=2,
            enforce_freshness=True,
            require_publication_dates=False,
            freshness_days_news=30,
            freshness_days_official_docs=365,
            freshness_days_security_advisory=120,
            freshness_days_general=90,
            strict=True,
        ),
    )

    secure_code_review_local = SecurityProfileTemplate(
        profile_id="secure_code_review_local",
        display_name="Secure Code Review Local",
        description="Analyze source code security posture in local smoke mode without live intelligence.",
        risk_level="medium",
        runtime_environment="local",
        budget_limit_usd=25.0,
        max_runtime_seconds=900,
        tools=secure_code_review.tools,
        data_scope=secure_code_review.data_scope,
        security_requirements=secure_code_review.security_requirements,
        live_data=LiveDataSettings(
            enabled=False,
            provider="openrouter",
            model="openai/gpt-5.2:online",
            max_results=5,
            min_citations=2,
            timeout_seconds=45,
            query="",
            strict=False,
        ),
    )

    return {
        secure_code_review.profile_id: secure_code_review,
        dependency_audit.profile_id: dependency_audit,
        runtime_threat_hunting.profile_id: runtime_threat_hunting,
        secure_code_review_local.profile_id: secure_code_review_local,
    }


_SECURITY_PROFILE_LIBRARY = _build_security_profile_library()
VALID_PROFILE_IDS = {"custom", *_SECURITY_PROFILE_LIBRARY.keys()}
