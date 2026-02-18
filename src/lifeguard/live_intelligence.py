from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib import error, parse, request

from .spec_schema import LiveDataSettings
from .trust_source_profiles import (
    TrustSourceProfileError,
    apply_managed_trust_source_profile,
)


class LiveDataError(RuntimeError):
    """Base exception for live intelligence failures."""


class LiveDataConfigurationError(LiveDataError):
    """Raised when live intelligence configuration is missing or invalid."""


class LiveDataProviderError(LiveDataError):
    """Raised when the remote intelligence provider request fails."""


class LiveDataValidationError(LiveDataError):
    """Raised when returned intelligence data does not meet policy."""

    def __init__(self, message: str, *, attempts: tuple[LiveDataAttempt, ...] = ()) -> None:
        super().__init__(message)
        self.attempts = attempts


@dataclass(frozen=True)
class Citation:
    url: str
    title: str
    domain: str
    trust_tier: str = "low"
    source_type: str = "general"
    published_at: str | None = None
    freshness_window_days: int | None = None
    age_days: int | None = None
    is_fresh: bool | None = None


@dataclass(frozen=True)
class LiveDataAttempt:
    attempt_number: int
    model: str
    query_variant: str
    citation_count: int
    assessment_passed: bool
    failure: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt_number": self.attempt_number,
            "model": self.model,
            "query_variant": self.query_variant,
            "citation_count": self.citation_count,
            "assessment_passed": self.assessment_passed,
            "failure": self.failure,
        }


@dataclass(frozen=True)
class LiveDataAssessment:
    passed: bool
    trusted_citation_count: int
    required_trusted_citation_count: int
    independent_trusted_domains: tuple[str, ...]
    required_independent_trusted_domains: int
    stale_citation_count: int
    unknown_freshness_count: int
    freshness_enforced: bool
    publication_dates_required: bool
    managed_profile: dict[str, str] | None = None
    failures: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "trusted_citation_count": self.trusted_citation_count,
            "required_trusted_citation_count": self.required_trusted_citation_count,
            "independent_trusted_domains": list(self.independent_trusted_domains),
            "required_independent_trusted_domains": self.required_independent_trusted_domains,
            "stale_citation_count": self.stale_citation_count,
            "unknown_freshness_count": self.unknown_freshness_count,
            "freshness_enforced": self.freshness_enforced,
            "publication_dates_required": self.publication_dates_required,
            "managed_profile": self.managed_profile,
            "failures": list(self.failures),
        }


@dataclass(frozen=True)
class LiveDataReport:
    provider: str
    model: str
    query: str
    summary: str
    citations: tuple[Citation, ...]
    fetched_at: str
    attempts: tuple[LiveDataAttempt, ...] = ()
    assessment: LiveDataAssessment = field(
        default_factory=lambda: LiveDataAssessment(
            passed=True,
            trusted_citation_count=0,
            required_trusted_citation_count=0,
            independent_trusted_domains=(),
            required_independent_trusted_domains=0,
            stale_citation_count=0,
            unknown_freshness_count=0,
            freshness_enforced=False,
            publication_dates_required=False,
            failures=(),
        )
    )


TransportCallable = Callable[[str, dict[str, str], dict[str, Any], int], dict[str, Any]]
ClockCallable = Callable[[], datetime]


class LiveIntelligenceClient:
    """Fetches fresh, cited intelligence using provider-backed web search tools."""

    def __init__(
        self,
        transport: TransportCallable | None = None,
        clock: ClockCallable | None = None,
    ) -> None:
        self._transport = transport or _default_transport
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def collect_latest(
        self,
        query: str,
        settings: LiveDataSettings,
        *,
        risk_level: str = "low",
    ) -> LiveDataReport:
        cleaned_query = query.strip()
        if not cleaned_query:
            raise LiveDataConfigurationError("Live intelligence query must not be empty.")
        if not settings.enabled:
            raise LiveDataConfigurationError("Live intelligence is disabled for this specification.")

        try:
            resolved_settings, managed_resolution = apply_managed_trust_source_profile(
                settings=settings,
                risk_level=risk_level,
            )
        except TrustSourceProfileError as exc:
            raise LiveDataConfigurationError(str(exc)) from exc

        max_attempts_raw = os.getenv("LIFEGUARD_LIVE_DATA_MAX_ATTEMPTS", "3").strip()
        try:
            max_attempts = int(max_attempts_raw)
        except ValueError:
            max_attempts = 3
        max_attempts = max(3, min(max_attempts, 5))

        last_validation_error: LiveDataValidationError | None = None
        response_payload: dict[str, Any] | None = None
        summary = ""
        bounded_citations: list[Citation] = []
        attempts: list[LiveDataAttempt] = []
        previous_citation_count = -1

        for attempt in range(max_attempts):
            attempt_query = cleaned_query
            attempt_settings = resolved_settings
            query_variant = "base"
            is_last_attempt = attempt == (max_attempts - 1) and attempt > 0
            if is_last_attempt:
                query_variant = "trusted_domain_constrained_fallback_model"
                attempt_query = _trusted_domain_constrained_query(
                    cleaned_query=cleaned_query,
                    settings=resolved_settings,
                    strict_wording=True,
                )
                fallback_model = _resolve_fallback_model(resolved_settings)
                if fallback_model:
                    attempt_settings = replace(attempt_settings, model=fallback_model)
            elif attempt == 1 and previous_citation_count == 0:
                query_variant = "trusted_domain_constrained"
                attempt_query = _trusted_domain_constrained_query(
                    cleaned_query=cleaned_query,
                    settings=resolved_settings,
                )
            elif attempt:
                query_variant = "quality_retry"
                attempt_query = _quality_retry_query(
                    cleaned_query=cleaned_query,
                    settings=resolved_settings,
                )
            if attempt:
                attempt_settings = replace(
                    attempt_settings,
                    max_results=max(
                        attempt_settings.max_results,
                        attempt_settings.min_citations * 4,
                        8,
                    ),
                )

            url, headers, payload = self._build_provider_request(
                attempt_query,
                attempt_settings,
                risk_level=risk_level,
            )
            response_payload = self._transport(url, headers, payload, attempt_settings.timeout_seconds)
            _maybe_capture_live_data_response(
                response_payload=response_payload,
                provider=attempt_settings.provider,
                model=attempt_settings.model,
                query=attempt_query,
            )

            summary, citations = _extract_summary_and_citations(
                response_payload,
                settings=attempt_settings,
            )
            bounded_citations = citations[: attempt_settings.max_results]
            previous_citation_count = len(bounded_citations)
            if len(bounded_citations) < attempt_settings.min_citations:
                failure = (
                    "Insufficient citation count from live intelligence provider: "
                    f"received {len(bounded_citations)}, required {attempt_settings.min_citations}."
                )
                attempts.append(
                    LiveDataAttempt(
                        attempt_number=attempt + 1,
                        model=attempt_settings.model,
                        query_variant=query_variant,
                        citation_count=len(bounded_citations),
                        assessment_passed=False,
                        failure=failure,
                    )
                )
                last_validation_error = LiveDataValidationError(
                    failure,
                    attempts=tuple(attempts),
                )
                continue

            if resolved_settings.allowed_domains:
                disallowed_domains = sorted(
                    {
                        citation.domain
                        for citation in bounded_citations
                        if not _domain_allowed(citation.domain, resolved_settings.allowed_domains)
                    }
                )
                if disallowed_domains:
                    failure = (
                        "Live intelligence returned sources outside allowed_domains: "
                        + ", ".join(disallowed_domains)
                    )
                    attempts.append(
                        LiveDataAttempt(
                            attempt_number=attempt + 1,
                            model=attempt_settings.model,
                            query_variant=query_variant,
                            citation_count=len(bounded_citations),
                            assessment_passed=False,
                            failure=failure,
                        )
                    )
                    last_validation_error = LiveDataValidationError(
                        failure,
                        attempts=tuple(attempts),
                    )
                    continue

            now = self._clock()
            annotated_citations = _annotate_citations(
                citations=tuple(bounded_citations),
                settings=resolved_settings,
                now=now,
            )
            assessment = _assess_citations(
                citations=annotated_citations,
                settings=resolved_settings,
                risk_level=risk_level,
            )
            if managed_resolution is not None:
                assessment = replace(assessment, managed_profile=managed_resolution.to_dict())
            if not assessment.passed:
                failure = "; ".join(assessment.failures)
                attempts.append(
                    LiveDataAttempt(
                        attempt_number=attempt + 1,
                        model=attempt_settings.model,
                        query_variant=query_variant,
                        citation_count=len(bounded_citations),
                        assessment_passed=False,
                        failure=failure,
                    )
                )
                last_validation_error = LiveDataValidationError(
                    failure,
                    attempts=tuple(attempts),
                )
                continue

            final_summary = summary.strip() or "No summary text returned by provider."
            attempts.append(
                LiveDataAttempt(
                    attempt_number=attempt + 1,
                    model=attempt_settings.model,
                    query_variant=query_variant,
                    citation_count=len(bounded_citations),
                    assessment_passed=True,
                    failure="",
                )
            )
            return LiveDataReport(
                provider=settings.provider,
                model=settings.model,
                query=cleaned_query,
                summary=final_summary,
                citations=annotated_citations,
                fetched_at=now.isoformat(),
                attempts=tuple(attempts),
                assessment=assessment,
            )

        raise last_validation_error or LiveDataValidationError(
            "Live intelligence response did not satisfy citation quality and trust requirements.",
            attempts=tuple(attempts),
        )

    def _build_provider_request(
        self,
        query: str,
        settings: LiveDataSettings,
        *,
        risk_level: str = "low",
    ) -> tuple[str, dict[str, str], dict[str, Any]]:
        if settings.provider == "openrouter":
            return self._build_openrouter_request(query, settings, risk_level=risk_level)
        if settings.provider == "openai":
            return self._build_openai_request(query, settings, risk_level=risk_level)
        if settings.provider == "anthropic":
            return self._build_anthropic_request(query, settings, risk_level=risk_level)
        raise LiveDataConfigurationError(
            f"Unsupported live intelligence provider: {settings.provider}"
        )

    def _build_openrouter_request(
        self,
        query: str,
        settings: LiveDataSettings,
        *,
        risk_level: str = "low",
    ) -> tuple[str, dict[str, str], dict[str, Any]]:
        api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
        if not api_key:
            raise LiveDataConfigurationError("OPENROUTER_API_KEY is required for provider openrouter.")

        base_url = os.getenv(
            "LIFEGUARD_OPENROUTER_BASE_URL",
            "https://openrouter.ai/api/v1",
        ).strip()
        url = base_url.rstrip("/") + "/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
        }
        prompt = _format_live_intelligence_prompt(
            query=query,
            settings=settings,
            risk_level=risk_level,
        )
        reasoning_effort = os.getenv("LIFEGUARD_OPENROUTER_REASONING_EFFORT", "low").strip()
        payload = {
            "model": settings.model,
            "messages": [{"role": "user", "content": prompt}],
            "plugins": [{"id": "web", "max_results": settings.max_results}],
            "temperature": 0.0,
            "max_tokens": 1200,
        }
        if reasoning_effort:
            payload["reasoning"] = {"effort": reasoning_effort}
        return url, headers, payload

    def _build_openai_request(
        self,
        query: str,
        settings: LiveDataSettings,
        *,
        risk_level: str = "low",
    ) -> tuple[str, dict[str, str], dict[str, Any]]:
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key:
            raise LiveDataConfigurationError("OPENAI_API_KEY is required for provider openai.")

        base_url = os.getenv("LIFEGUARD_OPENAI_BASE_URL", "https://api.openai.com/v1").strip()
        url = base_url.rstrip("/") + "/responses"
        headers = {
            "Authorization": f"Bearer {api_key}",
        }
        web_tool_type = os.getenv("LIFEGUARD_OPENAI_WEB_TOOL_TYPE", "web_search").strip()
        search_context_size = os.getenv("LIFEGUARD_OPENAI_SEARCH_CONTEXT_SIZE", "medium").strip()

        web_tool: dict[str, Any] = {"type": web_tool_type}
        if search_context_size:
            web_tool["search_context_size"] = search_context_size

        payload = {
            "model": settings.model,
            "input": _format_live_intelligence_prompt(
                query=query,
                settings=settings,
                risk_level=risk_level,
            ),
            "tools": [web_tool],
            "tool_choice": "auto",
            "temperature": 0.0,
            "max_output_tokens": 900,
        }
        return url, headers, payload

    def _build_anthropic_request(
        self,
        query: str,
        settings: LiveDataSettings,
        *,
        risk_level: str = "low",
    ) -> tuple[str, dict[str, str], dict[str, Any]]:
        api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
        if not api_key:
            raise LiveDataConfigurationError("ANTHROPIC_API_KEY is required for provider anthropic.")

        base_url = os.getenv("LIFEGUARD_ANTHROPIC_BASE_URL", "https://api.anthropic.com").strip()
        url = base_url.rstrip("/") + "/v1/messages"
        headers = {
            "x-api-key": api_key,
            "anthropic-version": os.getenv("LIFEGUARD_ANTHROPIC_VERSION", "2023-06-01").strip(),
        }
        beta_header = os.getenv("LIFEGUARD_ANTHROPIC_BETA", "").strip()
        if beta_header:
            headers["anthropic-beta"] = beta_header

        web_tool_type = os.getenv("LIFEGUARD_ANTHROPIC_WEB_TOOL_TYPE", "web_search_20250305").strip()
        payload = {
            "model": settings.model,
            "max_tokens": 900,
            "temperature": 0.0,
            "messages": [
                {
                    "role": "user",
                    "content": _format_live_intelligence_prompt(
                        query=query,
                        settings=settings,
                        risk_level=risk_level,
                    ),
                }
            ],
            "tools": [
                {
                    "type": web_tool_type,
                    "name": "web_search",
                    "max_uses": settings.max_results,
                }
            ],
        }
        return url, headers, payload


def _default_transport(
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    timeout_seconds: int,
) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    merged_headers = {"Content-Type": "application/json", **headers}
    http_request = request.Request(url, data=body, headers=merged_headers, method="POST")

    try:
        with request.urlopen(http_request, timeout=timeout_seconds) as response:
            response_body = response.read().decode("utf-8")
    except error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        raise LiveDataProviderError(
            f"Live intelligence request failed ({exc.code}): {error_body[:300]}"
        ) from exc
    except error.URLError as exc:
        raise LiveDataProviderError(f"Live intelligence request failed: {exc.reason}") from exc
    except TimeoutError as exc:
        raise LiveDataProviderError("Live intelligence request timed out.") from exc

    try:
        parsed_payload = json.loads(response_body)
    except json.JSONDecodeError as exc:
        raise LiveDataProviderError("Live intelligence response was not valid JSON.") from exc
    if not isinstance(parsed_payload, dict):
        raise LiveDataProviderError("Live intelligence response root must be a JSON object.")
    return parsed_payload


def _format_live_intelligence_prompt(
    *,
    query: str,
    settings: LiveDataSettings,
    risk_level: str = "low",
) -> str:
    cleaned_query = query.strip()
    required_independent_domains = _required_independent_trusted_domains(
        settings=settings,
        risk_level=risk_level,
    )
    trusted_domains = tuple(
        dict.fromkeys(
            [*settings.high_trust_domains, *settings.medium_trust_domains]
        )
    )
    lines = [
        cleaned_query,
        "",
        "Return:",
        "- A short summary.",
        (
            f"- A section 'Citations:' with at least {settings.min_citations} unique URLs "
            "(include https://), one per line."
        ),
        (
            "- Use citations from trusted sources across independent domains. "
            f"Required independent trusted domains: {required_independent_domains}."
        ),
        "- Do not repeat a citation domain until you meet the independent domain requirement.",
    ]
    if trusted_domains:
        lines.append("- Prioritize these trusted domains: " + ", ".join(trusted_domains))
    if settings.allowed_domains:
        lines.append("")
        lines.append(
            "Only cite sources from these domains: " + ", ".join(settings.allowed_domains)
        )
    return "\n".join(lines).strip()


def _quality_retry_query(*, cleaned_query: str, settings: LiveDataSettings) -> str:
    required_domains = max(1, int(settings.min_independent_trusted_domains))
    return (
        cleaned_query
        + "\n\nIMPORTANT: Include a 'Citations:' section with at least "
        f"{settings.min_citations} unique full https:// URLs, one per line."
        + "\nIMPORTANT: Use citations from at least "
        f"{required_domains} independent trusted domains. Do not repeat a domain until you meet this."
        + "\nIMPORTANT: Prioritize recent sources that satisfy freshness windows."
    )


def _trusted_domain_constrained_query(
    *,
    cleaned_query: str,
    settings: LiveDataSettings,
    strict_wording: bool = False,
) -> str:
    required_domains = max(1, int(settings.min_independent_trusted_domains))
    trusted_domains = tuple(
        dict.fromkeys(
            [*settings.high_trust_domains, *settings.medium_trust_domains]
        )
    )
    if trusted_domains:
        trusted_line = ", ".join(trusted_domains)
    else:
        trusted_line = "trusted official documentation and security advisory sources"
    emphasis = "STRICT" if strict_wording else "IMPORTANT"
    return (
        cleaned_query
        + "\n\n"
        + f"{emphasis}: Return a 'Citations:' section with at least {settings.min_citations} unique full https:// URLs."
        + "\n"
        + f"{emphasis}: Constrain sources to trusted domains only: {trusted_line}."
        + "\n"
        + f"{emphasis}: Use at least {required_domains} independent trusted domains. "
        + "Do not repeat a domain until you meet this requirement."
        + "\n"
        + f"{emphasis}: Prioritize recent publications that satisfy freshness windows."
    )


def _resolve_fallback_model(settings: LiveDataSettings) -> str:
    configured = os.getenv("LIFEGUARD_LIVE_DATA_FALLBACK_MODEL", "").strip()
    if configured:
        return configured
    fallback_by_provider = {
        "openrouter": "openai/gpt-4.1:online",
        "openai": "gpt-4.1",
        "anthropic": "claude-3-5-sonnet-latest",
    }
    fallback = fallback_by_provider.get(settings.provider, "").strip()
    if fallback and fallback != settings.model:
        return fallback
    return settings.model


def _maybe_capture_live_data_response(
    *,
    response_payload: dict[str, Any],
    provider: str,
    model: str,
    query: str,
) -> None:
    capture_path = os.getenv("LIFEGUARD_LIVE_DATA_CAPTURE_PATH", "").strip()
    if not capture_path:
        return
    try:
        resolved_capture_path = _resolve_live_data_capture_path(capture_path)
        payload = {
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "provider": provider,
            "model": model,
            "query": query,
            "response": _redact_live_data_capture_payload(response_payload),
        }
        resolved_capture_path.parent.mkdir(parents=True, exist_ok=True)
        with resolved_capture_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
    except (OSError, TypeError, ValueError):
        return


def _resolve_live_data_capture_path(capture_path: str) -> Path:
    configured_root = os.getenv("LIFEGUARD_LIVE_DATA_CAPTURE_ROOT", "").strip()
    if configured_root:
        capture_root = Path(configured_root).expanduser()
    else:
        capture_root = Path.cwd()
    capture_root = capture_root.resolve()

    requested_path = Path(capture_path).expanduser()
    if requested_path.is_absolute():
        resolved_path = requested_path.resolve()
    else:
        resolved_path = (capture_root / requested_path).resolve()

    try:
        resolved_path.relative_to(capture_root)
    except ValueError as exc:
        raise ValueError("Live data capture path must stay inside capture root.") from exc
    return resolved_path


def _redact_live_data_capture_payload(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, nested_value in value.items():
            key_text = str(key)
            key_lower = key_text.lower()
            if any(marker in key_lower for marker in _SENSITIVE_CAPTURE_KEY_MARKERS):
                redacted[key_text] = "<redacted>"
            else:
                redacted[key_text] = _redact_live_data_capture_payload(nested_value)
        return redacted
    if isinstance(value, list):
        return [_redact_live_data_capture_payload(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_live_data_capture_payload(item) for item in value]
    if isinstance(value, str):
        lowered = value.lower()
        if any(marker in lowered for marker in _SENSITIVE_CAPTURE_TEXT_MARKERS):
            return "<redacted>"
        return value
    return value


def _extract_summary_and_citations(
    payload: dict[str, Any],
    *,
    settings: LiveDataSettings | None = None,
) -> tuple[str, list[Citation]]:
    summary_parts: list[str] = []
    citation_candidates: list[Any] = []

    max_nodes_raw = os.getenv("LIFEGUARD_LIVE_DATA_PARSE_MAX_NODES", "50000").strip()
    try:
        max_nodes = int(max_nodes_raw)
    except ValueError:
        max_nodes = 50_000
    max_nodes = max(1_000, min(max_nodes, 250_000))

    max_summary_parts_raw = os.getenv("LIFEGUARD_LIVE_DATA_PARSE_MAX_SUMMARY_PARTS", "5000").strip()
    try:
        max_summary_parts = int(max_summary_parts_raw)
    except ValueError:
        max_summary_parts = 5_000
    max_summary_parts = max(100, min(max_summary_parts, 50_000))

    stack: list[Any] = [payload]
    nodes_seen = 0
    try:
        while stack:
            node = stack.pop()
            nodes_seen += 1
            if nodes_seen > max_nodes:
                raise LiveDataProviderError(
                    "Live intelligence response exceeded parse traversal limits."
                )

            if isinstance(node, str):
                cleaned = node.strip()
                if cleaned:
                    summary_parts.append(cleaned)
                    if len(summary_parts) > max_summary_parts:
                        raise LiveDataProviderError(
                            "Live intelligence response exceeded summary extraction limits."
                        )
                continue

            if isinstance(node, list):
                # Depth-first traversal while preserving approximate order.
                for item in reversed(node):
                    stack.append(item)
                continue

            if not isinstance(node, dict):
                continue

            text_value = node.get("text")
            if isinstance(text_value, str):
                cleaned_text = text_value.strip()
                if cleaned_text:
                    summary_parts.append(cleaned_text)
                    if len(summary_parts) > max_summary_parts:
                        raise LiveDataProviderError(
                            "Live intelligence response exceeded summary extraction limits."
                        )

            output_text = node.get("output_text")
            if isinstance(output_text, str):
                cleaned_output = output_text.strip()
                if cleaned_output:
                    summary_parts.append(cleaned_output)
                    if len(summary_parts) > max_summary_parts:
                        raise LiveDataProviderError(
                            "Live intelligence response exceeded summary extraction limits."
                        )

            annotations = node.get("annotations")
            if isinstance(annotations, list):
                citation_candidates.extend(annotations)

            citations = node.get("citations")
            if isinstance(citations, list):
                citation_candidates.extend(citations)

            sources = node.get("sources")
            if isinstance(sources, list):
                citation_candidates.extend(sources)

            url_value = node.get("url")
            if isinstance(url_value, str) and _is_http_url(url_value):
                citation_candidates.append(node)

            for key in (
                "content",
                "message",
                "output",
                "choices",
                "source",
                "sources",
                "data",
                "results",
                "reasoning",
                "reasoning_details",
                "summary",
            ):
                if key in node:
                    stack.append(node[key])
    except RecursionError as exc:  # pragma: no cover
        raise LiveDataProviderError("Live intelligence response recursion error.") from exc
    except MemoryError as exc:  # pragma: no cover
        raise LiveDataProviderError("Live intelligence response exhausted memory.") from exc

    summary_text = "\n".join(summary_parts).strip()
    citation_candidates.extend(_extract_urls_from_text(summary_text, settings=settings))

    summary = " ".join(summary_parts).strip()
    citations = _normalize_citations(citation_candidates)
    return summary, citations


_URL_PATTERN = re.compile(r"https?://[^\s<>\"')\]]+")
_SCHEMELESS_URL_PATTERN = re.compile(
    r"(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>\"')\]]+)?",
    re.IGNORECASE,
)

_SENSITIVE_CAPTURE_KEY_MARKERS = (
    "api_key",
    "authorization",
    "token",
    "secret",
    "password",
    "cookie",
)
_SENSITIVE_CAPTURE_TEXT_MARKERS = (
    "bearer ",
    "api_key",
    "authorization:",
)


def _extract_urls_from_text(
    text: str,
    *,
    settings: LiveDataSettings | None,
) -> list[str]:
    if not text.strip():
        return []

    lowered = text.lower()
    marker = "citations:"
    index = lowered.find(marker)
    primary_text = text[index + len(marker) :] if index >= 0 else ""

    raw_urls: list[str] = []
    if primary_text:
        raw_urls.extend(_URL_PATTERN.findall(primary_text))
    raw_urls.extend(_URL_PATTERN.findall(text))

    if primary_text:
        for line in primary_text.splitlines()[:50]:
            cleaned_line = line.strip()
            if not cleaned_line:
                continue
            lowered_line = cleaned_line.lower()
            if "http://" in lowered_line or "https://" in lowered_line:
                continue
            for match in _SCHEMELESS_URL_PATTERN.findall(cleaned_line):
                candidate = match.strip().rstrip(").,;:")
                if not candidate:
                    continue
                # Avoid false positives like "Mode.STRICT".
                if candidate.lower() != candidate:
                    continue
                raw_urls.append(f"https://{candidate}")

    urls: list[str] = []
    seen: set[str] = set()
    for raw in raw_urls:
        cleaned = raw.strip().rstrip(").,;:")
        if cleaned in seen:
            continue
        if not _is_http_url(cleaned):
            continue
        if settings is not None and settings.allowed_domains:
            domain = _extract_domain(cleaned)
            if not domain or not _domain_allowed(domain, settings.allowed_domains):
                continue
        seen.add(cleaned)
        urls.append(cleaned)
    return urls


def _normalize_citations(candidates: list[Any]) -> list[Citation]:
    citations: list[Citation] = []
    seen_urls: set[str] = set()

    for candidate in candidates:
        url_value, title_value, published_at = _extract_url_title_and_publication(candidate)
        if not url_value:
            continue
        if url_value in seen_urls:
            continue
        seen_urls.add(url_value)
        domain = _extract_domain(url_value)
        if not domain:
            continue
        final_title = title_value or domain
        citations.append(
            Citation(
                url=url_value,
                title=final_title,
                domain=domain,
                published_at=published_at,
            )
        )
    return citations


def _extract_url_title_and_publication(
    candidate: Any,
) -> tuple[str | None, str | None, str | None]:
    if isinstance(candidate, str):
        cleaned = candidate.strip()
        if _is_http_url(cleaned):
            return cleaned, None, None
        return None, None, None

    if not isinstance(candidate, dict):
        return None, None, None

    url_value = candidate.get("url")
    title_value = candidate.get("title")
    if isinstance(url_value, str) and _is_http_url(url_value):
        final_title = title_value if isinstance(title_value, str) else None
        published_at = _extract_publication_value(candidate)
        return url_value, final_title, published_at

    nested = candidate.get("url_citation")
    if isinstance(nested, dict):
        nested_url = nested.get("url")
        nested_title = nested.get("title")
        if isinstance(nested_url, str) and _is_http_url(nested_url):
            final_nested_title = nested_title if isinstance(nested_title, str) else None
            published_at = _extract_publication_value(nested) or _extract_publication_value(candidate)
            return nested_url, final_nested_title, published_at

    source = candidate.get("source")
    if isinstance(source, dict):
        source_url = source.get("url")
        source_title = source.get("title")
        if isinstance(source_url, str) and _is_http_url(source_url):
            final_source_title = source_title if isinstance(source_title, str) else None
            published_at = _extract_publication_value(source) or _extract_publication_value(candidate)
            return source_url, final_source_title, published_at

    return None, None, None


def _is_http_url(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith("http://") or lowered.startswith("https://")


def _extract_domain(url_value: str) -> str:
    parsed = parse.urlparse(url_value)
    domain = parsed.netloc.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def _domain_allowed(domain: str, allowed_domains: tuple[str, ...]) -> bool:
    for allowed in allowed_domains:
        cleaned_allowed = allowed.lower().strip()
        if cleaned_allowed.startswith("www."):
            cleaned_allowed = cleaned_allowed[4:]
        if domain == cleaned_allowed:
            return True
        if domain.endswith("." + cleaned_allowed):
            return True
    return False


def _extract_publication_value(candidate: dict[str, Any]) -> str | None:
    field_names = (
        "published_at",
        "publishedAt",
        "published",
        "publication_date",
        "date",
        "datetime",
        "timestamp",
        "updated_at",
        "last_updated",
    )
    for field_name in field_names:
        value = candidate.get(field_name)
        if isinstance(value, (int, float)):
            return str(int(value))
        if isinstance(value, str):
            cleaned = value.strip()
            if cleaned:
                return cleaned
    return None


def _annotate_citations(
    *,
    citations: tuple[Citation, ...],
    settings: LiveDataSettings,
    now: datetime,
) -> tuple[Citation, ...]:
    annotated: list[Citation] = []
    for citation in citations:
        trust_tier = _resolve_trust_tier(citation.domain, settings)
        source_type = _classify_source_type(citation.domain, citation.url)
        freshness_window = _freshness_window_days(source_type, settings)
        publication_time = _resolve_publication_datetime(citation.published_at, citation.url)
        normalized_published_at = publication_time.isoformat() if publication_time else None
        age_days: int | None = None
        is_fresh: bool | None = None
        if publication_time is not None:
            delta_seconds = (now - publication_time).total_seconds()
            age_days = max(0, int(delta_seconds // 86400))
            is_fresh = age_days <= freshness_window
        annotated.append(
            replace(
                citation,
                trust_tier=trust_tier,
                source_type=source_type,
                published_at=normalized_published_at,
                freshness_window_days=freshness_window,
                age_days=age_days,
                is_fresh=is_fresh,
            )
        )
    return tuple(annotated)


def _assess_citations(
    *,
    citations: tuple[Citation, ...],
    settings: LiveDataSettings,
    risk_level: str,
) -> LiveDataAssessment:
    trusted_citations = [
        citation for citation in citations if citation.trust_tier in {"high", "medium"}
    ]
    trusted_domains = sorted({citation.domain for citation in trusted_citations})
    stale_count = sum(1 for citation in citations if citation.is_fresh is False)
    unknown_freshness_count = sum(1 for citation in citations if citation.is_fresh is None)

    required_independent_domains = _required_independent_trusted_domains(
        settings=settings,
        risk_level=risk_level,
    )

    failures: list[str] = []
    if len(trusted_citations) < settings.min_trusted_citations:
        failures.append(
            "Trusted citation requirement failed: "
            f"received {len(trusted_citations)}, required {settings.min_trusted_citations}."
        )
    if len(trusted_domains) < required_independent_domains:
        failures.append(
            "Corroboration requirement failed: "
            f"received {len(trusted_domains)} independent trusted domains, "
            f"required {required_independent_domains}."
        )

    if settings.enforce_freshness and settings.strict and stale_count > 0:
        failures.append(
            f"Freshness requirement failed: {stale_count} citation(s) exceed freshness windows."
        )

    if (
        settings.enforce_freshness
        and settings.strict
        and settings.require_publication_dates
        and unknown_freshness_count > 0
    ):
        failures.append(
            "Freshness requirement failed: one or more citations have unknown publication date."
        )

    return LiveDataAssessment(
        passed=not failures,
        trusted_citation_count=len(trusted_citations),
        required_trusted_citation_count=settings.min_trusted_citations,
        independent_trusted_domains=tuple(trusted_domains),
        required_independent_trusted_domains=required_independent_domains,
        stale_citation_count=stale_count,
        unknown_freshness_count=unknown_freshness_count,
        freshness_enforced=settings.enforce_freshness,
        publication_dates_required=settings.require_publication_dates,
        failures=tuple(failures),
    )


def _required_independent_trusted_domains(
    *,
    settings: LiveDataSettings,
    risk_level: str,
) -> int:
    required_independent_domains = settings.min_independent_trusted_domains
    if risk_level == "high":
        required_independent_domains = max(2, required_independent_domains)
    return required_independent_domains


def _resolve_trust_tier(domain: str, settings: LiveDataSettings) -> str:
    if _domain_allowed(domain, settings.high_trust_domains):
        return "high"
    if _domain_allowed(domain, settings.medium_trust_domains):
        return "medium"
    if _domain_allowed(domain, settings.allowed_domains):
        return "medium"
    return "low"


def _classify_source_type(domain: str, url_value: str) -> str:
    lowered_domain = domain.lower()
    lowered_url = url_value.lower()
    advisory_domains = {
        "osv.dev",
        "nvd.nist.gov",
        "cve.mitre.org",
        "security-tracker.debian.org",
    }
    if lowered_domain in advisory_domains:
        return "security_advisory"
    if any(token in lowered_url for token in ("/advisory", "/advisories/", "/cve-")):
        return "security_advisory"
    if lowered_domain.startswith("docs.") or "/docs/" in lowered_url:
        return "official_docs"
    if lowered_domain.endswith(".gov") or lowered_domain.endswith(".edu"):
        return "official_docs"
    if "news" in lowered_domain or "/news/" in lowered_url or "/blog/" in lowered_url:
        return "news"
    return "general"


def _freshness_window_days(source_type: str, settings: LiveDataSettings) -> int:
    if source_type == "news":
        return settings.freshness_days_news
    if source_type == "official_docs":
        return settings.freshness_days_official_docs
    if source_type == "security_advisory":
        return settings.freshness_days_security_advisory
    return settings.freshness_days_general


def _resolve_publication_datetime(
    published_value: str | None,
    url_value: str,
) -> datetime | None:
    parsed = _parse_datetime_value(published_value)
    if parsed is not None:
        return parsed
    parsed_from_url = _parse_datetime_from_url(url_value)
    return parsed_from_url


def _parse_datetime_value(value: str | None) -> datetime | None:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None

    if cleaned.isdigit():
        timestamp = int(cleaned)
        if timestamp > 10_000_000_000:
            timestamp = timestamp // 1000
        try:
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except (OverflowError, ValueError):
            return None

    normalized = cleaned
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        pass

    for fmt in ("%Y-%m-%d", "%Y/%m/%d"):
        try:
            parsed = datetime.strptime(cleaned, fmt).replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            continue

    return None


def _parse_datetime_from_url(url_value: str) -> datetime | None:
    patterns = (
        re.compile(r"/(20\d{2})/(0[1-9]|1[0-2])/(0[1-9]|[12]\d|3[01])(?:/|$)"),
        re.compile(r"(20\d{2})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])"),
    )
    for pattern in patterns:
        match = pattern.search(url_value)
        if not match:
            continue
        year, month, day = match.groups()
        try:
            return datetime(
                year=int(year),
                month=int(month),
                day=int(day),
                tzinfo=timezone.utc,
            )
        except ValueError:
            continue
    return None
