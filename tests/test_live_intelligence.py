from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from lifeguard.live_intelligence import (
    LiveDataConfigurationError,
    LiveDataValidationError,
    LiveIntelligenceClient,
)
from lifeguard.spec_schema import LiveDataSettings


def test_openrouter_live_intelligence_parses_citations(monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-openrouter-key")
    captured: dict[str, object] = {}

    def fake_transport(url, headers, payload, timeout):
        captured["url"] = url
        captured["headers"] = headers
        captured["payload"] = payload
        captured["timeout"] = timeout
        return {
            "output": [
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "Use a trusted retrieval step before generating the design.",
                            "annotations": [
                                {
                                    "type": "url_citation",
                                    "url": "https://openai.com/index/new-tools-for-building-agents/",
                                    "title": "Open Artificial Intelligence Agents",
                                },
                                {
                                    "type": "url_citation",
                                    "url": "https://docs.anthropic.com/en/docs/build-with-claude/web-search",
                                    "title": "Anthropic Web Search",
                                },
                            ],
                        }
                    ],
                }
            ]
        }

    settings = LiveDataSettings(
        enabled=True,
        provider="openrouter",
        model="openai/gpt-5.2:online",
        max_results=5,
        min_citations=2,
        timeout_seconds=15,
        strict=True,
    )
    client = LiveIntelligenceClient(
        transport=fake_transport,
        clock=lambda: datetime(2026, 2, 14, 20, 0, tzinfo=timezone.utc),
    )
    report = client.collect_latest("latest secure agent design techniques", settings)

    assert report.provider == "openrouter"
    assert report.model == "openai/gpt-5.2:online"
    assert len(report.citations) == 2
    assert report.citations[0].domain == "openai.com"
    assert str(captured["url"]).endswith("/chat/completions")
    assert isinstance(captured["payload"], dict)
    assert "plugins" in captured["payload"]
    assert "messages" in captured["payload"]


def test_live_intelligence_fails_when_citations_below_threshold(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")

    def fake_transport(url, headers, payload, timeout):
        return {
            "output": [
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "Only one citation returned.",
                            "annotations": [
                                {
                                    "type": "url_citation",
                                    "url": "https://example.com/one",
                                    "title": "One",
                                }
                            ],
                        }
                    ],
                }
            ]
        }

    settings = LiveDataSettings(
        enabled=True,
        provider="openai",
        model="gpt-5",
        max_results=3,
        min_citations=2,
        timeout_seconds=15,
    )
    client = LiveIntelligenceClient(transport=fake_transport)
    with pytest.raises(LiveDataValidationError):
        client.collect_latest("latest secure design checks", settings)


def test_live_intelligence_enforces_allowed_domains(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key")

    def fake_transport(url, headers, payload, timeout):
        return {
            "content": [
                {
                    "type": "text",
                    "text": "Collected with one disallowed source.",
                    "citations": [
                        {
                            "url": "https://openrouter.ai/docs/use-cases/web-browsing",
                            "title": "Open Router Docs",
                        },
                        {
                            "url": "https://example.com/untrusted",
                            "title": "Untrusted",
                        },
                    ],
                }
            ]
        }

    settings = LiveDataSettings(
        enabled=True,
        provider="anthropic",
        model="claude-sonnet-4-5",
        max_results=5,
        min_citations=1,
        timeout_seconds=15,
        allowed_domains=("openrouter.ai",),
        strict=True,
    )
    client = LiveIntelligenceClient(transport=fake_transport)
    with pytest.raises(LiveDataValidationError):
        client.collect_latest("latest secure design checks", settings)


def test_openai_request_uses_web_search_tool(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    captured: dict[str, object] = {}

    def fake_transport(url, headers, payload, timeout):
        captured["url"] = url
        captured["payload"] = payload
        return {
            "output": [
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "Result",
                            "annotations": [
                                {
                                    "type": "url_citation",
                                    "url": "https://openai.com/index/new-tools-for-building-agents/",
                                    "title": "Open Artificial Intelligence",
                                }
                            ],
                        }
                    ],
                }
            ]
        }

    settings = LiveDataSettings(
        enabled=True,
        provider="openai",
        model="gpt-5",
        max_results=2,
        min_citations=1,
        timeout_seconds=15,
    )
    client = LiveIntelligenceClient(transport=fake_transport)
    client.collect_latest("latest secure design checks", settings)

    assert str(captured["url"]).endswith("/responses")
    assert isinstance(captured["payload"], dict)
    payload = captured["payload"]
    assert payload["tools"][0]["type"] == "web_search"


def test_missing_provider_key_raises_configuration_error(monkeypatch) -> None:
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    settings = LiveDataSettings(enabled=True, provider="openrouter")
    client = LiveIntelligenceClient(transport=lambda *args: {})
    with pytest.raises(LiveDataConfigurationError):
        client.collect_latest("latest secure design checks", settings)


def test_high_risk_live_intelligence_requires_independent_trusted_domains(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")

    def fake_transport(url, headers, payload, timeout):
        return {
            "output": [
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "Two citations from one trusted domain only.",
                            "annotations": [
                                {
                                    "type": "url_citation",
                                    "url": "https://openai.com/research/post-one",
                                    "title": "Post one",
                                },
                                {
                                    "type": "url_citation",
                                    "url": "https://openai.com/research/post-two",
                                    "title": "Post two",
                                },
                            ],
                        }
                    ],
                }
            ]
        }

    settings = LiveDataSettings(
        enabled=True,
        provider="openai",
        model="gpt-5",
        max_results=3,
        min_citations=1,
        min_trusted_citations=1,
        min_independent_trusted_domains=1,
        high_trust_domains=("openai.com",),
        timeout_seconds=15,
        strict=True,
    )
    client = LiveIntelligenceClient(transport=fake_transport)
    with pytest.raises(LiveDataValidationError):
        client.collect_latest(
            "latest secure design checks",
            settings,
            risk_level="high",
        )


def test_live_intelligence_retries_when_trust_assessment_fails(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    calls: list[dict[str, object]] = []

    def fake_transport(url, headers, payload, timeout):
        calls.append(
            {
                "url": url,
                "payload": payload,
                "timeout": timeout,
            }
        )
        if len(calls) == 1:
            return {
                "output": [
                    {
                        "type": "message",
                        "content": [
                            {
                                "type": "output_text",
                                "text": "First attempt has one trusted domain only.",
                                "annotations": [
                                    {
                                        "type": "url_citation",
                                        "url": "https://openai.com/research/post-one",
                                        "title": "Post one",
                                        "published_at": "2026-02-13T00:00:00+00:00",
                                    },
                                    {
                                        "type": "url_citation",
                                        "url": "https://openai.com/research/post-two",
                                        "title": "Post two",
                                        "published_at": "2026-02-12T00:00:00+00:00",
                                    },
                                ],
                            }
                        ],
                    }
                ]
            }
        return {
            "output": [
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "Second attempt uses multiple trusted domains.",
                            "annotations": [
                                {
                                    "type": "url_citation",
                                    "url": "https://openai.com/research/post-three",
                                    "title": "Post three",
                                    "published_at": "2026-02-13T00:00:00+00:00",
                                },
                                {
                                    "type": "url_citation",
                                    "url": "https://docs.anthropic.com/en/docs/build-with-claude/web-search",
                                    "title": "Anthropic docs",
                                    "published_at": "2026-02-13T00:00:00+00:00",
                                },
                            ],
                        }
                    ],
                }
            ]
        }

    settings = LiveDataSettings(
        enabled=True,
        provider="openai",
        model="gpt-5",
        max_results=4,
        min_citations=2,
        min_trusted_citations=2,
        min_independent_trusted_domains=2,
        high_trust_domains=("openai.com", "docs.anthropic.com"),
        timeout_seconds=15,
        strict=True,
    )
    client = LiveIntelligenceClient(
        transport=fake_transport,
        clock=lambda: datetime(2026, 2, 14, 20, 0, tzinfo=timezone.utc),
    )
    report = client.collect_latest(
        "latest secure design checks",
        settings,
        risk_level="high",
    )
    assert len(calls) == 2
    assert len(report.citations) == 2
    assert report.assessment.passed is True

    second_payload = calls[1]["payload"]
    assert isinstance(second_payload, dict)
    second_input = second_payload["input"]
    assert isinstance(second_input, str)
    assert "multiple independent trusted domains" in second_input


def test_live_intelligence_prompt_demands_independent_trusted_domains(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    captured: dict[str, object] = {}

    def fake_transport(url, headers, payload, timeout):
        captured["payload"] = payload
        return {
            "output": [
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "Collected with trusted sources.",
                            "annotations": [
                                {
                                    "type": "url_citation",
                                    "url": "https://openai.com/research/post-three",
                                    "title": "Post three",
                                    "published_at": "2026-02-13T00:00:00+00:00",
                                },
                                {
                                    "type": "url_citation",
                                    "url": "https://docs.anthropic.com/en/docs/build-with-claude/web-search",
                                    "title": "Anthropic docs",
                                    "published_at": "2026-02-13T00:00:00+00:00",
                                },
                            ],
                        }
                    ],
                }
            ]
        }

    settings = LiveDataSettings(
        enabled=True,
        provider="openai",
        model="gpt-5",
        max_results=4,
        min_citations=2,
        min_trusted_citations=2,
        min_independent_trusted_domains=2,
        high_trust_domains=("openai.com", "docs.anthropic.com"),
        timeout_seconds=15,
        strict=True,
    )
    client = LiveIntelligenceClient(
        transport=fake_transport,
        clock=lambda: datetime(2026, 2, 14, 20, 0, tzinfo=timezone.utc),
    )
    client.collect_latest("latest secure design checks", settings, risk_level="high")

    payload = captured["payload"]
    assert isinstance(payload, dict)
    input_prompt = payload["input"]
    assert isinstance(input_prompt, str)
    assert "Required independent trusted domains: 2." in input_prompt
    assert "Prioritize these trusted domains: openai.com, docs.anthropic.com" in input_prompt


def test_live_intelligence_uses_third_attempt_fallback_model_after_zero_citations(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    monkeypatch.setenv("LIFEGUARD_LIVE_DATA_MAX_ATTEMPTS", "3")
    monkeypatch.setenv("LIFEGUARD_LIVE_DATA_FALLBACK_MODEL", "gpt-4.1-mini")
    calls: list[dict[str, object]] = []

    def fake_transport(url, headers, payload, timeout):
        assert isinstance(payload, dict)
        calls.append(
            {
                "model": payload.get("model"),
                "input": payload.get("input"),
            }
        )
        if len(calls) < 3:
            return {
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": "No citations returned."}],
                    }
                ]
            }
        return {
            "output": [
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "Citations recovered.",
                            "annotations": [
                                {
                                    "type": "url_citation",
                                    "url": "https://openai.com/research/post-three",
                                    "title": "Post three",
                                    "published_at": "2026-02-13T00:00:00+00:00",
                                },
                                {
                                    "type": "url_citation",
                                    "url": "https://docs.anthropic.com/en/docs/build-with-claude/web-search",
                                    "title": "Anthropic docs",
                                    "published_at": "2026-02-13T00:00:00+00:00",
                                },
                            ],
                        }
                    ],
                }
            ]
        }

    settings = LiveDataSettings(
        enabled=True,
        provider="openai",
        model="gpt-5",
        max_results=4,
        min_citations=2,
        min_trusted_citations=2,
        min_independent_trusted_domains=2,
        high_trust_domains=("openai.com", "docs.anthropic.com"),
        timeout_seconds=15,
        strict=True,
    )
    client = LiveIntelligenceClient(
        transport=fake_transport,
        clock=lambda: datetime(2026, 2, 14, 20, 0, tzinfo=timezone.utc),
    )
    report = client.collect_latest("latest secure design checks", settings, risk_level="high")

    assert len(calls) == 3
    second_input = calls[1]["input"]
    assert isinstance(second_input, str)
    assert "Constrain sources to trusted domains only" in second_input
    assert calls[2]["model"] == "gpt-4.1-mini"
    assert len(report.attempts) == 3
    assert report.attempts[0].query_variant == "base"
    assert report.attempts[1].query_variant == "trusted_domain_constrained"
    assert report.attempts[2].query_variant == "trusted_domain_constrained_fallback_model"
    assert report.attempts[2].citation_count == 2


def test_live_intelligence_failure_includes_attempt_metadata(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    monkeypatch.setenv("LIFEGUARD_LIVE_DATA_MAX_ATTEMPTS", "3")
    monkeypatch.setenv("LIFEGUARD_LIVE_DATA_FALLBACK_MODEL", "gpt-4.1-mini")

    def fake_transport(url, headers, payload, timeout):
        return {
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": "No citations returned."}],
                }
            ]
        }

    settings = LiveDataSettings(
        enabled=True,
        provider="openai",
        model="gpt-5",
        max_results=4,
        min_citations=2,
        timeout_seconds=15,
        strict=True,
    )
    client = LiveIntelligenceClient(transport=fake_transport)
    with pytest.raises(LiveDataValidationError) as exc_info:
        client.collect_latest("latest secure design checks", settings, risk_level="high")

    attempts = exc_info.value.attempts
    assert len(attempts) == 3
    assert [item.citation_count for item in attempts] == [0, 0, 0]
    assert attempts[0].query_variant == "base"
    assert attempts[1].query_variant == "trusted_domain_constrained"
    assert attempts[2].query_variant == "trusted_domain_constrained_fallback_model"
    assert attempts[2].model == "gpt-4.1-mini"


def test_live_intelligence_rejects_stale_citations_in_strict_mode(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")

    def fake_transport(url, headers, payload, timeout):
        return {
            "output": [
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "One stale source.",
                            "annotations": [
                                {
                                    "type": "url_citation",
                                    "url": "https://security.example.com/advisories/old",
                                    "title": "Old advisory",
                                    "published_at": "2019-01-01T00:00:00+00:00",
                                }
                            ],
                        }
                    ],
                }
            ]
        }

    settings = LiveDataSettings(
        enabled=True,
        provider="openai",
        model="gpt-5",
        max_results=2,
        min_citations=1,
        min_trusted_citations=1,
        high_trust_domains=("security.example.com",),
        timeout_seconds=15,
        strict=True,
        enforce_freshness=True,
        freshness_days_security_advisory=30,
    )
    client = LiveIntelligenceClient(
        transport=fake_transport,
        clock=lambda: datetime(2026, 2, 14, 20, 0, tzinfo=timezone.utc),
    )
    with pytest.raises(LiveDataValidationError):
        client.collect_latest("latest secure design checks", settings, risk_level="low")


def test_live_intelligence_applies_managed_trust_profile(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    profile_file = tmp_path / "managed_profiles.json"
    profile_file.write_text(
        json.dumps(
            {
                "version": 1,
                "profiles": [
                    {
                        "profile_id": "managed-live-test",
                        "display_name": "Managed Live Test",
                        "description": "Managed profile for live intelligence unit test.",
                        "policy_version": "2026-02-14",
                        "approved_by": "security-team",
                        "approval_id": "approval-001",
                        "approved_at": "2026-02-14T00:00:00+00:00",
                        "high_trust_domains": ["trusted.example"],
                        "medium_trust_domains": ["reference.example"],
                        "allowed_domains": ["trusted.example", "reference.example"],
                        "min_trusted_citations_by_risk": {"low": 1, "medium": 2, "high": 2},
                        "min_independent_trusted_domains_by_risk": {
                            "low": 1,
                            "medium": 2,
                            "high": 2
                        },
                        "enforce_freshness": True,
                        "require_publication_dates": False,
                        "freshness_days_news": 45,
                        "freshness_days_official_docs": 365,
                        "freshness_days_security_advisory": 180,
                        "freshness_days_general": 120
                    }
                ]
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    def fake_transport(url, headers, payload, timeout):
        return {
            "output": [
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "Managed profile sources.",
                            "annotations": [
                                {
                                    "type": "url_citation",
                                    "url": "https://trusted.example/2026/02/10/report",
                                    "title": "Trusted report",
                                },
                                {
                                    "type": "url_citation",
                                    "url": "https://reference.example/2026/02/10/guide",
                                    "title": "Reference guide",
                                },
                            ],
                        }
                    ],
                }
            ]
        }

    settings = LiveDataSettings(
        enabled=True,
        provider="openai",
        model="gpt-5",
        max_results=5,
        min_citations=1,
        timeout_seconds=15,
        trust_profile_id="managed-live-test",
        trust_profile_file=str(profile_file),
    )
    client = LiveIntelligenceClient(
        transport=fake_transport,
        clock=lambda: datetime(2026, 2, 14, 20, 0, tzinfo=timezone.utc),
    )
    report = client.collect_latest("latest secure design checks", settings, risk_level="medium")
    assert report.assessment.managed_profile is not None
    assert report.assessment.managed_profile["profile_id"] == "managed-live-test"


def test_live_intelligence_handles_deeply_nested_payload_without_crashing(monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-openrouter-key")

    def fake_transport(url, headers, payload, timeout):
        leaf = {
            "text": "Deep response leaf.",
            "annotations": [
                {
                    "type": "url_citation",
                    "url": "https://openai.com/index/new-tools-for-building-agents/",
                    "title": "Open Artificial Intelligence Agents",
                }
            ],
        }
        node = leaf
        for _ in range(2500):
            node = {"content": node}
        return node

    settings = LiveDataSettings(
        enabled=True,
        provider="openrouter",
        model="openai/gpt-5.2:online",
        max_results=2,
        min_citations=1,
        timeout_seconds=15,
        strict=True,
    )
    client = LiveIntelligenceClient(transport=fake_transport)
    report = client.collect_latest("latest secure design checks", settings)
    assert len(report.citations) == 1


def test_live_intelligence_capture_redacts_sensitive_fields(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    monkeypatch.setenv("LIFEGUARD_LIVE_DATA_CAPTURE_ROOT", str(tmp_path))
    monkeypatch.setenv("LIFEGUARD_LIVE_DATA_CAPTURE_PATH", "captures/live_response.json")

    def fake_transport(url, headers, payload, timeout):
        return {
            "api_key": "top-secret",
            "response_headers": {"authorization": "Bearer should-not-leak"},
            "output": [
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "Use current references.",
                            "annotations": [
                                {
                                    "type": "url_citation",
                                    "url": "https://openai.com/index/new-tools-for-building-agents/",
                                    "title": "Open Artificial Intelligence Agents",
                                }
                            ],
                        }
                    ],
                }
            ],
        }

    settings = LiveDataSettings(
        enabled=True,
        provider="openai",
        model="gpt-5",
        max_results=2,
        min_citations=1,
        timeout_seconds=15,
        strict=True,
    )
    client = LiveIntelligenceClient(
        transport=fake_transport,
        clock=lambda: datetime(2026, 2, 14, 20, 0, tzinfo=timezone.utc),
    )
    client.collect_latest("latest secure design checks", settings)

    capture_file = tmp_path / "captures" / "live_response.json"
    assert capture_file.exists()
    payload = json.loads(capture_file.read_text(encoding="utf-8"))
    assert payload["response"]["api_key"] == "<redacted>"
    assert payload["response"]["response_headers"]["authorization"] == "<redacted>"


def test_live_intelligence_capture_blocks_paths_outside_capture_root(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    monkeypatch.setenv("LIFEGUARD_LIVE_DATA_CAPTURE_ROOT", str(tmp_path))
    monkeypatch.setenv("LIFEGUARD_LIVE_DATA_CAPTURE_PATH", "../outside.json")

    def fake_transport(url, headers, payload, timeout):
        return {
            "output": [
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "Use current references.",
                            "annotations": [
                                {
                                    "type": "url_citation",
                                    "url": "https://openai.com/index/new-tools-for-building-agents/",
                                    "title": "Open Artificial Intelligence Agents",
                                }
                            ],
                        }
                    ],
                }
            ],
        }

    settings = LiveDataSettings(
        enabled=True,
        provider="openai",
        model="gpt-5",
        max_results=2,
        min_citations=1,
        timeout_seconds=15,
        strict=True,
    )
    client = LiveIntelligenceClient(
        transport=fake_transport,
        clock=lambda: datetime(2026, 2, 14, 20, 0, tzinfo=timezone.utc),
    )
    client.collect_latest("latest secure design checks", settings)

    assert not Path(tmp_path).parent.joinpath("outside.json").exists()
