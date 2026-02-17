# Lifeguard
[![Lifeguard Workflow](https://github.com/shymonski-dev/Lifeguard/actions/workflows/lifeguard.yml/badge.svg)](https://github.com/shymonski-dev/Lifeguard/actions/workflows/lifeguard.yml)

Lifeguard is a standalone project for designing and verifying secure, tool-using agents.

The workflow uploads `sigstore_badge.json` and `owasp_control_badge.json` as run artifacts.

Latest workflow validation record:

1. Date: `2026-02-17`
2. Result: success
3. Workflow path: `.github/workflows/lifeguard.yml`

## Project status

Status date: `2026-02-17`

1. Completion gate: passed.
2. Full validation run one: `validation/hardening_run_20260217_full_confidence_fix2_run1`
3. Full validation run two: `validation/hardening_run_20260217_full_confidence_fix2_run2`
4. Completion declaration: `validation/COMPLETION_DECLARATION.md`

## What this project does

1. Loads an agent specification from JSON.
2. Compiles a concrete policy from that specification.
3. Applies runtime policy middleware checks to each declared tool command.
4. Applies threat checks based on risk level.
5. Runs a verification pipeline before release, including optional live intelligence freshness checks.
6. Writes append-only evidence records with a hash chain.
7. Runs deterministic adversarial validation packs and scores resilience by risk level.
8. Supports optional deterministic LangGraph runtime execution with checkpoint, resume, and replay.

## Project layout

- `src/lifeguard/spec_schema.py`: Specification model and validation.
- `src/lifeguard/policy_compiler.py`: Policy generation and command checks.
- `src/lifeguard/threat_model.py`: Risk templates and policy checks.
- `src/lifeguard/verification_pipeline.py`: Ordered verification steps.
- `src/lifeguard/evidence_store.py`: Tamper-evident evidence log.
- `src/lifeguard/live_intelligence.py`: Provider-backed live web intelligence with citations.
- `src/lifeguard/langgraph_runtime.py`: Deterministic LangGraph adapter runtime.
- `src/lifeguard/open_source_guardrails.py`: Open source mode startup guardrails.
- `src/lifeguard/release_workflow.py`: Adapter-backed release packaging with signature.
- `src/lifeguard/cli.py`: Command line entry point.
- `src/lifeguard/adapters/extracts_adapter.py`: Adapter layer for selected extracted modules.
- `src/lifeguard/adapters/contract.py`: Versioned adapter contract for action requests and results.

## Quick start

```bash
cd lifeguard
export OPENROUTER_API_KEY="your-key"
pip install -e ".[graph_runtime]"
PYTHONPATH=src python3 -m lifeguard profiles
PYTHONPATH=src python3 -m lifeguard trust-source-profiles
PYTHONPATH=src python3 -m lifeguard init --path spec.json --profile secure_code_review
PYTHONPATH=src python3 -m lifeguard quality --spec spec.json
PYTHONPATH=src python3 -m lifeguard verify --spec spec.json --evidence evidence/events.jsonl --repo /path/to/repo
PYTHONPATH=src python3 -m lifeguard adversarial-report --evidence evidence/events.jsonl --limit 10
PYTHONPATH=src python3 -m lifeguard verify --spec spec.json --evidence evidence/events.jsonl --runtime langgraph --checkpoint-dir checkpoints
PYTHONPATH=src python3 -m lifeguard resume --checkpoint checkpoints/<run>--003--compile_policy.json --evidence evidence/events_resume.jsonl --checkpoint-dir checkpoints_resume
PYTHONPATH=src python3 -m lifeguard replay --checkpoint checkpoints/<run>--006--verification.json --evidence evidence/events_replay.jsonl --checkpoint-dir checkpoints_replay
PYTHONPATH=src python3 -m lifeguard intelligence --spec spec.json
PYTHONPATH=src python3 -m lifeguard compat-export --spec spec.json --adapter langchain --output compatibility/langchain_export.json
PYTHONPATH=src python3 -m lifeguard compat-import --adapter langchain --input compatibility/langchain_export.json --output compatibility/lifeguard_from_langchain.json
PYTHONPATH=src python3 -m lifeguard compat-export --spec spec.json --adapter langgraph --output compatibility/langgraph_export.json
PYTHONPATH=src python3 -m lifeguard compat-import --adapter langgraph --input compatibility/langgraph_export.json --output compatibility/lifeguard_from_langgraph.json
PYTHONPATH=src python3 -m lifeguard compat-export --spec spec.json --adapter mcp --output compatibility/mcp_export.json
PYTHONPATH=src python3 -m lifeguard compat-import --adapter mcp --input compatibility/mcp_export.json --output compatibility/lifeguard_from_mcp.json
PYTHONPATH=src python3 -m lifeguard release --spec spec.json --evidence evidence/events.jsonl --output release_artifacts --runtime langgraph --checkpoint-dir checkpoints --approved-by security-reviewer --approval-id approval-001 --signing-key-file ./keys/release_signing.key
PYTHONPATH=src python3 -m lifeguard release --spec spec_local.json --evidence evidence/events_local.jsonl --output release_sigstore --signing-mode sigstore --sigstore-repository owner/repository --sigstore-workflow .github/workflows/lifeguard.yml
PYTHONPATH=src python3 -m lifeguard dashboard --validation-root validation --output validation/dashboard.html
```

Completion validation entry points:

1. Plan file: `validation/COMPLETION_PLAN.md`
2. Stage runner: `python3 scripts/run_completion_validation.py --stage stage-0`
3. Stage one runner: `python3 scripts/run_completion_validation.py --stage stage-1`
4. Stage two runner: `python3 scripts/run_completion_validation.py --stage stage-2`
5. Stage three runner: `python3 scripts/run_completion_validation.py --stage stage-3`
6. Stage four runner: `python3 scripts/run_completion_validation.py --stage stage-4`
7. Stage five runner: `python3 scripts/run_completion_validation.py --stage stage-5`
8. Stage six runner: `python3 scripts/run_completion_validation.py --stage stage-6`
9. Full runner: `python3 scripts/run_completion_validation.py --stage all`
10. Latest validation summary: `validation/latest_run_summary.txt`
11. Completion declaration: `validation/COMPLETION_DECLARATION.md`

Local smoke profile without live intelligence key:

```bash
PYTHONPATH=src python3 -m lifeguard init --path spec_local.json --profile secure_code_review_local
PYTHONPATH=src python3 -m lifeguard verify --spec spec_local.json --evidence evidence/events_local.jsonl
```

Default starter profile:

1. Agent type: secure code review
2. Risk strictness: high
3. Runtime environment: container
4. Live intelligence: enabled, provider `openrouter`, model `openai/gpt-5.2:online`
5. Trusted sources: high-trust and medium-trust domain tiers with corroboration rules
6. Managed trust source profile: `secure_code_review_primary`

## Notes

- This project is intentionally separate from the prior codebase.
- Lifeguard uses a deterministic design method and blocks evolutionary process commands.
- Lifeguard uses extracted modules so core verification can run in minimal environments.
- Lifeguard uses a hardened default container image for sandbox execution: `cgr.dev/chainguard/python:latest-dev`.
- Network-enabled sandbox runs use an isolated internal Docker network plus a dedicated outbound gateway that enforces allowed hosts at runtime.
- Host network mode is blocked by policy even if `LIFEGUARD_SANDBOX_NETWORK=host` is set.
- Unhardened container images are blocked by default. A two-part explicit override is required:
  - `LIFEGUARD_ALLOW_UNHARDENED_IMAGE=1`
  - `LIFEGUARD_ALLOW_UNHARDENED_IMAGE_ACK=I_UNDERSTAND_UNHARDENED_IMAGE_RISK`
- Optional sandbox network controls:
  - `LIFEGUARD_SANDBOX_GATEWAY_IMAGE` for gateway image selection.
  - `LIFEGUARD_ALLOWED_EGRESS_PORTS` for gateway outbound ports (default `80,443`).

## Adapter layer

Selected modules currently wrapped by the adapter layer:

1. `lifeguard.extracts.circuit_breaker`
2. `lifeguard.extracts.retry`
3. `lifeguard.extracts.json_parser`
4. `lifeguard.extracts.security_preflight`
5. `lifeguard.extracts.analyzer_usage`
6. `lifeguard.extracts.model_registry`
7. `lifeguard.extracts.ast_guard`

Verification and release use this adapter layer directly.

The adapter layer now exposes one stable contract:

1. `contract_version`: `1.0.0`
2. `list_tool_schemas()`: typed tool and action schema list
3. `execute_action(request)`: typed action result with structured error model and trust metadata

First external compatibility adapter:

1. `LangChainCompatibilityAdapter`
2. `langchain.export.agent_spec` converts a Lifeguard specification into a LangChain-style tool bundle.
3. `langchain.import.tool_bundle` converts a LangChain-style tool bundle into Lifeguard tool declarations plus data scope hints.

Second external compatibility adapter:

1. `LangGraphCompatibilityAdapter`
2. `langgraph.export.agent_spec` converts a Lifeguard specification into a LangGraph-style flow definition.
3. `langgraph.import.flow_definition` converts a LangGraph-style flow definition into Lifeguard tool declarations plus data scope hints.

Third external compatibility adapter:

1. `ModelContextProtocolCompatibilityAdapter`
2. `mcp.export.agent_spec` converts a Lifeguard specification into a Model Context Protocol server bundle.
3. `mcp.import.server_bundle` converts a Model Context Protocol server bundle into Lifeguard tool declarations plus strict gating metadata.
4. Import gating is deny-by-default and fail-closed:
   - pinned server version is required
   - trust profile identifier is required
   - host allow list metadata is required for network-enabled tools
   - local startup command fields are rejected
5. Release compatibility gate blocks advisory-only Model Context Protocol decisions.
6. Verification writes explicit evidence events for export, import, per-decision checks, and final gating status.

## Live intelligence

Lifeguard can enforce fresh, cited design intelligence during verification.

1. `live_data.enabled=true` turns the check on.
2. `live_data.provider` can be `openrouter`, `openai`, or `anthropic`.
3. `live_data.min_citations` enforces minimum source count.
4. `live_data.high_trust_domains` and `live_data.medium_trust_domains` define trust tiers.
5. `live_data.min_independent_trusted_domains` enforces corroboration across independent trusted domains.
6. Freshness windows are configured per source type:
   - `live_data.freshness_days_news`
   - `live_data.freshness_days_official_docs`
   - `live_data.freshness_days_security_advisory`
   - `live_data.freshness_days_general`
7. `live_data.strict=true` blocks verification when trust or freshness checks fail.
8. Managed trust source profile fields:
   - `live_data.trust_profile_id`
   - `live_data.trust_profile_file` (optional override path)
9. Default managed profile file:
   - `trust_profiles/managed_trust_profiles.json`

## Adversarial validation

Lifeguard runs a deterministic adversarial pack during verification.

1. Categories include prompt injection, command smuggling, and data exfiltration attempts.
2. Each case mutates declared tool commands and confirms runtime policy blocking.
3. Verification pass rate thresholds by risk level:
   - low: 0.70
   - medium: 0.85
   - high: 0.95
4. Release gate thresholds by risk level:
   - low: 0.80
   - medium: 0.90
   - high: 1.00
5. Release is blocked when adversarial gate thresholds are not met.
6. Every verification run writes:
   - a detailed artifact file in `<evidence_stem>.adversarial_reports/`
   - a line in `<evidence_stem>.adversarial_history.jsonl` for trend tracking.

Environment variables by provider:

1. OpenRouter: `OPENROUTER_API_KEY`
2. OpenAI: `OPENAI_API_KEY`
3. Anthropic: `ANTHROPIC_API_KEY`

## Open source guardrails

Lifeguard blocks LangSmith service configuration in open source mode.

Blocked environment variables:

1. `LANGSMITH_API_KEY`
2. `LANGCHAIN_API_KEY`
3. `LANGSMITH_ENDPOINT`
4. `LANGCHAIN_ENDPOINT`
5. `LANGCHAIN_TRACING_V2` when enabled
6. `LANGSMITH_TRACING` when enabled

You can run a local package license check with:

```bash
python scripts/check_open_source_licenses.py --allow-missing
```

## LangGraph runtime

`verify` supports two runtime modes:

1. `standard`: Current verification pipeline.
2. `langgraph`: Deterministic fixed-step graph:
   - load specification
   - collect live intelligence
   - compile policy
   - policy runtime gate
   - run threat checks
   - run verification pipeline
3. Runtime checkpoints are written after every node.
4. `resume` continues from any saved checkpoint.
5. `replay` re-runs from a checkpoint and compares state signatures.

## Release controls

1. High-risk release publishing requires `--approved-by` and `--approval-id`.
2. Release signing modes:
   - `hmac` (default): key-based `hmac-sha256`
   - `sigstore`: Sigstore bundle signing and identity verification
   - `auto`: try Sigstore first, then fall back to `hmac`
3. Compatibility gate validates adapter round trips before release packaging, including LangChain, LangGraph, and optional Model Context Protocol.
4. You can override compatibility gate adapters with `LIFEGUARD_COMPATIBILITY_GATE_ADAPTERS` (comma-separated), including `mcp`.
5. Signing key sources for `hmac` mode:
   - `--signing-key-file`
   - `LIFEGUARD_SIGNING_KEY_FILE`
   - `LIFEGUARD_SIGNING_KEY`
6. Sigstore identity binding settings:
   - `--sigstore-repository` or `LIFEGUARD_SIGSTORE_REPOSITORY`
   - `--sigstore-workflow` or `LIFEGUARD_SIGSTORE_WORKFLOW`
   - optional `--sigstore-bundle-path` or `LIFEGUARD_SIGSTORE_BUNDLE_PATH`
   - optional `--sigstore-certificate-oidc-issuer` or `LIFEGUARD_SIGSTORE_CERTIFICATE_OIDC_ISSUER`
7. Sigstore recommendation:
   - use `--signing-mode sigstore` in continuous integration workflows with identity token support
   - use `--signing-mode auto` or `--signing-mode hmac` for local developer runs
8. Control matrix gate:
   - release blocks when required control mappings are missing
   - default matrix file: `docs/compliance/owasp_control_matrix.json`
   - optional override: `--control-matrix-file`
9. Release output now includes:
   - `owasp_control_badge.json` badge material
   - `release_manifest_payload.json` when Sigstore signing is used

## Verification dashboard

Generate a read-only dashboard from validation artifacts:

```bash
PYTHONPATH=src python3 -m lifeguard dashboard --validation-root validation --output validation/dashboard.html
```

The dashboard includes release pass rates, signature algorithms, risk distribution, Model Context Protocol gating outcomes, live intelligence citation metrics, and manifest index rows.

## Continuous integration

Automated verification and release checks are defined in:

1. `.github/workflows/lifeguard.yml`

Operations and migration documents:

1. `docs/OPERATIONS_RUNBOOK.md`
2. `docs/ADAPTER_MIGRATION_POLICY.md`
