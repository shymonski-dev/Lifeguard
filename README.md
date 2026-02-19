# Lifeguard

[![Lifeguard Workflow](https://github.com/shymonski-dev/Lifeguard/actions/workflows/lifeguard.yml/badge.svg)](https://github.com/shymonski-dev/Lifeguard/actions/workflows/lifeguard.yml)

Lifeguard verifies that tool-using AI agents meet security, policy, and compliance requirements before they are released. It produces tamper-evident evidence logs, runs adversarial validation, and optionally gates releases on legislative review with a human decision record.

**Core has no third party Python dependencies.** Some features rely on external tools such as Docker and Sigstore. Pure Python. Deny by default.

Suggested use cases ..

Legislative Review Agent
Use case: checks contracts, policies, or guidance against current United Kingdom and European Union legal sources, flags conflicts, and creates an auditable decision pack for human approval.

Supplier Risk Review Agent
Use case: reviews supplier claims and documents, verifies trust and freshness of supporting evidence, applies security policy gates, and produces approve or reject recommendations with full traceability.

Tax and Administrative Readiness Agent
Use case: validates filings and supporting documents against current rules and internal controls, catches missing or weak evidence, and blocks release until required human decisions are recorded.



## Install

```bash
pip install -e .
# or, with optional LangGraph runtime support:
pip install -e ".[graph_runtime]"
```

## Quick start

```bash
# Generate a local spec (no API key required)
python3 -m lifeguard init --path spec.json --profile secure_code_review_local

# Verify the agent specification
python3 -m lifeguard verify --spec spec.json --evidence evidence.jsonl

# View available profiles
python3 -m lifeguard profiles
```

See [`examples/`](examples/) for a worked example with expected output.

## GitHub Action

Lifeguard now ships as a reusable GitHub Action from the repository root (`action.yml`), ready for free GitHub Marketplace listing.

```yaml
name: lifeguard-verify
on:
  workflow_dispatch:
  pull_request:
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Lifeguard verification
        uses: shymonski-dev/Lifeguard@v0.1.0
        with:
          spec_path: examples/spec_local.json
          evidence_path: .lifeguard/evidence.jsonl
```

When live intelligence is enabled in your specification, add one provider key as a repository secret and pass it through environment variables:

```yaml
      - name: Run Lifeguard verification
        uses: shymonski-dev/Lifeguard@v0.1.0
        with:
          spec_path: spec.json
          evidence_path: .lifeguard/evidence.jsonl
        env:
          OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
```

Publish steps for Marketplace:

1. Push the action file on `main`.
2. Create a semantic version tag (`v0.1.0`) and push the tag.
3. Create a GitHub release for that tag.
4. In GitHub Marketplace, publish the repository action listing.

## What Lifeguard does

1. Loads an agent specification from JSON.
2. Compiles a concrete policy from that specification.
3. Applies runtime policy middleware checks to each declared tool command.
4. Applies threat checks based on risk level.
5. Runs a verification pipeline before release, including optional live intelligence freshness checks.
6. Optionally runs a legislative review gate (United Kingdom and European Union) requiring a human decision record.
7. Writes append-only evidence records with a SHA-256 hash chain.
8. Runs deterministic adversarial validation packs and scores resilience by risk level.
9. Supports optional deterministic LangGraph runtime execution with checkpoint, resume, and replay.

## Project layout

| File | Purpose |
|------|---------|
| `src/lifeguard/spec_schema.py` | Specification model and validation |
| `src/lifeguard/policy_compiler.py` | Policy generation and command checks |
| `src/lifeguard/threat_model.py` | Risk templates and policy checks |
| `src/lifeguard/verification_pipeline.py` | Ordered verification steps |
| `src/lifeguard/evidence_store.py` | Tamper-evident evidence log |
| `src/lifeguard/live_intelligence.py` | Provider-backed live web intelligence with citations |
| `src/lifeguard/legislative_review.py` | Legislative review pack and decision file validation |
| `src/lifeguard/langgraph_runtime.py` | Deterministic LangGraph adapter runtime |
| `src/lifeguard/release_workflow.py` | Release packaging with signature |
| `src/lifeguard/docker_sandbox.py` | Hardened container sandbox execution |
| `src/lifeguard/cli.py` | Command line entry point |

## CLI commands

```bash
# Specification
python3 -m lifeguard init --path spec.json --profile secure_code_review
python3 -m lifeguard profiles
python3 -m lifeguard trust-source-profiles
python3 -m lifeguard quality --spec spec.json

# Verification
python3 -m lifeguard verify --spec spec.json --evidence evidence.jsonl
python3 -m lifeguard verify --spec spec.json --evidence evidence.jsonl --runtime langgraph --checkpoint-dir checkpoints

# Adversarial reporting
python3 -m lifeguard adversarial-report --evidence evidence.jsonl --limit 10

# Live intelligence (requires API key)
python3 -m lifeguard intelligence --spec spec.json

# Legislative review (requires API key)
python3 -m lifeguard legislative-review --spec spec.json --evidence evidence.jsonl

# Checkpoint resume and replay
python3 -m lifeguard resume --checkpoint checkpoints/<file>.json --evidence evidence_resume.jsonl --checkpoint-dir checkpoints_resume
python3 -m lifeguard replay --checkpoint checkpoints/<file>.json --evidence evidence_replay.jsonl --checkpoint-dir checkpoints_replay

# Compatibility adapters
python3 -m lifeguard compat-export --spec spec.json --adapter langchain --output export.json
python3 -m lifeguard compat-import --adapter langchain --input export.json --output imported.json

# Release
python3 -m lifeguard release --spec spec.json --evidence evidence.jsonl --output release_artifacts --signing-key-file signing.key

# Dashboard
python3 -m lifeguard dashboard --validation-root validation --output dashboard.html
```

## API keys

Live intelligence and legislative review require one provider key:

| Provider | Variable |
|----------|----------|
| OpenRouter | `OPENROUTER_API_KEY` |
| OpenAI | `OPENAI_API_KEY` |
| Anthropic | `ANTHROPIC_API_KEY` |

The local smoke profile (`secure_code_review_local`) runs without any API key.

## Adversarial validation

Lifeguard runs a deterministic adversarial pack during verification covering prompt injection, command smuggling, and data exfiltration attempts.

Pass rate thresholds by risk level:

| Risk | Verification | Release |
|------|-------------|---------|
| low | 0.70 | 0.80 |
| medium | 0.85 | 0.90 |
| high | 0.95 | 1.00 |

## Live intelligence

When `live_data.enabled=true`, verification enforces fresh, cited intelligence from trusted sources.

- Configurable trust tiers (high-trust and medium-trust domains)
- Corroboration across independent trusted domains
- Freshness windows per source type (news, official docs, security advisories)
- Managed trust source profiles with `python3 -m lifeguard trust-source-profiles`

## Legislative review

Optional legislative review gate for United Kingdom and European Union use cases.

1. Enable `legislative_review.enabled=true` in the specification.
2. Run `python3 -m lifeguard legislative-review --spec spec.json --evidence evidence.jsonl`.
3. Review the generated decision pack and set `decision=accept` in the decision file.
4. Verification and release are blocked until the human decision is recorded.

## Docker sandbox

Tool execution uses a hardened container image (`cgr.dev/chainguard/python:latest-dev`) with:

- `--cap-drop=ALL`, `--read-only`, `--no-new-privileges`
- Non-root user (65532:65532), PID and memory limits
- Network isolation with dedicated outbound gateway enforcing allowed hosts
- Host network mode blocked by policy

Unhardened images require a two-part explicit override:

```bash
LIFEGUARD_ALLOW_UNHARDENED_IMAGE=1
LIFEGUARD_ALLOW_UNHARDENED_IMAGE_ACK=I_UNDERSTAND_UNHARDENED_IMAGE_RISK
```

## Release controls

- High-risk releases require `--approved-by` and `--approval-id`
- Signing modes: `hmac` (default), `sigstore` (CI environments), `auto` (try Sigstore first)
- Compatibility gate validates adapter round trips before packaging
- OWASP control matrix gate blocks release when required mappings are missing

## Compatibility adapters

Export and import agent specifications to and from:

- **LangChain**: tool bundles with policy hints
- **LangGraph**: flow definitions with tool nodes
- **Model Context Protocol**: server bundles with deny-by-default gating

MCP import gating is fail-closed: pinned server version, trust profile, and host allow list are required. Local startup commands are blocked.

## Open source guardrails

Lifeguard blocks LangSmith service configuration in open source mode (`LANGSMITH_API_KEY`, `LANGCHAIN_TRACING_V2`, etc.).

## Design principles

- **Deterministic by default.** No evolutionary or mutation-driven agent design.
- **Deny by default.** Nothing executes unless explicitly permitted.
- **Human decision required** for tool execution that accesses the network or writes files.
- **Legislative review is decision support**, not automated legal advice.
- **Military and healthcare scopes are blocked** by specification validation.

## Notes

- This project uses extracted modules from a parent codebase so core verification runs in minimal environments.
- The `extracts/` directory contains vendored utility modules (circuit breaker, retry, JSON parser, AST guard, etc.).
- Zero runtime dependencies. Optional dependencies for LangGraph runtime and development tooling.

## Documentation

- [Operations Runbook](docs/OPERATIONS_RUNBOOK.md)
- [Forward Development Plan](docs/FORWARD_DEVELOPMENT_PLAN.md)
- [Adapter Migration Policy](docs/ADAPTER_MIGRATION_POLICY.md)

## License

[MIT](LICENSE)
