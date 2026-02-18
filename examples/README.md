# Examples

## Local smoke test (no API key required)

`spec_local.json` is a pre-built agent specification using the `secure_code_review_local` profile. It runs without live intelligence or API keys.

### Generate the spec yourself

```bash
python3 -m lifeguard init --path examples/spec_local.json --profile secure_code_review_local --force
```

### Run verification

```bash
python3 -m lifeguard verify --spec examples/spec_local.json --evidence examples/evidence.jsonl
```

### Expected output

All 13 checks pass. Evidence is written to `evidence.jsonl` as append-only JSONL with a SHA-256 hash chain.

```
[PASS] spec_quality_gate: Specification quality score 100/80.
[PASS] policy_compilation: Policy compiled successfully.
[PASS] adapter_module_readiness: Adapter module readiness satisfied.
[PASS] model_context_protocol_gating: Model Context Protocol gating decisions satisfied.
[PASS] secret_hygiene: No obvious secret markers detected.
[PASS] threat_controls: Threat controls satisfied.
[PASS] live_intelligence_freshness: Live intelligence is disabled.
[PASS] legislative_review_gate: Legislative review is disabled.
[PASS] runtime_environment_guardrail: Runtime environment guardrail satisfied.
[PASS] adapter_security_preflight: Security preflight satisfied.
[PASS] budget_guardrail: Budget cap satisfied.
[PASS] runtime_guardrail: Runtime guardrail satisfied.
[PASS] adversarial_resilience: pass_rate=1.00 threshold=0.85
```

### Verify the evidence hash chain

```bash
python3 -c "
from lifeguard import EvidenceStore
result = EvidenceStore('examples/evidence.jsonl').verify_chain()
print(f'Chain valid: {result.passed}, records: {result.record_count}')
"
```

## Profiles with live intelligence (requires API key)

Set one provider key:

```bash
export OPENROUTER_API_KEY="your-key"
# or: export OPENAI_API_KEY="your-key"
# or: export ANTHROPIC_API_KEY="your-key"
```

Then generate a full spec:

```bash
python3 -m lifeguard init --path spec.json --profile secure_code_review
python3 -m lifeguard verify --spec spec.json --evidence evidence.jsonl
```

## Available profiles

```bash
python3 -m lifeguard profiles
```
