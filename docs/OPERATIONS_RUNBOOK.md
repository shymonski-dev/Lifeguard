# Lifeguard Operations Runbook

This runbook documents local operator commands for deployment checks and runtime recovery.

Completion note:
1. Completion declaration file: `validation/COMPLETION_DECLARATION.md`
2. Completion date: `2026-02-17`

Continuous integration note:
1. The signed release workflow is `.github/workflows/lifeguard.yml`.
2. The workflow artifact bundle includes `sigstore_badge.json` and `owasp_control_badge.json`.

## 1. Prepare Environment

```bash
cd lifeguard
export PYTHONPATH=src
```

Optional provider key note:

1. The smoke profile below runs without live intelligence.
2. If you run a profile with live intelligence enabled, set one provider key: `OPENROUTER_API_KEY`, `OPENAI_API_KEY`, or `ANTHROPIC_API_KEY`.
3. If you enable the legislative review gate, it also requires a provider key.

## 2. Create a Local Smoke Specification

```bash
python3 -m lifeguard init --path runbook/spec_local.json --force --profile secure_code_review_local
```

## 3. Verify the Specification

```bash
python3 -m lifeguard verify --spec runbook/spec_local.json --evidence runbook/evidence_local.jsonl
```

## 4. Run Legislative Review (optional)

This is only required when `legislative_review.enabled=true` in the specification.

```bash
python3 -m lifeguard legislative-review --spec runbook/spec_local.json --evidence runbook/evidence_local.jsonl
```

If the decision file is missing, Lifeguard writes a template next to the evidence log. Fill it in and set `decision` to `accept`, then re-run `verify` and `release`.

## 5. Generate Adversarial History Summary

```bash
python3 -m lifeguard adversarial-report --evidence runbook/evidence_local.jsonl --limit 5
```

## 6. Verify Evidence Hash Chain

```bash
python3 - <<'PY'
from lifeguard import EvidenceStore
result = EvidenceStore("runbook/evidence_local.jsonl").verify_chain()
print({"passed": result.passed, "record_count": result.record_count, "failure_index": result.failure_index, "failure_reason": result.failure_reason})
PY
```

## 7. Build Signed Release Artifacts (key based)

Note: release is blocked when `legislative_review.enabled=true` and the human decision file is missing or not set to `accept`.

```bash
printf "lifeguard-runbook-signing-key-material-123456789" > runbook/signing.key
python3 -m lifeguard release --spec runbook/spec_local.json --evidence runbook/evidence_local.jsonl --output runbook/release --signing-key-file runbook/signing.key
```

## 8. Build Signed Release Artifacts (Sigstore mode)

Use this command in a continuous integration environment where identity token support is enabled:

```bash
python3 -m lifeguard release --spec runbook/spec_local.json --evidence runbook/evidence_local.jsonl --output runbook/release_sigstore --signing-mode sigstore --sigstore-repository owner/repository --sigstore-workflow .github/workflows/lifeguard.yml
```

For local developer runs, use `--signing-mode auto` or `--signing-mode hmac`.

## 9. Run Deterministic Graph Runtime with Checkpoint

Optional dependency note:

```bash
python3 -m pip install -e ".[graph_runtime]"
```

```bash
python3 -m lifeguard verify --spec runbook/spec_local.json --evidence runbook/evidence_graph.jsonl --runtime langgraph --checkpoint-dir runbook/checkpoints
```

## 10. Resume from Checkpoint

```bash
python3 -m lifeguard resume --checkpoint runbook/checkpoints/<checkpoint-file>.json --evidence runbook/evidence_resume.jsonl --checkpoint-dir runbook/checkpoints_resume
```

## 11. Replay from Checkpoint

```bash
python3 -m lifeguard replay --checkpoint runbook/checkpoints/<checkpoint-file>.json --evidence runbook/evidence_replay.jsonl --checkpoint-dir runbook/checkpoints_replay
```

## 12. Trust Source Profile Review

```bash
python3 -m lifeguard trust-source-profiles
```

## 13. Build Verification Dashboard

```bash
python3 -m lifeguard dashboard --validation-root validation --output validation/dashboard.html
```

## 14. Completion Validation (Optional)

Writes stage output under `validation/`.

```bash
python3 scripts/run_completion_validation.py --stage stage-0
python3 scripts/run_completion_validation.py --stage stage-1
python3 scripts/run_completion_validation.py --stage all --validation-root validation/hardening_run_20260217_full_confidence_fix2_run1
python3 scripts/run_completion_validation.py --stage all --validation-root validation/hardening_run_20260217_full_confidence_fix2_run2
python3 scripts/run_completion_validation.py --stage all --validation-root validation/legislative_review_20260217_full_escalated
```

## 15. Completion Record Review

```bash
cat validation/COMPLETION_DECLARATION.md
```
