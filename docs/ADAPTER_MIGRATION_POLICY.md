# Lifeguard Adapter Contract Migration Policy

Current contract version: `1.0.0`

This policy freezes the adapter contract for stable integrations and defines migration rules.

## Validation Record

Record date: `2026-02-17`

1. Full completion run one: `validation/hardening_run_20260217_full_confidence_fix2_run1`
2. Full completion run two: `validation/hardening_run_20260217_full_confidence_fix2_run2`
3. Stage six signoff exists in both runs.
4. Completion declaration: `validation/COMPLETION_DECLARATION.md`

## Contract Stability Rules

1. `1.x` versions must keep backward compatibility for existing request and result fields.
2. New optional fields may be added in minor versions.
3. Existing required fields must not be removed or renamed in minor versions.
4. Existing field semantics must not change in minor versions.

## Breaking Change Rules

1. Any breaking field removal, rename, or semantic change requires a major version bump.
2. Breaking changes require fixture updates and migration notes in this document.
3. Breaking changes require explicit compatibility guidance for one previous major version.

## Fixture and Version Policy Rules

1. Backward compatibility fixtures in `tests/fixtures/adapter_contract/` must pass in continuous integration.
2. Version policy test fixtures must be updated together with contract version changes.
3. Pull requests that change contract behavior must update both:
   - compatibility fixtures
   - this migration policy document
