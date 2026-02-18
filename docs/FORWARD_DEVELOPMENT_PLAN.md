# Lifeguard Forward Development Plan

Status date: `2026-02-18`

This plan focuses on shipping a compliance-producing release flow for security-focused agents used in administrative and tax work. Military and healthcare use cases remain out of scope and are blocked by specification checks.

## Current baseline (as of 2026-02-18)

Shipped:
1. Compliance pack release artifact and local verification command.
2. Legislative review gate with required human decision record (when enabled).
3. Hardened container sandbox default image plus outbound allow list gateway enforcement.
4. Sigstore bundle signing mode in supported environments, and key-based signing for offline use.
5. Compatibility adapters for LangChain, LangGraph, and Model Context Protocol with deny-by-default gating.
6. Verification dashboard generator for validation runs.

Known gaps:
1. The legislative review pack is decision support and does not attempt to enumerate all obligations and effective dates.
2. The live intelligence module remains large and should be split for maintainability.
3. Outbound network controls need deeper integration testing against real network behavior.

## Guiding rules

1. Deterministic by default. No evolutionary or mutation-driven agent design loops.
2. Open source dependencies only.
3. Human decision required for any tool execution that can access the network or write files.
4. Legislative review is decision support, not automated legal advice. Release requires an explicit human decision record when the gate is enabled.
5. Default to fail closed on integration and policy enforcement.

## Milestone 1: Compliance-producing release pack (shipped)

Goal: Every release emits a single directory that a reviewer can audit without running code.

Status:
1. Shipped and revalidated in `validation/compliance_pack_e2e_20260218_full_run2`.

Validation:
1. Unit tests for pack creation and pack validation.
2. Completion validation full run includes pack validation for each risk level.

Exit criteria:
1. A release pack can be verified without access to the original workspace.
2. Verification fails when any pack component is missing or mismatched.

## Milestone 2: Legislative review gate v2

Goal: Make legislative review more actionable and more reviewer-friendly for United Kingdom first, with European Union cross references.

Work:
1. Improve the pack structure to include:
   - identified obligations and effective dates (with explicit “unknown” markers when missing)
   - a short list of open questions the reviewer must answer
   - a change summary when a previous pack exists for the same agent
2. Tighten the prompt strategy:
   - require citations from multiple independent trusted domains
   - retry when trust or freshness assessment fails, not only when citation count is low
3. Expand managed trust profiles for legal sources and regulators, still excluding United States sources.

Validation:
1. Tests for pack schema stability and decision file validation.
2. A staged validation run that exercises legislative review in both local and container runtime modes using a fake intelligence client.

Exit criteria:
1. The gate is stable under transient provider failures.
2. A human decision file is always created when required, and release is blocked until it is set to accept.

## Milestone 3: True outbound network enforcement hardening

Goal: Ensure container tool execution cannot reach the public network except through an allow list boundary.

Work:
1. Add integration tests that attempt direct outbound connections from the tool container and confirm they fail.
2. Add integration tests that confirm allowed hosts succeed and disallowed hosts fail.
3. Document known limits, including redirects and name resolution behavior, and enforce safe defaults for high risk agents.

Validation:
1. Run the container integration tests as part of stage one when Docker is available.

Exit criteria:
1. No direct outbound network access is possible from the tool container when network is enabled.
2. Allowed hosts are enforced at runtime, not by command text scanning.

## Milestone 4: Signing and attestation tightening

Goal: Make releases harder to spoof and easier to verify.

Work:
1. Prefer Sigstore signing when a trusted workflow identity is available, and keep key-based signing for offline use.
2. Add an explicit “verify release” command that checks:
   - signature or attestation bundle
   - release anchor hash
   - evidence hash chain integrity

Validation:
1. Tests for both signing modes, including failure cases.
2. A full validation run that includes one Sigstore mode release in a supported environment.

Exit criteria:
1. A release can be verified with a single command.
2. Missing or invalid attestation always blocks release verification.

## Milestone 5: Safer ecosystem integration

Goal: Grow integration breadth without weakening security.

Work:
1. Keep Model Context Protocol import deny-by-default.
2. Add an allow list mechanism for approved Model Context Protocol servers:
   - pinned server version
   - pinned artifact hash or digest
   - explicit trust profile identifier
3. Add additional compatibility adapters only when they can be gated at the same level as current adapters.

Validation:
1. Negative tests for unsafe import fields and advisory-only outcomes.
2. Evidence events include per-decision gating detail.

Exit criteria:
1. Integrations cannot expand tool capabilities without explicit review.
2. Any advisory-only decision blocks release.

## Milestone 6: Maintainability and test debt paydown

Goal: Reduce risk from large modules and manual serialization.

Work:
1. Split the live intelligence module into transport, provider adapters, parsing, and assessment modules.
2. Replace manual checkpoint serialization with structured conversions on core types.
3. Consolidate duplicated adapter boilerplate into a single base implementation.

Validation:
1. No behavior regressions: full test suite remains green.
2. Backward compatibility tests for checkpoint and adapter formats.

Exit criteria:
1. Reduced module size and clearer ownership boundaries.
2. Fewer serialization bugs when dataclasses change.

## Milestone 7: Verification dashboard improvements

Goal: Make verification status obvious for reviewers.

Work:
1. Add dashboard panels for legislative review status and decision state.
2. Link to the compliance pack and highlight missing artifacts.
3. Add trend views for live intelligence failure patterns and adversarial pass rates.

Validation:
1. Snapshot tests for dashboard output.

Exit criteria:
1. A reviewer can identify why a release is blocked within one page view.
