# Ticket 001: Define exact-subject validation attestation standard

- **ID**: ticket-001
- **Owner**: unresolved:human
- **Status**: DONE
- **Workflow state**: DONE
- **Created**: 2026-08-14

## Goal and scope

Define a reusable exact-subject validation attestation that permits protected
automatic publication without per-PR human approval while preventing
self-approval, stale-head approval, replay and trust in advisory model output.

## Acceptance criteria

- [x] AC-01: The continuation request is recorded as bounded authorization.
- [x] AC-02: A closed contract binds repository, PR, head, base, ticket,
  correlation, grant, policy, profile and change digests.
- [x] AC-03: Validator independence from implementer and publisher is enforced.
- [x] AC-04: Required checks, decision, expiry, nonce, audience, signature and
  protected verification are fail-closed.
- [x] AC-05: LLM/model findings remain explicitly advisory.
- [x] AC-06: Exact runtime expectations can invalidate stale attestations.
- [x] AC-07: A Subactor/Semcod profile declares protected trust boundaries.
- [x] AC-08: Positive and adversarial fixtures and tests cover the contract.
- [x] AC-09: Architecture, logic flow and adoption guidance are documented.
- [x] AC-10: Governance, tests, compilation and lint pass.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-codex.md](ai-codex.md)
