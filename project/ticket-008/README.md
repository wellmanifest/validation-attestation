# Ticket 008: Harden attestation decision, subject, profile, and JSON parsing invariants

- **ID**: ticket-008
- **Owner**: agent:antigravity
- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-11-11

## Session authorization

- `SESSION_EXECUTION_AUTHORIZATION`: Autonomous execution, testing, and protected publication requested by the repository owner.

## Goal and scope

Close semantic validation gaps and unhandled runtime crashes in `src/attestation_check.py` so the dependency-free checker enforces every security invariant declared in `schemas/validation-attestation.schema.json`:

1. Reject non-enum `decision.outcome` values (which previously bypassed both `approved` and `rejected` branches with zero findings) and validate `decision.reasonCodes` items safely without `TypeError` on unhashable elements.
2. Guard `--at` validity checks when `issuedAt` or `expiresAt` fails RFC 3339 parsing, and reject date-only strings lacking a time separator.
3. Reject boolean `subject.pullRequest` (`isinstance(True, int)`) and enforce schema patterns on `attestationId`, `issuer.keyId`, `subject.ticket`, `subject.correlationId`, `checks[].conclusion`, `modelAdvice.model`, `antiReplay.audience`, `verification.verifier` implementer-independence, and profile `profileId`/`version`/`runtimeOwner`/`adopts`/`bindings[].uri`.
4. Enforce strict duplicate-key and non-finite-number rejection when loading JSON documents from disk.

## Acceptance criteria

- [x] AC-01: Unknown `decision.outcome`, unhashable `reasonCodes`, boolean `pullRequest`, malformed `issuedAt` with `--at`, and duplicate JSON keys fail closed with `Finding` diagnostics and zero unhandled exceptions.
- [x] AC-02: Schema-declared URI, SHA/digest, ticket, correlationId, check conclusion, verifier independence, and profile invariants are enforced and covered by unit tests.
- [x] AC-03: `unittest`, `self-test`, `ruff`, `./project/governance-check.sh --base origin/main`, and `wellman check` pass cleanly.
