# Ticket 009: Modularize attestation_check under 500 lines and harden unhashable JSON and file I/O

- **ID**: ticket-009
- **Owner**: tom
- **Status**: DONE
- **Workflow state**: DONE
- **Created**: 2026-11-11

## Goal and scope

Split `src/attestation_check.py` (664 lines) into cohesive modules strictly under 500 lines (`src/attestation_primitives.py` + `src/attestation_check.py`), guard unhashable JSON values before set lookups, and harden file loading:
- Extract shared constants, `Finding`, regular-file `O_NOFOLLOW | O_NONBLOCK` JSON loading (`<= 4 MiB`), and subject/check validators into `src/attestation_primitives.py`.
- Guard `principal.kind`, `checks[*].conclusion`, `decision.outcome`, and `signature.scheme` with `isinstance(..., str)` before set-membership checks so nested dicts/lists emit deterministic `Finding` records instead of raising `TypeError: unhashable type`.
- Reject symlinked files and symlinked subdirectories during `validate` directory scans via `os.walk(..., followlinks=False)`.
- Add regression tests and `< 500` line assertions in `tests/test_attestation.py`.

## Acceptance criteria

- [x] AC-01: Scope is approved by a human owner (continuous hardening/modularity session).
- [x] AC-02: `src/attestation_check.py` and `src/attestation_primitives.py` stay strictly under 500 lines and fail closed without runtime crashes on unhashable JSON fields and symlink inputs.
- [x] AC-03: `ruff check`, `unittest`, `src/attestation_check.py self-test`, `./project/governance-check.sh --actor ci --base origin/main --head HEAD`, and `wellman check` pass.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
