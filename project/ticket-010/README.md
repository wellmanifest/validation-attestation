# Ticket 010: Extract attestation_io and harden symlink-parent traversal, JSON bounds, RFC3339 subseconds, and secrets

- **ID**: ticket-010
- **Owner**: tom
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-11-11

## Goal and scope

SESSION_EXECUTION_AUTHORIZATION: On 2026-11-11 user authorized auditing, fixing bugs, optimizing, and hardening `wellmanifest/*` standard repositories.

Extract bounded regular-file/JSON I/O, symlink-ancestor guards, and JSON Pointer/directory helpers into `src/attestation_io.py` so `src/attestation_check.py` (481L -> ~445L) and `src/attestation_primitives.py` (~345L) stay comfortably below 500 lines; block symlink-parent traversal (`sym_dir/..`, `../sym_dir`) before `os.path.abspath` and enforce `(st_dev, st_ino)` inode checks in `_safe_read_json`; bound JSON integer digit length (`<= 309`), finite floats, and lone UTF-16 surrogates in `_strict_loads` so 5000-digit integers emit `SYNTAX` findings instead of raising uncaught `ValueError`; normalize 7–9 digit RFC3339 fractional seconds in `_time`; anchor regex constants with `\A...\Z`; replace recursive `_scan_secrets` with an iterative scanner covering GitHub/AWS/OpenAI/PEM token patterns; reject absolute/control-char `base` paths in `apply_invalid_case` and control characters in `modelAdvice.model`; expand `tests/test_attestation.py`; and reconcile merged `project/ticket-009/README.md` status to `DONE`.

## Acceptance criteria

- [x] AC-01: Extract `src/attestation_io.py` (< 500L), reject symlink-parent traversal and 5000-digit/non-finite/surrogate JSON payloads cleanly with `ATTEST-SYNTAX-001`, normalize 7–9 digit RFC3339 fractional seconds, iteratively scan token values in `_scan_secrets`, reject control characters in `modelAdvice.model` and absolute `base` paths in `apply_invalid_case`, and mark `project/ticket-009/README.md` `DONE`.
- [x] AC-02: All Python modules in `src/` and `tests/` remain strictly `< 500` lines and pass `ruff check --no-cache src tests`, `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v`, `PYTHONDONTWRITEBYTECODE=1 python3 src/attestation_check.py self-test`, `./project/governance-check.sh --base origin/main`, and `wellman check` with 0 errors.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
