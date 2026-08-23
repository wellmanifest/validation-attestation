# Ticket 005: Adopt new-project standard 0.18.6

- **ID**: ticket-005
- **Owner**: agent:gemini under SESSION_EXECUTION_AUTHORIZATION
- **Status**: DONE
- **Workflow state**: DONE
- **Created**: 2026-08-23

## Goal and scope

Adopt published `wellmanifest/new-project` 0.18.6 into `wellmanifest/validation-attestation` in one atomic transaction through `create_adoption_lock.py`.
Brings the host-agnostic contract (CLAUDE.md, GEMINI.md, Cursor rule, pre-commit hook, agent-hosts.json validator) and `governance / enforce` CI job.

## Acceptance criteria

- [x] AC-01: `python3 .governance/agent_host_check.py --root .` → `GOV-AGENT-HOST-PASS` after `./scripts/install-agent-hosts.sh`.
- [x] AC-02: `./project/governance-check.sh --actor agent` → `GOV-PASS`, all managed digests match lock.
- [x] AC-03: `python3 -m unittest discover -s tests -v` passes; domain contracts unaffected.

## Publication evidence

- Pull request: `wellmanifest/validation-attestation#7`
- Frozen and approved head: `3178578f0c3feeed5ad0987f30aa8e69036832d1`
- Merge commit: `d117662886a1420790327f2f11aeaf51eb9e8fc5`
- Validator approval: run `32665280844`.

## Participants

- Human participant: authorized via active session.
- Agent participant: [ai-gemini.md](ai-gemini.md)
