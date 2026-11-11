#!/usr/bin/env python3
"""Dependency-free semantic checker for validation attestation v1."""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

_SRC_DIR = str(Path(__file__).resolve().parent)
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from attestation_primitives import (  # noqa: E402
    ADOPT_REF,
    ATTESTATION_ID,
    AUDIENCE_URI,
    CHECK_CONCLUSIONS,
    CHECKS,
    CORRELATION_ID,
    DECISION,
    DIGEST,
    EXAMPLES,
    INDEPENDENCE,
    ISSUER_KEY_ID,
    PRINCIPAL_URI,
    PROCESS_URI,
    PROFILE,
    PROFILE_ID,
    PROFILE_MODES,
    REASON_CODE,
    REPLAY,
    RFC3339,
    ROOT,
    RUNTIME_OWNER,
    SECRET,
    SEMVER,
    SHA,
    SIGNATURE,
    SUBJECT,
    SUBJECT_FIELDS,
    SYNTAX,
    TICKET_ID,
    TIME,
    Finding,
    StrictJsonError,
    _add,
    _closed,
    _digest,
    _principal,
    _safe_read_json,
    _scan_secrets,
    _time,
    _validate_checks,
    _validate_profile,
    _validate_subject,
)

__all__ = [
    "ADOPT_REF",
    "ATTESTATION_ID",
    "AUDIENCE_URI",
    "CHECKS",
    "CHECK_CONCLUSIONS",
    "CORRELATION_ID",
    "DECISION",
    "DIGEST",
    "EXAMPLES",
    "Finding",
    "INDEPENDENCE",
    "ISSUER_KEY_ID",
    "PRINCIPAL_URI",
    "PROCESS_URI",
    "PROFILE",
    "PROFILE_ID",
    "PROFILE_MODES",
    "REASON_CODE",
    "REPLAY",
    "RFC3339",
    "ROOT",
    "RUNTIME_OWNER",
    "SECRET",
    "SEMVER",
    "SHA",
    "SIGNATURE",
    "SUBJECT",
    "SUBJECT_FIELDS",
    "SYNTAX",
    "TICKET_ID",
    "TIME",
    "apply_invalid_case",
    "load_and_validate",
    "main",
    "self_test",
    "validate_document",
]


def _validate_attestation(
    document: dict[str, Any],
    at: datetime | None,
    expected: dict[str, Any] | None,
    consumed_nonces: set[str],
) -> list[Finding]:
    findings: list[Finding] = []
    required = {
        "schema",
        "attestationId",
        "predicateType",
        "issuer",
        "subject",
        "checks",
        "decision",
        "validity",
        "antiReplay",
        "signature",
        "verification",
    }
    allowed = required | {"modelAdvice"}
    attestation = _closed(document, "", required, allowed, findings)
    if attestation is None:
        return findings
    attestation_id = attestation.get("attestationId")
    if not isinstance(attestation_id, str) or not ATTESTATION_ID.fullmatch(attestation_id):
        _add(findings, SYNTAX, "/attestationId", "invalid attestation identifier URI")
    if attestation.get("predicateType") != "https://wellmanifest.com/attestations/validator/v1":
        _add(findings, SIGNATURE, "/predicateType", "unsupported predicate type")

    issuer_data = _closed(
        attestation.get("issuer"),
        "/issuer",
        {"principal", "keyId"},
        {"principal", "keyId"},
        findings,
    )
    issuer: dict[str, Any] = {}
    issuer_key = None
    if issuer_data:
        issuer = _principal(issuer_data.get("principal"), "/issuer/principal", findings) or {}
        issuer_key = issuer_data.get("keyId")
        if issuer.get("kind") != "validator-app":
            _add(findings, INDEPENDENCE, "/issuer/principal", "validator-app issuer required")
        if not isinstance(issuer_key, str) or not ISSUER_KEY_ID.fullmatch(issuer_key):
            _add(findings, SIGNATURE, "/issuer/keyId", "issuer key ID required")

    _, implementer, publisher = _validate_subject(attestation.get("subject"), expected, findings)
    for role, principal in (("implementer", implementer), ("publisher", publisher)):
        if issuer.get("uri") and issuer.get("uri") == principal.get("uri"):
            _add(findings, INDEPENDENCE, f"/subject/{role}", f"issuer cannot be {role}")

    completed, all_success = _validate_checks(attestation.get("checks"), findings)
    decision = _closed(
        attestation.get("decision"),
        "/decision",
        {"outcome", "allowedEffect", "reasonCodes"},
        {"outcome", "allowedEffect", "reasonCodes"},
        findings,
    )
    if decision:
        outcome = decision.get("outcome")
        if not isinstance(outcome, str) or outcome not in {"approved", "rejected"}:
            _add(findings, DECISION, "/decision/outcome", "outcome must be approved or rejected")
        approved = outcome == "approved"
        if decision.get("allowedEffect") != "pull-request.merge":
            _add(
                findings, DECISION, "/decision/allowedEffect", "only bounded PR merge is supported"
            )
        reasons = decision.get("reasonCodes")
        reasons_valid = (
            isinstance(reasons, list)
            and all(isinstance(item, str) and REASON_CODE.fullmatch(item) for item in reasons)
            and len(reasons) == len(set(reasons))
        )
        if not reasons_valid:
            _add(findings, DECISION, "/decision/reasonCodes", "unique reason code array required")
        if approved and not all_success:
            _add(
                findings, DECISION, "/decision/outcome", "approval requires every check to succeed"
            )
        if approved and isinstance(reasons, list) and reasons:
            _add(
                findings,
                DECISION,
                "/decision/reasonCodes",
                "approved decision has no failure reasons",
            )
        if outcome == "rejected" and isinstance(reasons, list) and not reasons:
            _add(findings, DECISION, "/decision/reasonCodes", "rejection requires reason codes")

    if "modelAdvice" in attestation:
        advice = _closed(
            attestation.get("modelAdvice"),
            "/modelAdvice",
            {"advisory", "model", "findingsDigest"},
            {"advisory", "model", "findingsDigest"},
            findings,
        )
        if advice:
            if advice.get("advisory") is not True:
                _add(findings, DECISION, "/modelAdvice/advisory", "model evidence must be advisory")
            model = advice.get("model")
            if not isinstance(model, str) or not (3 <= len(model.strip()) <= 200):
                _add(findings, DECISION, "/modelAdvice/model", "valid model identifier required")
            _digest(advice.get("findingsDigest"), "/modelAdvice/findingsDigest", findings, CHECKS)

    validity = _closed(
        attestation.get("validity"),
        "/validity",
        {"issuedAt", "expiresAt"},
        {"issuedAt", "expiresAt"},
        findings,
    )
    issued = expires = None
    if validity:
        issued = _time(validity.get("issuedAt"), "/validity/issuedAt", findings)
        expires = _time(validity.get("expiresAt"), "/validity/expiresAt", findings)
        if issued and expires and (issued >= expires or expires - issued > timedelta(hours=24)):
            _add(findings, TIME, "/validity", "validity must be positive and at most 24 hours")
        if issued and any(check_time > issued for check_time in completed):
            _add(findings, TIME, "/checks", "checks must complete before issuance")
        if at and issued and expires and (at < issued or at >= expires):
            _add(findings, TIME, "/validity", "attestation is not current")

    anti_replay = _closed(
        attestation.get("antiReplay"),
        "/antiReplay",
        {"nonce", "audience", "singleUse"},
        {"nonce", "audience", "singleUse"},
        findings,
    )
    if anti_replay:
        nonce = anti_replay.get("nonce")
        if not isinstance(nonce, str) or not re.fullmatch(r"[A-Za-z0-9_-]{24,128}", nonce):
            _add(findings, REPLAY, "/antiReplay/nonce", "strong opaque nonce required")
        elif nonce in consumed_nonces:
            _add(findings, REPLAY, "/antiReplay/nonce", "nonce was already consumed")
        if anti_replay.get("singleUse") is not True:
            _add(findings, REPLAY, "/antiReplay/singleUse", "attestation must be single-use")
        audience = anti_replay.get("audience")
        if not isinstance(audience, str) or not AUDIENCE_URI.fullmatch(audience):
            _add(findings, REPLAY, "/antiReplay/audience", "exact audience required")

    signature = _closed(
        attestation.get("signature"),
        "/signature",
        {"scheme", "keyId", "valueDigest"},
        {"scheme", "keyId", "valueDigest"},
        findings,
    )
    if signature:
        scheme = signature.get("scheme")
        if not isinstance(scheme, str) or scheme not in {"sigstore", "ed25519"}:
            _add(findings, SIGNATURE, "/signature/scheme", "unsupported signature scheme")
        sig_key = signature.get("keyId")
        if not isinstance(sig_key, str) or not (3 <= len(sig_key) <= 200) or sig_key != issuer_key:
            _add(findings, SIGNATURE, "/signature/keyId", "signature key must match issuer")
        _digest(signature.get("valueDigest"), "/signature/valueDigest", findings, SIGNATURE)

    verification = _closed(
        attestation.get("verification"),
        "/verification",
        {"verifier", "verifiedAt", "signatureValid", "issuerTrusted", "subjectResolved"},
        {"verifier", "verifiedAt", "signatureValid", "issuerTrusted", "subjectResolved"},
        findings,
    )
    if verification:
        verifier = (
            _principal(verification.get("verifier"), "/verification/verifier", findings) or {}
        )
        if verifier.get("kind") != "protected-verifier":
            _add(findings, SIGNATURE, "/verification/verifier", "protected verifier required")
        forbidden_verifiers = {
            uri for uri in (issuer.get("uri"), publisher.get("uri"), implementer.get("uri")) if uri
        }
        if verifier.get("uri") in forbidden_verifiers:
            _add(findings, INDEPENDENCE, "/verification/verifier", "verifier must be independent")
        for field in ("signatureValid", "issuerTrusted", "subjectResolved"):
            if verification.get(field) is not True:
                _add(
                    findings, SIGNATURE, f"/verification/{field}", "protected verification required"
                )
        verified = _time(verification.get("verifiedAt"), "/verification/verifiedAt", findings)
        if issued and verified and verified < issued:
            _add(findings, TIME, "/verification/verifiedAt", "verification precedes issuance")
        if expires and verified and verified >= expires:
            _add(findings, TIME, "/verification/verifiedAt", "verification is stale")
    _scan_secrets(attestation, "", findings)
    return findings


def validate_document(
    document: Any,
    at: datetime | None = None,
    expected: dict[str, Any] | None = None,
    consumed_nonces: set[str] | None = None,
) -> list[Finding]:
    if not isinstance(document, dict):
        return [Finding(SYNTAX, "", "document must be an object")]
    schema = document.get("schema")
    if schema == "wellmanifest.validation/attestation/v1":
        return _validate_attestation(document, at, expected, consumed_nonces or set())
    if schema == "wellmanifest.validation/profile/v1":
        return _validate_profile(document)
    return [Finding(SYNTAX, "/schema", "unsupported validation schema")]


def _array_index(token: str) -> int:
    if not (token == "0" or (token.isdigit() and not token.startswith("0"))):
        raise ValueError("invalid JSON Pointer array index")
    return int(token)


def _pointer_parent(document: Any, pointer: str) -> tuple[Any, str]:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise ValueError("absolute JSON Pointer required")
    parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]
    current = document
    for part in parts[:-1]:
        current = current[_array_index(part)] if isinstance(current, list) else current[part]
    return current, parts[-1]


def apply_invalid_case(case: dict[str, Any], case_path: Path) -> tuple[Any, list[Finding]]:
    findings: list[Finding] = []
    try:
        raw_base = case["base"]
        if not isinstance(raw_base, str) or not raw_base:
            return {}, [Finding(SYNTAX, "/base", "base must be a non-empty string")]
        norm_base = Path(os.path.normpath(case_path.parent / raw_base))
        rel = norm_base.relative_to(EXAMPLES)
        probe = EXAMPLES
        for part in rel.parts:
            probe = probe / part
            if probe.is_symlink():
                return {}, [Finding(SYNTAX, "/base", "base cannot traverse symlinks")]
        base = probe
    except (KeyError, ValueError):
        return {}, [Finding(SYNTAX, "/base", "base escapes examples root")]
    try:
        document = copy.deepcopy(_safe_read_json(base))
        mutations = case.get("mutations", [])
        if not isinstance(mutations, list):
            raise ValueError("mutations must be an array")
        for mutation in mutations:
            if not isinstance(mutation, dict):
                raise ValueError("mutation must be an object")
            parent, key = _pointer_parent(document, mutation["path"])
            if mutation["op"] == "replace":
                if isinstance(parent, list):
                    parent[_array_index(key)] = mutation["value"]
                else:
                    parent[key] = mutation["value"]
            elif mutation["op"] == "remove":
                if isinstance(parent, list):
                    parent.pop(_array_index(key))
                else:
                    del parent[key]
            else:
                raise ValueError("unsupported mutation")
    except (
        OSError,
        UnicodeDecodeError,
        KeyError,
        IndexError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        StrictJsonError,
    ) as error:
        return {}, [Finding(SYNTAX, "/mutations", f"invalid case: {error}")]
    return document, findings


def load_and_validate(path: Path) -> list[Finding]:
    try:
        document = _safe_read_json(path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, StrictJsonError) as error:
        return [Finding(SYNTAX, "", str(error))]
    prefix: list[Finding] = []
    if (
        isinstance(document, dict)
        and document.get("schema") == "wellmanifest.validation/invalid-case/v1"
    ):
        document, prefix = apply_invalid_case(document, path.resolve())
    return prefix + validate_document(document)


def _iter_json_paths(target: Path) -> list[Path]:
    if target.is_symlink() or not target.is_dir():
        return [target]
    discovered: list[Path] = []
    for root_dir, dirnames, filenames in os.walk(target, followlinks=False):
        root_path = Path(root_dir)
        kept_dirs: list[str] = []
        for dirname in sorted(dirnames):
            candidate_dir = root_path / dirname
            if candidate_dir.is_symlink():
                discovered.append(candidate_dir)
            else:
                kept_dirs.append(dirname)
        dirnames[:] = kept_dirs
        for name in sorted(filenames):
            if name.endswith(".json"):
                discovered.append(root_path / name)
    return discovered


def self_test() -> int:
    failures: list[str] = []
    for path in sorted((EXAMPLES / "valid").glob("*.json")):
        findings = load_and_validate(path)
        if findings:
            failures.append(f"{path.name}: {[item.code for item in findings]}")
    profile_findings = load_and_validate(ROOT / "profiles" / "subactor-semcod.profile.json")
    if profile_findings:
        failures.append(f"profile: {[item.code for item in profile_findings]}")
    for path in sorted((EXAMPLES / "invalid").glob("*.json")):
        case = _safe_read_json(path)
        observed = {item.code for item in load_and_validate(path)}
        expected = set(case.get("expectedCodes", []))
        if not expected <= observed:
            failures.append(f"{path.name}: expected {sorted(expected)}, got {sorted(observed)}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("ATTEST-PASS: valid fixtures and declared negative findings passed")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("path", type=Path)
    validate.add_argument("--at")
    validate.add_argument("--expected-head")
    validate.add_argument("--expected-base")
    subparsers.add_parser("self-test")
    args = parser.parse_args(argv)
    if args.command == "self-test":
        return self_test()
    at = None
    if args.at:
        temporary: list[Finding] = []
        at = _time(args.at, "--at", temporary)
        if temporary:
            print(temporary[0].render(), file=sys.stderr)
            return 2
    expected = {
        key: value
        for key, value in {"headSha": args.expected_head, "baseSha": args.expected_base}.items()
        if value is not None
    }
    paths = _iter_json_paths(args.path)
    if not paths:
        print(f"{args.path}: {Finding(SYNTAX, '', 'no JSON documents found').render()}")
        return 1
    failed = False
    for path in paths:
        try:
            document = _safe_read_json(path)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, StrictJsonError) as error:
            findings = [Finding(SYNTAX, "", str(error))]
        else:
            findings = validate_document(document, at=at, expected=expected)
        for finding in findings:
            print(f"{path}: {finding.render()}")
        failed = failed or bool(findings)
    if not failed:
        print(f"ATTEST-PASS: {len(paths)} document(s) conform")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
