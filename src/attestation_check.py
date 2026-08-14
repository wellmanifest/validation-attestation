#!/usr/bin/env python3
"""Dependency-free semantic checker for validation attestation v1."""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = (ROOT / "examples").resolve()

SYNTAX = "ATTEST-SYNTAX-001"
SUBJECT = "ATTEST-SUBJECT-001"
INDEPENDENCE = "ATTEST-INDEPENDENCE-001"
CHECKS = "ATTEST-CHECKS-001"
DECISION = "ATTEST-DECISION-001"
TIME = "ATTEST-TIME-001"
REPLAY = "ATTEST-REPLAY-001"
SIGNATURE = "ATTEST-SIGNATURE-001"
SECRET = "ATTEST-SECRET-001"
PROFILE = "ATTEST-PROFILE-001"

DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
SHA = re.compile(r"^[a-f0-9]{40}$")
PRINCIPAL_URI = re.compile(r"^validation://principal/[a-z0-9][a-z0-9._/-]*$")
PROFILE_MODES = {
    "collect": "read-only",
    "validate": "candidate-read",
    "attest": "protected-sign",
    "verify": "protected-verify",
    "publish": "bounded-write",
    "readback": "observe-only",
}
SUBJECT_FIELDS = {
    "repository",
    "pullRequest",
    "headSha",
    "baseSha",
    "ticket",
    "correlationId",
    "implementer",
    "publisher",
    "grantDigest",
    "policyDigest",
    "profileDigest",
    "changeDigest",
}


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    message: str
    severity: str = "critical"

    def render(self) -> str:
        return f"{self.code} {self.severity} {self.path}: {self.message}"


def _add(findings: list[Finding], code: str, path: str, message: str) -> None:
    findings.append(Finding(code, path, message))


def _closed(
    value: Any,
    path: str,
    required: set[str],
    allowed: set[str],
    findings: list[Finding],
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        _add(findings, SYNTAX, path, "must be an object")
        return None
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - allowed)
    if missing:
        _add(findings, SYNTAX, path, f"missing fields: {', '.join(missing)}")
    if unknown:
        _add(findings, SYNTAX, path, f"unknown fields: {', '.join(unknown)}")
    return value


def _time(value: Any, path: str, findings: list[Finding]) -> datetime | None:
    if not isinstance(value, str):
        _add(findings, SYNTAX, path, "must be an RFC3339 timestamp")
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _add(findings, SYNTAX, path, "must be an RFC3339 timestamp")
        return None
    if parsed.tzinfo is None:
        _add(findings, SYNTAX, path, "timezone is required")
        return None
    return parsed


def _principal(value: Any, path: str, findings: list[Finding]) -> dict[str, Any] | None:
    principal = _closed(value, path, {"uri", "kind"}, {"uri", "kind"}, findings)
    if principal is None:
        return None
    uri = principal.get("uri")
    if not isinstance(uri, str) or not PRINCIPAL_URI.fullmatch(uri):
        _add(findings, SYNTAX, f"{path}/uri", "invalid validation principal URI")
    if principal.get("kind") not in {
        "validator-app",
        "protected-verifier",
        "implementer",
        "publisher",
        "service",
    }:
        _add(findings, SYNTAX, f"{path}/kind", "unknown principal kind")
    return principal


def _digest(value: Any, path: str, findings: list[Finding], code: str = SUBJECT) -> None:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        _add(findings, code, path, "exact SHA-256 digest required")


def _scan_secrets(value: Any, path: str, findings: list[Finding]) -> None:
    denied = ("token", "secret", "password", "credential", "privatekey", "apikey")
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = re.sub(r"[^a-z]", "", str(key).lower())
            if any(part in normalized for part in denied):
                _add(findings, SECRET, f"{path}/{key}", "secret-bearing field is forbidden")
            _scan_secrets(nested, f"{path}/{key}", findings)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _scan_secrets(nested, f"{path}/{index}", findings)
    elif isinstance(value, str) and re.search(r"(?i)\bbearer\s+[a-z0-9._-]+", value):
        _add(findings, SECRET, path, "credential-like value is forbidden")


def _validate_subject(
    value: Any,
    expected: dict[str, Any] | None,
    findings: list[Finding],
) -> tuple[dict[str, Any] | None, dict[str, Any], dict[str, Any]]:
    subject = _closed(value, "/subject", SUBJECT_FIELDS, SUBJECT_FIELDS, findings)
    if subject is None:
        return None, {}, {}
    repository = subject.get("repository")
    if not isinstance(repository, str) or not re.fullmatch(
        r"[a-z0-9_.-]+/[a-z0-9_.-]+", repository
    ):
        _add(findings, SUBJECT, "/subject/repository", "exact owner/repository required")
    if not isinstance(subject.get("pullRequest"), int) or subject["pullRequest"] < 1:
        _add(findings, SUBJECT, "/subject/pullRequest", "positive PR number required")
    for field in ("headSha", "baseSha"):
        if not isinstance(subject.get(field), str) or not SHA.fullmatch(subject[field]):
            _add(findings, SUBJECT, f"/subject/{field}", "exact 40-character SHA required")
    for field in ("grantDigest", "policyDigest", "profileDigest", "changeDigest"):
        _digest(subject.get(field), f"/subject/{field}", findings)
    implementer = _principal(subject.get("implementer"), "/subject/implementer", findings) or {}
    publisher = _principal(subject.get("publisher"), "/subject/publisher", findings) or {}
    if implementer.get("kind") != "implementer":
        _add(findings, INDEPENDENCE, "/subject/implementer", "implementer kind required")
    if publisher.get("kind") != "publisher":
        _add(findings, INDEPENDENCE, "/subject/publisher", "publisher kind required")
    if implementer.get("uri") == publisher.get("uri"):
        _add(findings, INDEPENDENCE, "/subject", "implementer and publisher must differ")
    if expected:
        for field, expected_value in expected.items():
            if field not in SUBJECT_FIELDS or field in {"implementer", "publisher"}:
                _add(findings, SUBJECT, f"/expected/{field}", "unsupported runtime binding")
            elif subject.get(field) != expected_value:
                _add(findings, SUBJECT, f"/subject/{field}", "runtime subject binding mismatch")
    return subject, implementer, publisher


def _validate_checks(value: Any, findings: list[Finding]) -> tuple[list[datetime], bool]:
    if not isinstance(value, list) or not value:
        _add(findings, CHECKS, "/checks", "at least one required check is needed")
        return [], False
    completed: list[datetime] = []
    names: set[str] = set()
    all_success = True
    fields = {"name", "commandDigest", "conclusion", "completedAt", "evidenceDigest"}
    for index, item in enumerate(value):
        path = f"/checks/{index}"
        check = _closed(item, path, fields, fields, findings)
        if check is None:
            all_success = False
            continue
        name = check.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9._/-]{1,100}", name):
            _add(findings, CHECKS, f"{path}/name", "invalid check name")
        elif name in names:
            _add(findings, CHECKS, f"{path}/name", "duplicate check")
        else:
            names.add(name)
        _digest(check.get("commandDigest"), f"{path}/commandDigest", findings, CHECKS)
        _digest(check.get("evidenceDigest"), f"{path}/evidenceDigest", findings, CHECKS)
        timestamp = _time(check.get("completedAt"), f"{path}/completedAt", findings)
        if timestamp:
            completed.append(timestamp)
        if check.get("conclusion") != "success":
            all_success = False
    return completed, all_success


def _validate_attestation(
    document: dict[str, Any],
    at: datetime | None,
    expected: dict[str, Any] | None,
    consumed_nonces: set[str],
) -> list[Finding]:
    findings: list[Finding] = []
    required = {
        "schema", "attestationId", "predicateType", "issuer", "subject", "checks",
        "decision", "validity", "antiReplay", "signature", "verification",
    }
    allowed = required | {"modelAdvice"}
    attestation = _closed(document, "", required, allowed, findings)
    if attestation is None:
        return findings
    if attestation.get("predicateType") != "https://wellmanifest.dev/attestations/validator/v1":
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
        if not isinstance(issuer_key, str) or len(issuer_key) < 3:
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
        approved = decision.get("outcome") == "approved"
        if decision.get("allowedEffect") != "pull-request.merge":
            _add(
                findings,
                DECISION,
                "/decision/allowedEffect",
                "only bounded PR merge is supported",
            )
        reasons = decision.get("reasonCodes")
        if not isinstance(reasons, list) or len(reasons) != len(set(reasons)):
            _add(findings, DECISION, "/decision/reasonCodes", "unique reason code array required")
        if approved and not all_success:
            _add(
                findings,
                DECISION,
                "/decision/outcome",
                "approval requires every check to succeed",
            )
        if approved and reasons:
            _add(
                findings,
                DECISION,
                "/decision/reasonCodes",
                "approved decision has no failure reasons",
            )
        if decision.get("outcome") == "rejected" and not reasons:
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
        if at and (at < issued or at >= expires):
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
        if not isinstance(audience, str) or not audience.startswith("validation://audience/"):
            _add(findings, REPLAY, "/antiReplay/audience", "exact audience required")

    signature = _closed(
        attestation.get("signature"),
        "/signature",
        {"scheme", "keyId", "valueDigest"},
        {"scheme", "keyId", "valueDigest"},
        findings,
    )
    if signature:
        if signature.get("scheme") not in {"sigstore", "ed25519"}:
            _add(findings, SIGNATURE, "/signature/scheme", "unsupported signature scheme")
        if signature.get("keyId") != issuer_key:
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
            _principal(verification.get("verifier"), "/verification/verifier", findings)
            or {}
        )
        if verifier.get("kind") != "protected-verifier":
            _add(findings, SIGNATURE, "/verification/verifier", "protected verifier required")
        if verifier.get("uri") in {issuer.get("uri"), publisher.get("uri")}:
            _add(findings, INDEPENDENCE, "/verification/verifier", "verifier must be independent")
        for field in ("signatureValid", "issuerTrusted", "subjectResolved"):
            if verification.get(field) is not True:
                _add(
                    findings,
                    SIGNATURE,
                    f"/verification/{field}",
                    "protected verification required",
                )
        verified = _time(verification.get("verifiedAt"), "/verification/verifiedAt", findings)
        if issued and verified and verified < issued:
            _add(findings, TIME, "/verification/verifiedAt", "verification precedes issuance")
        if expires and verified and verified >= expires:
            _add(findings, TIME, "/verification/verifiedAt", "verification is stale")
    _scan_secrets(attestation, "", findings)
    return findings


def _validate_profile(document: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    fields = {"schema", "profileId", "version", "ownership", "bindings"}
    profile = _closed(document, "", fields, fields, findings)
    if profile is None:
        return findings
    ownership = _closed(
        profile.get("ownership"),
        "/ownership",
        {"standardOwner", "runtimeOwner", "adopts"},
        {"standardOwner", "runtimeOwner", "adopts"},
        findings,
    )
    if ownership:
        if ownership.get("standardOwner") != "wellmanifest/validation-attestation":
            _add(findings, PROFILE, "/ownership/standardOwner", "wrong standard owner")
        owner = ownership.get("runtimeOwner")
        if not isinstance(owner, str) or owner.startswith("wellmanifest/"):
            _add(findings, PROFILE, "/ownership/runtimeOwner", "runtime must remain external")
        adopts = ownership.get("adopts")
        if not isinstance(adopts, list) or "wellmanifest/autonomy" not in adopts:
            _add(findings, PROFILE, "/ownership/adopts", "autonomy adoption required")
    bindings = profile.get("bindings")
    if not isinstance(bindings, list):
        _add(findings, SYNTAX, "/bindings", "must be an array")
        return findings
    observed: dict[str, str] = {}
    principals: dict[str, str] = {}
    for index, item in enumerate(bindings):
        path = f"/bindings/{index}"
        binding = _closed(
            item,
            path,
            {"stage", "uri", "principal", "mode"},
            {"stage", "uri", "principal", "mode"},
            findings,
        )
        if binding:
            stage = str(binding.get("stage"))
            if stage in observed:
                _add(findings, PROFILE, f"{path}/stage", "duplicate stage")
            observed[stage] = str(binding.get("mode"))
            principal = _principal(binding.get("principal"), f"{path}/principal", findings) or {}
            principals[stage] = str(principal.get("uri"))
    if observed != PROFILE_MODES:
        _add(findings, PROFILE, "/bindings", "exact stage and mode map required")
    if principals.get("publish") in {principals.get("attest"), principals.get("verify")}:
        _add(findings, PROFILE, "/bindings", "publisher must be independent")
    if principals.get("verify") == principals.get("attest"):
        _add(findings, PROFILE, "/bindings", "verifier must differ from attester")
    _scan_secrets(profile, "", findings)
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


def _pointer_parent(document: Any, pointer: str) -> tuple[Any, str]:
    if not pointer.startswith("/"):
        raise ValueError("absolute JSON Pointer required")
    parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]
    current = document
    for part in parts[:-1]:
        current = current[int(part)] if isinstance(current, list) else current[part]
    return current, parts[-1]


def apply_invalid_case(case: dict[str, Any], case_path: Path) -> tuple[Any, list[Finding]]:
    findings: list[Finding] = []
    try:
        base = (case_path.parent / str(case["base"])).resolve()
        base.relative_to(EXAMPLES)
    except (KeyError, ValueError):
        return {}, [Finding(SYNTAX, "/base", "base escapes examples root")]
    try:
        document = copy.deepcopy(json.loads(base.read_text(encoding="utf-8")))
        for mutation in case.get("mutations", []):
            parent, key = _pointer_parent(document, mutation["path"])
            if mutation["op"] == "replace":
                if isinstance(parent, list):
                    parent[int(key)] = mutation["value"]
                else:
                    parent[key] = mutation["value"]
            elif mutation["op"] == "remove":
                if isinstance(parent, list):
                    parent.pop(int(key))
                else:
                    del parent[key]
            else:
                raise ValueError("unsupported mutation")
    except (OSError, KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as error:
        return {}, [Finding(SYNTAX, "/mutations", f"invalid case: {error}")]
    return document, findings


def load_and_validate(path: Path) -> list[Finding]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [Finding(SYNTAX, "", str(error))]
    prefix: list[Finding] = []
    if (
        isinstance(document, dict)
        and document.get("schema") == "wellmanifest.validation/invalid-case/v1"
    ):
        document, prefix = apply_invalid_case(document, path.resolve())
    return prefix + validate_document(document)


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
        case = json.loads(path.read_text(encoding="utf-8"))
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
    paths = sorted(args.path.rglob("*.json")) if args.path.is_dir() else [args.path]
    failed = False
    for path in paths:
        document = json.loads(path.read_text(encoding="utf-8"))
        findings = validate_document(document, at=at, expected=expected)
        for finding in findings:
            print(f"{path}: {finding.render()}")
        failed = failed or bool(findings)
    if not failed:
        print(f"ATTEST-PASS: {len(paths)} document(s) conform")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
