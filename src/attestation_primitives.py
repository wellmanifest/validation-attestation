"""Shared primitives, regular-file JSON loader, and subject/check validators for attestation v1."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

_SRC_DIR = str(Path(__file__).resolve().parent)
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from attestation_io import (  # noqa: E402
    _DENIED_FIELD_MARKERS,
    _SENSITIVE_RE,
    MAX_ATTESTATION_BYTES,
    MAX_JSON_DEPTH,
    StrictJsonError,
    _safe_read_json,
    _strict_loads,
)

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

DIGEST = re.compile(r"\Asha256:[a-f0-9]{64}\Z")
SHA = re.compile(r"\A[a-f0-9]{40}\Z")
PRINCIPAL_URI = re.compile(r"\Avalidation://principal/[a-z0-9][a-z0-9._/-]*\Z")
ATTESTATION_ID = re.compile(r"\Avalidation://attestation/[a-z0-9][a-z0-9._/-]*\Z")
AUDIENCE_URI = re.compile(r"\Avalidation://audience/[a-z0-9][a-z0-9._/-]*\Z")
PROFILE_ID = re.compile(r"\Avalidation://profile/[a-z0-9][a-z0-9._/-]*\Z")
PROCESS_URI = re.compile(r"\Asubactor://process/[a-z0-9][a-z0-9._/-]*\Z")
ISSUER_KEY_ID = re.compile(r"\A[a-z][a-z0-9._:/-]{2,200}\Z")
TICKET_ID = re.compile(r"\Aticket-[0-9]{3,}\Z")
CORRELATION_ID = re.compile(r"\A[a-z0-9][a-z0-9._:-]{7,127}\Z")
REASON_CODE = re.compile(r"\A[A-Z][A-Z0-9-]{2,80}\Z")
SEMVER = re.compile(r"\A[0-9]+\.[0-9]+\.[0-9]+\Z")
RUNTIME_OWNER = re.compile(r"\A(subactor|semcod)/[a-z0-9][a-z0-9._/-]*\Z")
ADOPT_REF = re.compile(r"\Awellmanifest/[a-z0-9][a-z0-9._/-]*\Z")
RFC3339 = re.compile(
    r"\A\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.(\d{1,9}))?(?:[Zz]|[+-]\d{2}:\d{2})\Z"
)
PRINCIPAL_KINDS = {
    "validator-app",
    "protected-verifier",
    "implementer",
    "publisher",
    "service",
}
CHECK_CONCLUSIONS = {"success", "failure", "cancelled", "skipped", "neutral"}
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
    "MAX_ATTESTATION_BYTES",
    "MAX_JSON_DEPTH",
    "PRINCIPAL_KINDS",
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
    "StrictJsonError",
    "TICKET_ID",
    "TIME",
    "_add",
    "_closed",
    "_digest",
    "_principal",
    "_safe_read_json",
    "_scan_secrets",
    "_strict_loads",
    "_time",
    "_validate_checks",
    "_validate_profile",
    "_validate_subject",
]


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
    match = RFC3339.fullmatch(value)
    if not match:
        _add(findings, SYNTAX, path, "must be an RFC3339 timestamp")
        return None
    normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    frac = match.group(1)
    if frac and len(frac) > 6:
        tz_len = 6
        prefix_end = len(normalized) - tz_len - (len(frac) + 1)
        normalized = f"{normalized[:prefix_end]}.{frac[:6]}{normalized[-tz_len:]}"
    try:
        parsed = datetime.fromisoformat(normalized)
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
    kind = principal.get("kind")
    if not isinstance(kind, str) or kind not in PRINCIPAL_KINDS:
        _add(findings, SYNTAX, f"{path}/kind", "unknown principal kind")
    return principal


def _digest(value: Any, path: str, findings: list[Finding], code: str = SUBJECT) -> None:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        _add(findings, code, path, "exact SHA-256 digest required")


def _scan_secrets(value: Any, path: str, findings: list[Finding], depth: int = 0) -> None:
    stack: list[tuple[Any, str, int]] = [(value, path, depth)]
    while stack:
        current, cur_path, cur_depth = stack.pop()
        if cur_depth > MAX_JSON_DEPTH:
            _add(findings, SYNTAX, cur_path, "maximum JSON nesting depth exceeded")
            continue
        if isinstance(current, dict):
            for key, nested in reversed(list(current.items())):
                normalized = re.sub(r"[^a-z]", "", str(key).lower())
                if any(part in normalized for part in _DENIED_FIELD_MARKERS):
                    _add(findings, SECRET, f"{cur_path}/{key}", "secret-bearing field is forbidden")
                stack.append((nested, f"{cur_path}/{key}", cur_depth + 1))
        elif isinstance(current, list):
            for index in range(len(current) - 1, -1, -1):
                stack.append((current[index], f"{cur_path}/{index}", cur_depth + 1))
        elif isinstance(current, str) and _SENSITIVE_RE.search(current):
            _add(findings, SECRET, cur_path, "credential-like value is forbidden")


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
    pull_request = subject.get("pullRequest")
    if isinstance(pull_request, bool) or not isinstance(pull_request, int) or pull_request < 1:
        _add(findings, SUBJECT, "/subject/pullRequest", "positive PR number required")
    ticket = subject.get("ticket")
    if not isinstance(ticket, str) or not TICKET_ID.fullmatch(ticket):
        _add(findings, SUBJECT, "/subject/ticket", "canonical ticket identifier required")
    correlation = subject.get("correlationId")
    if not isinstance(correlation, str) or not CORRELATION_ID.fullmatch(correlation):
        _add(findings, SUBJECT, "/subject/correlationId", "valid correlationId required")
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
        conclusion = check.get("conclusion")
        if not isinstance(conclusion, str) or conclusion not in CHECK_CONCLUSIONS:
            _add(findings, CHECKS, f"{path}/conclusion", "invalid check conclusion")
            all_success = False
        elif conclusion != "success":
            all_success = False
    return completed, all_success


def _validate_profile(document: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    fields = {"schema", "profileId", "version", "ownership", "bindings"}
    profile = _closed(document, "", fields, fields, findings)
    if profile is None:
        return findings
    profile_id = profile.get("profileId")
    if not isinstance(profile_id, str) or not PROFILE_ID.fullmatch(profile_id):
        _add(findings, PROFILE, "/profileId", "invalid validation profile URI")
    version = profile.get("version")
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        _add(findings, PROFILE, "/version", "exact semantic version required")
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
        if not isinstance(owner, str) or not RUNTIME_OWNER.fullmatch(owner):
            _add(findings, PROFILE, "/ownership/runtimeOwner", "runtime must remain external")
        adopts = ownership.get("adopts")
        adopts_valid = (
            isinstance(adopts, list)
            and bool(adopts)
            and all(isinstance(item, str) and ADOPT_REF.fullmatch(item) for item in adopts)
            and len(adopts) == len(set(adopts))
            and "wellmanifest/autonomy" in adopts
        )
        if not adopts_valid:
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
            stage = binding.get("stage")
            stage_key = stage if isinstance(stage, str) else repr(stage)
            if stage_key in observed:
                _add(findings, PROFILE, f"{path}/stage", "duplicate stage")
            mode = binding.get("mode")
            observed[stage_key] = mode if isinstance(mode, str) else repr(mode)
            uri = binding.get("uri")
            if not isinstance(uri, str) or not PROCESS_URI.fullmatch(uri):
                _add(findings, PROFILE, f"{path}/uri", "invalid subactor process URI")
            principal = _principal(binding.get("principal"), f"{path}/principal", findings) or {}
            principals[stage_key] = str(principal.get("uri"))
    if observed != PROFILE_MODES:
        _add(findings, PROFILE, "/bindings", "exact stage and mode map required")
    if principals.get("publish") in {principals.get("attest"), principals.get("verify")}:
        _add(findings, PROFILE, "/bindings", "publisher must be independent")
    if principals.get("verify") == principals.get("attest"):
        _add(findings, PROFILE, "/bindings", "verifier must differ from attester")
    _scan_secrets(profile, "", findings)
    return findings
