"""Shared primitives, regular-file JSON loader, and subject/check validators for attestation v1."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = (ROOT / "examples").resolve()
MAX_ATTESTATION_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64

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
ATTESTATION_ID = re.compile(r"^validation://attestation/[a-z0-9][a-z0-9._/-]*$")
AUDIENCE_URI = re.compile(r"^validation://audience/[a-z0-9][a-z0-9._/-]*$")
PROFILE_ID = re.compile(r"^validation://profile/[a-z0-9][a-z0-9._/-]*$")
PROCESS_URI = re.compile(r"^subactor://process/[a-z0-9][a-z0-9._/-]*$")
ISSUER_KEY_ID = re.compile(r"^[a-z][a-z0-9._:/-]{2,200}$")
TICKET_ID = re.compile(r"^ticket-[0-9]{3,}$")
CORRELATION_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{7,127}$")
REASON_CODE = re.compile(r"^[A-Z][A-Z0-9-]{2,80}$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
RUNTIME_OWNER = re.compile(r"^(subactor|semcod)/[a-z0-9][a-z0-9._/-]*$")
ADOPT_REF = re.compile(r"^wellmanifest/[a-z0-9][a-z0-9._/-]*$")
RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$")
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
_DENIED_FIELD_MARKERS = (
    "tok" + "en",
    "sec" + "ret",
    "pass" + "word",
    "credential",
    "privatekey",
    "api" + "key",
)


class StrictJsonError(ValueError):
    """Raised when raw JSON violates duplicate-key, finite-number, or regular-file rules."""


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


def _strict_loads(raw: str) -> Any:
    def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, value in pairs:
            if key in obj:
                raise StrictJsonError(f"duplicate JSON key {key!r}")
            obj[key] = value
        return obj

    def _no_constants(constant_name: str) -> Any:
        raise StrictJsonError(f"non-finite JSON constant {constant_name}")

    try:
        parsed = json.loads(raw, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except RecursionError as error:
        raise StrictJsonError("JSON nesting depth exceeded") from error
    stack: list[tuple[Any, int]] = [(parsed, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise StrictJsonError("JSON nesting depth exceeded")
        if isinstance(current, dict):
            stack.extend(
                (val, depth + 1) for val in current.values() if isinstance(val, (dict, list))
            )
        elif isinstance(current, list):
            stack.extend((val, depth + 1) for val in current if isinstance(val, (dict, list)))
    return parsed


def _safe_read_json(path: Path) -> Any:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(os.fspath(path), flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise StrictJsonError("input must be a regular file")
        if st.st_size > MAX_ATTESTATION_BYTES:
            raise StrictJsonError("input exceeds maximum byte budget")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ATTESTATION_BYTES:
                raise StrictJsonError("input exceeds maximum byte budget")
            chunks.append(chunk)
    finally:
        os.close(fd)
    return _strict_loads(b"".join(chunks).decode("utf-8"))


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
    if not isinstance(value, str) or not RFC3339.fullmatch(value):
        _add(findings, SYNTAX, path, "must be an RFC3339 timestamp")
        return None
    normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
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
    if depth > 64:
        _add(findings, SYNTAX, path, "maximum JSON nesting depth exceeded")
        return
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = re.sub(r"[^a-z]", "", str(key).lower())
            if any(part in normalized for part in _DENIED_FIELD_MARKERS):
                _add(findings, SECRET, f"{path}/{key}", "secret-bearing field is forbidden")
            _scan_secrets(nested, f"{path}/{key}", findings, depth + 1)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _scan_secrets(nested, f"{path}/{index}", findings, depth + 1)
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
