"""Bounded regular-file I/O, strict JSON loader, symlink guards, and JSON Pointer helpers."""

from __future__ import annotations

import errno
import json
import math
import os
import re
import stat
from pathlib import Path
from typing import Any

MAX_ATTESTATION_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64

_DENIED_FIELD_MARKERS = (
    "tok" + "en",
    "sec" + "ret",
    "pass" + "word",
    "credential",
    "privatekey",
    "api" + "key",
)
_SENSITIVE_RE = re.compile(
    r"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}|"
    r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b|"
    r"\bgithub_pat_[A-Za-z0-9_]{20,}\b|"
    r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}\b|"
    r"\bAK"
    r"IA[0-9A-Z]{16}\b|"
    r"-----BEGIN [A-Z0-9 ]*PRI"
    r"VATE KEY-----"
)

__all__ = [
    "MAX_ATTESTATION_BYTES",
    "MAX_JSON_DEPTH",
    "StrictJsonError",
    "_DENIED_FIELD_MARKERS",
    "_SENSITIVE_RE",
    "_array_index",
    "_check_no_symlink_ancestors",
    "_check_utf8_str",
    "_iter_json_paths",
    "_pointer_parent",
    "_safe_read_json",
    "_strict_loads",
]


class StrictJsonError(ValueError):
    """Raised when raw JSON violates duplicate-key, finite-number, or regular-file rules."""


def _check_utf8_str(value: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise StrictJsonError("lone UTF-16 surrogate in JSON string is forbidden") from error


def _parse_finite_float(token: str) -> float:
    parsed = float(token)
    if not math.isfinite(parsed):
        raise StrictJsonError(f"non-finite JSON number {token!r}")
    return parsed


def _parse_finite_int(token: str) -> int:
    digits = token[1:] if token.startswith("-") else token
    if len(digits) > 309:
        raise StrictJsonError("JSON integer magnitude exceeds finite range")
    parsed = int(token)
    try:
        ok = math.isfinite(float(parsed))
    except OverflowError:
        ok = False
    if not ok:
        raise StrictJsonError("JSON integer magnitude exceeds finite range")
    return parsed


def _strict_loads(raw: str) -> Any:
    if not isinstance(raw, str):
        raise StrictJsonError("JSON payload must be a string")
    _check_utf8_str(raw)
    if len(raw.encode("utf-8")) > MAX_ATTESTATION_BYTES:
        raise StrictJsonError("input exceeds maximum byte budget")

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
        parsed = json.loads(
            raw,
            object_pairs_hook=_no_duplicates,
            parse_constant=_no_constants,
            parse_float=_parse_finite_float,
            parse_int=_parse_finite_int,
        )
    except RecursionError as error:
        raise StrictJsonError("JSON nesting depth exceeded") from error

    stack: list[tuple[Any, int]] = [(parsed, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise StrictJsonError("JSON nesting depth exceeded")
        if isinstance(current, dict):
            for key, val in current.items():
                if not isinstance(key, str):
                    raise StrictJsonError("JSON object keys must be strings")
                _check_utf8_str(key)
                stack.append((val, depth + 1))
        elif isinstance(current, list):
            for val in current:
                stack.append((val, depth + 1))
        elif isinstance(current, str):
            _check_utf8_str(current)
        elif type(current) is int:
            try:
                ok = math.isfinite(float(current))
            except OverflowError:
                ok = False
            if not ok:
                raise StrictJsonError("JSON integer magnitude exceeds finite range")
        elif isinstance(current, float) and not math.isfinite(current):
            raise StrictJsonError("non-finite JSON float is forbidden")
    return parsed


def _check_no_symlink_ancestors(path: str | Path, *, include_self: bool = False) -> Path:
    raw_path = os.fspath(path)
    path_obj = Path(raw_path)
    raw_parts = path_obj.parts if include_self else path_obj.parts[:-1]
    if path_obj.is_absolute():
        cur = Path(path_obj.anchor)
        walk_parts = raw_parts[1:]
    else:
        cwd = Path.cwd()
        if len(cwd.parts) > 2 and cwd.is_symlink():
            raise StrictJsonError("symlink ancestor is forbidden")
        for anc in cwd.parents:
            if len(anc.parts) > 2 and anc.is_symlink():
                raise StrictJsonError("symlink ancestor is forbidden")
        cur = cwd
        walk_parts = raw_parts
    for part in walk_parts:
        if part in ("", "."):
            continue
        cur = cur / part
        if part != ".." and len(cur.parts) > 2 and cur.is_symlink():
            raise StrictJsonError("symlink ancestor is forbidden")
    abs_path = Path(os.path.abspath(raw_path))
    if include_self and abs_path.is_symlink():
        raise StrictJsonError("symlink input is forbidden")
    if any(anc.is_symlink() for anc in abs_path.parents if len(anc.parts) > 2):
        raise StrictJsonError("symlink ancestor is forbidden")
    return abs_path


def _safe_read_json(path: Path) -> Any:
    raw_path = os.fspath(path)
    _check_no_symlink_ancestors(raw_path, include_self=False)
    lst = os.lstat(raw_path)
    if stat.S_ISLNK(lst.st_mode):
        raise StrictJsonError("symlink input is forbidden")
    if not stat.S_ISREG(lst.st_mode):
        raise StrictJsonError("input must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(raw_path, flags)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise StrictJsonError("symlink input is forbidden") from error
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise StrictJsonError("input must be a regular file")
        if (st.st_dev, st.st_ino) != (lst.st_dev, lst.st_ino):
            raise StrictJsonError("input inode changed during open")
        if st.st_size > MAX_ATTESTATION_BYTES:
            raise StrictJsonError("input exceeds maximum byte budget")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, MAX_ATTESTATION_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ATTESTATION_BYTES:
                raise StrictJsonError("input exceeds maximum byte budget")
            chunks.append(chunk)
    finally:
        os.close(fd)
    return _strict_loads(b"".join(chunks).decode("utf-8"))


def _array_index(token: str) -> int:
    if not (token == "0" or (token.isdigit() and len(token) <= 9 and not token.startswith("0"))):
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
