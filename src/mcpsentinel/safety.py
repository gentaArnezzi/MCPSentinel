"""Credential-safe representations for reports and local metadata snapshots."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .models import TargetConfig, to_primitive

_SENSITIVE_FIELD = re.compile(
    r"(?:api[_-]?key|access[_-]?token|auth(?:entication|orization)?|"
    r"credential|password|private[_-]?key|secret|session|token)",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_SENSITIVE_REPLACEMENTS = (
    (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b"), "[REDACTED_OPENAI_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "[REDACTED_AWS_ACCESS_KEY]"),
    (
        re.compile(
            r"-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----.*?-----END(?: [A-Z]+)? PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (
        re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer|basic)\s+)[^\s\"',]+"),
        r"\1[REDACTED_AUTHORIZATION]",
    ),
    (
        re.compile(
            r'(?i)("(?:api[_-]?key|access[_-]?token|secret|password|credential|token)"'
            r'\s*:\s*")[^"]+',
        ),
        r"\1[REDACTED_SECRET]",
    ),
    (
        re.compile(
            r"(?i)\b((?:api[_-]?key|access[_-]?token|secret|password|"
            r"credential|token)\s*[:=]\s*)[^\s,;'\"]+"
        ),
        r"\1[REDACTED_SECRET]",
    ),
)


def sanitize_url(value: str) -> str:
    """Remove HTTP URL user-info without changing the destination or path."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    if not parsed.scheme or parsed.username is None:
        return value
    hostname = parsed.hostname
    if not hostname:
        return value
    host = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
    try:
        port = parsed.port
    except ValueError:
        return value
    netloc = f"{host}:{port}" if port is not None else host
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def sanitize_text(value: str) -> str:
    """Redact credential-shaped strings and credentials embedded in HTTP URLs."""
    redacted = _URL.sub(lambda match: sanitize_url(match.group(0)), value)
    for pattern, replacement in _SENSITIVE_REPLACEMENTS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def sanitize_value(value: Any, *, field_name: str | None = None) -> Any:
    """Return a safe, JSON-compatible copy without mutating scanner evidence."""
    if field_name is not None and _SENSITIVE_FIELD.search(field_name):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(key): sanitize_value(item, field_name=str(key)) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [sanitize_value(item) for item in value]
    if isinstance(value, str):
        return sanitize_text(value)
    return value


def safe_target_identity(target: TargetConfig) -> str:
    """Produce the report identity without serializing environment values or URL user-info."""
    if target.transport == "http":
        return sanitize_url(target.url or target.identity)
    if target.command:
        arguments = _safe_command_arguments(target.arguments)
        return " ".join([sanitize_text(target.command), *arguments])
    return sanitize_text(target.identity)


def safe_target_payload(target: TargetConfig) -> dict[str, Any]:
    """Serialize connection configuration without ever retaining env values."""
    payload: dict[str, Any] = {
        "transport": target.transport,
        "identity": safe_target_identity(target),
        "url": sanitize_url(target.url) if target.url else None,
        "command": sanitize_text(target.command) if target.command else None,
        "arguments": _safe_command_arguments(target.arguments),
        "environment": {key: "[REDACTED]" for key in sorted(target.environment)},
        "inherit_environment": target.inherit_environment,
        "restrict_to_public_network": target.restrict_to_public_network,
    }
    return payload


def safe_report_payload(report: Any) -> dict[str, Any]:
    """Build the public JSON/HTML report payload from a credential-safe copy."""
    payload = to_primitive(report)
    payload["target"] = safe_target_payload(report.target)
    return sanitize_value(payload)


def _safe_command_arguments(arguments: tuple[str, ...]) -> list[str]:
    safe: list[str] = []
    redact_next = False
    for argument in arguments:
        if redact_next:
            safe.append("[REDACTED]")
            redact_next = False
            continue
        key, separator, _ = argument.partition("=")
        if separator and _SENSITIVE_FIELD.search(key.lstrip("-")):
            safe.append(f"{key}=[REDACTED]")
        elif _SENSITIVE_FIELD.search(argument.lstrip("-")):
            safe.append(sanitize_text(argument))
            redact_next = argument.startswith("-")
        else:
            safe.append(sanitize_text(argument))
    return safe
