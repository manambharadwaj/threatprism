"""STRIDE threat categorization engine.

Spoofing · Tampering · Repudiation · Information Disclosure ·
Denial of Service · Elevation of Privilege

Analyses a system description and returns categorised threats with
affected components and initial severity estimates.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from threatlens.models import Severity, StrideCategory, Threat

if TYPE_CHECKING:
    from collections.abc import Sequence

# ---------------------------------------------------------------------------
# Pattern database — maps keywords & component types to STRIDE categories
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ThreatTemplate:
    title: str
    description: str
    severity: Severity
    mitigations: list[str] = field(default_factory=list)


_STRIDE_INTEL: dict[StrideCategory, dict[str, object]] = {
    StrideCategory.SPOOFING: {
        "keywords": [
            "auth",
            "login",
            "credential",
            "token",
            "session",
            "identity",
            "password",
            "api.key",
            "oauth",
            "jwt",
            "sso",
            "certificate",
            "cookie",
        ],
        "components": [
            "authentication",
            "identity provider",
            "login",
            "api gateway",
            "sso",
        ],
        "templates": [
            _ThreatTemplate(
                "Authentication Bypass",
                "An attacker circumvents authentication "
                "controls to impersonate a legitimate "
                "user or service.",
                Severity.HIGH,
                [
                    "Enforce multi-factor authentication",
                    "Use strong credential storage (bcrypt/argon2)",
                    "Implement account lockout policies",
                ],
            ),
            _ThreatTemplate(
                "Token Forgery or Replay",
                "An attacker forges, steals, or replays "
                "authentication tokens to gain "
                "unauthorized access.",
                Severity.HIGH,
                [
                    "Use short-lived, signed tokens (e.g. JWTs with expiry)",
                    "Implement token rotation and revocation",
                    "Bind tokens to client fingerprint",
                ],
            ),
            _ThreatTemplate(
                "Session Hijacking",
                "An attacker steals or predicts session "
                "identifiers to take over an active "
                "session.",
                Severity.HIGH,
                [
                    "Set Secure, HttpOnly, SameSite flags on cookies",
                    "Regenerate session IDs after login",
                    "Use TLS for all session traffic",
                ],
            ),
        ],
    },
    StrideCategory.TAMPERING: {
        "keywords": [
            "database",
            "storage",
            "file",
            "input",
            "form",
            "api",
            "config",
            "write",
            "update",
            "upload",
            "modify",
            "mutation",
            "patch",
            "put",
        ],
        "components": [
            "database",
            "file system",
            "api endpoint",
            "message queue",
            "configuration",
        ],
        "templates": [
            _ThreatTemplate(
                "Unauthorized Data Modification",
                "An attacker modifies data in transit or "
                "at rest without authorization.",
                Severity.HIGH,
                [
                    "Implement integrity checks (HMAC, digital signatures)",
                    "Enforce authorization on all write operations",
                    "Use parameterised queries to prevent injection",
                ],
            ),
            _ThreatTemplate(
                "Input Manipulation / Injection",
                "An attacker submits crafted input to "
                "alter application logic or execute "
                "arbitrary commands.",
                Severity.CRITICAL,
                [
                    "Validate and sanitise all input at trust boundaries",
                    "Use parameterised queries / prepared statements",
                    "Apply Content-Security-Policy headers",
                ],
            ),
            _ThreatTemplate(
                "Configuration Tampering",
                "An attacker modifies application or "
                "infrastructure configuration to weaken "
                "security posture.",
                Severity.MEDIUM,
                [
                    "Store configuration in version-controlled, signed manifests",
                    "Restrict write access to config stores",
                    "Monitor for configuration drift",
                ],
            ),
        ],
    },
    StrideCategory.REPUDIATION: {
        "keywords": [
            "log",
            "audit",
            "trace",
            "transaction",
            "payment",
            "order",
            "consent",
            "signature",
            "receipt",
            "compliance",
        ],
        "components": [
            "logging",
            "audit trail",
            "payment",
            "transaction processor",
        ],
        "templates": [
            _ThreatTemplate(
                "Action Denial",
                "A user or system denies performing an "
                "action when no audit trail exists to "
                "prove otherwise.",
                Severity.MEDIUM,
                [
                    "Implement tamper-evident audit logging",
                    "Require digital signatures for critical actions",
                    "Use append-only log stores with integrity verification",
                ],
            ),
            _ThreatTemplate(
                "Audit Log Tampering",
                "An attacker modifies or deletes audit "
                "logs to hide malicious activity.",
                Severity.HIGH,
                [
                    "Ship logs to a write-once external store",
                    "Implement log integrity hashing",
                    "Restrict log deletion privileges",
                ],
            ),
        ],
    },
    StrideCategory.INFORMATION_DISCLOSURE: {
        "keywords": [
            "pii",
            "personal",
            "email",
            "address",
            "ssn",
            "credit.card",
            "secret",
            "key",
            "password",
            "encrypt",
            "sensitive",
            "health",
            "financial",
            "export",
            "download",
            "report",
        ],
        "components": [
            "database",
            "api",
            "report",
            "export",
            "cache",
            "search",
        ],
        "templates": [
            _ThreatTemplate(
                "Sensitive Data Exposure",
                "Sensitive data (PII, credentials, "
                "financial) is exposed through insecure "
                "storage, transit, or error messages.",
                Severity.HIGH,
                [
                    "Encrypt data at rest and in transit (TLS 1.2+)",
                    "Classify data and apply appropriate controls",
                    "Strip sensitive fields from error responses and logs",
                ],
            ),
            _ThreatTemplate(
                "Excessive Data in API Responses",
                "API endpoints return more data than the "
                "client requires, leaking internal "
                "details.",
                Severity.MEDIUM,
                [
                    "Implement field-level response filtering",
                    "Use DTOs / view models to control serialisation",
                    "Apply principle of least privilege to query scopes",
                ],
            ),
        ],
    },
    StrideCategory.DENIAL_OF_SERVICE: {
        "keywords": [
            "rate",
            "limit",
            "queue",
            "upload",
            "stream",
            "websocket",
            "poll",
            "batch",
            "bulk",
            "import",
            "export",
            "search",
            "public",
            "open",
        ],
        "components": [
            "api",
            "public endpoint",
            "queue",
            "worker",
            "load balancer",
        ],
        "templates": [
            _ThreatTemplate(
                "Resource Exhaustion",
                "An attacker overwhelms system resources "
                "(CPU, memory, connections) causing "
                "service degradation.",
                Severity.MEDIUM,
                [
                    "Implement rate limiting and request throttling",
                    "Set timeouts on all external calls",
                    "Use circuit breakers for downstream services",
                ],
            ),
            _ThreatTemplate(
                "Application-Layer DoS",
                "An attacker crafts requests that trigger "
                "expensive operations (regex, complex "
                "queries, large uploads).",
                Severity.MEDIUM,
                [
                    "Limit request body sizes and query complexity",
                    "Use async processing for heavy operations",
                    "Implement request cost budgets",
                ],
            ),
        ],
    },
    StrideCategory.ELEVATION_OF_PRIVILEGE: {
        "keywords": [
            "role",
            "admin",
            "permission",
            "privilege",
            "access.control",
            "rbac",
            "abac",
            "sudo",
            "root",
            "superuser",
            "tenant",
            "multi.tenant",
        ],
        "components": [
            "authorization",
            "role management",
            "admin panel",
            "tenant isolation",
        ],
        "templates": [
            _ThreatTemplate(
                "Horizontal Privilege Escalation",
                "A user accesses resources belonging to "
                "another user at the same privilege "
                "level (IDOR).",
                Severity.HIGH,
                [
                    "Enforce object-level authorization on every request",
                    "Use indirect reference maps instead of raw IDs",
                    "Implement ownership checks in data access layer",
                ],
            ),
            _ThreatTemplate(
                "Vertical Privilege Escalation",
                "A regular user gains access to "
                "administrative functions or "
                "elevated roles.",
                Severity.CRITICAL,
                [
                    "Enforce role checks at the controller/handler level",
                    "Separate admin and user code paths",
                    "Apply defense-in-depth with multiple authz layers",
                ],
            ),
            _ThreatTemplate(
                "Tenant Boundary Bypass",
                "In a multi-tenant system, one tenant "
                "accesses another tenant's data or "
                "configuration.",
                Severity.CRITICAL,
                [
                    "Enforce tenant context on every data query",
                    "Use row-level security or schema isolation",
                    "Audit cross-tenant access patterns",
                ],
            ),
        ],
    },
}


def _text_matches(text: str, patterns: Sequence[str]) -> list[str]:
    """Return patterns that match anywhere in the lowered text."""
    lowered = text.lower()
    hits: list[str] = []
    for p in patterns:
        if re.search(p.replace(".", r"[\s._-]?"), lowered):
            hits.append(p)
    return hits


def _make_id(category: str, title: str) -> str:
    digest = hashlib.sha256(f"{category}:{title}".encode()).hexdigest()[:8]
    return f"STRIDE-{digest}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_stride(
    system_description: str,
    tech_stack: Sequence[str] | None = None,
    components: Sequence[str] | None = None,
) -> list[Threat]:
    """Analyse a system description and return STRIDE-categorised threats.

    Args:
        system_description: Free-text description of the system or feature.
        tech_stack: Optional list of technologies in use.
        components: Optional list of system components / services.

    Returns:
        List of identified threats mapped to STRIDE categories.
    """
    corpus = system_description
    if tech_stack:
        corpus += " " + " ".join(tech_stack)
    if components:
        corpus += " " + " ".join(components)

    threats: list[Threat] = []

    for category, intel in _STRIDE_INTEL.items():
        kw_hits = _text_matches(corpus, intel["keywords"])  # type: ignore[arg-type]
        comp_hits = _text_matches(corpus, intel["components"])  # type: ignore[arg-type]

        if not kw_hits and not comp_hits:
            continue

        templates: list[_ThreatTemplate] = intel["templates"]  # type: ignore[assignment]
        for tmpl in templates:
            threats.append(
                Threat(
                    id=_make_id(category.value, tmpl.title),
                    title=tmpl.title,
                    description=tmpl.description,
                    stride_categories=[category],
                    severity=tmpl.severity,
                    mitigations=list(tmpl.mitigations),
                    affected_components=list(set(kw_hits + comp_hits)),
                )
            )

    return threats


def stride_categories_for_text(text: str) -> list[StrideCategory]:
    """Return which STRIDE categories are relevant for the given text."""
    categories: list[StrideCategory] = []
    for category, intel in _STRIDE_INTEL.items():
        if _text_matches(text, intel["keywords"]) or _text_matches(  # type: ignore[arg-type]
            text,
            intel["components"],  # type: ignore[arg-type]
        ):
            categories.append(category)
    return categories
