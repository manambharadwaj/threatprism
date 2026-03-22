"""LINDDUN privacy threat analysis engine.

Linkability · Identifiability · Non-repudiation · Detectability ·
Disclosure · Unawareness · Non-compliance

Analyses system descriptions for privacy-specific threats, with focus on
personal data types and processing activities.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from threatlens.models import LinddunCategory, PrivacyImpact, Severity

if TYPE_CHECKING:
    from collections.abc import Sequence

# ---------------------------------------------------------------------------
# Privacy signal database
# ---------------------------------------------------------------------------

_DATA_TYPES: dict[str, list[str]] = {
    "identifiers": [
        "name",
        "email",
        "phone",
        "address",
        "ssn",
        "national id",
        "passport",
    ],
    "financial": ["credit card", "bank account", "payment", "salary", "income", "tax"],
    "health": [
        "medical",
        "health",
        "diagnosis",
        "prescription",
        "insurance",
        "patient",
    ],
    "biometric": [
        "fingerprint",
        "face",
        "iris",
        "voice",
        "biometric",
        "facial recognition",
    ],
    "behavioral": [
        "browsing",
        "clickstream",
        "purchase history",
        "location",
        "gps",
        "tracking",
    ],
    "credentials": ["password", "pin", "secret", "key", "token", "credential"],
    "demographic": [
        "age",
        "gender",
        "ethnicity",
        "religion",
        "political",
        "sexual orientation",
    ],
}

_PROCESSING_ACTIVITIES: dict[str, list[str]] = {
    "collection": [
        "collect",
        "gather",
        "capture",
        "ingest",
        "receive",
        "accept",
        "form",
        "input",
        "register",
    ],
    "storage": ["store", "persist", "save", "database", "cache", "retain", "archive"],
    "sharing": [
        "share",
        "transfer",
        "export",
        "send",
        "disclose",
        "third.party",
        "vendor",
        "partner",
    ],
    "profiling": [
        "profile",
        "score",
        "segment",
        "classify",
        "predict",
        "recommend",
        "personali",
    ],
    "automated_decision": [
        "automat",
        "decision",
        "eligib",
        "approve",
        "deny",
        "reject",
        "flag",
    ],
    "cross_border": [
        "international",
        "cross.border",
        r"\beu\b",
        "gdpr",
        "transfer abroad",
        "global",
    ],
}


@dataclass(frozen=True)
class _PrivacyThreatTemplate:
    category: LinddunCategory
    title: str
    description: str
    severity: Severity
    triggers_data: list[str] = field(default_factory=list)
    triggers_activity: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


_PRIVACY_THREATS: list[_PrivacyThreatTemplate] = [
    _PrivacyThreatTemplate(
        LinddunCategory.LINKABILITY,
        "Cross-Dataset Linkability",
        "Data from multiple sources can be correlated to build "
        "comprehensive user profiles, even without direct "
        "identifiers.",
        Severity.HIGH,
        triggers_data=["behavioral", "demographic"],
        triggers_activity=["profiling", "sharing"],
        recommendations=[
            "Apply data minimisation — collect only what is necessary",
            "Use pseudonymisation or k-anonymity techniques",
            "Separate storage of linkable datasets",
        ],
    ),
    _PrivacyThreatTemplate(
        LinddunCategory.IDENTIFIABILITY,
        "Direct Re-identification",
        "Stored personal identifiers allow direct "
        "identification of individuals from the dataset.",
        Severity.HIGH,
        triggers_data=["identifiers", "biometric"],
        triggers_activity=["storage", "collection"],
        recommendations=[
            "Hash or tokenise direct identifiers",
            "Implement access controls on identifier fields",
            "Use differential privacy for analytics",
        ],
    ),
    _PrivacyThreatTemplate(
        LinddunCategory.NON_REPUDIATION,
        "Irrefutable Action Attribution",
        "System records immutably link actions to specific "
        "individuals, preventing plausible deniability even "
        "for legitimate activities.",
        Severity.MEDIUM,
        triggers_data=["identifiers", "credentials"],
        triggers_activity=["automated_decision"],
        recommendations=[
            "Allow users to contest automated decisions",
            "Provide mechanisms for data correction",
            "Implement privacy-preserving audit logs",
        ],
    ),
    _PrivacyThreatTemplate(
        LinddunCategory.DETECTABILITY,
        "Existence Disclosure",
        "An adversary can determine whether data about a "
        "specific individual exists in the system, even "
        "without accessing the data itself.",
        Severity.MEDIUM,
        triggers_data=["health", "financial", "demographic"],
        triggers_activity=["storage"],
        recommendations=[
            "Use uniform API responses regardless of record existence",
            "Implement dummy records or noise",
            "Apply rate limiting on lookup endpoints",
        ],
    ),
    _PrivacyThreatTemplate(
        LinddunCategory.DISCLOSURE,
        "Unauthorized Data Disclosure",
        "Personal data is exposed to unauthorized parties "
        "through breaches, insecure APIs, or excessive "
        "logging.",
        Severity.CRITICAL,
        triggers_data=["identifiers", "financial", "health", "biometric"],
        triggers_activity=["sharing", "storage"],
        recommendations=[
            "Encrypt PII at rest and in transit",
            "Implement field-level encryption for sensitive columns",
            "Audit all data access and sharing paths",
        ],
    ),
    _PrivacyThreatTemplate(
        LinddunCategory.UNAWARENESS,
        "Opaque Data Processing",
        "Users are unaware of how their data is collected, "
        "processed, shared, or used for automated decisions.",
        Severity.MEDIUM,
        triggers_data=["behavioral", "demographic"],
        triggers_activity=["profiling", "automated_decision", "sharing"],
        recommendations=[
            "Provide clear, accessible privacy notices",
            "Implement preference centres for data use consent",
            "Send notifications when data processing purposes change",
        ],
    ),
    _PrivacyThreatTemplate(
        LinddunCategory.NON_COMPLIANCE,
        "Regulatory Non-compliance",
        "Data processing activities violate applicable "
        "privacy regulations (GDPR, CCPA, HIPAA, etc.).",
        Severity.CRITICAL,
        triggers_data=["health", "financial", "biometric", "demographic"],
        triggers_activity=["cross_border", "automated_decision", "sharing"],
        recommendations=[
            "Conduct Data Protection Impact Assessment (DPIA)",
            "Maintain Records of Processing Activities (RoPA)",
            "Implement data subject rights endpoints (access, delete, port)",
        ],
    ),
]


def _kw_match(keyword: str, text: str) -> bool:
    """Match keyword against text using word boundaries for short tokens."""
    if keyword.startswith(r"\b"):
        return bool(re.search(keyword, text))
    if len(keyword) <= 3:
        return bool(re.search(rf"\b{re.escape(keyword)}\b", text))
    return keyword in text


def _detect_data_types(text: str) -> list[str]:
    lowered = text.lower()
    found: list[str] = []
    for dtype, keywords in _DATA_TYPES.items():
        if any(_kw_match(kw, lowered) for kw in keywords):
            found.append(dtype)
    return found


def _detect_activities(text: str) -> list[str]:
    lowered = text.lower()
    found: list[str] = []
    for activity, keywords in _PROCESSING_ACTIVITIES.items():
        if any(_kw_match(kw, lowered) for kw in keywords):
            found.append(activity)
    return found


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def assess_privacy(
    system_description: str,
    data_types: Sequence[str] | None = None,
) -> list[PrivacyImpact]:
    """Assess privacy threats using the LINDDUN framework.

    Args:
        system_description: Free-text description of the system or feature.
        data_types: Optional explicit list of personal data types handled.

    Returns:
        List of privacy impact findings with LINDDUN categorisation.
    """
    detected_data = _detect_data_types(system_description)
    if data_types:
        detected_data = list(set(detected_data + list(data_types)))

    detected_activities = _detect_activities(system_description)

    if not detected_data and not detected_activities:
        return []

    impacts: list[PrivacyImpact] = []
    for tmpl in _PRIVACY_THREATS:
        data_match = any(d in detected_data for d in tmpl.triggers_data)
        activity_match = any(a in detected_activities for a in tmpl.triggers_activity)

        if not data_match and not activity_match:
            continue

        impacts.append(
            PrivacyImpact(
                category=tmpl.category,
                description=f"{tmpl.title}: {tmpl.description}",
                severity=tmpl.severity,
                affected_data_types=[
                    d for d in detected_data if d in tmpl.triggers_data
                ]
                or detected_data,
                recommendations=list(tmpl.recommendations),
            )
        )

    return impacts


def detect_privacy_signals(text: str) -> dict[str, list[str]]:
    """Detect privacy-relevant signals in text without full analysis.

    Returns:
        Dict with 'data_types' and 'activities' keys.
    """
    return {
        "data_types": _detect_data_types(text),
        "activities": _detect_activities(text),
    }
