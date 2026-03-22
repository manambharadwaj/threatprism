"""PASTA — Process for Attack Simulation and Threat Analysis.

Seven-stage risk-centric threat modeling methodology that produces structured
analysis from business objectives through to risk quantification.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from threatlens.models import PastaStage, PastaStageResult, Severity, Threat

if TYPE_CHECKING:
    from collections.abc import Sequence

# ---------------------------------------------------------------------------
# Stage processors
# ---------------------------------------------------------------------------

_BUSINESS_KEYWORDS: dict[str, str] = {
    "payment": "Financial transaction integrity",
    "auth": "Identity and access management",
    "compliance": "Regulatory compliance requirements",
    "privacy": "User privacy obligations",
    "uptime": "Service availability SLA",
    "customer": "Customer data protection",
    "partner": "Third-party trust boundaries",
    "api": "API security and access control",
    "health": "PHI protection (HIPAA)",
    "financial": "Financial data protection (PCI-DSS / SOX)",
}

_TECH_CATEGORIES: dict[str, list[str]] = {
    "web_frontend": [
        "react",
        "angular",
        "vue",
        "html",
        "css",
        "javascript",
        "typescript",
        "next",
        "svelte",
    ],
    "backend": [
        "python",
        "java",
        "go",
        "rust",
        "node",
        "django",
        "flask",
        "spring",
        "express",
        "fastapi",
    ],
    "database": [
        "postgres",
        "mysql",
        "mongodb",
        "redis",
        "dynamodb",
        "sqlite",
        "sql",
        "elasticsearch",
    ],
    "cloud": [
        "aws",
        "azure",
        "gcp",
        "kubernetes",
        "docker",
        "lambda",
        "s3",
        "ec2",
        "cloud",
    ],
    "messaging": ["kafka", "rabbitmq", "sqs", "pubsub", "nats", "websocket", "grpc"],
    "mobile": ["ios", "android", "react native", "flutter", "swift", "kotlin"],
}

_COMPONENT_PATTERNS: dict[str, list[str]] = {
    "trust_boundary": [
        "api gateway",
        "firewall",
        "load balancer",
        "reverse proxy",
        "waf",
        "cdn",
    ],
    "data_store": ["database", "cache", "file storage", "blob", "s3", "queue"],
    "external_entity": ["user", "admin", "third party", "partner", "vendor", "client"],
    "process": ["service", "worker", "scheduler", "pipeline", "handler", "controller"],
}

_ATTACK_VECTORS: dict[str, list[str]] = {
    "injection": [
        "sql injection",
        "xss",
        "command injection",
        "ldap injection",
        "nosql injection",
    ],
    "broken_auth": [
        "credential stuffing",
        "brute force",
        "session fixation",
        "token theft",
    ],
    "data_exposure": [
        "data leak",
        "insecure storage",
        "missing encryption",
        "verbose errors",
    ],
    "access_control": [
        "idor",
        "privilege escalation",
        "forced browsing",
        "path traversal",
    ],
    "misconfiguration": [
        "default credentials",
        "open ports",
        "debug mode",
        "cors misconfiguration",
    ],
    "supply_chain": [
        "dependency confusion",
        "typosquatting",
        "compromised library",
        "malicious package",
    ],
}


def _extract_matches(text: str, patterns: dict[str, list[str]]) -> dict[str, list[str]]:
    lowered = text.lower()
    results: dict[str, list[str]] = {}
    for category, keywords in patterns.items():
        hits = [kw for kw in keywords if kw in lowered]
        if hits:
            results[category] = hits
    return results


def _stage_1_business_objectives(description: str) -> PastaStageResult:
    findings: list[str] = []
    for keyword, objective in _BUSINESS_KEYWORDS.items():
        if keyword in description.lower():
            findings.append(objective)

    if not findings:
        findings.append("General application security and data protection")

    return PastaStageResult(
        stage=PastaStage.BUSINESS_OBJECTIVES,
        title="Define Business Objectives",
        findings=findings,
        artifacts={"objective_count": str(len(findings))},
    )


def _stage_2_technical_scope(
    description: str, tech_stack: Sequence[str] | None
) -> PastaStageResult:
    corpus = description + (" " + " ".join(tech_stack) if tech_stack else "")
    detected = _extract_matches(corpus, _TECH_CATEGORIES)

    findings = [
        f"Technology area: {area} — detected: {', '.join(techs)}"
        for area, techs in detected.items()
    ]
    if not findings:
        findings.append(
            "No specific technologies detected; manual scope definition recommended"
        )

    return PastaStageResult(
        stage=PastaStage.TECHNICAL_SCOPE,
        title="Define Technical Scope",
        findings=findings,
        artifacts={"tech_areas": str(list(detected.keys()))},
    )


def _stage_3_decomposition(description: str) -> PastaStageResult:
    detected = _extract_matches(description, _COMPONENT_PATTERNS)

    findings: list[str] = []
    for comp_type, items in detected.items():
        label = comp_type.replace("_", " ").title()
        findings.append(f"{label}: {', '.join(items)}")

    if not findings:
        findings.append("Decomposition requires more detailed architecture description")

    return PastaStageResult(
        stage=PastaStage.DECOMPOSITION,
        title="Application Decomposition",
        findings=findings,
        artifacts={"component_types": str(list(detected.keys()))},
    )


def _stage_4_threat_analysis(threats: Sequence[Threat]) -> PastaStageResult:
    findings = [
        f"[{t.severity.value.upper()}] {t.title}"
        f" — {', '.join(c.value for c in t.stride_categories)}"
        for t in threats
    ]
    if not findings:
        findings.append(
            "No threats identified from STRIDE analysis; review system description"
        )

    return PastaStageResult(
        stage=PastaStage.THREAT_ANALYSIS,
        title="Threat Analysis",
        findings=findings,
        artifacts={"threat_count": str(len(threats))},
    )


def _stage_5_vulnerability_analysis(description: str) -> PastaStageResult:
    detected = _extract_matches(description, _ATTACK_VECTORS)

    findings: list[str] = []
    for vector, techniques in detected.items():
        label = vector.replace("_", " ").title()
        findings.append(f"Attack vector: {label} — techniques: {', '.join(techniques)}")

    if not findings:
        findings.append(
            "No specific vulnerability patterns detected; perform manual code review"
        )

    return PastaStageResult(
        stage=PastaStage.VULNERABILITY_ANALYSIS,
        title="Vulnerability Analysis",
        findings=findings,
        artifacts={"vector_count": str(len(detected))},
    )


def _stage_6_attack_modeling(
    threats: Sequence[Threat], description: str
) -> PastaStageResult:
    critical_threats = [
        t for t in threats if t.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    findings = [
        f"Attack scenario: {t.title} → {t.description}" for t in critical_threats[:5]
    ]
    if not findings:
        findings.append("No high-severity attack scenarios identified")

    return PastaStageResult(
        stage=PastaStage.ATTACK_MODELING,
        title="Attack Modeling",
        findings=findings,
        artifacts={"critical_threat_count": str(len(critical_threats))},
    )


def _stage_7_risk_impact(threats: Sequence[Threat]) -> PastaStageResult:
    severity_counts: dict[str, int] = {}
    for t in threats:
        severity_counts[t.severity.value] = severity_counts.get(t.severity.value, 0) + 1

    findings: list[str] = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = severity_counts.get(sev, 0)
        if count:
            findings.append(f"{sev.upper()}: {count} threat(s)")

    total = len(threats)
    if total:
        findings.append(f"Total threats identified: {total}")
    else:
        findings.append("No quantifiable risks identified")

    return PastaStageResult(
        stage=PastaStage.RISK_IMPACT,
        title="Risk & Impact Analysis",
        findings=findings,
        artifacts={"severity_distribution": str(severity_counts)},
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_pasta(
    system_description: str,
    threats: Sequence[Threat],
    tech_stack: Sequence[str] | None = None,
) -> list[PastaStageResult]:
    """Execute the full 7-stage PASTA analysis.

    Args:
        system_description: Free-text system/feature description.
        threats: Pre-identified threats (typically from STRIDE analysis).
        tech_stack: Optional list of technologies.

    Returns:
        Ordered list of results from each PASTA stage.
    """
    return [
        _stage_1_business_objectives(system_description),
        _stage_2_technical_scope(system_description, tech_stack),
        _stage_3_decomposition(system_description),
        _stage_4_threat_analysis(threats),
        _stage_5_vulnerability_analysis(system_description),
        _stage_6_attack_modeling(threats, system_description),
        _stage_7_risk_impact(threats),
    ]
