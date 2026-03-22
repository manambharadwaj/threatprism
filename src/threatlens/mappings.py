"""CWE and MITRE ATT&CK mappings for cross-referencing threats."""

from __future__ import annotations

from threatlens.models import LinddunCategory, StrideCategory

# ---------------------------------------------------------------------------
# STRIDE → CWE mapping (curated from public CWE/CAPEC data)
# ---------------------------------------------------------------------------

STRIDE_TO_CWE: dict[StrideCategory, list[dict[str, str]]] = {
    StrideCategory.SPOOFING: [
        {
            "id": "CWE-287",
            "name": "Improper Authentication",
            "url": "https://cwe.mitre.org/data/definitions/287.html",
        },
        {
            "id": "CWE-290",
            "name": "Authentication Bypass by Spoofing",
            "url": "https://cwe.mitre.org/data/definitions/290.html",
        },
        {
            "id": "CWE-384",
            "name": "Session Fixation",
            "url": "https://cwe.mitre.org/data/definitions/384.html",
        },
        {
            "id": "CWE-613",
            "name": "Insufficient Session Expiration",
            "url": "https://cwe.mitre.org/data/definitions/613.html",
        },
        {
            "id": "CWE-798",
            "name": "Use of Hard-coded Credentials",
            "url": "https://cwe.mitre.org/data/definitions/798.html",
        },
    ],
    StrideCategory.TAMPERING: [
        {
            "id": "CWE-20",
            "name": "Improper Input Validation",
            "url": "https://cwe.mitre.org/data/definitions/20.html",
        },
        {
            "id": "CWE-89",
            "name": "SQL Injection",
            "url": "https://cwe.mitre.org/data/definitions/89.html",
        },
        {
            "id": "CWE-79",
            "name": "Cross-site Scripting (XSS)",
            "url": "https://cwe.mitre.org/data/definitions/79.html",
        },
        {
            "id": "CWE-352",
            "name": "Cross-Site Request Forgery (CSRF)",
            "url": "https://cwe.mitre.org/data/definitions/352.html",
        },
        {
            "id": "CWE-94",
            "name": "Code Injection",
            "url": "https://cwe.mitre.org/data/definitions/94.html",
        },
    ],
    StrideCategory.REPUDIATION: [
        {
            "id": "CWE-778",
            "name": "Insufficient Logging",
            "url": "https://cwe.mitre.org/data/definitions/778.html",
        },
        {
            "id": "CWE-223",
            "name": "Omission of Security-relevant Information",
            "url": "https://cwe.mitre.org/data/definitions/223.html",
        },
        {
            "id": "CWE-532",
            "name": "Insertion of Sensitive Info into Log",
            "url": "https://cwe.mitre.org/data/definitions/532.html",
        },
    ],
    StrideCategory.INFORMATION_DISCLOSURE: [
        {
            "id": "CWE-200",
            "name": "Exposure of Sensitive Information",
            "url": "https://cwe.mitre.org/data/definitions/200.html",
        },
        {
            "id": "CWE-209",
            "name": "Error Message Information Leak",
            "url": "https://cwe.mitre.org/data/definitions/209.html",
        },
        {
            "id": "CWE-312",
            "name": "Cleartext Storage of Sensitive Info",
            "url": "https://cwe.mitre.org/data/definitions/312.html",
        },
        {
            "id": "CWE-319",
            "name": "Cleartext Transmission of Sensitive Info",
            "url": "https://cwe.mitre.org/data/definitions/319.html",
        },
        {
            "id": "CWE-359",
            "name": "Exposure of Private Personal Information",
            "url": "https://cwe.mitre.org/data/definitions/359.html",
        },
    ],
    StrideCategory.DENIAL_OF_SERVICE: [
        {
            "id": "CWE-400",
            "name": "Uncontrolled Resource Consumption",
            "url": "https://cwe.mitre.org/data/definitions/400.html",
        },
        {
            "id": "CWE-770",
            "name": "Allocation of Resources Without Limits",
            "url": "https://cwe.mitre.org/data/definitions/770.html",
        },
        {
            "id": "CWE-1333",
            "name": "Inefficient Regular Expression Complexity",
            "url": "https://cwe.mitre.org/data/definitions/1333.html",
        },
    ],
    StrideCategory.ELEVATION_OF_PRIVILEGE: [
        {
            "id": "CWE-269",
            "name": "Improper Privilege Management",
            "url": "https://cwe.mitre.org/data/definitions/269.html",
        },
        {
            "id": "CWE-862",
            "name": "Missing Authorization",
            "url": "https://cwe.mitre.org/data/definitions/862.html",
        },
        {
            "id": "CWE-639",
            "name": "Authorization Bypass (IDOR)",
            "url": "https://cwe.mitre.org/data/definitions/639.html",
        },
        {
            "id": "CWE-22",
            "name": "Path Traversal",
            "url": "https://cwe.mitre.org/data/definitions/22.html",
        },
        {
            "id": "CWE-732",
            "name": "Incorrect Permission Assignment",
            "url": "https://cwe.mitre.org/data/definitions/732.html",
        },
    ],
}

# ---------------------------------------------------------------------------
# STRIDE → MITRE ATT&CK technique mapping (curated subset)
# ---------------------------------------------------------------------------

STRIDE_TO_MITRE: dict[StrideCategory, list[dict[str, str]]] = {
    StrideCategory.SPOOFING: [
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
        {
            "id": "T1539",
            "name": "Steal Web Session Cookie",
            "tactic": "Credential Access",
        },
        {
            "id": "T1528",
            "name": "Steal Application Access Token",
            "tactic": "Credential Access",
        },
    ],
    StrideCategory.TAMPERING: [
        {"id": "T1565", "name": "Data Manipulation", "tactic": "Impact"},
        {
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
        },
        {
            "id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution",
        },
    ],
    StrideCategory.REPUDIATION: [
        {"id": "T1070", "name": "Indicator Removal", "tactic": "Defense Evasion"},
        {"id": "T1562", "name": "Impair Defenses", "tactic": "Defense Evasion"},
    ],
    StrideCategory.INFORMATION_DISCLOSURE: [
        {"id": "T1530", "name": "Data from Cloud Storage", "tactic": "Collection"},
        {
            "id": "T1213",
            "name": "Data from Information Repositories",
            "tactic": "Collection",
        },
        {
            "id": "T1567",
            "name": "Exfiltration Over Web Service",
            "tactic": "Exfiltration",
        },
    ],
    StrideCategory.DENIAL_OF_SERVICE: [
        {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
        {"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
    ],
    StrideCategory.ELEVATION_OF_PRIVILEGE: [
        {
            "id": "T1068",
            "name": "Exploitation for Privilege Escalation",
            "tactic": "Privilege Escalation",
        },
        {
            "id": "T1548",
            "name": "Abuse Elevation Control Mechanism",
            "tactic": "Privilege Escalation",
        },
    ],
}

# ---------------------------------------------------------------------------
# STRIDE ↔ LINDDUN cross-reference
# ---------------------------------------------------------------------------

STRIDE_TO_LINDDUN: dict[StrideCategory, list[LinddunCategory]] = {
    StrideCategory.SPOOFING: [
        LinddunCategory.IDENTIFIABILITY,
        LinddunCategory.NON_REPUDIATION,
    ],
    StrideCategory.TAMPERING: [
        LinddunCategory.DISCLOSURE,
        LinddunCategory.NON_COMPLIANCE,
    ],
    StrideCategory.REPUDIATION: [
        LinddunCategory.NON_REPUDIATION,
        LinddunCategory.UNAWARENESS,
    ],
    StrideCategory.INFORMATION_DISCLOSURE: [
        LinddunCategory.DISCLOSURE,
        LinddunCategory.LINKABILITY,
        LinddunCategory.IDENTIFIABILITY,
        LinddunCategory.DETECTABILITY,
    ],
    StrideCategory.DENIAL_OF_SERVICE: [LinddunCategory.UNAWARENESS],
    StrideCategory.ELEVATION_OF_PRIVILEGE: [
        LinddunCategory.DISCLOSURE,
        LinddunCategory.NON_COMPLIANCE,
    ],
}


# ---------------------------------------------------------------------------
# Public lookup helpers
# ---------------------------------------------------------------------------


def cwes_for_threat_categories(
    categories: list[StrideCategory],
) -> list[dict[str, str]]:
    """Return deduplicated CWE entries for the given STRIDE categories."""
    seen: set[str] = set()
    results: list[dict[str, str]] = []
    for cat in categories:
        for cwe in STRIDE_TO_CWE.get(cat, []):
            if cwe["id"] not in seen:
                seen.add(cwe["id"])
                results.append(cwe)
    return results


def mitre_for_threat_categories(
    categories: list[StrideCategory],
) -> list[dict[str, str]]:
    """Return deduplicated MITRE ATT&CK techniques for the given STRIDE categories."""
    seen: set[str] = set()
    results: list[dict[str, str]] = []
    for cat in categories:
        for technique in STRIDE_TO_MITRE.get(cat, []):
            if technique["id"] not in seen:
                seen.add(technique["id"])
                results.append(technique)
    return results


def linddun_for_stride(categories: list[StrideCategory]) -> list[LinddunCategory]:
    """Return LINDDUN categories correlated with the given STRIDE categories."""
    seen: set[LinddunCategory] = set()
    for cat in categories:
        for lcat in STRIDE_TO_LINDDUN.get(cat, []):
            seen.add(lcat)
    return sorted(seen, key=lambda c: c.value)
