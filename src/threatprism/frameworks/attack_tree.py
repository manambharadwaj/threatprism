"""Attack tree generation engine.

Builds structured attack decomposition trees from identified threats,
breaking high-level goals into concrete attack paths with AND/OR gates.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from threatprism.models import AttackNode, AttackTree, GateType, StrideCategory, Threat

if TYPE_CHECKING:
    from collections.abc import Sequence

# ---------------------------------------------------------------------------
# Attack path templates per STRIDE category
# ---------------------------------------------------------------------------

_ATTACK_SUBTREES: dict[StrideCategory, list[dict]] = {
    StrideCategory.SPOOFING: [
        {
            "label": "Obtain valid credentials",
            "gate": "OR",
            "children": [
                {"label": "Phishing attack on user", "likelihood": 0.4, "impact": 8},
                {
                    "label": "Credential stuffing from breached database",
                    "likelihood": 0.5,
                    "impact": 8,
                },
                {"label": "Brute-force weak passwords", "likelihood": 0.3, "impact": 7},
                {
                    "label": "Exploit password reset flow",
                    "likelihood": 0.2,
                    "impact": 7,
                },
            ],
        },
        {
            "label": "Forge authentication token",
            "gate": "OR",
            "children": [
                {
                    "label": "Exploit weak JWT signing (alg=none)",
                    "likelihood": 0.15,
                    "impact": 9,
                },
                {
                    "label": "Steal signing key from config leak",
                    "likelihood": 0.1,
                    "impact": 10,
                },
                {"label": "Session fixation attack", "likelihood": 0.2, "impact": 7},
            ],
        },
    ],
    StrideCategory.TAMPERING: [
        {
            "label": "Modify data in transit",
            "gate": "AND",
            "children": [
                {
                    "label": "Perform MitM on unencrypted channel",
                    "likelihood": 0.2,
                    "impact": 8,
                },
                {
                    "label": "Intercept and alter request payload",
                    "likelihood": 0.3,
                    "impact": 8,
                },
            ],
        },
        {
            "label": "Modify data at rest",
            "gate": "OR",
            "children": [
                {
                    "label": "SQL injection to alter records",
                    "likelihood": 0.3,
                    "impact": 9,
                },
                {
                    "label": "Exploit insecure direct object reference",
                    "likelihood": 0.35,
                    "impact": 7,
                },
                {
                    "label": "Abuse mass assignment vulnerability",
                    "likelihood": 0.25,
                    "impact": 7,
                },
            ],
        },
    ],
    StrideCategory.REPUDIATION: [
        {
            "label": "Deny malicious action",
            "gate": "OR",
            "children": [
                {
                    "label": "Exploit missing audit logging",
                    "likelihood": 0.4,
                    "impact": 5,
                },
                {"label": "Tamper with log files", "likelihood": 0.2, "impact": 7},
                {
                    "label": "Use shared/anonymous account",
                    "likelihood": 0.3,
                    "impact": 5,
                },
            ],
        },
    ],
    StrideCategory.INFORMATION_DISCLOSURE: [
        {
            "label": "Extract sensitive data",
            "gate": "OR",
            "children": [
                {
                    "label": "Exploit verbose error messages",
                    "likelihood": 0.5,
                    "impact": 5,
                },
                {
                    "label": "Access unprotected API endpoint",
                    "likelihood": 0.3,
                    "impact": 8,
                },
                {
                    "label": "Query data via SQL injection",
                    "likelihood": 0.25,
                    "impact": 9,
                },
                {
                    "label": "Enumerate user records via IDOR",
                    "likelihood": 0.35,
                    "impact": 7,
                },
            ],
        },
        {
            "label": "Intercept data in transit",
            "gate": "AND",
            "children": [
                {
                    "label": "Exploit missing or weak TLS",
                    "likelihood": 0.15,
                    "impact": 8,
                },
                {"label": "Sniff network traffic", "likelihood": 0.2, "impact": 7},
            ],
        },
    ],
    StrideCategory.DENIAL_OF_SERVICE: [
        {
            "label": "Exhaust system resources",
            "gate": "OR",
            "children": [
                {
                    "label": "Volumetric flood (HTTP/TCP)",
                    "likelihood": 0.5,
                    "impact": 7,
                },
                {
                    "label": "Algorithmic complexity attack (ReDoS)",
                    "likelihood": 0.2,
                    "impact": 6,
                },
                {
                    "label": "Resource-intensive query abuse",
                    "likelihood": 0.3,
                    "impact": 7,
                },
                {
                    "label": "Connection pool exhaustion",
                    "likelihood": 0.25,
                    "impact": 8,
                },
            ],
        },
    ],
    StrideCategory.ELEVATION_OF_PRIVILEGE: [
        {
            "label": "Gain elevated access",
            "gate": "OR",
            "children": [
                {
                    "label": "Exploit broken access control (IDOR)",
                    "likelihood": 0.35,
                    "impact": 8,
                },
                {
                    "label": "Manipulate role/permission parameters",
                    "likelihood": 0.2,
                    "impact": 9,
                },
                {
                    "label": "Exploit default admin credentials",
                    "likelihood": 0.15,
                    "impact": 10,
                },
                {
                    "label": "Path traversal to admin functions",
                    "likelihood": 0.2,
                    "impact": 9,
                },
            ],
        },
        {
            "label": "Escape tenant boundary",
            "gate": "AND",
            "children": [
                {
                    "label": "Discover tenant identifier scheme",
                    "likelihood": 0.3,
                    "impact": 5,
                },
                {
                    "label": "Forge or swap tenant context",
                    "likelihood": 0.15,
                    "impact": 10,
                },
            ],
        },
    ],
}


def _node_id(prefix: str, label: str) -> str:
    h = hashlib.sha256(f"{prefix}:{label}".encode()).hexdigest()[:6]
    return f"ATK-{h}"


def _build_subtree(spec: dict, prefix: str) -> AttackNode:
    children_specs = spec.get("children", [])
    children: list[AttackNode] = []

    for child_spec in children_specs:
        if "children" in child_spec:
            children.append(_build_subtree(child_spec, prefix))
        else:
            children.append(
                AttackNode(
                    id=_node_id(prefix, child_spec["label"]),
                    label=child_spec["label"],
                    gate=GateType.LEAF,
                    likelihood=child_spec.get("likelihood"),
                    impact=child_spec.get("impact"),
                )
            )

    return AttackNode(
        id=_node_id(prefix, spec["label"]),
        label=spec["label"],
        gate=GateType(spec.get("gate", "OR")),
        children=children,
        likelihood=None,
        impact=None,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_attack_tree(threat: Threat) -> AttackTree:
    """Build an attack tree for a given threat.

    Args:
        threat: The threat to decompose into attack paths.

    Returns:
        An AttackTree with hierarchical AND/OR decomposition.
    """
    subtrees: list[AttackNode] = []
    for cat in threat.stride_categories:
        specs = _ATTACK_SUBTREES.get(cat, [])
        for spec in specs:
            subtrees.append(_build_subtree(spec, threat.id))

    root = AttackNode(
        id=_node_id("root", threat.title),
        label=f"GOAL: {threat.title}",
        gate=GateType.OR if len(subtrees) > 1 else GateType.AND,
        children=subtrees,
        likelihood=None,
        impact=None,
    )

    return AttackTree(
        target=threat.title,
        description=threat.description,
        root=root,
    )


def build_attack_trees(threats: Sequence[Threat]) -> list[AttackTree]:
    """Build attack trees for multiple threats."""
    return [build_attack_tree(t) for t in threats]
