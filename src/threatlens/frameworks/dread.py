"""DREAD quantitative risk scoring engine.

Damage · Reproducibility · Exploitability · Affected Users · Discoverability

Produces numeric scores (1-10 per dimension) for identified threats based on
their attributes, context signals, and STRIDE category heuristics.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from threatlens.models import DreadScore, Severity, StrideCategory, Threat

if TYPE_CHECKING:
    from collections.abc import Sequence

# ---------------------------------------------------------------------------
# Base score heuristics per STRIDE category
# ---------------------------------------------------------------------------

_CATEGORY_BASELINES: dict[StrideCategory, dict[str, float]] = {
    StrideCategory.SPOOFING: {
        "damage": 7,
        "reproducibility": 6,
        "exploitability": 5,
        "affected_users": 7,
        "discoverability": 5,
    },
    StrideCategory.TAMPERING: {
        "damage": 8,
        "reproducibility": 5,
        "exploitability": 5,
        "affected_users": 6,
        "discoverability": 4,
    },
    StrideCategory.REPUDIATION: {
        "damage": 4,
        "reproducibility": 7,
        "exploitability": 6,
        "affected_users": 3,
        "discoverability": 3,
    },
    StrideCategory.INFORMATION_DISCLOSURE: {
        "damage": 7,
        "reproducibility": 6,
        "exploitability": 5,
        "affected_users": 8,
        "discoverability": 5,
    },
    StrideCategory.DENIAL_OF_SERVICE: {
        "damage": 5,
        "reproducibility": 8,
        "exploitability": 7,
        "affected_users": 9,
        "discoverability": 7,
    },
    StrideCategory.ELEVATION_OF_PRIVILEGE: {
        "damage": 9,
        "reproducibility": 4,
        "exploitability": 4,
        "affected_users": 6,
        "discoverability": 4,
    },
}

# Keywords that adjust specific DREAD dimensions upward
_SEVERITY_BOOSTERS: dict[str, dict[str, float]] = {
    "public": {"affected_users": 1.5, "discoverability": 1.0},
    "internet": {"affected_users": 1.5, "discoverability": 1.5},
    "pii": {"damage": 1.5, "affected_users": 1.0},
    "financial": {"damage": 2.0, "affected_users": 1.0},
    "health": {"damage": 2.0},
    "admin": {"damage": 1.5, "exploitability": -0.5},
    "unauthenticated": {"exploitability": 2.0, "discoverability": 1.5},
    "internal": {"affected_users": -1.5, "discoverability": -1.0},
    "encrypted": {"exploitability": -1.0, "damage": -0.5},
    "automated": {"reproducibility": 1.5},
}


def _clamp(value: float, low: float = 1.0, high: float = 10.0) -> float:
    return max(low, min(high, round(value, 1)))


def _compute_baseline(categories: Sequence[StrideCategory]) -> dict[str, float]:
    """Average baseline scores across all applicable STRIDE categories."""
    if not categories:
        return {
            "damage": 5,
            "reproducibility": 5,
            "exploitability": 5,
            "affected_users": 5,
            "discoverability": 5,
        }

    dims = [
        "damage",
        "reproducibility",
        "exploitability",
        "affected_users",
        "discoverability",
    ]
    totals = {d: 0.0 for d in dims}
    for cat in categories:
        baseline = _CATEGORY_BASELINES[cat]
        for d in dims:
            totals[d] += baseline[d]
    return {d: totals[d] / len(categories) for d in dims}


def _apply_context_modifiers(
    scores: dict[str, float], context: str
) -> dict[str, float]:
    """Adjust scores based on contextual keywords."""
    lowered = context.lower()
    adjusted = dict(scores)
    for keyword, modifiers in _SEVERITY_BOOSTERS.items():
        if keyword in lowered:
            for dim, delta in modifiers.items():
                adjusted[dim] = adjusted[dim] + delta
    return {k: _clamp(v) for k, v in adjusted.items()}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def score_threat(threat: Threat, system_context: str = "") -> DreadScore:
    """Compute a DREAD score for a given threat.

    Args:
        threat: The threat to score.
        system_context: Additional text describing the system (used for
            contextual adjustments).

    Returns:
        A DreadScore with per-dimension values and overall rating.
    """
    baseline = _compute_baseline(threat.stride_categories)
    context = f"{threat.description} {system_context}"
    adjusted = _apply_context_modifiers(baseline, context)

    if threat.severity == Severity.CRITICAL:
        adjusted["damage"] = _clamp(adjusted["damage"] + 1.0)
        adjusted["exploitability"] = _clamp(adjusted["exploitability"] + 0.5)
    elif threat.severity == Severity.LOW:
        adjusted["damage"] = _clamp(adjusted["damage"] - 1.0)

    return DreadScore(**adjusted)


def score_threats(
    threats: Sequence[Threat], system_context: str = ""
) -> list[tuple[Threat, DreadScore]]:
    """Score a batch of threats and return them sorted by overall score (desc)."""
    scored = [(t, score_threat(t, system_context)) for t in threats]
    scored.sort(key=lambda pair: pair[1].overall, reverse=True)
    return scored


def aggregate_risk(scores: Sequence[DreadScore]) -> dict[str, float]:
    """Aggregate statistics across multiple DREAD scores."""
    if not scores:
        return {"mean": 0, "max": 0, "min": 0, "count": 0}

    overalls = [s.overall for s in scores]
    return {
        "mean": round(sum(overalls) / len(overalls), 1),
        "max": max(overalls),
        "min": min(overalls),
        "count": len(overalls),
    }
