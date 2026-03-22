"""Cross-framework correlation engine.

Maps threats simultaneously across STRIDE, DREAD, LINDDUN, CWE, and
MITRE ATT&CK to provide a unified multi-dimensional view.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from threatprism.frameworks.dread import score_threat
from threatprism.mappings import (
    cwes_for_threat_categories,
    linddun_for_stride,
    mitre_for_threat_categories,
)
from threatprism.models import FrameworkCorrelation, Threat

if TYPE_CHECKING:
    from collections.abc import Sequence


def correlate_threat(threat: Threat, system_context: str = "") -> FrameworkCorrelation:
    """Build a cross-framework correlation for a single threat.

    Args:
        threat: The threat to correlate.
        system_context: Additional system description for DREAD scoring context.

    Returns:
        A FrameworkCorrelation with mappings across all supported frameworks.
    """
    dread = threat.dread_score or score_threat(threat, system_context)

    cwes = cwes_for_threat_categories(threat.stride_categories)
    cwe_ids = [c["id"] for c in cwes]

    mitre = mitre_for_threat_categories(threat.stride_categories)
    mitre_ids = [f"{t['id']} ({t['name']})" for t in mitre]

    linddun_cats = linddun_for_stride(threat.stride_categories)
    combined_linddun = sorted(
        set(threat.privacy_categories + linddun_cats), key=lambda c: c.value
    )

    return FrameworkCorrelation(
        threat_id=threat.id,
        threat_title=threat.title,
        stride=list(threat.stride_categories),
        dread=dread,
        linddun=combined_linddun,
        cwe_ids=sorted(set(threat.cwe_ids + cwe_ids)),
        mitre_techniques=mitre_ids,
    )


def correlate_all(
    threats: Sequence[Threat], system_context: str = ""
) -> list[FrameworkCorrelation]:
    """Correlate all threats across frameworks.

    Args:
        threats: List of threats to correlate.
        system_context: Additional system description.

    Returns:
        List of correlations sorted by DREAD severity (highest first).
    """
    correlations = [correlate_threat(t, system_context) for t in threats]
    correlations.sort(key=lambda c: c.dread.overall if c.dread else 0, reverse=True)
    return correlations


def framework_coverage_summary(
    correlations: Sequence[FrameworkCorrelation],
) -> dict[str, dict[str, int]]:
    """Summarise coverage across all frameworks.

    Returns:
        Dict keyed by framework name, each containing category/count pairs.
    """
    stride_counts: dict[str, int] = {}
    linddun_counts: dict[str, int] = {}
    cwe_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}

    for corr in correlations:
        for cat in corr.stride:
            stride_counts[cat.value] = stride_counts.get(cat.value, 0) + 1
        for cat in corr.linddun:
            linddun_counts[cat.value] = linddun_counts.get(cat.value, 0) + 1
        for cwe_id in corr.cwe_ids:
            cwe_counts[cwe_id] = cwe_counts.get(cwe_id, 0) + 1
        if corr.dread:
            rating = corr.dread.rating.value
            severity_counts[rating] = severity_counts.get(rating, 0) + 1

    return {
        "stride": stride_counts,
        "linddun": linddun_counts,
        "cwe": cwe_counts,
        "dread_severity": severity_counts,
    }
