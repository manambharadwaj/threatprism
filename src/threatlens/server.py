"""ThreatLens MCP server — exposes multi-framework threat analysis as tools.

Provides STRIDE, DREAD, LINDDUN, and PASTA analysis to any
MCP-compatible client via the Model Context Protocol.
"""

from __future__ import annotations

from fastmcp import FastMCP

from threatlens.correlation import correlate_all, framework_coverage_summary
from threatlens.frameworks.attack_tree import build_attack_tree, build_attack_trees
from threatlens.frameworks.dread import aggregate_risk, score_threats
from threatlens.frameworks.linddun import assess_privacy, detect_privacy_signals
from threatlens.frameworks.pasta import run_pasta
from threatlens.frameworks.stride import analyze_stride
from threatlens.mappings import cwes_for_threat_categories, mitre_for_threat_categories
from threatlens.models import Severity, Threat
from threatlens.reports import generate_report

_INSTRUCTIONS = """\
## ThreatLens — Multi-Framework Threat Intelligence

You have access to threat analysis tools spanning four security frameworks:
STRIDE, DREAD, LINDDUN, and PASTA, plus CWE/MITRE ATT&CK cross-references.

### Recommended workflow

1. **Before coding** — call `analyze_threat_landscape` with the feature
   description and tech stack. This returns STRIDE-categorised threats.
2. **Score risks** — call `score_risks` to get quantitative DREAD scores
   for the identified threats.
3. **Privacy check** — if the feature handles personal data, call
   `assess_privacy_impact` for LINDDUN analysis.
4. **Deep analysis** — for high-risk components, call `build_attack_tree`
   to decompose attack paths.
5. **Full picture** — call `correlate_frameworks` to map threats across
   STRIDE → DREAD → LINDDUN → CWE → MITRE ATT&CK simultaneously.
6. **Document** — call `generate_threat_report` to produce a comprehensive
   markdown report, or `run_pasta_analysis` for a structured 7-stage process.
"""

mcp = FastMCP("ThreatLens", instructions=_INSTRUCTIONS)

# ---------------------------------------------------------------------------
# Tool: analyze_threat_landscape
# ---------------------------------------------------------------------------


@mcp.tool(tags={"stride", "analysis"})
def analyze_threat_landscape(
    system_description: str,
    tech_stack: list[str] | None = None,
    components: list[str] | None = None,
) -> dict:
    """Analyse a system for security threats using the STRIDE framework.

    Scans the description for security-relevant patterns and returns
    categorised threats with severity estimates and mitigations.

    Args:
        system_description: Free-text description of the system or feature.
        tech_stack: Technologies in use (e.g. ["Python", "PostgreSQL", "React"]).
        components: System components (e.g. ["API gateway", "auth service"]).

    Returns:
        Dict with identified threats and risk summary.
    """
    threats = analyze_stride(system_description, tech_stack, components)

    risk_summary: dict[str, int] = {}
    for t in threats:
        risk_summary[t.severity.value] = risk_summary.get(t.severity.value, 0) + 1

    stride_coverage: dict[str, int] = {}
    for t in threats:
        for cat in t.stride_categories:
            stride_coverage[cat.value] = stride_coverage.get(cat.value, 0) + 1

    return {
        "threat_count": len(threats),
        "threats": [t.model_dump() for t in threats],
        "risk_summary": risk_summary,
        "stride_coverage": stride_coverage,
        "analysis_note": (
            "Threats identified via keyword and component pattern matching against "
            "STRIDE categories. Review each threat in your specific context and "
            "adjust severity as needed."
        ),
    }


# ---------------------------------------------------------------------------
# Tool: score_risks
# ---------------------------------------------------------------------------


@mcp.tool(tags={"dread", "scoring"})
def score_risks(
    threats_json: list[dict],
    system_context: str = "",
) -> dict:
    """Score identified threats using the DREAD quantitative model.

    Each threat gets a 1-10 score on five dimensions: Damage,
    Reproducibility, Exploitability, Affected Users, Discoverability.

    Args:
        threats_json: List of threat dicts (from analyze_threat_landscape).
        system_context: Additional description for scoring context adjustments.

    Returns:
        Dict with scored threats sorted by severity and aggregate statistics.
    """
    threats = [Threat(**t) for t in threats_json]
    scored = score_threats(threats, system_context)

    results = []
    for threat, dread in scored:
        results.append(
            {
                "threat_id": threat.id,
                "threat_title": threat.title,
                "dread_scores": {
                    "damage": dread.damage,
                    "reproducibility": dread.reproducibility,
                    "exploitability": dread.exploitability,
                    "affected_users": dread.affected_users,
                    "discoverability": dread.discoverability,
                    "overall": dread.overall,
                    "rating": dread.rating.value,
                },
            }
        )

    agg = aggregate_risk([dread for _, dread in scored])

    return {
        "scored_threats": results,
        "aggregate": agg,
    }


# ---------------------------------------------------------------------------
# Tool: assess_privacy_impact
# ---------------------------------------------------------------------------


@mcp.tool(tags={"linddun", "privacy"})
def assess_privacy_impact(
    system_description: str,
    data_types: list[str] | None = None,
) -> dict:
    """Assess privacy threats using the LINDDUN framework.

    Analyses the system for privacy-specific risks: Linkability,
    Identifiability, Non-repudiation, Detectability, Disclosure,
    Unawareness, and Non-compliance.

    Args:
        system_description: Free-text description of the system.
        data_types: Explicit personal data types (e.g. ["email", "health records"]).

    Returns:
        Dict with privacy impacts and detected data signals.
    """
    impacts = assess_privacy(system_description, data_types)
    signals = detect_privacy_signals(system_description)

    return {
        "impact_count": len(impacts),
        "impacts": [i.model_dump() for i in impacts],
        "detected_signals": signals,
        "analysis_note": (
            "Privacy threats assessed against LINDDUN categories. Consider "
            "performing a full DPIA for high/critical findings."
        ),
    }


# ---------------------------------------------------------------------------
# Tool: build_attack_tree
# ---------------------------------------------------------------------------


@mcp.tool(name="build_attack_tree", tags={"attack_tree", "analysis"})
def build_attack_tree_tool(
    threat_json: dict,
) -> dict:
    """Build an attack tree decomposition for a specific threat.

    Breaks down the high-level threat into concrete attack paths
    using AND/OR gate decomposition with likelihood estimates.

    Args:
        threat_json: A single threat dict (from analyze_threat_landscape).

    Returns:
        Dict with the attack tree structure.
    """
    threat = Threat(**threat_json)
    tree = build_attack_tree(threat)
    return tree.model_dump()


# ---------------------------------------------------------------------------
# Tool: correlate_frameworks
# ---------------------------------------------------------------------------


@mcp.tool(tags={"correlation", "multi_framework"})
def correlate_frameworks(
    threats_json: list[dict],
    system_context: str = "",
) -> dict:
    """Map threats simultaneously across STRIDE, DREAD, LINDDUN, CWE, and MITRE ATT&CK.

    This is the core multi-framework correlation that shows how each
    threat appears from different security perspectives.

    Args:
        threats_json: List of threat dicts (from analyze_threat_landscape).
        system_context: Additional system description.

    Returns:
        Dict with per-threat correlations and framework coverage summary.
    """
    threats = [Threat(**t) for t in threats_json]
    correlations = correlate_all(threats, system_context)
    coverage = framework_coverage_summary(correlations)

    return {
        "correlations": [c.model_dump() for c in correlations],
        "framework_coverage": coverage,
    }


# ---------------------------------------------------------------------------
# Tool: map_to_cwe
# ---------------------------------------------------------------------------


@mcp.tool(tags={"cwe", "mapping"})
def map_to_cwe(
    threats_json: list[dict],
) -> dict:
    """Map identified threats to CWE (Common Weakness Enumeration) entries.

    Each threat's STRIDE categories are mapped to relevant CWE IDs with
    descriptions and reference links.

    Args:
        threats_json: List of threat dicts.

    Returns:
        Dict with per-threat CWE mappings.
    """
    results = []
    for t_data in threats_json:
        threat = Threat(**t_data)
        cwes = cwes_for_threat_categories(threat.stride_categories)
        mitre = mitre_for_threat_categories(threat.stride_categories)
        results.append(
            {
                "threat_id": threat.id,
                "threat_title": threat.title,
                "cwe_entries": cwes,
                "mitre_techniques": mitre,
            }
        )

    return {"mappings": results}


# ---------------------------------------------------------------------------
# Tool: run_pasta_analysis
# ---------------------------------------------------------------------------


@mcp.tool(tags={"pasta", "process"})
def run_pasta_analysis(
    system_description: str,
    threats_json: list[dict],
    tech_stack: list[str] | None = None,
) -> dict:
    """Run a full PASTA (Process for Attack Simulation and Threat Analysis).

    Executes all seven PASTA stages: business objectives, technical scope,
    application decomposition, threat analysis, vulnerability analysis,
    attack modeling, and risk/impact analysis.

    Args:
        system_description: Free-text system description.
        threats_json: Pre-identified threats (from analyze_threat_landscape).
        tech_stack: Optional list of technologies.

    Returns:
        Dict with results from all seven PASTA stages.
    """
    threats = [Threat(**t) for t in threats_json]
    stages = run_pasta(system_description, threats, tech_stack)
    return {
        "stages": [s.model_dump() for s in stages],
        "stage_count": len(stages),
    }


# ---------------------------------------------------------------------------
# Tool: generate_threat_report
# ---------------------------------------------------------------------------


@mcp.tool(tags={"report", "documentation"})
def generate_threat_report(
    system_name: str,
    system_description: str,
    tech_stack: list[str] | None = None,
    components: list[str] | None = None,
    include_privacy: bool = True,
    include_pasta: bool = True,
    include_attack_trees: bool = True,
) -> dict:
    """Generate a comprehensive multi-framework threat analysis report.

    Runs the full analysis pipeline (STRIDE → DREAD → LINDDUN → PASTA)
    and produces a formatted markdown report.

    Args:
        system_name: Name of the system being analysed.
        system_description: Detailed system description.
        tech_stack: Technologies in use.
        components: System components.
        include_privacy: Include LINDDUN privacy analysis (default True).
        include_pasta: Include PASTA 7-stage process (default True).
        include_attack_trees: Include attack tree decompositions (default True).

    Returns:
        Dict with the markdown report and analysis metadata.
    """
    threats = analyze_stride(system_description, tech_stack, components)
    scored = score_threats(threats, system_description)

    privacy_impacts = assess_privacy(system_description) if include_privacy else None
    pasta_stages = (
        run_pasta(system_description, threats, tech_stack) if include_pasta else None
    )

    trees = None
    if include_attack_trees:
        high_threats = [
            t for t in threats if t.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        trees = build_attack_trees(high_threats[:3])

    correlations = correlate_all(threats, system_description)

    report = generate_report(
        system_name=system_name,
        threats=threats,
        scored=scored,
        privacy_impacts=privacy_impacts,
        pasta_stages=pasta_stages,
        attack_trees=trees,
        correlations=correlations,
    )

    return {
        "report_markdown": report,
        "metadata": {
            "threat_count": len(threats),
            "frameworks_used": ["STRIDE", "DREAD"]
            + (["LINDDUN"] if include_privacy else [])
            + (["PASTA"] if include_pasta else []),
            "attack_trees_generated": len(trees) if trees else 0,
        },
    }


# ---------------------------------------------------------------------------
# Tool: suggest_mitigations
# ---------------------------------------------------------------------------


@mcp.tool(tags={"mitigation", "remediation"})
def suggest_mitigations(
    threats_json: list[dict],
) -> dict:
    """Get prioritised mitigation strategies for identified threats.

    Aggregates mitigations from all threats, deduplicates, and returns
    them grouped by priority based on threat severity.

    Args:
        threats_json: List of threat dicts.

    Returns:
        Dict with prioritised mitigation recommendations.
    """
    threats = [Threat(**t) for t in threats_json]

    priority_groups: dict[str, list[dict[str, str]]] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
    }
    seen: set[str] = set()

    for t in sorted(threats, key=lambda x: list(Severity).index(x.severity)):
        for m in t.mitigations:
            if m not in seen:
                seen.add(m)
                bucket = (
                    t.severity.value
                    if t.severity.value in priority_groups
                    else "medium"
                )
                priority_groups[bucket].append(
                    {
                        "mitigation": m,
                        "addresses_threat": t.title,
                        "threat_id": t.id,
                    }
                )

    return {
        "prioritised_mitigations": {k: v for k, v in priority_groups.items() if v},
        "total_unique_mitigations": len(seen),
    }
