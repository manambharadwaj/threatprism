"""Evaluation runner — tests ThreatLens against known-vulnerable projects.

Runs three analysis modes (STRIDE-only, STRIDE+DREAD, Full multi-framework)
against each ground truth project and records structured results for
comparison.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from threatlens.correlation import correlate_all
from threatlens.frameworks.attack_tree import build_attack_trees
from threatlens.frameworks.dread import score_threats
from threatlens.frameworks.linddun import assess_privacy
from threatlens.frameworks.pasta import run_pasta
from threatlens.frameworks.stride import analyze_stride
from threatlens.models import Severity

GROUND_TRUTH_DIR = Path(__file__).parent / "ground_truth"
RESULTS_DIR = Path(__file__).parent / "results"


def load_ground_truth(path: Path) -> dict[str, Any]:
    with open(path) as f:
        return json.load(f)


def _run_stride_only(
    description: str,
    tech_stack: list[str] | None,
    components: list[str] | None,
) -> dict[str, Any]:
    """Mode 1: STRIDE analysis only."""
    t0 = time.perf_counter()
    threats = analyze_stride(description, tech_stack, components)
    elapsed = time.perf_counter() - t0

    stride_cats: set[str] = set()
    for t in threats:
        for c in t.stride_categories:
            stride_cats.add(c.value)

    return {
        "mode": "stride_only",
        "elapsed_seconds": round(elapsed, 4),
        "threat_count": len(threats),
        "threats": [
            {
                "id": t.id,
                "title": t.title,
                "description": t.description,
                "severity": t.severity.value,
                "stride_categories": [c.value for c in t.stride_categories],
                "cwe_ids": t.cwe_ids,
                "mitigations": t.mitigations,
            }
            for t in threats
        ],
        "stride_categories_found": sorted(stride_cats),
        "cwe_ids_found": [],
        "mitre_techniques_found": [],
        "linddun_categories_found": [],
        "frameworks_used": ["STRIDE"],
    }


def _run_stride_dread(
    description: str,
    tech_stack: list[str] | None,
    components: list[str] | None,
) -> dict[str, Any]:
    """Mode 2: STRIDE + DREAD scoring."""
    t0 = time.perf_counter()
    threats = analyze_stride(description, tech_stack, components)
    scored = score_threats(threats, description)
    elapsed = time.perf_counter() - t0

    stride_cats: set[str] = set()
    for t in threats:
        for c in t.stride_categories:
            stride_cats.add(c.value)

    return {
        "mode": "stride_dread",
        "elapsed_seconds": round(elapsed, 4),
        "threat_count": len(threats),
        "threats": [
            {
                "id": t.id,
                "title": t.title,
                "description": t.description,
                "severity": t.severity.value,
                "stride_categories": [c.value for c in t.stride_categories],
                "cwe_ids": t.cwe_ids,
                "dread_overall": ds.overall,
                "dread_rating": ds.rating.value,
                "mitigations": t.mitigations,
            }
            for t, ds in scored
        ],
        "stride_categories_found": sorted(stride_cats),
        "cwe_ids_found": [],
        "mitre_techniques_found": [],
        "linddun_categories_found": [],
        "frameworks_used": ["STRIDE", "DREAD"],
    }


def _run_full(
    description: str,
    tech_stack: list[str] | None,
    components: list[str] | None,
) -> dict[str, Any]:
    """Mode 3: Full multi-framework analysis."""
    t0 = time.perf_counter()

    threats = analyze_stride(description, tech_stack, components)
    scored = score_threats(threats, description)
    privacy = assess_privacy(description)
    pasta_stages = run_pasta(description, threats, tech_stack)

    high_threats = [
        t for t in threats if t.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    trees = build_attack_trees(high_threats[:5])
    correlations = correlate_all(threats, description)

    elapsed = time.perf_counter() - t0

    stride_cats: set[str] = set()
    cwe_ids: set[str] = set()
    mitre_techniques: set[str] = set()
    linddun_cats: set[str] = set()

    for c in correlations:
        for s in c.stride:
            stride_cats.add(s.value)
        cwe_ids.update(c.cwe_ids)
        for tech in c.mitre_techniques:
            mitre_techniques.add(tech.split(" ")[0])
        for l in c.linddun:
            linddun_cats.add(l.value)

    for imp in privacy:
        linddun_cats.add(imp.category.value)

    return {
        "mode": "full_threatlens",
        "elapsed_seconds": round(elapsed, 4),
        "threat_count": len(threats),
        "threats": [
            {
                "id": t.id,
                "title": t.title,
                "description": t.description,
                "severity": t.severity.value,
                "stride_categories": [c.value for c in t.stride_categories],
                "cwe_ids": t.cwe_ids,
                "dread_overall": ds.overall,
                "dread_rating": ds.rating.value,
                "mitigations": t.mitigations,
            }
            for t, ds in scored
        ],
        "correlations": [
            {
                "threat_title": c.threat_title,
                "stride": [s.value for s in c.stride],
                "dread_overall": c.dread.overall if c.dread else None,
                "linddun": [l.value for l in c.linddun],
                "cwe_ids": c.cwe_ids,
                "mitre_techniques": c.mitre_techniques,
            }
            for c in correlations
        ],
        "privacy_impacts": [
            {
                "category": imp.category.value,
                "severity": imp.severity.value,
                "description": imp.description,
            }
            for imp in privacy
        ],
        "pasta_stage_count": len(pasta_stages),
        "attack_tree_count": len(trees),
        "stride_categories_found": sorted(stride_cats),
        "cwe_ids_found": sorted(cwe_ids),
        "mitre_techniques_found": sorted(mitre_techniques),
        "linddun_categories_found": sorted(linddun_cats),
        "frameworks_used": ["STRIDE", "DREAD", "LINDDUN", "PASTA", "Attack Trees", "CWE", "MITRE ATT&CK"],
    }


def evaluate_project(gt_path: Path) -> dict[str, Any]:
    """Run all three modes against a single ground truth project."""
    gt = load_ground_truth(gt_path)
    desc = gt["description"]
    tech = gt.get("tech_stack")
    comps = gt.get("components")

    print(f"  Evaluating: {gt['project']}")

    print("    Mode 1: STRIDE only ...", end=" ", flush=True)
    stride_result = _run_stride_only(desc, tech, comps)
    print(f"{stride_result['threat_count']} threats in {stride_result['elapsed_seconds']}s")

    print("    Mode 2: STRIDE + DREAD ...", end=" ", flush=True)
    dread_result = _run_stride_dread(desc, tech, comps)
    print(f"{dread_result['threat_count']} threats in {dread_result['elapsed_seconds']}s")

    print("    Mode 3: Full ThreatLens ...", end=" ", flush=True)
    full_result = _run_full(desc, tech, comps)
    print(f"{full_result['threat_count']} threats in {full_result['elapsed_seconds']}s")

    return {
        "project": gt["project"],
        "ground_truth_vulns": len(gt["vulnerabilities"]),
        "ground_truth": gt["vulnerabilities"],
        "results": {
            "stride_only": stride_result,
            "stride_dread": dread_result,
            "full_threatlens": full_result,
        },
    }


def run_all() -> list[dict[str, Any]]:
    """Evaluate all ground truth projects."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    gt_files = sorted(GROUND_TRUTH_DIR.glob("*.json"))
    if not gt_files:
        raise FileNotFoundError(f"No ground truth files in {GROUND_TRUTH_DIR}")

    print(f"Found {len(gt_files)} ground truth projects\n")
    all_results = []

    for gt_path in gt_files:
        result = evaluate_project(gt_path)
        all_results.append(result)

        out_path = RESULTS_DIR / f"{gt_path.stem}_results.json"
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2)
        print(f"    Saved: {out_path.name}\n")

    combined_path = RESULTS_DIR / "all_results.json"
    with open(combined_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"Combined results saved to {combined_path}")

    return all_results


if __name__ == "__main__":
    run_all()
