"""Metrics computation — precision, recall, F1, and coverage analysis.

Compares ThreatPrism output against ground truth using CWE overlap
and STRIDE category matching to produce per-project and aggregate
evaluation metrics.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

RESULTS_DIR = Path(__file__).parent / "results"


def _normalise_cwe(cwe: str) -> str:
    """Normalise CWE ID to 'CWE-NNN' form."""
    cwe = cwe.strip().upper()
    if not cwe.startswith("CWE-"):
        cwe = f"CWE-{cwe}"
    return cwe


def _extract_gt_cwe_set(gt_vulns: list[dict]) -> set[str]:
    cwe_set: set[str] = set()
    for v in gt_vulns:
        for cwe in v.get("cwe_ids", []):
            cwe_set.add(_normalise_cwe(cwe))
    return cwe_set


def _extract_gt_stride_set(gt_vulns: list[dict]) -> set[str]:
    cats: set[str] = set()
    for v in gt_vulns:
        for c in v.get("stride_categories", []):
            cats.add(c)
    return cats


def _extract_gt_linddun_set(gt_vulns: list[dict]) -> set[str]:
    cats: set[str] = set()
    for v in gt_vulns:
        for c in v.get("linddun_categories", []):
            cats.add(c)
    return cats


def _match_threats(
    gt_vulns: list[dict],
    detected_threats: list[dict],
    correlations: list[dict] | None = None,
) -> dict[str, Any]:
    """Match detected threats to ground truth via multiple signals.

    Matching criteria (any one is sufficient within shared STRIDE category):
    1. Keyword overlap (>= 2 meaningful shared words)
    2. CWE ID overlap (if correlation data available)
    """
    gt_matched: set[int] = set()
    det_matched: set[int] = set()

    corr_cwe_map: dict[str, set[str]] = {}
    if correlations:
        for c in correlations:
            title = c.get("threat_title", "")
            corr_cwe_map[title] = {_normalise_cwe(cid) for cid in c.get("cwe_ids", [])}

    for gi, gv in enumerate(gt_vulns):
        gt_keywords = set(gv["name"].lower().split()) | set(
            gv.get("description", "").lower().split()
        )
        gt_stride = set(gv.get("stride_categories", []))
        gt_cwes = {_normalise_cwe(c) for c in gv.get("cwe_ids", [])}

        for di, dt in enumerate(detected_threats):
            det_stride = set(dt.get("stride_categories", []))
            if not gt_stride & det_stride:
                continue

            # Signal 1: keyword overlap
            det_keywords = set(dt["title"].lower().split()) | set(
                dt.get("description", "").lower().split()
            )
            overlap = gt_keywords & det_keywords
            meaningful = overlap - {
                "the",
                "a",
                "an",
                "in",
                "on",
                "of",
                "to",
                "for",
                "and",
                "or",
                "is",
                "are",
                "with",
                "from",
                "by",
                "via",
                "can",
                "that",
                "this",
                "be",
                "at",
                "it",
                "as",
                "no",
                "not",
            }
            keyword_match = len(meaningful) >= 2

            # Signal 2: CWE overlap from correlation data
            det_cwes = corr_cwe_map.get(dt.get("title", ""), set())
            cwe_match = bool(gt_cwes & det_cwes)

            if keyword_match or cwe_match:
                gt_matched.add(gi)
                det_matched.add(di)

    return {
        "gt_matched_indices": sorted(gt_matched),
        "det_matched_indices": sorted(det_matched),
        "gt_matched_count": len(gt_matched),
        "det_matched_count": len(det_matched),
    }


def compute_project_metrics(project_result: dict[str, Any]) -> dict[str, Any]:
    """Compute precision, recall, F1 for each mode of a single project."""
    gt_vulns = project_result["ground_truth"]
    gt_total = len(gt_vulns)
    gt_cwes = _extract_gt_cwe_set(gt_vulns)
    gt_stride = _extract_gt_stride_set(gt_vulns)
    gt_linddun = _extract_gt_linddun_set(gt_vulns)

    mode_metrics: dict[str, Any] = {}

    for mode_name, mode_result in project_result["results"].items():
        detected = mode_result["threats"]
        det_total = len(detected)

        correlations = mode_result.get("correlations")
        match_info = _match_threats(gt_vulns, detected, correlations)

        recall = match_info["gt_matched_count"] / gt_total if gt_total > 0 else 0.0
        precision = (
            match_info["det_matched_count"] / det_total if det_total > 0 else 0.0
        )
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        det_stride = set(mode_result.get("stride_categories_found", []))
        det_cwes = {_normalise_cwe(c) for c in mode_result.get("cwe_ids_found", [])}
        det_linddun = set(mode_result.get("linddun_categories_found", []))
        det_mitre = set(mode_result.get("mitre_techniques_found", []))

        stride_coverage = (
            len(gt_stride & det_stride) / len(gt_stride) if gt_stride else 0.0
        )
        cwe_coverage = len(gt_cwes & det_cwes) / len(gt_cwes) if gt_cwes else 0.0
        linddun_coverage = (
            len(gt_linddun & det_linddun) / len(gt_linddun) if gt_linddun else 0.0
        )

        mode_metrics[mode_name] = {
            "threats_detected": det_total,
            "gt_matched": match_info["gt_matched_count"],
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "stride_coverage": round(stride_coverage, 4),
            "cwe_coverage": round(cwe_coverage, 4),
            "linddun_coverage": round(linddun_coverage, 4),
            "cwe_ids_found": sorted(det_cwes),
            "mitre_techniques_found": sorted(det_mitre),
            "linddun_categories_found": sorted(det_linddun),
            "frameworks_used": mode_result.get("frameworks_used", []),
            "elapsed_seconds": mode_result.get("elapsed_seconds", 0),
        }

    return {
        "project": project_result["project"],
        "ground_truth_count": gt_total,
        "ground_truth_cwes": sorted(gt_cwes),
        "ground_truth_stride": sorted(gt_stride),
        "ground_truth_linddun": sorted(gt_linddun),
        "modes": mode_metrics,
    }


def compute_aggregate(project_metrics: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute aggregate metrics across all projects."""
    modes = ["stride_only", "stride_dread", "full_threatprism"]
    aggregate: dict[str, Any] = {}

    for mode in modes:
        total_gt = 0
        total_matched = 0
        total_detected = 0
        total_det_matched = 0
        f1_sum = 0.0
        stride_cov_sum = 0.0
        cwe_cov_sum = 0.0
        linddun_cov_sum = 0.0
        all_cwes: set[str] = set()
        all_mitre: set[str] = set()
        all_linddun: set[str] = set()
        elapsed_sum = 0.0
        n = len(project_metrics)

        for pm in project_metrics:
            m = pm["modes"][mode]
            total_gt += pm["ground_truth_count"]
            total_matched += m["gt_matched"]
            total_detected += m["threats_detected"]
            total_det_matched += min(m["gt_matched"], m["threats_detected"])
            f1_sum += m["f1"]
            stride_cov_sum += m["stride_coverage"]
            cwe_cov_sum += m["cwe_coverage"]
            linddun_cov_sum += m["linddun_coverage"]
            all_cwes.update(m.get("cwe_ids_found", []))
            all_mitre.update(m.get("mitre_techniques_found", []))
            all_linddun.update(m.get("linddun_categories_found", []))
            elapsed_sum += m["elapsed_seconds"]

        agg_recall = total_matched / total_gt if total_gt > 0 else 0.0
        agg_precision = (
            total_det_matched / total_detected if total_detected > 0 else 0.0
        )
        agg_f1 = (
            2 * agg_precision * agg_recall / (agg_precision + agg_recall)
            if (agg_precision + agg_recall) > 0
            else 0.0
        )

        aggregate[mode] = {
            "total_gt_vulns": total_gt,
            "total_threats_detected": total_detected,
            "total_gt_matched": total_matched,
            "aggregate_precision": round(agg_precision, 4),
            "aggregate_recall": round(agg_recall, 4),
            "aggregate_f1": round(agg_f1, 4),
            "mean_f1": round(f1_sum / n, 4) if n > 0 else 0.0,
            "mean_stride_coverage": round(stride_cov_sum / n, 4) if n > 0 else 0.0,
            "mean_cwe_coverage": round(cwe_cov_sum / n, 4) if n > 0 else 0.0,
            "mean_linddun_coverage": round(linddun_cov_sum / n, 4) if n > 0 else 0.0,
            "unique_cwes_found": len(all_cwes),
            "unique_mitre_found": len(all_mitre),
            "unique_linddun_found": len(all_linddun),
            "total_elapsed_seconds": round(elapsed_sum, 4),
        }

    multi_only = {
        "extra_cwe_count": aggregate["full_threatprism"]["unique_cwes_found"],
        "extra_mitre_count": aggregate["full_threatprism"]["unique_mitre_found"],
        "extra_linddun_count": aggregate["full_threatprism"]["unique_linddun_found"],
        "recall_improvement": round(
            aggregate["full_threatprism"]["aggregate_recall"]
            - aggregate["stride_only"]["aggregate_recall"],
            4,
        ),
        "f1_improvement": round(
            aggregate["full_threatprism"]["aggregate_f1"]
            - aggregate["stride_only"]["aggregate_f1"],
            4,
        ),
    }

    return {
        "project_count": len(project_metrics),
        "modes": aggregate,
        "multi_framework_advantage": multi_only,
    }


def run_metrics() -> dict[str, Any]:
    """Load results, compute metrics, and save."""
    results_path = RESULTS_DIR / "all_results.json"
    if not results_path.exists():
        raise FileNotFoundError(f"{results_path} not found. Run eval_runner.py first.")

    with open(results_path) as f:
        all_results = json.load(f)

    project_metrics = [compute_project_metrics(r) for r in all_results]
    aggregate = compute_aggregate(project_metrics)

    output = {
        "per_project": project_metrics,
        "aggregate": aggregate,
    }

    metrics_path = RESULTS_DIR / "metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"Metrics saved to {metrics_path}")

    return output


if __name__ == "__main__":
    run_metrics()
