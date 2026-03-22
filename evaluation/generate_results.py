"""Results generator — produces markdown, CSV, and LaTeX-ready tables.

Reads metrics.json and generates formatted output suitable for
inclusion in a research paper.
"""

from __future__ import annotations

import csv
import json
from io import StringIO
from pathlib import Path
from typing import Any

RESULTS_DIR = Path(__file__).parent / "results"


def _pct(v: float) -> str:
    return f"{v * 100:.1f}%"


def generate_markdown_summary(metrics: dict[str, Any]) -> str:
    """Generate a complete markdown evaluation report."""
    lines: list[str] = []
    lines.append("# ThreatLens Evaluation Results\n")

    agg = metrics["aggregate"]
    n = agg["project_count"]
    lines.append(f"**Projects evaluated:** {n}\n")

    # Per-project comparison table
    lines.append("## Per-Project Results\n")
    lines.append("| Project | GT Vulns | Mode | Detected | Matched | Precision | Recall | F1 |")
    lines.append("|---------|----------|------|----------|---------|-----------|--------|----|")

    for pm in metrics["per_project"]:
        proj = pm["project"]
        gt_count = pm["ground_truth_count"]
        for mode_name in ["stride_only", "stride_dread", "full_threatlens"]:
            m = pm["modes"][mode_name]
            mode_label = {
                "stride_only": "STRIDE",
                "stride_dread": "STRIDE+DREAD",
                "full_threatlens": "**Full ThreatLens**",
            }[mode_name]
            lines.append(
                f"| {proj} | {gt_count} | {mode_label} "
                f"| {m['threats_detected']} | {m['gt_matched']} "
                f"| {_pct(m['precision'])} | {_pct(m['recall'])} "
                f"| {_pct(m['f1'])} |"
            )
    lines.append("")

    # Aggregate comparison
    lines.append("## Aggregate Metrics\n")
    lines.append("| Metric | STRIDE Only | STRIDE+DREAD | Full ThreatLens | Improvement |")
    lines.append("|--------|-------------|--------------|-----------------|-------------|")

    s = agg["modes"]["stride_only"]
    sd = agg["modes"]["stride_dread"]
    f = agg["modes"]["full_threatlens"]
    adv = agg["multi_framework_advantage"]

    lines.append(
        f"| Precision | {_pct(s['aggregate_precision'])} "
        f"| {_pct(sd['aggregate_precision'])} "
        f"| {_pct(f['aggregate_precision'])} | — |"
    )
    lines.append(
        f"| Recall | {_pct(s['aggregate_recall'])} "
        f"| {_pct(sd['aggregate_recall'])} "
        f"| {_pct(f['aggregate_recall'])} "
        f"| +{_pct(adv['recall_improvement'])} |"
    )
    lines.append(
        f"| F1 Score | {_pct(s['aggregate_f1'])} "
        f"| {_pct(sd['aggregate_f1'])} "
        f"| {_pct(f['aggregate_f1'])} "
        f"| +{_pct(adv['f1_improvement'])} |"
    )
    lines.append(
        f"| Mean STRIDE Coverage | {_pct(s['mean_stride_coverage'])} "
        f"| {_pct(sd['mean_stride_coverage'])} "
        f"| {_pct(f['mean_stride_coverage'])} | — |"
    )
    lines.append(
        f"| Mean CWE Coverage | {_pct(s['mean_cwe_coverage'])} "
        f"| {_pct(sd['mean_cwe_coverage'])} "
        f"| {_pct(f['mean_cwe_coverage'])} | — |"
    )
    lines.append(
        f"| Mean LINDDUN Coverage | {_pct(s['mean_linddun_coverage'])} "
        f"| {_pct(sd['mean_linddun_coverage'])} "
        f"| {_pct(f['mean_linddun_coverage'])} | — |"
    )
    lines.append("")

    # Multi-framework advantage
    lines.append("## Multi-Framework Advantage\n")
    lines.append(
        f"- **CWE mappings found:** {adv['extra_cwe_count']} unique CWE IDs "
        f"(0 from STRIDE-only)"
    )
    lines.append(
        f"- **MITRE ATT&CK techniques:** {adv['extra_mitre_count']} unique techniques "
        f"(0 from STRIDE-only)"
    )
    lines.append(
        f"- **LINDDUN categories:** {adv['extra_linddun_count']} privacy threat categories "
        f"(0 from STRIDE-only)"
    )
    lines.append(f"- **Recall improvement:** +{_pct(adv['recall_improvement'])}")
    lines.append(f"- **F1 improvement:** +{_pct(adv['f1_improvement'])}")
    lines.append("")

    # Framework coverage per project
    lines.append("## Framework Coverage by Project\n")
    lines.append("| Project | STRIDE Categories | CWE IDs | MITRE Techniques | LINDDUN Categories |")
    lines.append("|---------|-------------------|---------|------------------|--------------------|")
    for pm in metrics["per_project"]:
        m = pm["modes"]["full_threatlens"]
        lines.append(
            f"| {pm['project']} "
            f"| {_pct(m.get('stride_coverage', 0))} "
            f"| {len(m.get('cwe_ids_found', []))} "
            f"| {len(m.get('mitre_techniques_found', []))} "
            f"| {len(m.get('linddun_categories_found', []))} |"
        )
    lines.append("")

    # Timing
    lines.append("## Performance\n")
    lines.append("| Mode | Total Time (s) |")
    lines.append("|------|---------------|")
    for mode_name, label in [
        ("stride_only", "STRIDE Only"),
        ("stride_dread", "STRIDE+DREAD"),
        ("full_threatlens", "Full ThreatLens"),
    ]:
        t = agg["modes"][mode_name]["total_elapsed_seconds"]
        lines.append(f"| {label} | {t:.3f} |")
    lines.append("")

    return "\n".join(lines)


def generate_csv(metrics: dict[str, Any]) -> str:
    """Generate CSV output for spreadsheet analysis."""
    output = StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Project", "Mode", "GT_Vulns", "Detected", "Matched",
        "Precision", "Recall", "F1",
        "STRIDE_Coverage", "CWE_Coverage", "LINDDUN_Coverage",
        "CWE_Count", "MITRE_Count", "LINDDUN_Count",
        "Elapsed_s",
    ])

    for pm in metrics["per_project"]:
        for mode_name in ["stride_only", "stride_dread", "full_threatlens"]:
            m = pm["modes"][mode_name]
            writer.writerow([
                pm["project"],
                mode_name,
                pm["ground_truth_count"],
                m["threats_detected"],
                m["gt_matched"],
                m["precision"],
                m["recall"],
                m["f1"],
                m["stride_coverage"],
                m["cwe_coverage"],
                m["linddun_coverage"],
                len(m.get("cwe_ids_found", [])),
                len(m.get("mitre_techniques_found", [])),
                len(m.get("linddun_categories_found", [])),
                m["elapsed_seconds"],
            ])

    return output.getvalue()


def generate_latex_tables(metrics: dict[str, Any]) -> str:
    """Generate LaTeX-formatted tables for the paper."""
    lines: list[str] = []

    # Table 1: Aggregate comparison
    lines.append("% Table 1: Aggregate Metrics Comparison")
    lines.append(r"\begin{table}[htbp]")
    lines.append(r"\centering")
    lines.append(r"\caption{Aggregate evaluation metrics across five OWASP projects}")
    lines.append(r"\label{tab:aggregate}")
    lines.append(r"\begin{tabular}{lccc}")
    lines.append(r"\toprule")
    lines.append(r"\textbf{Metric} & \textbf{STRIDE} & \textbf{STRIDE+DREAD} & \textbf{Full ThreatLens} \\")
    lines.append(r"\midrule")

    agg = metrics["aggregate"]["modes"]
    for metric, key in [
        ("Precision", "aggregate_precision"),
        ("Recall", "aggregate_recall"),
        ("F1 Score", "aggregate_f1"),
        ("Mean STRIDE Cov.", "mean_stride_coverage"),
        ("Mean CWE Cov.", "mean_cwe_coverage"),
        ("Mean LINDDUN Cov.", "mean_linddun_coverage"),
    ]:
        s_val = agg["stride_only"][key]
        sd_val = agg["stride_dread"][key]
        f_val = agg["full_threatlens"][key]
        lines.append(
            f"{metric} & {_pct(s_val)} & {_pct(sd_val)} & \\textbf{{{_pct(f_val)}}} \\\\"
        )

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")
    lines.append("")

    # Table 2: Per-project F1 comparison
    lines.append("% Table 2: Per-Project F1 Scores")
    lines.append(r"\begin{table}[htbp]")
    lines.append(r"\centering")
    lines.append(r"\caption{F1 scores per project across analysis modes}")
    lines.append(r"\label{tab:per-project}")
    lines.append(r"\begin{tabular}{lccc}")
    lines.append(r"\toprule")
    lines.append(r"\textbf{Project} & \textbf{STRIDE} & \textbf{STRIDE+DREAD} & \textbf{Full ThreatLens} \\")
    lines.append(r"\midrule")

    for pm in metrics["per_project"]:
        name = pm["project"].replace("OWASP ", "")
        s_f1 = pm["modes"]["stride_only"]["f1"]
        sd_f1 = pm["modes"]["stride_dread"]["f1"]
        f_f1 = pm["modes"]["full_threatlens"]["f1"]
        lines.append(
            f"{name} & {_pct(s_f1)} & {_pct(sd_f1)} & \\textbf{{{_pct(f_f1)}}} \\\\"
        )

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")
    lines.append("")

    # Table 3: Multi-framework unique findings
    lines.append("% Table 3: Multi-Framework Advantage")
    lines.append(r"\begin{table}[htbp]")
    lines.append(r"\centering")
    lines.append(r"\caption{Additional findings from multi-framework analysis}")
    lines.append(r"\label{tab:advantage}")
    lines.append(r"\begin{tabular}{lc}")
    lines.append(r"\toprule")
    lines.append(r"\textbf{Dimension} & \textbf{Count} \\")
    lines.append(r"\midrule")

    adv = metrics["aggregate"]["multi_framework_advantage"]
    lines.append(f"Unique CWE mappings & {adv['extra_cwe_count']} \\\\")
    lines.append(f"MITRE ATT\\&CK techniques & {adv['extra_mitre_count']} \\\\")
    lines.append(f"LINDDUN privacy categories & {adv['extra_linddun_count']} \\\\")
    lines.append(f"Recall improvement & +{_pct(adv['recall_improvement'])} \\\\")
    lines.append(f"F1 improvement & +{_pct(adv['f1_improvement'])} \\\\")

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")

    return "\n".join(lines)


def generate_all() -> None:
    """Generate all output formats from metrics."""
    metrics_path = RESULTS_DIR / "metrics.json"
    if not metrics_path.exists():
        raise FileNotFoundError(
            f"{metrics_path} not found. Run metrics.py first."
        )

    with open(metrics_path) as f:
        metrics = json.load(f)

    md = generate_markdown_summary(metrics)
    md_path = RESULTS_DIR / "evaluation_report.md"
    md_path.write_text(md)
    print(f"Markdown report: {md_path}")

    csv_data = generate_csv(metrics)
    csv_path = RESULTS_DIR / "evaluation_data.csv"
    csv_path.write_text(csv_data)
    print(f"CSV data: {csv_path}")

    latex = generate_latex_tables(metrics)
    latex_path = RESULTS_DIR / "latex_tables.tex"
    latex_path.write_text(latex)
    print(f"LaTeX tables: {latex_path}")


if __name__ == "__main__":
    generate_all()
