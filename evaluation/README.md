# ThreatPrism Evaluation Framework

Reproducible evaluation pipeline comparing single-framework (STRIDE-only) vs multi-framework (Full ThreatPrism) threat analysis against known-vulnerable OWASP projects.

## Quick Start

```bash
# Run the full pipeline
cd evaluation
uv run python eval_runner.py   # Run analysis against all projects
uv run python metrics.py       # Compute precision/recall/F1
uv run python generate_results.py  # Generate markdown, CSV, LaTeX
```

## Ground Truth

Five OWASP projects with manually catalogued vulnerabilities:

| Project | Vulns | Source |
|---------|-------|--------|
| Juice Shop | 13 | OWASP project docs |
| WebGoat | 11 | OWASP project docs |
| DVWA | 11 | GitHub + CVE databases |
| NodeGoat | 11 | OWASP project docs |
| RailsGoat | 11 | OWASP project docs |

Each ground truth file includes vulnerability name, CWE IDs, STRIDE categories, severity, affected component, and (where applicable) LINDDUN categories.

## Analysis Modes

1. **STRIDE Only** — `analyze_stride()` alone
2. **STRIDE + DREAD** — adds quantitative scoring
3. **Full ThreatPrism** — all frameworks + CWE/MITRE/LINDDUN correlation

## Output

- `results/evaluation_report.md` — Markdown summary
- `results/evaluation_data.csv` — Spreadsheet-ready data
- `results/latex_tables.tex` — LaTeX tables for the paper
- `results/metrics.json` — Full structured metrics
