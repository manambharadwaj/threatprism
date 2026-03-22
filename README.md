# ThreatLens

**Multi-framework threat intelligence for AI coding agents**

[![CI](https://github.com/manambharadwaj/threatlens/actions/workflows/ci.yml/badge.svg)](https://github.com/manambharadwaj/threatlens/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

ThreatLens is an MCP (Model Context Protocol) server that provides **simultaneous threat analysis across four security frameworks** — STRIDE, DREAD, LINDDUN, and PASTA — with automatic cross-referencing to CWE and MITRE ATT&CK.

Unlike single-framework tools, ThreatLens gives you a **multi-dimensional view** of every threat: *what category* (STRIDE), *how severe* (DREAD), *what privacy impact* (LINDDUN), and *what attack process* (PASTA), all correlated in one analysis.

---

## What Makes This Different

| Capability | ThreatLens | Typical Security Tools |
|---|---|---|
| Multi-framework correlation | STRIDE + DREAD + LINDDUN + PASTA in one pass | Usually one framework |
| Quantitative scoring | DREAD 1-10 scores with weighted context | Qualitative High/Med/Low |
| Privacy-first analysis | Built-in LINDDUN engine | Usually separate DPIA tool |
| Attack tree generation | AND/OR decomposition with likelihood | Manual diagramming |
| CWE + MITRE ATT&CK mapping | Automatic cross-reference | Manual lookup |
| AI agent workflow | MCP server with auto-instructions | IDE plugin or CLI |

---

## Tools

### Analysis

| Tool | Framework | Purpose |
|------|-----------|---------|
| `analyze_threat_landscape` | STRIDE | Categorise threats from a system description |
| `score_risks` | DREAD | Quantitative risk scoring (1-10 per dimension) |
| `assess_privacy_impact` | LINDDUN | Privacy threat assessment for personal data |
| `run_pasta_analysis` | PASTA | 7-stage attack simulation process |
| `build_attack_tree` | Attack Trees | AND/OR decomposition of attack paths |

### Cross-Reference

| Tool | Purpose |
|------|---------|
| `correlate_frameworks` | Map threats across STRIDE → DREAD → LINDDUN → CWE → MITRE ATT&CK |
| `map_to_cwe` | Link threats to CWE entries with remediation links |
| `suggest_mitigations` | Prioritised mitigation strategies |

### Documentation

| Tool | Purpose |
|------|---------|
| `generate_threat_report` | Full markdown report combining all frameworks |

---

## Quick Start

### Install

```bash
# Using uv (recommended)
uv pip install .

# Or with pip
pip install .
```

### Run the Server

```bash
# stdio (default — for IDE integration)
threatlens

# HTTP transport (for shared/team use)
threatlens --transport streamable-http --port 8000

# SSE transport
threatlens --transport sse --port 8000
```

---

## IDE Integration

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "threatlens": {
      "command": "threatlens",
      "args": []
    }
  }
}
```

Or with uv (no install required):

```json
{
  "mcpServers": {
    "threatlens": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/threatlens", "threatlens"]
    }
  }
}
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "threatlens": {
      "command": "threatlens",
      "args": []
    }
  }
}
```

### VS Code (GitHub Copilot)

Add to `.vscode/mcp.json`:

```json
{
  "servers": {
    "threatlens": {
      "command": "threatlens",
      "args": []
    }
  }
}
```

### Docker

```bash
docker build -t threatlens:latest .
```

```json
{
  "mcpServers": {
    "threatlens": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "threatlens:latest"]
    }
  }
}
```

---

## Agent Workflow

When an AI agent connects, ThreatLens automatically sends workflow instructions via the MCP handshake. The agent will follow this flow:

```
┌─────────────────────────────┐
│  1. analyze_threat_landscape │  ← STRIDE categorisation
├─────────────────────────────┤
│  2. score_risks              │  ← DREAD quantitative scoring
├─────────────────────────────┤
│  3. assess_privacy_impact    │  ← LINDDUN privacy analysis
├─────────────────────────────┤
│  4. build_attack_tree        │  ← Attack path decomposition
├─────────────────────────────┤
│  5. correlate_frameworks     │  ← Multi-framework mapping
├─────────────────────────────┤
│  6. generate_threat_report   │  ← Comprehensive documentation
└─────────────────────────────┘
```

No manual configuration needed — the agent receives the instructions on connect.

---

## Example Output

### DREAD Score Table

| Threat | D | R | E | A | D | Overall | Rating |
|--------|---|---|---|---|---|---------|--------|
| Authentication Bypass | 8.0 | 7.5 | 7.0 | 8.5 | 6.5 | **7.5** | HIGH |
| Input Manipulation | 9.0 | 6.0 | 6.5 | 7.0 | 5.5 | **6.8** | HIGH |
| Session Hijacking | 7.5 | 6.0 | 5.5 | 7.0 | 5.5 | **6.3** | HIGH |

### Cross-Framework Correlation

| Threat | STRIDE | DREAD | LINDDUN | CWE | MITRE |
|--------|--------|-------|---------|-----|-------|
| Auth Bypass | SPOO | 7.5 | IDEN, NON_ | CWE-287, CWE-290 | T1078, T1110 |
| Data Exposure | INFO | 6.8 | DISC, LINK, IDEN | CWE-200, CWE-312 | T1530, T1567 |

---

## Frameworks

### STRIDE (Threat Categorisation)
Classifies threats into six categories: **S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service, **E**levation of Privilege.

### DREAD (Risk Scoring)
Quantitative scoring on five dimensions (1-10 each): **D**amage, **R**eproducibility, **E**xploitability, **A**ffected Users, **D**iscoverability. Overall score = average.

### LINDDUN (Privacy Threats)
Privacy-specific analysis across seven categories: **L**inkability, **I**dentifiability, **N**on-repudiation, **D**etectability, **D**isclosure, **U**nawareness, **N**on-compliance.

### PASTA (Attack Simulation)
Seven-stage process: Business Objectives → Technical Scope → Decomposition → Threat Analysis → Vulnerability Analysis → Attack Modeling → Risk/Impact Analysis.

---

## Development

```bash
# Install with dev dependencies
uv sync --frozen --all-extras --dev

# Run tests
uv run pytest

# Lint & type-check
uv run ruff check .
uv run pyright
```

---

## License

MIT — see [LICENSE](LICENSE).
