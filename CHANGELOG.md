# Changelog

All notable changes to ThreatLens will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-03-22

### Added

- **STRIDE** threat identification engine with category-based analysis
- **DREAD** quantitative risk scoring (1-10 scale with weighted context)
- **LINDDUN** privacy threat assessment with data type and activity detection
- **PASTA** process-oriented threat modeling with attack simulation
- **Attack tree** decomposition with AND/OR nodes and likelihood estimation
- **CWE** cross-referencing with automatic ID mapping
- **MITRE ATT&CK** technique correlation
- **Cross-framework correlation** engine linking findings across all frameworks
- **Markdown report generation** with comprehensive threat summaries
- MCP server compatible with Claude Desktop, Claude Code, VS Code (Copilot), and Cursor
- Full test suite (35 tests), ruff linting, and pyright type checking
- GitHub Actions CI across Python 3.10–3.13
- Evaluation framework with ground truth for 5 OWASP projects

[0.1.0]: https://github.com/manambharadwaj/threatlens/releases/tag/v0.1.0
