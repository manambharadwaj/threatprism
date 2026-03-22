# Contributing to ThreatLens

Thanks for your interest in contributing! This guide covers everything you need to get started.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/manambharadwaj/threatlens.git
cd threatlens

# Install uv (if you don't have it)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies (including dev tools)
uv sync --all-extras

# Verify everything works
uv run pytest -q
uv run ruff check .
uv run pyright
```

## Making Changes

1. **Fork** the repository and create a branch from `master`
2. **Write code** — follow the existing style (ruff handles formatting)
3. **Add tests** for any new functionality in `tests/`
4. **Run the full check suite** before committing:

```bash
uv run pytest -q          # Tests pass
uv run ruff check .       # Lint clean
uv run pyright            # Types clean
```

## Project Structure

```
src/threatlens/
├── __init__.py          # Package entry point and CLI
├── server.py            # MCP server and tool definitions
├── models.py            # Pydantic models (Threat, DreadScore, etc.)
├── correlation.py       # Cross-framework correlation engine
├── reports.py           # Markdown report generation
└── frameworks/
    ├── stride.py        # STRIDE analysis engine
    ├── dread.py         # DREAD risk scoring
    ├── linddun.py       # LINDDUN privacy analysis
    ├── pasta.py         # PASTA threat modeling
    └── attack_tree.py   # Attack tree decomposition
```

## What to Contribute

**Good first issues:**
- Improve keyword heuristics in LINDDUN/PASTA detection
- Add new CWE mappings for under-covered threat categories
- Expand MITRE ATT&CK technique coverage
- Improve test coverage for edge cases

**Larger contributions:**
- SARIF output format for CI/CD integration
- Architecture diagram parsing (Mermaid/PlantUML)
- New analysis frameworks
- Performance optimizations

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Include tests for new functionality
- Ensure all three checks pass (pytest, ruff, pyright)
- Write a clear PR description explaining *what* and *why*

## Code Style

- Line length: 88 characters
- Python 3.10+ syntax (use `X | Y` union types, not `Union[X, Y]`)
- Type annotations on all public functions
- Pydantic models for data structures

These are enforced by ruff and pyright — just run the checks and fix what they flag.

## Reporting Bugs

Open an issue at [github.com/manambharadwaj/threatlens/issues](https://github.com/manambharadwaj/threatlens/issues) with:
- What you expected vs what happened
- Minimal reproduction steps
- Python version and OS

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
