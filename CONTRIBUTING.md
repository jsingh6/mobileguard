# Contributing to MobileGuard

Thank you for your interest in contributing to MobileGuard. This tool is the reference
implementation of the MobileGuard governance framework for agentic AI on consumer mobile
platforms. Every contribution should be traceable to one of the four governance pillars:
**PDQC**, **TAC-M**, **PGSG**, or **AABE**.

## Getting Started

```bash
git clone https://github.com/jsingh6/mobileguard
cd mobileguard
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests/ -v
ruff check mobileguard/
mypy mobileguard/
bandit -r mobileguard/
```

All four checks must pass before submitting a PR. CI enforces them automatically.

## Adding a New Rule

1. Choose the appropriate rule module in `mobileguard/rules/` (app_store, google_play,
   eu_ai_act, or owasp_mobile).
2. Add your rule to the `RULES` dict with a stable ID (e.g., `AS-006`). Rule IDs are
   permanent — they will be cited in research papers and cannot be renumbered.
3. Implement the detection pattern in the appropriate detector(s) under `mobileguard/detectors/`.
4. Add a test fixture file under `tests/fixtures/<platform>/` that contains the violation.
5. Add a test case in `tests/test_rules.py` that verifies your detector finds the violation
   in the fixture.
6. Update `README.md` to document the new rule in the Rule Sets table.

## Rule ID Stability

Rule IDs (`AS-001`, `GP-001`, `EU-001`, `OW-001`, etc.) are **permanent and stable**.
They appear in the research paper, in SARIF output uploaded to GitHub Security, and in
audit logs that teams retain for compliance. Never renumber or reuse a rule ID.
If a rule is retired, mark it `deprecated: true` in the RULES dict — do not delete it.

## Adding a New Platform Detector

1. Create `mobileguard/detectors/<language>.py`.
2. Implement a `detect(file_path: str, content: str) -> list[Finding]` function.
3. Register the detector in `mobileguard/scanner.py` under the appropriate platform and
   file extension.
4. Add fixture files and tests.

## Code Style

- Python 3.11+, type hints on all public functions
- Docstrings on all public functions (one-line summary)
- No TODOs in committed code
- Apache 2.0 license header in every new source file
- Line length: 100 characters (enforced by ruff)

## Pull Request Guidelines

- One logical change per PR
- Title format: `feat(pillar): description` or `fix(rule-id): description`
  - Example: `feat(pgsg): add AS-006 rule for on-device model disclosure`
  - Example: `fix(AS-002): improve key pattern to avoid false positives`
- Include a test that fails before your change and passes after
- Update RULES dict and README if adding or modifying rules

## No Telemetry Policy

MobileGuard does not and must not collect usage data, send analytics, or phone home.
Any PR that adds network calls to non-AI-target endpoints will be rejected.

## License

By contributing, you agree that your contributions will be licensed under Apache 2.0,
consistent with the project license.
