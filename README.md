# MobileGuard

> AI governance for consumer mobile platforms.
> Prevents App Store and Google Play rejections caused by AI-generated code.

[![PyPI version](https://img.shields.io/pypi/v/mobileguard.svg)](https://pypi.org/project/mobileguard/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Paper](https://img.shields.io/badge/arXiv-XXXX.XXXXX-b31b1b.svg)](https://arxiv.org/abs/XXXX.XXXXX)
[![CI](https://github.com/jsingh6/mobileguard/actions/workflows/ci.yml/badge.svg)](https://github.com/jsingh6/mobileguard/actions/workflows/ci.yml)

## The Problem

AI coding agents (Claude Code, GitHub Copilot, Cursor, Codex) generate mobile code
with zero awareness of mobile governance constraints:

- **Apple App Store Guideline 5.1.2(i)** — AI data disclosure and consent (Nov 2025)
- **Google Play AI Policy** — data safety declarations for AI features
- **EU AI Act Article 50** — transparency obligations (enforcement: Aug 2, 2026)
- **Binary immutability** — no hotfix without 1–3 day App Store review
- **Ambient AI boundaries** — Siri App Intents, Android AppFunctions permission scopes

72% of AI-generated mobile apps leak secrets. 45% introduce OWASP vulnerabilities.
20 documented incidents exposed tens of millions of users between Jan 2025–Feb 2026.
MobileGuard catches these violations before they reach the store.

## Install

```bash
pip install mobileguard
```

Requires Python 3.11+. The `scan` command works offline with no API key.
The `contract` command requires an Anthropic API key.

## Quick Start

```bash
# Scan your project for governance violations
mobileguard scan ./MyApp

# Generate an EU AI Act compliance report
mobileguard audit ./MyApp --app-name "My App" --version "2.0.0"

# Create a quality contract
mobileguard init --platform ios --bundle-id com.example.myapp

# Evaluate AI-generated code against the contract (requires ANTHROPIC_API_KEY)
mobileguard contract ./GeneratedFeature.swift --stage code-generation --agent claude-code

# Check an AI agent's current autonomy tier
mobileguard tier my-agent-01
```

## Using on a Real Project

### 1. Scan a repo locally

```bash
# Clone any iOS / Android / Flutter app and scan it
git clone https://github.com/some-org/some-app
mobileguard scan ./some-app --platform ios

# Focus on store-blocking issues only
mobileguard scan ./some-app --platform ios --fail-on critical --rules app-store,eu-ai-act

# Export SARIF for the GitHub Security tab
mobileguard scan ./some-app --platform ios --format sarif --output results.sarif
```

### 2. Add to the app's CI pipeline

Add this to the **app repo's** workflow (not MobileGuard's own CI). Pin the version so
governance rules don't silently change between runs.

```yaml
- name: MobileGuard governance scan
  run: |
    pip install mobileguard==1.1.0
    mobileguard scan . --platform ios --fail-on critical --format sarif --output mobileguard.sarif

- name: Upload to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mobileguard.sarif
```

With `--fail-on critical`, the step exits 1 and blocks the PR if any App Store or EU AI Act
critical violation is found. Violations appear inline on the PR diff in the Security tab.

### 3. Pre-release compliance audit

Run before cutting a release branch to generate the formal document for legal or App Store review:

```bash
mobileguard audit ./MyApp \
  --app-name "MyApp" \
  --version "3.2.0" \
  --platform ios \
  --format html \
  --output audit-3.2.0.html
```

Open `audit-3.2.0.html` in a browser and use File → Print → Save as PDF to produce the
compliance document. (PDF export direct from the CLI is planned for v1.2.)

### 4. Evaluate AI-generated code against a contract

```bash
# One-time setup
mobileguard init --platform ios --bundle-id com.example.myapp
export ANTHROPIC_API_KEY=sk-ant-...

# Run after each AI agent produces code
mobileguard contract ./GeneratedFeature.swift --stage code-review --agent claude-code
```

Results are appended to an append-only audit log at `.mobileguard/audit/`. Use
`mobileguard tier <agent-id>` to see how much autonomous authority the agent has earned
based on its history of clean evaluation cycles.

## Supported Platforms

| Platform | Language | Detector |
|---|---|---|
| iOS | Swift | Full |
| Android | Kotlin | Full |
| Flutter | Dart | Full |
| React Native | JavaScript / TypeScript | Full |

## Rule Sets

| Rule Set | Rules | Enforces |
|---|---|---|
| `app-store` | AS-001 to AS-005 | Apple Guideline 5.1.2(i), 4.1(c) |
| `google-play` | GP-001 to GP-005 | Google Play AI Policy, Data Safety |
| `eu-ai-act` | EU-001 to EU-004 | EU AI Act Article 50, 12, 14 |
| `owasp` | OW-001 to OW-005 | OWASP Mobile AI Top 10 |

### App Store Rules (Apple)

| ID | Severity | Description |
|---|---|---|
| AS-001 | CRITICAL | Third-party AI data sharing without 5.1.2(i) disclosure |
| AS-002 | ERROR | Hardcoded AI API key in source code |
| AS-003 | ERROR | App Intent exposes sensitive scope without authorization |
| AS-004 | WARNING | Generic AI-generated privacy description in Info.plist |
| AS-005 | WARNING | Missing NSPrivacyCollectedDataTypes for AI data collection |

### Google Play Rules (Android)

| ID | Severity | Description |
|---|---|---|
| GP-001 | CRITICAL | AI data transmission without DATA_SAFETY declaration |
| GP-002 | ERROR | Hardcoded AI API key in Kotlin source or Gradle |
| GP-003 | ERROR | AppFunction exposes sensitive permissions without declaration |
| GP-004 | WARNING | Ambient AI feature missing biometric/consent flow |
| GP-005 | WARNING | Missing `<queries>` manifest declaration for AI packages |

### EU AI Act Rules

| ID | Severity | Description |
|---|---|---|
| EU-001 | CRITICAL | AI system interacts with users without transparency disclosure (Art. 50) |
| EU-002 | ERROR | Automated AI decision modifies user data without human oversight (Art. 14) |
| EU-003 | WARNING | No logging or audit trail for AI decisions (Art. 12) |
| EU-004 | WARNING | AI feature has no user opt-out mechanism at runtime (Art. 50(2)) |

### OWASP Mobile AI Rules

| ID | Severity | Description |
|---|---|---|
| OW-001 | CRITICAL | Prompt injection — user input interpolated into system prompt |
| OW-002 | ERROR | AI output rendered in WebView without HTML sanitization |
| OW-003 | ERROR | Sensitive PII passed to external AI API without masking |
| OW-004 | WARNING | AI response cached to device storage without encryption |
| OW-005 | WARNING | No rate limiting on AI API calls (denial-of-wallet risk) |

## CLI Reference

### `mobileguard scan`

```
Usage: mobileguard scan [OPTIONS] PATH

  Scan a mobile codebase for governance violations.

Options:
  --platform [ios|android|flutter|react-native|auto]  default: auto
  --rules TEXT           Comma-separated: app-store,google-play,eu-ai-act,owasp
  --severity [critical|error|warning|info]            default: warning
  --format [table|json|sarif|markdown]                default: table
  --output PATH          Write report to file
  --fail-on [critical|error|warning]                  Exit 1 if violations found
  --llm                  Use Claude API for semantic analysis (pattern-only by default)
  --api-key TEXT         Anthropic API key (default: ANTHROPIC_API_KEY env var)
```

### `mobileguard contract`

```
Usage: mobileguard contract [OPTIONS] PATH

  Evaluate AI-generated code against a quality contract (PDQC pillar).

Options:
  --contract PATH        Path to mobileguard.json  [default: ./mobileguard.json]
  --stage [code-generation|test-generation|code-review]  default: code-generation
  --agent TEXT           AI agent identifier
  --platform [ios|android|flutter|react-native]
  --api-key TEXT         Anthropic API key (required)
  --fail-fast            Exit 1 if pipeline should halt
```

### `mobileguard audit`

```
Usage: mobileguard audit [OPTIONS] PATH

  Generate a compliance report (EU AI Act, App Store, Google Play).

Options:
  --format [markdown|json|html]    default: markdown
  --output PATH                    default: mobileguard-audit-report.md
  --platform [ios|android|flutter|react-native|all]
  --app-name TEXT
  --version TEXT
  --include-evidence               Include code snippets as evidence
```

> **PDF export:** Planned for v1.2. For now, convert the HTML output using your
> browser's print-to-PDF (Chrome: File → Print → Save as PDF).

### `mobileguard tier`

```
Usage: mobileguard tier [OPTIONS] AGENT_ID

  Show the current TAC-M autonomy tier for an AI agent.

Options:
  --history PATH    Audit log directory  [default: .mobileguard/audit/]
  --contract PATH   mobileguard.json (optional)
  --cfsr FLOAT      Current crash-free session rate (e.g. 0.997)
```

### `mobileguard init`

```
Usage: mobileguard init [OPTIONS]

  Create a mobileguard.json quality contract.

Options:
  --platform [ios|android|flutter|react-native]  (required)
  --bundle-id TEXT   App bundle identifier
  --app-name TEXT    App display name
  --strict           Stricter thresholds (recommended for finance/health apps)
```

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Pass — no violations at or above threshold |
| 1 | Fail — violations found |
| 2 | Error — bad path, missing API key, or configuration problem |

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/mobileguard.yml
name: MobileGuard

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write

    steps:
      - uses: actions/checkout@v4
      - run: pip install mobileguard
      - name: Scan
        run: |
          mobileguard scan . \
            --format sarif \
            --output mobileguard.sarif \
            --fail-on critical
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: mobileguard.sarif
```

See [`examples/github_actions.yml`](examples/github_actions.yml) for the full workflow.

### Fastlane

```ruby
# Fastfile
lane :governance_check do
  sh "mobileguard scan . --platform ios --fail-on critical"
end

before_all do
  governance_check
end
```

### Xcode Cloud

```bash
#!/bin/bash
# ci_post_clone.sh
pip install mobileguard
mobileguard scan $CI_PRIMARY_REPOSITORY_PATH \
  --platform ios \
  --fail-on critical \
  --format sarif \
  --output mobileguard.sarif
```

## Quality Contract (`mobileguard.json`)

```json
{
  "version": "1.0",
  "platform": "ios",
  "bundle_id": "com.example.myapp",
  "app_name": "My App",
  "thresholds": {
    "min_score": 0.80,
    "max_critical_violations": 0,
    "max_error_violations": 2,
    "min_regression_coverage": 0.80,
    "min_crash_free_session_rate": 0.997
  },
  "stages": {
    "code-generation": { "min_score": 0.70, "halt_on_critical": true },
    "test-generation":  { "min_score": 0.75, "halt_on_critical": true },
    "code-review":      { "min_score": 0.85, "halt_on_critical": true }
  },
  "rules": {
    "enabled": ["app-store", "google-play", "eu-ai-act", "owasp"],
    "disabled": []
  }
}
```

Generate with: `mobileguard init --platform ios --bundle-id com.example.myapp`

## TAC-M Autonomy Tiers

| Tier | Label | Clean Cycles Required | Max Deployment Reach |
|---|---|---|---|
| L1 | Autocomplete only | 0 | 0% |
| L2 | Draft for review | 1 | 100% (human-reviewed) |
| L3 | Conditional autonomous | 5 | 10% |
| L4 | Supervised deployment | 10 | 50% |
| L5 | Full autonomous | 20 | 100% |

Check an agent's tier: `mobileguard tier my-agent-01 --cfsr 0.997`

## Privacy

MobileGuard does not collect telemetry, send analytics, or phone home.
All analysis is performed locally. The only outbound network calls are to
the Anthropic API when `--llm` is passed to `scan`, or when running `contract`.
API responses are never logged.

## The Research

MobileGuard is the reference implementation of:

> **"MobileGuard: A Stack-Agnostic Governance Framework for Agentic AI
> Across Consumer Mobile Delivery Platforms"**
> Jaspreet Singh · [arXiv:XXXX.XXXXX](https://arxiv.org/abs/XXXX.XXXXX) · 2026

### Four Governance Pillars

| Pillar | Command | Problem Addressed |
|---|---|---|
| **PDQC** — Pre-Deployment Quality Contracting | `mobileguard contract` | Binary immutability (no hotfix without store review) |
| **TAC-M** — Tiered Autonomy Calibration | `mobileguard tier` | Consumer-scale blast radius of AI agents |
| **PGSG** — Platform Gatekeeper Simulation | `mobileguard scan` | Dual-gatekeeper non-determinism (App Store + Play Store) |
| **AABE** — Ambient Agent Boundary Enforcement | `mobileguard scan` | Siri App Intents, Android AppFunctions permission scopes |

## Citation

```bibtex
@article{singh2026mobileguard,
  title   = {{MobileGuard}: A Stack-Agnostic Governance Framework for Agentic {AI}
             Across Consumer Mobile Delivery Platforms},
  author  = {Singh, Jaspreet},
  journal = {arXiv preprint arXiv:XXXX.XXXXX},
  year    = {2026},
  url     = {https://arxiv.org/abs/XXXX.XXXXX}
}
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Every contribution must be traceable to
one of the four governance pillars. Rule IDs are stable and cannot be renumbered.

## License

[Apache 2.0](LICENSE) © 2026 Jaspreet Singh
