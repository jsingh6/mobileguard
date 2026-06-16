# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Anthropic API client for MobileGuard contract evaluation.

Used only by `mobileguard contract` (and `mobileguard scan --llm`).
The `mobileguard scan` command is pattern-only by default and does not
call this module. No telemetry, usage tracking, or data logging occurs here.
"""

from __future__ import annotations

import json
import time
from typing import Any

import anthropic

from mobileguard.models import ContractVerdict, Finding, Platform, RuleCategory, Severity

_MODEL = "claude-sonnet-4-6"
_MAX_RETRIES = 3
_BACKOFF_BASE = 2.0

_PLATFORM_INVARIANTS = {
    Platform.IOS: """
- No synchronous URLSession calls on the main thread (use async/await or background queue)
- All interactive UI elements must have accessibilityLabel
- Memory footprint: avoid retaining large model outputs in memory; stream and discard
- Entitlements: every capability used must be declared in the .entitlements file
- AI-generated UI text must be wrapped in NSLocalizedString for localization
""",
    Platform.ANDROID: """
- No network calls on the main thread (StrictMode will crash in debug builds)
- ANR risk: all AI API calls must be on a background coroutine or WorkManager job
- Declare all permissions used by AI features in AndroidManifest.xml
- Enable ProGuard/R8 rules for any AI SDK classes to prevent stripping
- AI-generated text must go through string resource pipeline for localization
""",
    Platform.FLUTTER: """
- Platform channel calls must not be made from a background Isolate
- Heavy AI inference should use compute() to avoid jank on UI thread
- Jank threshold: no frame should take > 16ms; AI-triggered rebuilds must be async
- Use permission_handler before accessing any device capability for AI features
- Dart Isolates cannot share memory; pass AI results via SendPort, not global state
""",
    Platform.REACT_NATIVE: """
- Native module calls are async; never block the JS thread waiting for AI response
- Bridge call frequency: batch AI-triggered state updates to avoid bridge saturation
- Native modules must be thread-safe if called from multiple async contexts
- Use ErrorBoundary components around any UI that renders AI-generated content
- Expo modules: declare permissions in app.json before using them in AI features
""",
}

_CONTRACT_PROMPT = """You are a mobile AI governance expert evaluating AI-generated code
against a MobileGuard quality contract. Analyze the provided code strictly and return
a JSON object matching the schema below.

Platform: {platform}
Stage: {stage}
Agent: {agent_id}
Contract thresholds: {thresholds}

Platform-specific invariants to check:
{invariants}

Code to evaluate:
```
{code}
```

Evaluate across four dimensions:
1. Output consistency (0-1): Would this code produce consistent behavior across runs?
   Check for: non-deterministic logic, race conditions, unguarded async calls.
2. Platform behavioral invariants (0-1): Does the code respect platform constraints listed above?
3. Regression surface coverage (0-1): What fraction of UI states/paths does this code cover?
   Estimate based on visible branching, error handling, and edge case coverage.
4. Security (0-1): Injection risks, insecure storage, network security, auth bypass, data leakage.

Overall score = weighted average: consistency×0.25 + invariants×0.35 + coverage×0.15 + security×0.25

Return ONLY valid JSON in this exact schema (no markdown, no explanation):
{{
  "score": <float 0.0-1.0>,
  "outcome": "<PASS|WARNING|FAIL>",
  "halt_pipeline": <bool>,
  "human_override_required": <bool>,
  "recommendation": "<one actionable sentence>",
  "findings": [
    {{
      "rule_id": "<pillar>-LLM-<n>",
      "severity": "<critical|error|warning|info>",
      "category": "<app-store|google-play|eu-ai-act|owasp>",
      "description": "<specific issue found>",
      "file_path": "<file path or 'evaluated-code'>",
      "line_number": <int or null>,
      "column": null,
      "evidence": "<relevant code snippet>",
      "fix": "<actionable fix>",
      "reference": null,
      "pillar": "<PDQC|TACM|PGSG|AABE>"
    }}
  ]
}}

Rules for outcome:
- PASS: score >= min_score and no critical findings
- WARNING: score >= min_score but has warnings, or score slightly below min_score
- FAIL: score < min_score - 0.1, or any critical finding, or platform invariant violated

halt_pipeline = true when outcome is FAIL and stage is code-generation or test-generation
human_override_required = true when halt_pipeline is true
"""


def evaluate_contract(
    *,
    code: str,
    file_path: str,
    platform: Platform,
    stage: str,
    agent_id: str,
    thresholds: dict[str, Any],
    api_key: str,
) -> ContractVerdict:
    """Call Claude API to evaluate code against a quality contract.

    Retries up to _MAX_RETRIES times on rate limit (429) responses with
    exponential backoff. Returns a ContractVerdict on success or raises
    on unrecoverable error.
    """
    from datetime import datetime, timezone

    client = anthropic.Anthropic(api_key=api_key)
    prompt = _CONTRACT_PROMPT.format(
        platform=platform.value,
        stage=stage,
        agent_id=agent_id,
        thresholds=json.dumps(thresholds, indent=2),
        invariants=_PLATFORM_INVARIANTS.get(platform, ""),
        code=code[:8000],  # keep within context; truncate large files
    )

    last_error: Exception | None = None
    for attempt in range(_MAX_RETRIES):
        try:
            response = client.messages.create(
                model=_MODEL,
                max_tokens=2048,
                temperature=0.1,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = response.content[0].text.strip()
            data = json.loads(raw)
            break
        except anthropic.RateLimitError as exc:
            last_error = exc
            wait = _BACKOFF_BASE ** attempt
            time.sleep(wait)
        except (json.JSONDecodeError, KeyError, IndexError) as exc:
            last_error = exc
            break
    else:
        raise RuntimeError(
            f"Claude API unavailable after {_MAX_RETRIES} retries: {last_error}"
        ) from last_error

    if last_error and not isinstance(last_error, anthropic.RateLimitError):
        raise RuntimeError(
            f"Failed to parse Claude response: {last_error}. "
            "Check that the API returned valid JSON."
        ) from last_error

    raw_findings = data.get("findings", [])
    findings = []
    for f in raw_findings:
        try:
            findings.append(
                Finding(
                    rule_id=f.get("rule_id", "LLM-000"),
                    severity=Severity(f.get("severity", "warning")),
                    category=RuleCategory(f.get("category", "owasp")),
                    description=f.get("description", ""),
                    file_path=f.get("file_path", file_path),
                    line_number=f.get("line_number"),
                    column=f.get("column"),
                    evidence=f.get("evidence"),
                    fix=f.get("fix", ""),
                    reference=f.get("reference"),
                    pillar=f.get("pillar", "PDQC"),
                )
            )
        except (ValueError, KeyError):
            continue

    outcome = data.get("outcome", "WARNING")
    score = float(data.get("score", 0.5))
    halt = bool(data.get("halt_pipeline", False))

    return ContractVerdict(
        stage=stage,
        agent_id=agent_id,
        platform=platform,
        score=score,
        outcome=outcome,
        findings=findings,
        halt_pipeline=halt,
        human_override_required=bool(data.get("human_override_required", halt)),
        recommendation=data.get("recommendation", "Review findings before proceeding."),
        timestamp=datetime.now(tz=timezone.utc),
    )
