# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""PDQC — Pre-Deployment Quality Contracting.

Evaluates AI-generated mobile code against a mobileguard.json quality contract
using the Claude API. Results are appended to an append-only JSONL audit log.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from mobileguard.models import ContractVerdict, Platform

_DEFAULT_CONTRACT_PATH = "mobileguard.json"
_AUDIT_DIR = ".mobileguard/audit"


def load_contract(contract_path: str) -> dict[str, Any]:
    """Load and validate a mobileguard.json quality contract.

    Raises FileNotFoundError with helpful message if the contract is missing.
    """
    path = Path(contract_path)
    if not path.exists():
        raise FileNotFoundError(
            f"No mobileguard.json found at '{contract_path}'.\n"
            "Run 'mobileguard init --platform <ios|android|flutter|react-native>' "
            "to create one."
        )
    try:
        return cast(dict[str, Any], json.loads(path.read_text()))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"mobileguard.json is not valid JSON: {exc}\n"
            "Fix the JSON syntax or run 'mobileguard init' to regenerate."
        ) from exc


def evaluate(
    *,
    target_path: str,
    contract_path: str = _DEFAULT_CONTRACT_PATH,
    stage: str = "code-generation",
    agent_id: str = "unknown-agent",
    platform: str | None = None,
    api_key: str,
) -> ContractVerdict:
    """Evaluate AI-generated code against the quality contract.

    Calls the Claude API (claude-sonnet-4-6) and writes the verdict to the
    append-only audit JSONL log. Returns the ContractVerdict.
    """
    from mobileguard.llm import evaluate_contract
    from mobileguard.scanner import detect_platform

    contract = load_contract(contract_path)

    # Resolve platform
    if platform:
        resolved_platform = Platform(platform)
    elif "platform" in contract:
        resolved_platform = Platform(contract["platform"])
    else:
        resolved_platform = detect_platform(Path(target_path))

    # Read code
    target = Path(target_path)
    if target.is_file():
        code = target.read_text(encoding="utf-8", errors="replace")
        file_path = str(target)
    elif target.is_dir():
        # Concatenate all source files up to 12 000 chars
        parts = []
        for f in sorted(target.rglob("*")):
            exts = {".swift", ".kt", ".dart", ".ts", ".js", ".tsx", ".jsx"}
            if f.is_file() and f.suffix.lower() in exts:
                content = f.read_text(encoding="utf-8", errors="replace")
                parts.append(f"// --- {f.name} ---\n{content}")
                if sum(len(p) for p in parts) > 12_000:
                    break
        code = "\n\n".join(parts)
        file_path = str(target)
    else:
        raise FileNotFoundError(f"Target path not found: {target_path}")

    thresholds = contract.get("thresholds", {})
    stage_overrides = contract.get("stages", {}).get(stage, {})
    effective_thresholds = {**thresholds, **stage_overrides}

    verdict = evaluate_contract(
        code=code,
        file_path=file_path,
        platform=resolved_platform,
        stage=stage,
        agent_id=agent_id,
        thresholds=effective_thresholds,
        api_key=api_key,
    )

    _append_audit_log(verdict)
    return verdict


def _append_audit_log(verdict: ContractVerdict) -> None:
    """Append a ContractVerdict to the append-only JSONL audit log."""
    audit_dir = Path(_AUDIT_DIR)
    audit_dir.mkdir(parents=True, exist_ok=True)

    today = datetime.now(tz=UTC).strftime("%Y-%m-%d")
    log_file = audit_dir / f"mobileguard-{today}.jsonl"

    entry = verdict.model_dump(mode="json")
    with log_file.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
