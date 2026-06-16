# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""AS-006: PrivacyInfo.xcprivacy mismatch detector.

Real rejection evidence:
"Privacy Manifests are the sneakiest blocker. Now every third-party library
bundled in your app needs it. Miss one, and you're rejected before a human
even looks at your app." — OpenSpace Services, May 2026

"The bar is higher in 2026. New AI consent rules (November 2025) and a mandatory
Xcode 26 SDK requirement (April 2026) have added new hard stops to the review
process." — OpenSpace Services, April 2026

Apple Guideline reference: 5.1.2(i) — November 2025 update
"If your app shares personal data with third-party AI services, you must
explicitly disclose the AI provider and obtain explicit user consent before
any data transmission."
"""

from __future__ import annotations

import plistlib
import re
from pathlib import Path

from mobileguard.models import Finding
from mobileguard.rules.app_store import RULES as APP_STORE_RULES

# All known AI API domains — extended set beyond the core detector
_AI_DOMAIN = re.compile(
    r"https?://(?P<domain>"
    r"api\.openai\.com|api\.anthropic\.com|"
    r"generativelanguage\.googleapis\.com|[\w\-]+\.openai\.azure\.com|"
    r"api\.cohere\.ai|api\.mistral\.ai|api\.groq\.com|api\.together\.xyz|"
    r"api\.perplexity\.ai|openrouter\.ai|api\.replicate\.com|"
    r"bedrock\.[\w\-]+\.amazonaws\.com|[\w\-]+\.cognitiveservices\.azure\.com)",
    re.IGNORECASE,
)

_SKIP_DIRS = {
    "Pods", "node_modules", ".build", "DerivedData", "Packages",
    ".git", ".github", ".mobileguard", "build", "dist", ".gradle", "__pycache__",
}

_SOURCE_EXTS = {".swift", ".kt", ".kts", ".ts", ".tsx", ".js", ".jsx", ".dart"}


def check_privacy_manifest(root: Path) -> list[Finding]:
    """Cross-reference AI API calls in source against PrivacyInfo.xcprivacy.

    Returns AS-006 findings for:
    - Each AI domain called in source that is absent from NSPrivacyTrackingDomains
    - No PrivacyInfo.xcprivacy at all when AI API calls are present
    """
    rule = APP_STORE_RULES["AS-006"]

    # Step 1 — collect AI domains used in source (first occurrence per domain)
    used_domains: dict[str, tuple[str, int]] = {}
    for f in root.rglob("*"):
        if not f.is_file():
            continue
        if any(part in _SKIP_DIRS for part in f.parts):
            continue
        if f.suffix.lower() not in _SOURCE_EXTS:
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(content.splitlines(), start=1):
            m = _AI_DOMAIN.search(line)
            if m:
                domain = m.group("domain").lower()
                if domain not in used_domains:
                    rel = str(f.relative_to(root))
                    used_domains[domain] = (rel, i)

    if not used_domains:
        return []

    # Step 2 — locate PrivacyInfo.xcprivacy (skip skip-dirs)
    privacy_info: Path | None = None
    for candidate in root.rglob("PrivacyInfo.xcprivacy"):
        if any(part in _SKIP_DIRS for part in candidate.parts):
            continue
        privacy_info = candidate
        break

    findings: list[Finding] = []

    # Step 3 — no manifest at all
    if privacy_info is None:
        for domain, (file_path, line_num) in used_domains.items():
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    category=rule.category,
                    description=rule.description,
                    file_path=file_path,
                    line_number=line_num,
                    evidence=(
                        f"AI API call to {domain} detected but no "
                        "PrivacyInfo.xcprivacy found in project"
                    ),
                    fix=rule.fix,
                    reference=rule.reference,
                    pillar=rule.pillar,
                )
            )
        return findings

    # Step 4 — parse manifest
    try:
        plist_data = plistlib.loads(privacy_info.read_bytes())
    except Exception:
        for domain, (_file_path, _line_num) in used_domains.items():
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    category=rule.category,
                    description=rule.description,
                    file_path=str(privacy_info.relative_to(root)),
                    line_number=None,
                    evidence=f"PrivacyInfo.xcprivacy could not be parsed (domain: {domain})",
                    fix=rule.fix,
                    reference=rule.reference,
                    pillar=rule.pillar,
                )
            )
        return findings

    # NSPrivacyTrackingDomains: list of declared external domains
    declared: set[str] = {
        d.lower()
        for d in plist_data.get("NSPrivacyTrackingDomains", [])
        if isinstance(d, str)
    }

    # Step 5 — flag undeclared AI domains
    for domain, (file_path, line_num) in used_domains.items():
        if domain in declared:
            continue
        findings.append(
            Finding(
                rule_id=rule.id,
                severity=rule.severity,
                category=rule.category,
                description=rule.description,
                file_path=file_path,
                line_number=line_num,
                evidence=(
                    f"AI API call to {domain} detected but not declared in "
                    "PrivacyInfo.xcprivacy (NSPrivacyTrackingDomains)"
                ),
                fix=rule.fix,
                reference=rule.reference,
                pillar=rule.pillar,
            )
        )

    return findings
