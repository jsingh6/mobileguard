# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""AS-009: Release Notes AI Disclosure Scanner (TAC-M + PGSG pillars).

Scans App Store (iOS) and Google Play (Android) release notes / "What's New"
fields for AI governance signals defined under Apple Guideline 5.1.2(i) and
the MobileGuard AS-009 rule family.

Study 3 of the MobileGuard research paper (DOI: 10.5281/zenodo.20970167)
validated this scanner against 942 real mobile platform apps, finding a 4.0%
governance signal rate including enterprise-scale developers Adobe Inc. and
Moleskine Srl.

Cohort presets:
  ai-native     — 15 AI-related search terms (Cohort 1 in Study 3)
  traditional   — 15 established category terms (Cohort 2 in Study 3)
  social        — social media and messaging apps (Cohort 3 — TAC-M focus)

Rules:
  AS-009-A  CRITICAL  Multiple named AI providers without consent modal update
  AS-009-B  WARNING   AI feature introduced to non-AI user base without disclosure
  AS-009-C  INFO      Training data collection language without opt-out disclosure
  AS-009-D  WARNING   Biometric/behavioral data used by AI without explicit disclosure
  AS-009-F  CRITICAL  Autonomous action without per-action user confirmation (TAC-M)
"""

from __future__ import annotations

import re
import time
import urllib.parse
import urllib.request
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator


# ── First-party exclusions (prevent false positives) ─────────────────────────

_FIRST_PARTY_BUNDLES = {
    "com.anthropic.",
    "com.openai.",
    "com.meta.",
    "com.google.",
    "com.microsoft.",
    "com.apple.",
}

_FIRST_PARTY_NAMES = {
    "claude",
    "chatgpt",
    "gemini",
    "copilot",
    "meta ai",
    "bing",
    "cortana",
}


# ── Cohort search term presets ────────────────────────────────────────────────

COHORT_TERMS: dict[str, list[str]] = {
    "ai-native": [
        "AI assistant", "ChatGPT", "AI writing", "Gemini AI", "Claude AI",
        "AI chat", "AI generator", "GPT", "AI tutor", "AI photo",
        "AI video", "AI music", "AI code", "AI tools", "LLM",
    ],
    "traditional": [
        "photo editor", "notes app", "fitness tracker", "journal app",
        "weather app", "recipe app", "meditation app", "budget tracker",
        "habit tracker", "calendar app", "todo list", "podcast app",
        "news reader", "language learning", "workout tracker",
    ],
    "social": [
        "social media", "messaging app", "chat app", "dating app",
        "video sharing", "photo sharing", "community app", "forum app",
        "live streaming", "short video", "group chat", "voice chat",
        "social network", "content creator", "influencer",
    ],
}


# ── AS-009 rule patterns ──────────────────────────────────────────────────────

# AS-009-A: Multiple named AI providers in one release note
_PROVIDER_NAMES = re.compile(
    r'\b(OpenAI|ChatGPT|GPT-4|GPT-3|Claude|Anthropic|Gemini|Bard|'
    r'Llama|Meta AI|Mistral|Grok|xAI|DeepSeek|Cohere|Perplexity|'
    r'Copilot|Bing AI|Stable Diffusion|DALL-E|Midjourney|Sora)\b',
    re.IGNORECASE,
)

# AS-009-B: AI feature introduced without disclosure
_AI_INTRO_PATTERNS = re.compile(
    r'\b(AI[-\s]powered|powered by AI|new AI|AI feature|'
    r'AI-generated|AI assistant|machine learning|ML model|'
    r'smart suggestions|intelligent|neural network|'
    r'now uses AI|added AI|introducing AI|AI enhancement|'
    r'AI upgrade|AI capability|AI tools)\b',
    re.IGNORECASE,
)

_DISCLOSURE_PATTERNS = re.compile(
    r'\b(on-device|on device|cloud processing|privacy|'
    r'data policy|consent|opt.?out|your data|'
    r'processed locally|no data sent)\b',
    re.IGNORECASE,
)

# AS-009-C: Training data collection
_TRAINING_PATTERNS = re.compile(
    r'\b(improve our (AI|model|service)|train(ing)? (our )?(AI|model)|'
    r'help us improve|feedback (to|for) (improve|train)|'
    r'data (to|for) (train|improve))\b',
    re.IGNORECASE,
)

# AS-009-D: Biometric/behavioral data
_BIOMETRIC_PATTERNS = re.compile(
    r'\b(face (recognition|detection|ID)|voice (recognition|ID|print)|'
    r'fingerprint|biometric|behavioral (data|analysis)|'
    r'eye tracking|emotion (detection|recognition)|'
    r'gait analysis|typing pattern)\b',
    re.IGNORECASE,
)

# AS-009-F: Autonomous actions
_AUTONOMOUS_PATTERNS = re.compile(
    r'\b(automatically (post|send|share|upload|publish|reply|respond|'
    r'submit|schedule|delete|purchase|book|order|pay|sent|shared|posted|uploaded)|'
    r'auto.?(post|send|share|reply|respond|schedule)|'
    r'(post|send|share|upload|publish|reply|replies|response|responses|achievement\w*)'
    r'\s+(are|is|were)\s+automatically|'
    r'on your behalf|for you automatically|without asking|'
    r'background (posting|sending|sharing|uploading)|'
    r'smart (reply|response) (sent|posted) automatically)\b',
    re.IGNORECASE,
)


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class AppRecord:
    """Minimal app metadata from the store API."""
    app_id: str
    name: str
    developer: str
    bundle_id: str
    category: str
    version: str
    release_notes: str
    platform: str
    search_term: str


@dataclass
class ReleasesFinding:
    """A single AS-009 governance signal."""
    rule_id: str
    severity: str          # critical / warning / info
    app_id: str
    app_name: str
    developer: str
    bundle_id: str
    version: str
    category: str
    platform: str
    pillar: str
    description: str
    matched_text: str
    fix: str
    search_term: str
    scanned_at: str = field(default_factory=lambda: datetime.now(tz=__import__('datetime').timezone.utc).isoformat())


@dataclass
class ReleasesScanResult:
    """Aggregated result of a releases scan run."""
    platform: str
    cohort: str
    terms_used: list[str]
    apps_scanned: int
    apps_flagged: int
    findings: list[ReleasesFinding]
    scan_duration_seconds: float
    first_party_excluded: int
    android_null_count: int = 0
    scan_warnings: list[str] = field(default_factory=list)

    @property
    def flag_rate(self) -> float:
        if self.apps_scanned == 0:
            return 0.0
        return self.apps_flagged / self.apps_scanned

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {"critical": 0, "warning": 0, "info": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


# ── iTunes Search API fetcher ─────────────────────────────────────────────────

def _fetch_ios_apps(term: str, limit: int = 50) -> list[AppRecord]:
    """Fetch iOS apps from iTunes Search API for a given search term."""
    params = urllib.parse.urlencode({
        "term": term,
        "entity": "software",
        "limit": min(limit, 200),
        "country": "us",
        "lang": "en_us",
    })
    url = f"https://itunes.apple.com/search?{params}"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "MobileGuard/3.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return []

    records = []
    for item in data.get("results", []):
        release_notes = item.get("releaseNotes", "") or ""
        if not release_notes.strip():
            continue
        records.append(AppRecord(
            app_id=str(item.get("trackId", "")),
            name=item.get("trackName", "Unknown"),
            developer=item.get("artistName", "Unknown"),
            bundle_id=item.get("bundleId", ""),
            category=item.get("primaryGenreName", "Unknown"),
            version=item.get("version", "Unknown"),
            release_notes=release_notes,
            platform="ios",
            search_term=term,
        ))
    return records


def _fetch_android_apps(term: str, limit: int = 50) -> tuple[list[AppRecord], int]:
    """Fetch Android apps via google-play-scraper. Returns (records, null_count)."""
    try:
        from google_play_scraper import search, app as gp_app  # type: ignore
    except ImportError:
        return [], 0

    null_count = 0
    records = []

    try:
        results = search(term, n_hits=min(limit, 30), lang="en", country="us")
    except Exception:
        return [], 0

    for item in results:
        app_id = item.get("appId", "")
        if not app_id:
            continue
        try:
            detail = gp_app(app_id, lang="en", country="us")
            recent_changes = detail.get("recentChanges", "") or ""
            if not recent_changes.strip():
                null_count += 1
                continue
            # Strip HTML tags
            clean = re.sub(r"<[^>]+>", " ", recent_changes).strip()
            if not clean:
                null_count += 1
                continue
            records.append(AppRecord(
                app_id=app_id,
                name=detail.get("title", "Unknown"),
                developer=detail.get("developer", "Unknown"),
                bundle_id=app_id,
                category=detail.get("genre", "Unknown"),
                version=detail.get("version", "Unknown"),
                release_notes=clean,
                platform="android",
                search_term=term,
            ))
            time.sleep(0.3)  # be polite
        except Exception:
            null_count += 1

    return records, null_count


# ── AS-009 rule engine ────────────────────────────────────────────────────────

def _is_first_party(record: AppRecord) -> bool:
    """Return True if this is a first-party AI provider app."""
    bundle = record.bundle_id.lower()
    name = record.name.lower()
    for prefix in _FIRST_PARTY_BUNDLES:
        if bundle.startswith(prefix):
            return True
    for fp_name in _FIRST_PARTY_NAMES:
        if fp_name in name:
            return True
    return False


def _apply_as009_rules(record: AppRecord) -> list[ReleasesFinding]:
    """Apply AS-009-A through AS-009-F rules to a single app record."""
    findings: list[ReleasesFinding] = []
    notes = record.release_notes
    seen_rules: set[str] = set()

    def add(rule_id: str, severity: str, pillar: str, description: str,
            matched: str, fix: str) -> None:
        if rule_id not in seen_rules:
            findings.append(ReleasesFinding(
                rule_id=rule_id,
                severity=severity,
                app_id=record.app_id,
                app_name=record.name,
                developer=record.developer,
                bundle_id=record.bundle_id,
                version=record.version,
                category=record.category,
                platform=record.platform,
                pillar=pillar,
                description=description,
                matched_text=matched[:200],
                fix=fix,
                search_term=record.search_term,
            ))
            seen_rules.add(rule_id)

    # AS-009-A: Multiple named AI providers
    providers_found = _PROVIDER_NAMES.findall(notes)
    unique_providers = list(dict.fromkeys(p.lower() for p in providers_found))
    if len(unique_providers) >= 2:
        add(
            "AS-009-A", "critical", "PGSG",
            f"Multiple named AI providers ({', '.join(unique_providers[:5])}) "
            f"without corresponding consent modal update",
            f"Providers mentioned: {', '.join(unique_providers[:5])}",
            "Update your privacy nutrition label and show a consent modal "
            "for each new AI provider before the feature activates. Each "
            "named provider is a separate disclosure requirement under "
            "Apple Guideline 5.1.2(i).",
        )

    # AS-009-B: AI introduced without disclosure
    ai_match = _AI_INTRO_PATTERNS.search(notes)
    if ai_match and not _DISCLOSURE_PATTERNS.search(notes):
        add(
            "AS-009-B", "warning", "PGSG",
            "AI feature introduced to existing user base without "
            "on/off-device processing disclosure",
            ai_match.group(0),
            "Add disclosure language specifying whether AI processing "
            "is on-device or cloud-based. Existing users did not consent "
            "to AI data flows at install time. Required under Apple "
            "Guideline 5.1.2(i) and EU AI Act Article 13.",
        )

    # AS-009-C: Training data collection
    train_match = _TRAINING_PATTERNS.search(notes)
    if train_match:
        add(
            "AS-009-C", "info", "PGSG",
            "Release notes mention training data collection without "
            "explicit opt-out disclosure",
            train_match.group(0),
            "Add an opt-out mechanism and link to your privacy policy "
            "in the release note. Users must be able to decline "
            "contributing data to model training.",
        )

    # AS-009-D: Biometric/behavioral data
    bio_match = _BIOMETRIC_PATTERNS.search(notes)
    if bio_match:
        add(
            "AS-009-D", "warning", "AABE",
            "Biometric or behavioral data used by AI feature without "
            "explicit consent disclosure",
            bio_match.group(0),
            "Add explicit consent language before collecting biometric "
            "or behavioral data. Show a dedicated consent screen the "
            "first time the feature activates.",
        )

    # AS-009-F: Autonomous action without confirmation (TAC-M)
    auto_match = _AUTONOMOUS_PATTERNS.search(notes)
    if auto_match:
        add(
            "AS-009-F", "critical", "TAC-M",
            "Autonomous action taken on user's behalf without "
            "per-action confirmation — TAC-M blast radius violation",
            auto_match.group(0),
            "Add a per-action confirmation gate before every autonomous "
            "action. 'Automatically post/send/share' patterns require "
            "explicit user approval each time under MobileGuard TAC-M "
            "and Apple Guideline 5.1.2(i). Binary immutability means "
            "you cannot patch this after release.",
        )

    return findings


# ── Main scan entry point ─────────────────────────────────────────────────────

def run_releases_scan(
    platform: str = "ios",
    cohort: str = "ai-native",
    terms: list[str] | None = None,
    limit_per_term: int = 50,
    progress_callback: object = None,
) -> ReleasesScanResult:
    """Run an AS-009 release notes governance scan.

    Args:
        platform: 'ios' or 'android'
        cohort: 'ai-native', 'traditional', or 'social' (ignored if terms provided)
        terms: Custom search terms (overrides cohort preset)
        limit_per_term: Max apps to fetch per search term
        progress_callback: Optional callable(term, fetched, flagged)

    Returns:
        ReleasesScanResult with all AS-009 findings
    """
    start = time.monotonic()

    search_terms = terms if terms else COHORT_TERMS.get(cohort, COHORT_TERMS["ai-native"])

    all_findings: list[ReleasesFinding] = []
    seen_app_ids: set[str] = set()
    apps_scanned = 0
    first_party_excluded = 0
    android_null_count = 0
    scan_warnings: list[str] = []

    for term in search_terms:
        if platform == "ios":
            records = _fetch_ios_apps(term, limit=limit_per_term)
            null_count = 0
        else:
            records, null_count = _fetch_android_apps(term, limit=limit_per_term)
            android_null_count += null_count
            if null_count > 0 and len(records) == 0:
                scan_warnings.append(
                    f"Android: '{term}' returned {null_count} apps with null "
                    f"recentChanges — Google Play does not mandate update disclosure."
                )

        term_flagged = 0
        for record in records:
            # Deduplicate across search terms
            if record.app_id in seen_app_ids:
                continue
            seen_app_ids.add(record.app_id)

            # Skip first-party AI provider apps
            if _is_first_party(record):
                first_party_excluded += 1
                continue

            apps_scanned += 1
            findings = _apply_as009_rules(record)
            if findings:
                term_flagged += 1
                all_findings.extend(findings)

        if callable(progress_callback):
            progress_callback(term, len(records), term_flagged)

        time.sleep(0.2)  # rate limit

    # Warn if Android null rate is high
    if platform == "android" and android_null_count > apps_scanned:
        scan_warnings.append(
            f"Android recentChanges null rate is high ({android_null_count} null vs "
            f"{apps_scanned} usable). Google Play does not mandate release note "
            f"disclosure — this is a platform governance asymmetry, not a scanner error."
        )

    apps_flagged = len({f.app_id for f in all_findings})

    return ReleasesScanResult(
        platform=platform,
        cohort=cohort,
        terms_used=search_terms,
        apps_scanned=apps_scanned,
        apps_flagged=apps_flagged,
        findings=all_findings,
        scan_duration_seconds=round(time.monotonic() - start, 2),
        first_party_excluded=first_party_excluded,
        android_null_count=android_null_count,
        scan_warnings=scan_warnings,
    )
