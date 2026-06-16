# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Core scanner for mobileguard scan.

Walks a mobile codebase, dispatches files to language-specific detectors,
and aggregates findings into a ScanResult. Pattern-only by default; the
--llm flag adds a Claude API semantic pass.
"""

from __future__ import annotations

import time
from collections import Counter
from pathlib import Path
from typing import Callable

import pathspec

from mobileguard.detectors import detect_dart, detect_javascript, detect_kotlin, detect_swift
from mobileguard.models import Finding, Platform, RuleCategory, Severity, ScanResult

# ── Skip lists ────────────────────────────────────────────────────────────────

_SKIP_DIRS = {
    "Pods",
    "node_modules",
    ".build",
    "DerivedData",
    "Packages",
    ".git",
    ".mobileguard",
    "build",
    "dist",
    ".gradle",
    "__pycache__",
}

_SKIP_SUFFIXES = {
    ".generated.swift",
    ".pb.swift",
    ".grpc.swift",
}

# ── Platform / extension mapping ──────────────────────────────────────────────

_EXT_TO_PLATFORM: dict[str, Platform] = {
    ".swift": Platform.IOS,
    ".plist": Platform.IOS,
    ".kt": Platform.ANDROID,
    ".kts": Platform.ANDROID,
    ".dart": Platform.FLUTTER,
    ".js": Platform.REACT_NATIVE,
    ".ts": Platform.REACT_NATIVE,
    ".jsx": Platform.REACT_NATIVE,
    ".tsx": Platform.REACT_NATIVE,
}

_DETECTOR_MAP: dict[Platform, Callable[[str, str], list[Finding]]] = {
    Platform.IOS: detect_swift,
    Platform.ANDROID: detect_kotlin,
    Platform.FLUTTER: detect_dart,
    Platform.REACT_NATIVE: detect_javascript,
}

# ── Rule category filter ──────────────────────────────────────────────────────

_CATEGORY_ALIASES: dict[str, RuleCategory] = {
    "app-store": RuleCategory.APP_STORE,
    "google-play": RuleCategory.GOOGLE_PLAY,
    "eu-ai-act": RuleCategory.EU_AI_ACT,
    "owasp": RuleCategory.OWASP,
}

_SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.ERROR: 3,
    Severity.WARNING: 2,
    Severity.INFO: 1,
}


def _load_gitignore(root: Path) -> pathspec.PathSpec | None:
    """Load .gitignore from the project root, or return None if absent."""
    gitignore = root / ".gitignore"
    if gitignore.exists():
        return pathspec.PathSpec.from_lines("gitwildmatch", gitignore.read_text().splitlines())
    return None


def _should_skip(path: Path, root: Path, spec: pathspec.PathSpec | None) -> bool:
    """Return True if this path should be excluded from scanning."""
    for part in path.parts:
        if part in _SKIP_DIRS:
            return True

    name = path.name
    for suffix in _SKIP_SUFFIXES:
        if name.endswith(suffix):
            return True

    if spec is not None:
        rel = str(path.relative_to(root))
        if spec.match_file(rel):
            return True

    return False


def detect_platform(root: Path) -> Platform:
    """Infer the dominant platform from file extensions in the project tree."""
    counts: Counter[Platform] = Counter()
    for f in root.rglob("*"):
        if f.is_file():
            p = _EXT_TO_PLATFORM.get(f.suffix.lower())
            if p:
                counts[p] += 1
    if not counts:
        return Platform.IOS
    return counts.most_common(1)[0][0]


def run_scan(
    path: str,
    *,
    platform: str = "auto",
    rules: str = "all",
    min_severity: Severity = Severity.WARNING,
    enabled_categories: set[RuleCategory] | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> ScanResult:
    """Scan a mobile project directory for governance violations.

    Args:
        path: Absolute or relative path to the project root or a single file.
        platform: Platform hint; 'auto' detects from file extensions.
        rules: Comma-separated rule categories, or 'all'.
        min_severity: Minimum severity level to include in results.
        enabled_categories: Override rule category filter (derived from rules if None).
        progress_callback: Optional callable receiving the current file path string.

    Returns:
        ScanResult with all findings at or above min_severity.
    """
    start = time.monotonic()
    root = Path(path).resolve()

    # Resolve enabled categories
    if enabled_categories is None:
        if rules.strip().lower() == "all":
            enabled_categories = set(RuleCategory)
        else:
            enabled_categories = set()
            for token in rules.split(","):
                token = token.strip().lower()
                if token in _CATEGORY_ALIASES:
                    enabled_categories.add(_CATEGORY_ALIASES[token])

    # Detect platform
    if platform == "auto":
        detected_platform = detect_platform(root) if root.is_dir() else _detect_file_platform(root)
    else:
        detected_platform = Platform(platform)

    spec = _load_gitignore(root) if root.is_dir() else None

    # Collect files to scan
    if root.is_file():
        files_to_scan = [root]
    else:
        files_to_scan = [
            f
            for f in root.rglob("*")
            if f.is_file()
            and f.suffix.lower() in _EXT_TO_PLATFORM
            and not _should_skip(f, root, spec)
        ]

    all_findings: list[Finding] = []
    files_scanned = 0

    for file_path in files_to_scan:
        file_platform = _EXT_TO_PLATFORM.get(file_path.suffix.lower(), detected_platform)
        detector = _DETECTOR_MAP.get(file_platform)
        if detector is None:
            continue

        if progress_callback:
            progress_callback(str(file_path.relative_to(root) if root.is_dir() else file_path))

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel_path = str(file_path.relative_to(root)) if root.is_dir() else str(file_path)
        findings = detector(rel_path, content)

        for finding in findings:
            if finding.category not in enabled_categories:
                continue
            if _SEVERITY_ORDER[finding.severity] < _SEVERITY_ORDER[min_severity]:
                continue
            all_findings.append(finding)

        files_scanned += 1

    summary = {
        "critical": sum(1 for f in all_findings if f.severity == Severity.CRITICAL),
        "error": sum(1 for f in all_findings if f.severity == Severity.ERROR),
        "warning": sum(1 for f in all_findings if f.severity == Severity.WARNING),
        "info": sum(1 for f in all_findings if f.severity == Severity.INFO),
    }

    passed = summary["critical"] == 0 and summary["error"] == 0

    return ScanResult(
        project_path=str(root),
        platform=detected_platform,
        files_scanned=files_scanned,
        scan_duration_seconds=round(time.monotonic() - start, 2),
        findings=all_findings,
        passed=passed,
        summary=summary,
    )


def _detect_file_platform(path: Path) -> Platform:
    """Detect platform from a single file's extension."""
    return _EXT_TO_PLATFORM.get(path.suffix.lower(), Platform.IOS)


def findings_meet_fail_threshold(findings: list[Finding], fail_on: str) -> bool:
    """Return True if any finding meets or exceeds the fail_on severity."""
    threshold = Severity(fail_on)
    threshold_weight = _SEVERITY_ORDER[threshold]
    return any(_SEVERITY_ORDER[f.severity] >= threshold_weight for f in findings)
