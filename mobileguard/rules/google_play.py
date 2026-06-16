# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Google Play AI policy governance rules.

Rule IDs are stable and cited in the MobileGuard research paper (arXiv:XXXX.XXXXX).
Pillar: PGSG (Platform Gatekeeper Simulation Gates).
"""

from mobileguard.models import RuleCategory, RuleDefinition, Severity

RULES: dict[str, RuleDefinition] = {
    "GP-001": RuleDefinition(
        id="GP-001",
        severity=Severity.CRITICAL,
        category=RuleCategory.GOOGLE_PLAY,
        description="AI data transmission without DATA_SAFETY declaration",
        fix=(
            "Add a data_safety section to your AndroidManifest.xml or Play Console Data "
            "Safety form declaring that your app shares data with an AI service. Users must "
            "be able to see this declaration before installing."
        ),
        reference="https://support.google.com/googleplay/android-developer/answer/10787469",
        pillar="PGSG",
    ),
    "GP-002": RuleDefinition(
        id="GP-002",
        severity=Severity.ERROR,
        category=RuleCategory.GOOGLE_PLAY,
        description="Hardcoded AI API key in Kotlin source or Gradle build file",
        fix=(
            "Remove the key from source immediately. Use BuildConfig fields populated from "
            "local.properties (git-ignored) during development, and a secure secrets manager "
            "or server-side proxy in production. Never commit API keys to version control."
        ),
        reference="https://developer.android.com/topic/security/risks/hardcoded-cryptographic-secrets",
        pillar="PGSG",
    ),
    "GP-003": RuleDefinition(
        id="GP-003",
        severity=Severity.ERROR,
        category=RuleCategory.GOOGLE_PLAY,
        description="AppFunction declaration exposes sensitive permissions without MANAGE_APP_FUNCTIONS",
        fix=(
            "Declare android.permission.MANAGE_APP_FUNCTIONS in AndroidManifest.xml and "
            "add runtime permission checks before your AppFunction accesses sensitive data. "
            "Each permission scope must be explicitly declared and requested."
        ),
        reference="https://developer.android.com/guide/app-functions",
        pillar="AABE",
    ),
    "GP-004": RuleDefinition(
        id="GP-004",
        severity=Severity.WARNING,
        category=RuleCategory.GOOGLE_PLAY,
        description="Ambient AI feature missing biometric or explicit consent flow",
        fix=(
            "Add a BiometricPrompt or AlertDialog consent step before activating ambient "
            "AI features that access device sensors or background context. Consider using "
            "android.permission.USE_EXACT_ALARM for scheduled AI tasks."
        ),
        reference="https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt",
        pillar="AABE",
    ),
    "GP-005": RuleDefinition(
        id="GP-005",
        severity=Severity.WARNING,
        category=RuleCategory.GOOGLE_PLAY,
        description="Missing <queries> manifest declaration for AI service packages",
        fix=(
            "Add a <queries> element to AndroidManifest.xml listing the package names or "
            "intents for AI services your app communicates with. Required for Android 11+ "
            "(API 30+) package visibility."
        ),
        reference="https://developer.android.com/training/package-visibility",
        pillar="PGSG",
    ),
}
