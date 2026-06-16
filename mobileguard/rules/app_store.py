# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Apple App Store governance rules.

Rule IDs are stable and cited in the MobileGuard research paper (arXiv:XXXX.XXXXX).
Pillar: PGSG (Platform Gatekeeper Simulation Gates).
"""

from mobileguard.models import RuleCategory, RuleDefinition, Severity

RULES: dict[str, RuleDefinition] = {
    "AS-001": RuleDefinition(
        id="AS-001",
        severity=Severity.CRITICAL,
        category=RuleCategory.APP_STORE,
        description="Third-party AI data sharing without 5.1.2(i) disclosure",
        fix=(
            "Add a PrivacyDisclosureView or ATTrackingManager.requestTrackingAuthorization "
            "call before the first AI API request. Users must be informed that their data "
            "is being sent to a third-party AI service."
        ),
        reference="https://developer.apple.com/app-store/review/guidelines/#data-collection-and-storage",
        pillar="PGSG",
    ),
    "AS-002": RuleDefinition(
        id="AS-002",
        severity=Severity.ERROR,
        category=RuleCategory.APP_STORE,
        description="Hardcoded AI API key in source code",
        fix=(
            "Remove the key from source code immediately. Store it in environment variables "
            "during development and in the iOS Keychain at runtime. Never commit API keys "
            "to version control."
        ),
        reference="https://developer.apple.com/app-store/review/guidelines/#5.4",
        pillar="PGSG",
    ),
    "AS-003": RuleDefinition(
        id="AS-003",
        severity=Severity.ERROR,
        category=RuleCategory.APP_STORE,
        description="App Intent exposes sensitive data scope without explicit user authorization",
        fix=(
            "Add a requestAuthorization() call before accessing contacts, calendar, health, "
            "or location data in your AppIntent. The authorization must be requested and "
            "granted before the intent can access the resource."
        ),
        reference="https://developer.apple.com/documentation/appintents",
        pillar="AABE",
    ),
    "AS-004": RuleDefinition(
        id="AS-004",
        severity=Severity.WARNING,
        category=RuleCategory.APP_STORE,
        description="Generic AI-generated privacy description in Info.plist may trigger App Store review",
        fix=(
            "Replace boilerplate privacy descriptions with specific, accurate descriptions "
            "of how your app uses the requested resource. Generic descriptions like 'improve "
            "your experience' are commonly cited in App Store rejections."
        ),
        reference="https://developer.apple.com/documentation/bundleresources/information_property_list/protected_resources",
        pillar="PGSG",
    ),
    "AS-005": RuleDefinition(
        id="AS-005",
        severity=Severity.WARNING,
        category=RuleCategory.APP_STORE,
        description="Missing NSPrivacyCollectedDataTypes declaration for AI feature that collects user data",
        fix=(
            "Add a PrivacyInfo.xcprivacy file declaring all data types collected by your "
            "AI integration. Required for apps targeting iOS 17+ that use third-party AI APIs."
        ),
        reference="https://developer.apple.com/documentation/bundleresources/privacy_manifest_files",
        pillar="PGSG",
    ),
}
