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
        description=(
            "Generic AI-generated privacy description in Info.plist may trigger App Store review"
        ),
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
        description=(
            "Missing NSPrivacyCollectedDataTypes declaration for AI feature that collects user data"
        ),
        fix=(
            "Add a PrivacyInfo.xcprivacy file declaring all data types collected by your "
            "AI integration. Required for apps targeting iOS 17+ that use third-party AI APIs."
        ),
        reference="https://developer.apple.com/documentation/bundleresources/privacy_manifest_files",
        pillar="PGSG",
    ),
    "AS-006": RuleDefinition(
        id="AS-006",
        severity=Severity.CRITICAL,
        category=RuleCategory.APP_STORE,
        description=(
            "AI API domain detected in source but not declared in PrivacyInfo.xcprivacy "
            "(NSPrivacyTrackingDomains)"
        ),
        fix=(
            "Add the AI domain to NSPrivacyTrackingDomains in PrivacyInfo.xcprivacy and declare "
            "the corresponding NSPrivacyCollectedDataType entry. Apple rejects apps before human "
            "review if third-party data collectors are undeclared in the privacy manifest."
        ),
        reference="https://developer.apple.com/documentation/bundleresources/privacy_manifest_files",
        pillar="PGSG",
    ),
    "AS-007": RuleDefinition(
        id="AS-007",
        severity=Severity.CRITICAL,
        category=RuleCategory.APP_STORE,
        description=(
            "WKWebView or JavaScript engine executing dynamic content violates "
            "App Store Guideline 2.5.2 (self-contained apps)"
        ),
        fix=(
            "Open AI-generated content in an external browser via UIApplication.shared.open() "
            "or SFSafariViewController. Never load AI-generated HTML strings or evaluate "
            "AI-generated JavaScript inside WKWebView. Apple blocked Replit and Vibecode in "
            "March 2026 for this exact pattern."
        ),
        reference="https://developer.apple.com/app-store/review/guidelines/#2.5.2",
        pillar="PGSG",
    ),
    "AS-010": RuleDefinition(
        id="AS-010",
        severity=Severity.ERROR,
        category=RuleCategory.APP_STORE,
        description=(
            "Platform reference to Android, Google Play, or other non-Apple platforms "
            "detected in user-facing strings — violates App Store Guideline 2.3.7"
        ),
        fix=(
            "Remove or replace all references to 'Android', 'Google Play', 'Play Store', "
            "'Windows', 'PC', or other non-Apple platforms in user-facing strings, "
            "localizable strings files, and UI copy. This commonly occurs when AI coding "
            "tools port Android apps to iOS without sanitizing platform-specific language. "
            "Apple rejects apps that reference competing platforms in their UI. "
            "Source: Apple App Store Guideline 2.3.7."
        ),
        reference="https://developer.apple.com/app-store/review/guidelines/#2.3.7",
        pillar="PGSG",
    ),
    "AS-011": RuleDefinition(
        id="AS-011",
        severity=Severity.ERROR,
        category=RuleCategory.APP_STORE,
        description=(
            "Placeholder or incomplete content detected in user-facing strings "
            "— violates App Store Guideline 2.1 (App Completeness). "
            "Apple's 2024 Transparency Report attributes 40%+ of unresolved rejections "
            "to App Completeness issues including placeholder content."
        ),
        fix=(
            "Replace all placeholder text with final production content before submission. "
            "Common patterns include 'Lorem ipsum', 'Coming Soon', 'TBD', 'TODO', "
            "'FIXME', 'Placeholder', 'Sample Text', 'Test Content', and 'Under Construction'. "
            "AI coding tools (Claude Code, Copilot, Cursor) generate placeholder strings "
            "frequently during scaffolding. Search your Localizable.strings and all "
            "SwiftUI/UIKit string literals before submission. "
            "Source: Apple 2024 App Store Transparency Report — 40%+ of unresolved "
            "rejections cite App Completeness (Guideline 2.1)."
        ),
        reference="https://developer.apple.com/app-store/review/guidelines/#2.1",
        pillar="PGSG",
    ),
    "AS-012": RuleDefinition(
        id="AS-012",
        severity=Severity.WARNING,
        category=RuleCategory.APP_STORE,
        description=(
            "Vague or generic permission usage description detected in Info.plist — "
            "violates App Store Guideline 5.1.1. "
            "Statista's 2024 app compliance survey found nearly one third of rejected "
            "apps fail due to missing or inconsistent privacy explanations."
        ),
        fix=(
            "Replace generic permission strings with specific explanations of WHY your app "
            "needs access. Bad: 'Camera needed', 'For camera access', 'Required for app'. "
            "Good: 'PostureGuard uses your camera to analyze sitting posture in real time. "
            "Video is processed on-device and never stored or transmitted.' "
            "Apple reviewers reject apps whose permission strings do not explain the "
            "specific use case. AI coding tools generate generic strings by default. "
            "Source: Statista 2024 — one third of rejections cite privacy explanation gaps "
            "(Guideline 5.1.1)."
        ),
        reference="https://developer.apple.com/app-store/review/guidelines/#5.1.1",
        pillar="PGSG",
    ),
    "AABE-001": RuleDefinition(
        id="AABE-001",
        severity=Severity.CRITICAL,
        category=RuleCategory.APP_STORE,
        description=(
            "AppIntent accesses financial or payment data without requestConfirmation() — "
            "ambient agent can initiate payment without explicit user approval"
        ),
        fix=(
            "Add requestConfirmation() before any financial action: "
            "try await requestConfirmation(result: .result(value: preview)). "
            "Apple Guideline 5.1.2(i) requires explicit consent before any AI-triggered "
            "action that involves financial or sensitive user data."
        ),
        reference="https://developer.apple.com/documentation/appintents/requesting-user-confirmation",
        pillar="AABE",
    ),
    "AABE-002": RuleDefinition(
        id="AABE-002",
        severity=Severity.ERROR,
        category=RuleCategory.APP_STORE,
        description=(
            "AppIntent accesses sensitive user data (contacts, health, location, calendar) "
            "without requestConfirmation() or explicit authorization check"
        ),
        fix=(
            "Add requestConfirmation() or a dedicated authorization check before accessing "
            "contacts, health, location, or calendar data from an AppIntent. "
            "Siri and Apple Intelligence can invoke this intent without the user directly "
            "opening the app."
        ),
        reference="https://developer.apple.com/documentation/appintents/requesting-user-confirmation",
        pillar="AABE",
    ),
}
