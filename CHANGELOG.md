# Changelog

All notable changes to MobileGuard are documented here.

## [3.2.0] — 2026-10-10

### Added
- **MobileGuard agent skill** (`skills/mobileguard/`), installable with
  `npx skills add jsingh6/mobileguard`. It traces AI data flows and checks them
  against Apple/Google guidelines, OWASP LLM Top 10 (2025), OWASP Agentic Top 10
  (2026), and MASVS v2: 12 store-rejection checks (MG-R) and 13 AI-security
  checks (MG-S), with deep React Native / Expo coverage.
- Skill modes for the whole release cycle: build (guardrails), pr, review, release
  (drift, declarations, App Review notes, go/no-go), rejection (fix, reply,
  permanent project check), and lookback (escapes, recurrence, noise, staleness).
- `MOBILEGUARD.md` ledger: committed per-project memory shared by all modes.
- `skills/mobileguard/scripts/ai_surface.py`: dependency-free AI surface mapper,
  with `--snapshot`, `--diff-ledger`, and `--fail-on-drift` for CI.

### Fixed
- **AS-006 gave harmful advice.** It told developers to add AI provider domains to
  `NSPrivacyTrackingDomains`. iOS blocks requests to tracking domains until the user
  grants App Tracking Transparency, so following the advice broke AI features for
  most users. AS-006 now flags AI hosts listed as tracking domains, a missing
  manifest, and missing `NSPrivacyCollectedDataTypes`.
- **AS-001 treated the ATT prompt as AI consent.** ATT covers cross-app tracking
  only. The fix text now describes a real AI consent gate, and the Swift detector no
  longer counts `ATTrackingManager` as disclosure.

- `mobileguard preflight` crashed with the default `--platform auto`.
- `mobileguard contract` raised `TypeError` with current Anthropic SDKs
  (unsupported `temperature` argument).
- AS-006/AS-007 project-wide checks now honour `.gitignore` and
  generated-file suffixes, like the per-file detectors.
- `mobileguard --version` and SARIF output reported 1.3.0.

### Removed
- Stale, unused duplicates `mobileguard/swift.py`, `mobileguard/app_store.py`, and
  `mobileguard/test_rules.py`. They shipped in the package with the old advice.

## [1.3.0] — 2026-06-16

### Added
- AS-006: PrivacyInfo.xcprivacy mismatch detector — cross-references
  AI API calls in source against privacy manifest declarations (PGSG pillar)
- AS-007: Guideline 2.5.2 architectural violation detector — catches
  WKWebView and JSContext executing AI-generated code (PGSG pillar)
- `mobileguard surface` command — maps ambient AI agent entry points,
  flags AppIntents accessing sensitive data without confirmation (AABE pillar)
- AABE-001: AppIntent financial data access without requestConfirmation (CRITICAL)
- AABE-002: AppIntent sensitive data access without requestConfirmation (ERROR)
- `--platform macos` flag — suppresses macOS-only project warning
- macOS-only xcodeproj detection via SDKROOT inspection
- `ScanResult.warnings` field for non-fatal diagnostic messages

### Not added (out of scope)
- Code quality rules (use SwiftLint, Xcode analyzer)
- General security scanning (use Snyk, Semgrep)
- Test coverage analysis (use Xcode Coverage)
- Performance profiling (use Instruments)

### Why the "not added" list matters
MobileGuard's value comes from its narrow, deep focus on governance
violations specific to AI-generated code in mobile delivery pipelines.
Every rule must be traceable to one of the four pillars (PDQC, TAC-M,
PGSG, AABE) from the research paper. Rules that could be caught by
Xcode's static analyzer, SwiftLint, or a general security scanner do
not belong here.

## [1.2.0] — 2026-06-14

### Added
- `_NON_CALL_CTX` pattern across all four detectors (Swift, JS, Kotlin, Dart)
  to suppress false positives from HTML placeholder attributes, href= values,
  comments, and JSDoc containing AI domain URLs

## [1.0.0] — 2026-06-01

### Added
- Initial release with four governance pillars: PDQC, TAC-M, PGSG, AABE
- `mobileguard scan` — source-level governance scan (AS-001 through AS-005,
  GP-001 through GP-005, EU-001 through EU-004, OW-001 through OW-005)
- `mobileguard audit` — EU AI Act compliance report generation
- `mobileguard contract` — pre-deployment quality contracting
- `mobileguard tier` — tiered autonomy calibration
- `mobileguard init` — contract initialization
- Swift, Kotlin, Dart, JavaScript/TypeScript detectors
