# Changelog

All notable changes to MobileGuard are documented here.

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
