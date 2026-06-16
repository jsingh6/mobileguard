#!/usr/bin/env bash
# MobileGuard — Example iOS project scan
# Drop this into your iOS project root and run: bash scan_ios_project.sh

set -euo pipefail

PROJECT_DIR="${1:-.}"
FAIL_ON="${FAIL_ON:-critical}"

echo "MobileGuard iOS Scan"
echo "Project: $PROJECT_DIR"
echo ""

# Pattern-only scan (no API key needed)
mobileguard scan "$PROJECT_DIR" \
  --platform ios \
  --rules app-store,eu-ai-act,owasp \
  --severity warning \
  --format table \
  --fail-on "$FAIL_ON"

# Optionally generate a full compliance report
# mobileguard audit "$PROJECT_DIR" \
#   --app-name "My App" \
#   --version "$(cat VERSION)" \
#   --format markdown \
#   --output mobileguard-audit-report.md
