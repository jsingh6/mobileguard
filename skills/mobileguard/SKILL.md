---
name: mobileguard
description: App Store / Google Play rejection and AI-security guard for mobile apps (React Native/Expo, iOS, Android, Flutter), grounded in Apple/Google guidelines, OWASP LLM & Agentic Top 10, and MASVS, with a per-project ledger. Use when implementing an LLM/AI feature in a mobile app, reviewing a mobile PR or repo, preparing a store submission, handling an App Store or Google Play rejection, or running a compliance retro.
---

# MobileGuard

Review a mobile app the way App Review and an attacker will, before the binary ships. A shipped binary cannot be hotfixed past review, so every miss costs a review cycle or an incident.

## Modes

Pick the mode from the moment, and read the ledger first in every mode.

| Moment | Mode | Do |
|---|---|---|
| Writing or changing AI feature code | **build** | Apply every rule in [references/guardrails.md](references/guardrails.md) to the code you write. Offer to add the guardrails to the project's `AGENTS.md`/`CLAUDE.md` if they are missing. Finish with the review steps scoped to the touched files. |
| A PR or diff | **pr** | Review steps scoped to call sites the diff adds or changes; gate checks run app-wide, since a diff adding the first AI call makes consent, moderation, declarations, and deletion newly required. |
| Full audit, or no ledger yet | **review** | Review steps over the whole app; create the ledger. |
| Preparing a store submission | **release** | [references/modes/release.md](references/modes/release.md) |
| A rejection or policy notice arrived | **rejection** | [references/modes/rejection.md](references/modes/rejection.md) |
| Quarterly, after a rejection, or every few releases | **lookback** | [references/modes/lookback.md](references/modes/lookback.md) |

**The ledger** is `MOBILEGUARD.md` at the repo root: the AI surface, what each store was told, accepted risks, project checks earned from past rejections, and the findings history. Format and writing rules are in [references/ledger.md](references/ledger.md). Every mode reads it before working, applies its **Project checks** (MG-P*), honours its **Decisions** within their scope, and records what it found before finishing. This history makes each run sharper than the last, so keep it current.

## Vocabulary

- **Lead**: a place worth reading (script output, a grep hit). Unverified.
- **Trace**: the code path you actually read from a source (user input, key, model output) to a sink (network, WebView, tool, storage, log).
- **Gate**: something that must execute *before* a sink on every path: consent, confirmation, moderation, auth.
- **Finding**: a lead confirmed by a trace, or a missing gate confirmed app-wide.
- **Drift**: the code's AI surface diverging from the ledger or from the store declarations.

## Review steps

### 1. Inventory

```bash
python3 <skill-dir>/scripts/ai_surface.py <repo> > /tmp/mg-surface.json   # leads (stdlib, Python 3.8+)
python3 <skill-dir>/scripts/ai_surface.py <repo> --snapshot               # stable facts for the ledger
```

Establish the **distribution channels** (App Store, TestFlight, Google Play, enterprise, sideload, F-Droid) from the ledger, `eas.json` submit profiles, fastlane, or Play publishing config, or ask. Store checks apply only to store channels; security checks apply everywhere.

Done when you can state: stack, channels, each AI provider (cloud vs on-device), who holds each credential (client, user BYOK, or server), and every AI call site.

### 2. Map the AI data flow

For every AI call site in scope, read the code and fill one row:

| Call site | Inputs (and their sources) | Output goes to | Credential | Gates on path |
|---|---|---|---|---|

Inputs include indirect sources: clipboard, share extensions, notifications, OCR'd images, web pages, files, contacts, health, location. Outputs include text views, markdown renderers, WebViews, tool dispatch, deep links, storage, logs, and analytics.

Done when every in-scope call site has a row, and every output column names concrete code (a component or function), not "UI".

### 3. Load the checks

- Always: [references/store-rejection.md](references/store-rejection.md) (MG-R), [references/ai-security.md](references/ai-security.md) (MG-S), and the ledger's Project checks (MG-P).
- React Native or Expo in the stack: [references/react-native.md](references/react-native.md), read in full.
- Swift, Kotlin, or Dart code on a flow row: [references/platform-apis.md](references/platform-apis.md).

### 4. Verify

Apply **every** loaded check to the flow table and to the script's `leads` and `absent` lists:

- Promote a lead to a finding only with a trace. Quote the lines.
- Prove a gate app-wide: a consent screen in another file counts if it runs before **every** send path, including Siri/App Intents, share extensions, widgets, background tasks, and deep links.
- Set aside `test_code: true` leads. Treat server-side files (Expo `+api` routes, `functions/`, `server/`) as the fix location for secrets, not as findings.
- A matching Decision downgrades or skips a check only inside its stated scope and only until its revisit trigger fires.
- A check you cannot settle from code (Console forms, privacy label, age rating) is **needs-human**: state the exact question.

Done when every check ID is marked `finding`, `clear`, `n/a`, or `needs-human`, with one line of evidence each.

### 5. Report and record

```
## MobileGuard <mode> — <app> (<stack>, channels: <...>)

### Blockers (will be rejected, or exploitable now)
**MG-S01 · Provider key ships in the JS bundle** — Confirmed
- Where: src/lib/openai.ts:4 ← .env:1 (EXPO_PUBLIC_OPENAI_API_KEY)
- Trace: <quoted lines, source → sink>
- Impact: <who can do what: e.g. anyone with the IPA extracts the key in minutes and bills your account>
- Rule: OWASP LLM10 · MASVS-STORAGE-1 · <store guideline if any>
- Fix: <concrete change, with code for this stack>

### High / Medium / Advisory
...

### Drift (vs ledger)
<new or removed surface; declarations now stale>

### Coverage
<check ID → finding | clear | n/a | needs-human, one line each>
```

Severity reflects consequence: **Blocker** means a predictable rejection or a currently exploitable path, **High** means likely rejection or serious exposure, **Medium** means a reviewer-dependent or chained risk, and **Advisory** means hardening. Confidence is **Confirmed** (traced), **Likely** (one hop unread), or **Needs-human**.

Then update the ledger: append findings with their `Caught at` stage, refresh Surface, and add Decisions the user makes. Release mode also replaces the Snapshot block.

## The `mobileguard` CLI

If the `mobileguard` CLI is installed, `mobileguard scan . --format json` adds deterministic leads. Its rule IDs map as AS-001→MG-R01, AS-006→MG-R02, AS-007→MG-R05, GP-001→MG-R03, OW-001→MG-S03, OW-002→MG-S04, OW-005→MG-S02, AABE-*→MG-S05. Verify CLI leads with a trace like any other lead.
