# Rejection mode: a store said no

Input: the rejection text, either an App Store Connect Resolution Center message or a Google Play policy email or Console notice, plus the version rejected. Goal: fix the root cause everywhere it occurs, draft the reply, and make sure this rejection can never recur unnoticed.

## 1. Parse the rejection

Extract:

- **Store.**
- **Every guideline or policy cited:** reviewers often cite several. Handle each one.
- **The reviewer's concrete evidence:** screen, device, steps, screenshot description, and quoted text.
- **The rejected artifact:** binary, metadata, or declaration.
- **For Play:** the enforcement level (update rejected, app removed, warning) and any deadline.

Done when every citation has a line, with the evidence the reviewer gave for it.

## 2. Map to checks

Use the table below, then the full check in [store-rejection.md](../store-rejection.md). The first column lists common citation phrasings: Apple guideline numbers and Google policy names.

| Citation | Usual MobileGuard check | First thing to verify |
|---|---|---|
| Apple 2.1 App Completeness | MG-R06 (reviewer access), MG-P* | Can the reviewer reach every AI feature without their own key or paid plan? |
| Apple 2.3.1 / hidden features | MG-R06 | Remote flags that differ between the review build and production |
| Apple 2.5.2 | MG-R05 | Generated code executed in-process or previewed in a WebView |
| Apple 4.7.x (chatbots, mini apps) | MG-R04, MG-R05 | Filtering, reporting, native API exposure |
| Apple 1.2 | MG-R04 | Report and block affordances on generated content |
| Apple 3.1.1 | MG-R07 | What unlocks AI usage |
| Apple 4.1(c) / 5.2.1 / Play Impersonation | MG-R08 | Name, icon, metadata |
| Apple 4.2 / 4.3 / Play Spam & Minimum Functionality | MG-R09 | Wrapper depth |
| Apple 5.1.1 / 5.1.2 / Play User Data | MG-R01, MG-R12, MG-R10 | Consent gate on every path; purpose strings; deletion |
| ITMS-91053 / privacy manifest emails | MG-R02 | Required-reason APIs and collected types |
| Play Data safety mismatch | MG-R03 | Data types the code sends that the form omits |
| Play AI-Generated Content | MG-R04 | In-app report without leaving the app; restricted-content filter |
| Play Device and Network Abuse | MG-R05, MG-R06 | Downloaded executable code; interpreted code enabling violations |
| Play Permissions / foreground service | MG-R12 | Undeclared or unused sensitive permissions |

No row fits? Then this is a new pattern. Note that, and go on to step 3 anyway.

## 3. Find the root cause

Trace the reviewer's evidence into the code, config, or metadata. Classify the fix:

- **Code:** the app does the prohibited thing.
- **Declaration:** the app is fine but the manifest or form is wrong.
- **Metadata:** name, screenshots, or description.
- **Reviewer access:** the feature works but the reviewer could not reach it.
- **Misread:** the reviewer misunderstood. Reply with evidence; appeal to the App Review Board, or file a Play appeal, only if a clarification fails.

Then **hunt siblings**: the same pattern at every other entry point, screen, and platform target. Reviewers report one instance; the resubmission is judged on all of them.

Done when the root cause is named, with file:line or the exact metadata field, and the sibling hunt is recorded.

## 4. Fix and verify

Make the fix (build mode guardrails apply), then run SKILL.md step 4 for the cited checks across the whole app. On the other store, check whether the same root cause is live there too; it usually is.

## 5. Draft the reply

A Resolution Center reply or Play appeal or resubmission note:

- Thank the reviewer in one line, then state what changed, in the reviewer's terms and with the guideline number.
- Give exact steps to see the fix: screen, tap path, demo credentials.
- For a misread, state the facts with evidence (a screenshot description, a code-behaviour summary). Keep the tone factual and short.

## 6. Make it permanent

In the ledger:

- Append to Rejections.
- Log the finding with `Caught at: review-rejection`.
- Add a **Project check** `MG-P<next>` that names what to look for and when it passes, written so release mode can apply it without context.

If the pattern is new to MobileGuard and generalizes beyond this app, offer the user a short anonymized write-up for upstream contribution to the MobileGuard rule set. Submit it only with their explicit go-ahead.
