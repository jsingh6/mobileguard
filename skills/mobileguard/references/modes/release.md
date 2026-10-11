# Release mode: before every store submission

Goal: a go/no-go decision for this binary, plus store declarations and App Review notes that match what the binary actually does. The work is a **delta** against the last submission recorded in the ledger.

## 1. Establish the baseline

From the ledger, take the last Releases row (version, tag or commit) and the Snapshot block. With no ledger or no release row, this is a first submission: run the full review (SKILL.md steps 1–4) and skip to step 4 below.

Done when you have a base ref and its snapshot.

## 2. Find the drift

```bash
python3 <skill-dir>/scripts/ai_surface.py <repo> --diff-ledger <repo>/MOBILEGUARD.md
git diff --stat <base-ref>..HEAD
```

`+` lines are surface that is new since the last release, and `-` lines are surface that was removed. Exit code 3 means the ledger has no Snapshot block, so treat the release as a first submission.

Classify every `+`/`-` line, plus each changed AI file in the git diff:

- **New surface**: a provider, endpoint, data source, permission, tool, or sink. It needs review (step 3) and probably a declaration change (step 4).
- **Removed surface**: a declaration that may now over-declare. That's harmless for review; tidy it.
- **Gate changes**: an `absent:` line appeared, or consent, moderation, or confirmation code changed.

Done when every diff line has a class.

## 3. Review the delta

Run SKILL.md step 4 on the new surface and gate changes, and apply the ledger's Project checks (MG-P*) to the whole app. Then re-open the Decisions whose **revisit trigger** has fired, judging the trigger against the drift, the date, and the policy baseline.

If the skill's references are newer than the ledger's policy baseline, re-run the checks whose guideline text changed across the whole app, not just the delta.

Done when every delta item and every fired trigger has a status.

## 4. Regenerate declarations

From the current flow table, produce:

- **PrivacyInfo.xcprivacy / `expo.ios.privacyManifests`**: exact entries.
- **App Store Connect privacy label**: answers per data type (collected, linked, tracking, purpose).
- **Play Data safety**: answers per data type (collected vs shared, purpose, optional or required, encrypted in transit, deletable).

Diff these against the ledger's Declarations row and list each change as a **human action**, for example: "In Play Console → Data safety, add *Voice or sound recordings: collected, app functionality*". Consoles live outside the repo, so a declaration counts as updated only when a human confirms it.

## 5. Draft App Review notes

Cover:

- **New and changed AI features since the last version:** what each does and the path to reach it.
- **Reviewer access:** demo credentials, or how AI works without a user-supplied key.
- **Which provider receives which data:** and where the consent screen appears.
- **Where users report AI content:** and what moderation runs.
- **Anything a reviewer might misread:** for example, "generated HTML renders with JavaScript disabled".

Keep it to what changed plus the standing essentials. Reviewers read short notes.

## 6. Decide and record

- **No-go:** any open Blocker, or a declaration change not yet confirmed by a human.
- **Go with conditions:** High findings with an owner and date.
- **Go:** everything else.

Append the Releases row, replace the Snapshot block with the current snapshot, update Declarations once the human confirms the submission, and log findings with `Caught at: release`.
