# Lookback mode: what the ledger teaches

Goal: make this project's next releases cheaper by learning from its history: which problems **escaped** to late stages, which keep **recurring**, which flags are **noise**, and which decisions have gone **stale**. The output is concrete edits, not a report to file away.

Run it quarterly, after any rejection, or every few releases. It needs history: at least two Releases rows, or one Rejection. With less, say there isn't enough history yet and stop.

## 1. Read the history

Take the ledger's Findings log, Rejections, Releases, and Decisions, plus `git log --since=<last lookback or first release>` over AI files and `MOBILEGUARD.md`.

## 2. Answer four questions

1. **Escapes:** which findings were caught at `release`, `review-rejection`, or `production` when the pattern was knowable at `build` or `pr`? For each, name the guardrail or project check that would have stopped it earlier.
2. **Recurrence:** which checks fired in two or more releases or PRs? A repeating check signals a structural gap: one AI client that every call must pass through, a shared confirmation component, a lint rule. Name the structural fix.
3. **Noise:** which checks were repeatedly accepted or dismissed with the same reason? Record the reason once as a Decision with a scope, so future runs skip that scope deliberately rather than by fatigue.
4. **Staleness:** which Decisions have a fired revisit trigger or are older than six months? Which Declarations rows predate surface changes in the Releases log? Is the policy baseline older than the skill's references?

Done when each question has an answer, even if the answer is "none, with evidence".

## 3. Turn answers into edits

Propose, and apply once the user approves:

- **Project guardrails:** new lines for the project's `AGENTS.md`/`CLAUDE.md`, phrased as the target behaviour, for each escape.
- **Project checks:** new `MG-P*` rows for escapes that guardrails alone will not catch.
- **Structural fixes:** one ticket-sized description per recurrence.
- **Decisions:** add (noise), re-open (stale), or retire.
- **Ledger:** update the policy baseline if you re-ran the checks against newer references.

Close with three lines: what to **keep** doing, what to **change**, and what to **retire**.
