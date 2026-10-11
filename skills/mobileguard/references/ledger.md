# The ledger

The ledger is the project's store-compliance memory: what the AI surface is, what was declared to each store, what was decided, and what went wrong. Every mode reads it first and writes it last. Commit it at the repo root as `MOBILEGUARD.md` so changes are reviewed in PRs like any other code.

Writing rules:

- Record facts and decisions; secrets, keys, and user data stay out.
- Append to logs (Findings, Rejections, Releases); edit tables in place.
- Every accepted risk names a **revisit trigger**. A decision without one never gets re-examined.
- Dates are absolute (`2026-10-10`).
- When no ledger exists, create it from the template below. Fill Surface from the flow table and Snapshot from `ai_surface.py --snapshot`, and leave Declarations as `unknown` until a human confirms what was submitted.

## Template

````markdown
# MobileGuard ledger — <App name>

Channels: <App Store, TestFlight, Google Play, ...> · Policy baseline: <date of the skill's references used at the last full review>

## Surface
| Provider | Kind | Data sent | Credential lives | Entry points | Consent gate |
|---|---|---|---|---|---|
| OpenAI gpt-4o | cloud | chat text, images | server (`app/api/chat+api.ts`) | chat screen, share extension | `useAIConsent()` in `src/ai/client.ts` |

## Tools & ambient entry points
| Tool / intent | Side effect | Gate |
|---|---|---|
| send_sms | sends SMS | native confirm sheet `ConfirmToolSheet` |

## Declarations (as last submitted)
| Store | Version | Date | Data types declared | Review notes summary |
|---|---|---|---|---|
| App Store | 2.3.0 | 2026-09-14 | OtherUserContent (linked, app functionality), AudioData | demo account; consent on first launch |
| Google Play | 2.3.0 | 2026-09-15 | Messages, Voice recordings (collected, not shared) | — |

## Snapshot (last release)
```
<output of ai_surface.py --snapshot at the last release tag>
```

## Decisions
| ID | Check | Scope | Decision & reason | Decided | Revisit when |
|---|---|---|---|---|---|
| D-01 | MG-R01 | BYOK flow | Medium, not Blocker: user picks provider and pastes key; one-time disclosure added | 2026-08-02 | provider list changes or Apple updates 5.1.2 |

## Project checks
Checks this project earned from its own rejections and escapes. Every mode applies them alongside the MG checks.
| ID | Origin | Look for | Pass when |
|---|---|---|---|
| MG-P01 | Rejection 2026-09-02, 2.1 | AI features behind paywall or BYOK | review notes include demo credentials reaching every AI feature |

## Findings log
| Date | Mode | Check | Where | Caught at | Status |
|---|---|---|---|---|---|
| 2026-09-10 | pr | MG-S04 | `src/chat/Message.tsx` | pr | fixed |

`Caught at` is one of: build · pr · release · review-rejection · production.

## Rejections
| Date | Store | Version | Cited | Root cause | Fix | Project check added |
|---|---|---|---|---|---|---|

## Releases
| Date | Version | Tag/commit | Go/no-go | Surface changes | Declarations changed |
|---|---|---|---|---|---|
````
