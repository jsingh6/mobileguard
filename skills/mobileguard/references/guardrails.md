# MobileGuard guardrails: building AI features in a mobile app

Follow these rules while writing AI features. They are designed to be pasted as-is into a project's `AGENTS.md` / `CLAUDE.md` so every coding agent applies them. Each rule prevents the check named in brackets.

## Credentials and cost
- Call AI providers from the server: an Expo Router `+api` route, a cloud function, or your backend. The app holds only the user's session. Firebase AI Logic is the client-side exception, and only with App Check enforced. [MG-S01]
- Keep provider keys in server-side env vars without the `EXPO_PUBLIC_` prefix. Store BYOK keys the user types in `expo-secure-store` / Keychain / Keystore. [MG-S01, MG-S07]
- Set `max_tokens` on every model call, enforce per-user quotas on the server, and cap agent-loop iterations. [MG-S02]

## Consent and declarations
- Route every cloud AI request through one client function that checks a stored, revocable consent flag naming the provider and data sent. Entry points (Siri, share extension, deep link, background) call that function. [MG-R01]
- When a new data type reaches a provider, update `PrivacyInfo.xcprivacy` (or `expo.ios.privacyManifests`) `NSPrivacyCollectedDataTypes` in the same change and note the Play Data safety update in the PR. AI hosts stay out of `NSPrivacyTrackingDomains`. [MG-R02, MG-R03]
- Purpose strings for microphone, camera, photos, and speech say the content is sent for AI processing, and to whom. [MG-R12]

## Rendering model output
- Render model output as native text or markdown with images off and links routed through an allow-list (`https:` plus known hosts) with confirmation. [MG-S04]
- Any WebView showing model output runs with `javaScriptEnabled={false}` and no `onMessage` bridge. Generated apps and previews open in the system browser on a hosted URL. [MG-S04, MG-R05]
- Parse structured output against a schema. Model output stays data, never code. [MG-S04, MG-R05]

## Tools and agents
- Side-effecting tools (send, pay, delete, post, share, read contacts/health/location) show the exact parameters in native UI and run only after the user taps confirm. Dispatch through an explicit allow-list. [MG-S05]
- App Intents with side effects call `requestConfirmation`. Intents touching private data set `authenticationPolicy = .requiresAuthentication`. Each Android `@AppFunction` checks permissions itself. [MG-S05]

## Data handling
- Send the minimum to the model: strip EXIF from images and redact identifiers. [MG-S06]
- Store conversation history encrypted (MMKV with a Keychain-held `encryptionKey`), exclude it from backup, and clear it on logout and account deletion, including provider-side threads and files. [MG-S07, MG-R10]
- Log AI metadata (model, latency, token counts). Prompt and response text stays out of `console.log`, crash breadcrumbs, and analytics. [MG-S08]

## Shipping
- Every generated surface has an in-app "Report" action and passes through a moderation layer. [MG-R04]
- New AI capabilities ship in a reviewed binary, with App Review notes and demo access. OTA updates carry fixes and copy, and are code-signed. [MG-R06, MG-S11]
- AI usage is sold through IAP / Play Billing. The app name and icon carry your brand, not the provider's. [MG-R07, MG-R08]
