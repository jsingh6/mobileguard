# Store-rejection checks (MG-R)

Each check names the guideline App Review or Play policy enforcement will cite, what to trace, when it is **not** a finding, and the fix. Tags: **[Both]**, **[iOS]**, **[Android]**. Apply only to store channels (App Store, TestFlight, Google Play).

Guideline text quoted here was verified against the live App Review Guidelines in October 2026. Reviewers apply guidelines with discretion, so phrase findings as rejection *risk* and cite the guideline number.

---

## MG-R01 · Third-party AI receives personal data without disclosure and explicit permission [Both]

- **Rule:** Apple 5.1.2(i): "You must clearly disclose where personal data will be shared with third parties, including with third-party AI, and obtain explicit permission before doing so." Google Play User Data policy: Prominent Disclosure & Consent when data use is outside what the user would reasonably expect.
- **Trace:** for every cloud-AI flow row, find a gate that (a) names the provider or "third-party AI", (b) says what data is sent (messages, voice, photos, documents), (c) requires an affirmative tap, (d) is persisted and revocable, and (e) runs before the **first** send on every entry path: onboarding, deep link, share extension, widget, App Intent, push-reply, background sync.
- **Not a finding:** on-device models only (Apple Foundation Models, llama.rn, ExecuTorch, MediaPipe, Gemini Nano) with no network egress of user data. A privacy-policy link alone does **not** count as a gate.
- **BYOK apps** (the user pastes their own provider key): the user chose the provider, so drop severity to Medium. A one-time disclosure of what is sent is still needed, because 5.1.2(i) has no BYOK exemption.
- **Fix:** a consent screen before the first AI request that names the provider and data types, stored as a flag that every AI client checks before it sends (put the check inside the client, not in the screen), plus a Settings toggle that revokes it. Reviewers look for this copy, so mention it in the App Review notes.
- **Related:** an "ATT prompt" is **not** AI consent. App Tracking Transparency covers cross-app tracking only.

## MG-R02 · Privacy manifest / privacy label contradicts what the code sends [iOS]

- **Rule:** Apple privacy manifest requirements (PrivacyInfo.xcprivacy) and App Store Connect privacy "nutrition label". Missing required-reason API declarations are reported at upload (ITMS-91053).
- **Trace:**
  1. **AI hosts in `NSPrivacyTrackingDomains` (Blocker).** iOS fails network requests to declared tracking domains until the user grants ATT, so the AI feature silently breaks for most users. AI providers belong there only if you really use them for tracking.
  2. **`NSPrivacyCollectedDataTypes`.** For each data type on a flow row, check for a matching entry: `NSPrivacyCollectedDataTypeOtherUserContent` for chat text, `...AudioData` for voice, `...PhotosorVideos`, `...Contacts`, `...Health`, `...PreciseLocation` or `...CoarseLocation`, plus `Linked` (true if tied to an account) and purpose (usually `NSPrivacyCollectedDataTypePurposeAppFunctionality`).
  3. **Required-reason APIs.** React Native core and many libraries use UserDefaults, file timestamps, system boot time, and disk space. Expo SDK 50+ merges these from `expo.ios.privacyManifests` in app.json.
- **Not a finding:** data processed fully on-device.
- **Fix:** produce the exact manifest entries, and the matching App Store Connect privacy-label answers, under "Store declarations" in the report.

## MG-R03 · Play Data safety form contradicts what the code sends [Android]

- **Rule:** Google Play User Data policy, Data safety section. A mismatch with observed behaviour leads to enforcement or an update rejection.
- **Trace:** list every data type sent to AI providers and AI-adjacent SDKs (analytics, crash reporting, voice): Messages (in-app messages), Other user-generated content, Voice or sound recordings, Photos, Files and docs, Contacts, Health info, Location.
- **Nuance:** a provider processing data **on your behalf** under a service-provider contract counts as **collected**, not **shared**. Data the provider may use for its own purposes (for example, training on consumer API terms) counts as **shared**. State which applies, or mark it needs-human.
- **Always needs-human:** the Console form itself. Output the answer sheet.

## MG-R04 · Generative output without moderation and in-app reporting [Both]

- **Rule:** Google Play AI-Generated Content policy requires in-app reporting or flagging of offensive AI output **without leaving the app**, and prevention of restricted content (CSAM, deceptive content, and so on). Apple 1.2 (UGC: filtering, reporting, blocking) and 4.7.1 (chatbots: "a method for filtering objectionable material, a mechanism to report content and timely responses to concerns").
- **Trace:** each surface showing generated text, images, or audio has (a) a report affordance reachable from the content itself (long-press, flag icon) that sends the report somewhere, and (b) an input/output safety layer: a provider moderation endpoint, Gemini `safetySettings`, Azure content filters, or a server-side classifier. A system prompt saying "be safe" is not a filter.
- **Also check:** the age rating matches unrestricted generation; image generation of real people (deepfakes, Play Deceptive Behavior); apps in the Kids category or Play Families that ship open-ended chat.
- **Not a finding:** AI used only for non-generative tasks (classification, OCR, ranking) with no free-form output shown to users.

## MG-R05 · Downloaded or generated code changes app functionality [iOS primary; Android variant]

- **Rule:** Apple 2.5.2: apps may not "download, install, or execute code which introduces or changes features or functionality of the app". Apple 4.7.2: apps may not "extend or expose native platform APIs or technologies to the software without prior permission from Apple". Google Play Device and Network Abuse: no downloading dex, JAR, or .so outside Play. Interpreted JS in a WebView is exempt but "must not allow potential violations of Google Play policies".
- **Trace (highest risk first):**
  1. Model output executed as code: `eval`, `new Function`, `JSContext.evaluateScript`, or `evaluateJavaScript`/`injectJavaScript` with generated strings.
  2. Generated mini-apps or HTML previews rendered in a WebView. This is the pattern Apple blocked for vibe-coding apps (Replit, Vibecode, Anything) in March 2026.
  3. A **native bridge** (`onMessage`, `addJavascriptInterface`, `WKScriptMessageHandler`, Flutter JS channels) reachable from generated content. That is 4.7.2 exposure and also MG-S05.
- **Calibrate:** enforcement tracks whether generated code acquires *app features* or *native capability*. Rendering generated `<script>` in sandboxed chat bubbles has passed review for some apps. Severity by tier:

  | Pattern | Severity |
  |---|---|
  | Generated code with native access (a bridge, or in-process `eval`) | Blocker |
  | Generated apps or previews with JS enabled by default, or an app-like runner | High |
  | User-tapped preview with JS enabled, behind a CSP, navigation pinned to `about:blank`, and no bridge | Medium, reviewer-dependent. Describe it in the App Review notes. |
  | Rendering with JS disabled | Advisory |
- **Fix:** open generated apps in Safari/`SFSafariViewController`/Custom Tabs on a hosted URL; render model output as text or sanitized markdown; set `javaScriptEnabled={false}` where scripts are not essential; remove bridges from any WebView showing model output.

## MG-R06 · AI capability shipped or hidden around review [Both; React Native/Expo critical]

- **Rule:** Apple 2.5.2 (above) and the Developer Program License Agreement's interpreted-code clause, which allows OTA updates of interpreted code only if they do not change the app's primary purpose or add features inconsistent with the reviewed app. Apple 2.3.1: no "hidden, dormant, or undocumented features". Apple 2.1: the reviewer must be able to exercise every feature.
- **Trace:**
  - **OTA updates** (`expo-updates`/EAS Update, `react-native-code-push`, hot-updater): check the update history and roadmap for new AI features, new providers, or new tools delivered as JS-only updates. Prompt or copy tweaks are fine; a new agent capability is not.
  - **Remote feature flags** that keep AI features off during review, or enable them by region or date after approval.
  - **BYOK or paywalled AI** with no reviewer path: the reviewer has no key, so the feature appears broken (2.1 App Completeness).
- **Fix:** ship capability changes through review; describe every AI feature in the App Review notes with demo credentials or a reviewer-funded key path; use flags only for gradual rollout of reviewed features.

## MG-R07 · AI credits or subscriptions sold outside platform billing [Both]

- **Rule:** Apple 3.1.1: unlocking features or functionality requires in-app purchase. Google Play Payments policy: digital goods use Google Play Billing.
- **Trace:** what unlocks AI usage (tokens, credits, premium models, message limits)? Look for Stripe (`@stripe/stripe-react-native`, PaymentSheet), web checkout links, or license-key entry.
- **Calibrate:** regional exceptions exist (US external purchase links on iOS since 2025, EU DMA alternatives, Play alternative-billing programs). These require entitlements or specific implementations, so mark needs-human rather than clear.
- **Not a finding:** BYOK where the user pays the provider directly and the app sells nothing.

## MG-R08 · Provider brand used as the app's identity [Both]

- **Rule:** Apple 4.1(c): "You cannot use another developer's icon, brand, or product name in your app's icon or name, without approval". Google Play Impersonation policy.
- **Trace:** app name, display name, Android label, store-listing metadata in the repo (fastlane `metadata/`), and icon assets for ChatGPT, GPT, OpenAI, Gemini, Claude, Copilot, or Grok.
- **Not a finding:** a factual mention in the description ("uses OpenAI models"), or the provider's own first-party app.

## MG-R09 · Thin wrapper around a model API [Both]

- **Rule:** Apple 4.2 Minimum Functionality ("elevate it beyond a repackaged website"), 4.3 Spam. Google Play Spam and Minimum Functionality.
- **Trace:** is the app a single chat screen forwarding text to one provider, with no domain features, native integration, or persistent value? Judge it from code and screens; mark it Medium unless the app is trivially thin.

## MG-R10 · Account deletion leaves AI data behind [Both]

- **Rule:** Apple 5.1.1(v): apps that support account creation must "offer account deletion within the app". Google Play requires in-app and web account-deletion paths that delete associated data.
- **Trace:** does deletion remove conversation history, uploaded files, embeddings and vector-store entries, voice recordings, and provider-side objects created on the user's behalf (Assistants threads, files, fine-tune data)? Does logout clear local AI history so the next user on the device does not inherit it?

## MG-R11 · Regulated advice without guardrails [Both]

- **Rule:** Apple 1.4.1 (medical apps get greater scrutiny; "remind users to check with a doctor"), 5.1.1(ix) (regulated fields). Google Play Health apps policy and financial-services policies.
- **Trace:** do system prompts or features position the AI as diagnosing, prescribing, giving dosage, or giving investment or legal advice? Is there disclaimer copy at the point of output and escalation guidance? Are health data flows (MG-S06) disclosed?

## MG-R12 · Permission purpose strings that hide the AI processor [Both]

- **Rule:** Apple 5.1.1 (purpose strings must clearly describe use). Google Play Permissions policy and the foreground-service type declarations required on Android 14+.
- **Trace:** for voice, camera, photos, and contacts feeding AI, the purpose string should say the data is sent for AI processing, and to whom if it is a third party. `SFSpeechRecognizer` needs `NSSpeechRecognitionUsageDescription`. Background voice on Android needs `FOREGROUND_SERVICE_MICROPHONE` plus a Play declaration. Look for permissions added transitively by libraries (for example `expo-av` adds `RECORD_AUDIO`) that the app never uses; remove them with `android.blockedPermissions`.
