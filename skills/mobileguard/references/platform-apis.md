# Native & Flutter API map

The source and sink APIs to trace for each check, per platform. React Native specifics are in [react-native.md](react-native.md).

| Check | Swift / iOS | Kotlin / Android | Dart / Flutter |
|---|---|---|---|
| **MG-S01** shipped secret | Literals, `.xcconfig`, `Bundle.main.object(forInfoDictionaryKey:)` | Literals, `buildConfigField`, `local.properties` → `BuildConfig`, `resValue` | Literals, `String.fromEnvironment`, `flutter_dotenv` with `.env` listed under `assets:` |
| **MG-S01** sanctioned | Firebase AI Logic + App Check (`AppAttestProvider`) | Firebase AI Logic + App Check (`PlayIntegrityAppCheckProviderFactory`) | `firebase_ai` + `firebase_app_check` |
| **MG-S04** output sinks | `WKWebView.loadHTMLString`, `evaluateJavaScript`, `callAsyncJavaScript`, `JSContext.evaluateScript`, `UIApplication.shared.open`, `AttributedString(markdown:)` links, `NSPredicate(format:)` with output | `WebView.loadData`/`loadDataWithBaseURL`, `evaluateJavascript`, `Intent.parseUri`, `startActivity` from generated URIs, `rawQuery`/`execSQL`, Compose `LinkAnnotation` handlers | `webview_flutter` `loadHtmlString`/`runJavaScript`, `url_launcher` `launchUrl`, `flutter_markdown` `onTapLink` / image builder |
| **MG-S05** bridges & tools | `WKScriptMessageHandler`, `AppIntent.perform()` (look for `requestConfirmation`, `authenticationPolicy`, `openAppWhenRun`), `AppShortcutsProvider` | `addJavascriptInterface` / `@JavascriptInterface`, `@AppFunction`, exported Activities/Services reachable via generated intents, `AccessibilityService` | `addJavaScriptChannel`, platform channels (`MethodChannel`) invoked from tool dispatch |
| **MG-S06** sensitive sources | `CNContactStore`, `HKHealthStore`, `CLLocationManager`, `PHPickerViewController` (EXIF), `UIPasteboard` | `ContactsContract`, Health Connect, `FusedLocationProviderClient`, `ClipboardManager`, MediaStore (EXIF) | `contacts_service`/`flutter_contacts`, `health`, `geolocator`, `image_picker` (EXIF), `Clipboard.getData` |
| **MG-S07** storage | `UserDefaults` (unsafe), Keychain (safe), `FileProtectionType.complete`, `isExcludedFromBackup` | `SharedPreferences` (unsafe), `EncryptedSharedPreferences`/Keystore, `allowBackup`, `dataExtractionRules` | `shared_preferences`/Hive (unsafe), `flutter_secure_storage` (safe) |
| **MG-S08** logs | `print`, `NSLog`, `os_log` with `.public` privacy | `Log.*`, Timber trees in release | `print`, `debugPrint`, `log` (kept in release) |
| **MG-S10** transport | `NSAppTransportSecurity` exceptions, `URLSessionDelegate` `didReceive challenge` accepting any trust | `usesCleartextTraffic`, `network_security_config` `cleartextTrafficPermitted`, trust-all `X509TrustManager`, `HostnameVerifier` returning true | `HttpClient.badCertificateCallback = (_,_,_) => true` |
| **MG-R02/R03** declarations | `PrivacyInfo.xcprivacy` (`NSPrivacyCollectedDataTypes`, `NSPrivacyAccessedAPITypes`, `NSPrivacyTrackingDomains`) | Play Data safety form (Console); `AndroidManifest.xml` permissions | Both of the above, via `ios/Runner/` and `android/app/src/main/` |
| **MG-R12** purpose strings | Info.plist `NS*UsageDescription` | Manifest permissions; `foregroundServiceType="microphone"` (Android 14+) | Same files under `ios/` and `android/` |

**On-device model APIs** (MG-R01 usually n/a, MG-S11 applies): Apple `FoundationModels`, Core ML, MLX; Android Gemini Nano via ML Kit GenAI / AICore, MediaPipe LLM Inference; Flutter `flutter_gemma`, `llama_cpp_dart`, `tflite_flutter`.
