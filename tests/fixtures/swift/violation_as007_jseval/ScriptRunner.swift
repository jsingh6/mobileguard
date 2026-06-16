import JavaScriptCore
import WebKit

class ScriptRunner: NSObject {
    let webView = WKWebView()
    let jsContext = JSContext()

    // AS-007 violation: evaluating AI-generated JavaScript in WKWebView
    func runInWebView(_ script: String) {
        webView.evaluateJavaScript(script, completionHandler: nil)
    }

    // AS-007 violation: evaluating AI-generated script in JSContext
    func runInContext(_ generatedCode: String) {
        jsContext?.evaluateScript(generatedCode)
    }
}
