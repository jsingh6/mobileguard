import WebKit

class ContentViewController: UIViewController {
    var webView = WKWebView()
    var aiResponse: String = ""

    // AS-007 violation: loading AI-generated HTML in WKWebView
    func displayAIContent() {
        webView.loadHTMLString(aiResponse, baseURL: nil)
    }

    // AS-007 violation: evaluating AI-generated JavaScript
    func runAICode(_ generatedCode: String) {
        webView.evaluateJavaScript(generatedCode, completionHandler: nil)
    }
}
