import SafariServices
import UIKit

class ContentViewController: UIViewController {
    // Safe pattern: Apple requires AI-generated content to open in external browser
    func showAIContent(url: URL) {
        let safari = SFSafariViewController(url: url)
        present(safari, animated: true)
    }

    // Safe pattern: opening in default browser
    func openInBrowser(url: URL) {
        UIApplication.shared.open(url)
    }
}
