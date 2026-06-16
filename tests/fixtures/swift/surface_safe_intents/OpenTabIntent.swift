import AppIntents

struct OpenTabIntent: AppIntent {
    static var title: LocalizedStringResource = "Open Tab"

    @Parameter(title: "URL")
    var urlString: String

    // Low risk: no sensitive data accessed, no confirmation needed
    func perform() async throws -> some IntentResult {
        return .result()
    }
}

struct SearchIntent: AppIntent {
    static var title: LocalizedStringResource = "Search"

    @Parameter(title: "Query")
    var query: String

    // Low risk: search only, no sensitive data
    func perform() async throws -> some IntentResult {
        return .result()
    }
}
