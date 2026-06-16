import AppIntents

struct SendPaymentIntent: AppIntent {
    static var title: LocalizedStringResource = "Send Payment"

    @Parameter(title: "Amount")
    var amount: Double

    @Parameter(title: "Recipient")
    var recipient: String

    // AABE-001: no requestConfirmation() before financial action
    func perform() async throws -> some IntentResult {
        PaymentService.shared.sendPayment(amount: amount, to: recipient)
        return .result()
    }
}

struct OpenTabIntent: AppIntent {
    static var title: LocalizedStringResource = "Open Tab"

    // Low risk: no sensitive data, no confirmation needed
    func perform() async throws -> some IntentResult {
        return .result()
    }
}
