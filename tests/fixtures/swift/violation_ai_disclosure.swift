// Copyright 2026 Jaspreet Singh
// Apache-2.0
//
// This file contains INTENTIONAL violations for MobileGuard test fixtures.
// Do NOT use this code in production.
//
// Expected violations:
//   AS-001 (CRITICAL) — URLSession to Anthropic API without disclosure view
//   AS-002 (ERROR)    — Hardcoded Anthropic API key
//   EU-001 (CRITICAL) — AI call without transparency label
//   OW-001 (CRITICAL) — User input interpolated directly into system prompt

import Foundation

class NetworkManager {
    func sendToAI(userMessage: String) {
        // AS-001 violation: sending to Anthropic API without disclosure
        var request = URLRequest(url: URL(string: "https://api.anthropic.com/v1/messages")!)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        // OW-001 violation: user input directly in system prompt string interpolation
        let body = """
        {
          "model": "claude-sonnet-4-6",
          "system": "You are a helpful assistant. User context: \(userMessage)",
          "messages": [{"role": "user", "content": "\(userMessage)"}]
        }
        """
        request.httpBody = body.data(using: .utf8)
        URLSession.shared.dataTask(with: request).resume()
    }

    // AS-002 violation: hardcoded API key in source code
    let apiKey = "sk-ant-api03-hardcoded-key-here"
}
