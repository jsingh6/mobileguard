// Copyright 2026 Jaspreet Singh
// Apache-2.0
//
// This file contains INTENTIONAL violations for MobileGuard test fixtures.
// Do NOT use this code in production.
//
// Expected violations:
//   AS-001 (CRITICAL) — http.post to Anthropic API without disclosure
//   GP-001 (CRITICAL) — http.post to Anthropic API without DATA_SAFETY
//   AS-002 (ERROR)    — Hardcoded API key
//   GP-002 (ERROR)    — Hardcoded API key (same, reported for both platforms)
//   OW-001 (CRITICAL) — User input in string interpolation

import 'dart:convert';
import 'package:http/http.dart' as http;

class AIService {
  // AS-002 / GP-002 violation: hardcoded API key
  final String apiKey = 'sk-ant-api03-hardcoded-key-here';

  Future<String> sendMessage(String userMessage) async {
    // AS-001 / GP-001 violation: AI data transmission without disclosure
    // OW-001 violation: user input interpolated into system prompt
    final response = await http.post(
      Uri.parse('https://api.anthropic.com/v1/messages'),
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
      },
      body: jsonEncode({
        'model': 'claude-sonnet-4-6',
        'system': 'You are helpful. Context: ${userMessage}',
        'messages': [
          {'role': 'user', 'content': '${userMessage}'}
        ],
      }),
    );
    return response.body;
  }
}
