// Copyright 2026 Jaspreet Singh
// Apache-2.0
//
// This file contains INTENTIONAL violations for MobileGuard test fixtures.
// Do NOT use this code in production.
//
// Expected violations:
//   AS-001 (CRITICAL) — fetch() to Anthropic API without disclosure
//   GP-001 (CRITICAL) — fetch() to Anthropic API without DATA_SAFETY
//   AS-002 (ERROR)    — Hardcoded API key in string literal
//   GP-002 (ERROR)    — Hardcoded API key (same, reported for both platforms)
//   OW-001 (CRITICAL) — User input in template literal sent to AI

// AS-002 / GP-002 violation: hardcoded API key
const API_KEY = 'sk-ant-api03-hardcoded-key-here';

// AS-001 / GP-001 violation: fetch to AI API without disclosure UI
// OW-001 violation: userMessage interpolated into system prompt template literal
async function sendToAI(userMessage) {
  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': API_KEY,
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-6',
      system: `You are a helpful assistant. User context: ${userMessage}`,
      messages: [{ role: 'user', content: `${userMessage}` }],
    }),
  });
  return response.json();
}
