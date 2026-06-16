// Copyright 2026 Jaspreet Singh
// Apache-2.0
//
// This file contains INTENTIONAL violations for MobileGuard test fixtures.
// Do NOT use this code in production.
//
// Expected violations:
//   GP-001 (CRITICAL) — OkHttpClient to Anthropic API without data safety declaration
//   GP-002 (ERROR)    — Hardcoded Anthropic API key
//   OW-003 (ERROR)    — PII (email, phoneNumber) passed to external AI API

import okhttp3.*
import org.json.JSONObject

class AIService {
    // GP-002 violation: hardcoded API key in Kotlin source
    private val apiKey = "sk-ant-api03-hardcoded-key-here"

    // GP-001 violation: AI data transmission without data safety declaration
    // OW-003 violation: PII fields sent to external AI API
    fun analyzeUser(email: String, phoneNumber: String) {
        val client = OkHttpClient()
        val json = JSONObject()
        json.put("user_email", email)        // OW-003: PII sent to AI
        json.put("phone", phoneNumber)        // OW-003: PII sent to AI

        val mediaType = MediaType.parse("application/json")
        val body = RequestBody.create(mediaType, json.toString())
        val request = Request.Builder()
            .url("https://api.anthropic.com/v1/messages")
            .post(body)
            .addHeader("x-api-key", apiKey)
            .build()
        client.newCall(request).execute()
    }
}
