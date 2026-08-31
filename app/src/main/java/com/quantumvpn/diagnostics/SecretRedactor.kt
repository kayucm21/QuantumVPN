package com.quantumvpn.diagnostics

import com.quantumvpn.config.JsonConfig
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

object SecretRedactor {
    const val MASK = "•••"

    fun redact(text: String): String {
        val jsonRedacted = runCatching {
            JsonConfig.format(redactElement(JsonConfig.parse(text)))
        }.getOrNull()
        return redactInline(jsonRedacted ?: text)
    }

    fun redactInline(text: String): String {
        var result = text
        result = URL_USER_INFO.replace(result) { match -> "${match.groupValues[1]}$MASK@" }
        result = URL_QUERY.replace(result) { match -> "${match.groupValues[1]}?$MASK" }
        result = HEADER_SECRET.replace(result) { match ->
            "${match.groupValues[1]}${match.groupValues[2]}$MASK"
        }
        result = BEARER_SECRET.replace(result, "Bearer $MASK")
        result = KEY_VALUE_SECRET.replace(result) { match -> "${match.groupValues[1]}$MASK" }
        result = UUID.replace(result, MASK)
        result = JSON_SECRET.replace(result) { match ->
            "${match.groupValues[1]}$MASK${match.groupValues[3]}"
        }
        return result
    }

    private fun redactElement(element: JsonElement, key: String? = null): JsonElement {
        if (key != null && key.lowercase() in SECRET_KEYS) return JsonPrimitive(MASK)
        return when (element) {
            is JsonObject -> JsonObject(element.mapValues { (childKey, child) ->
                redactElement(child, childKey)
            })
            is JsonArray -> JsonArray(element.map { redactElement(it) })
            else -> element
        }
    }

    private val SECRET_KEYS = setOf(
        "uuid",
        "password",
        "token",
        "access_token",
        "authorization",
        "auth",
        "private_key",
        "client_secret",
        "obfs_password",
    )
    private val URL_USER_INFO = Regex("(?i)([a-z][a-z0-9+.-]*://)([^/@\\s]+)@")
    private val URL_QUERY = Regex(
        "(?i)([a-z][a-z0-9+.-]*://[^\\s?#\\\"]+)\\?[^\\s#\\\"\\\\},]+",
    )
    private val HEADER_SECRET = Regex(
        "(?i)\\b(token|password|passwd|secret|authorization|auth|uuid)(\\s*:\\s*)" +
            "(?:bearer\\s+)?[^\\s,;\\\"\\\\}]+",
    )
    private val BEARER_SECRET = Regex("(?i)\\bbearer\\s+[a-z0-9._~+/-]+=*")
    private val UUID = Regex("(?i)\\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\\b")
    private val KEY_VALUE_SECRET = Regex(
        "(?i)((?:token|password|passwd|secret|authorization|auth|uuid)=)" +
            "[^&\\s#\\\"\\\\},;]+",
    )
    private val JSON_SECRET = Regex(
        "(?i)(\\\"(?:uuid|password|token|access_token|authorization|auth|private_key|client_secret)\\\"\\s*:\\s*\\\")(.*?)(\\\")",
    )
}
