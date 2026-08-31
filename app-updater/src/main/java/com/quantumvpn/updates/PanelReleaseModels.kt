package com.quantumvpn.updates

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull

/**
 * The RosPanel admin API publishes a single app release the client polls for auto-update.
 * Shape of GET <base>/api/app/version:
 *   { "version": "2.5.0", "version_code": 20500, "url": "https://.../app.apk",
 *     "sha256": "hex", "note": "known issue / fix" }
 *
 * Empty version/url means "no release published" — the caller treats that as up-to-date.
 */
data class PanelAppVersion(
    val version: String,
    val versionCode: Long,
    val url: String,
    val sha256: String,
    val note: String,
)

object PanelVersionJson {
    private val json = Json { isLenient = true; ignoreUnknownKeys = true }

    fun parse(raw: String): PanelAppVersion {
        val root = try {
            json.parseToJsonElement(raw)
        } catch (error: Exception) {
            throw UpdateException("Панель вернула некорректный JSON версии.", cause = error)
        } as? JsonObject ?: throw UpdateException("Панель вернула некорректный JSON версии.")
        return PanelAppVersion(
            version = (root["version"] as? JsonPrimitive)?.contentOrNull?.takeIf(String::isNotBlank).orEmpty(),
            versionCode = (root["version_code"] as? JsonPrimitive)?.intOrNull?.toLong() ?: 0L,
            url = (root["url"] as? JsonPrimitive)?.contentOrNull?.takeIf(String::isNotBlank).orEmpty(),
            sha256 = (root["sha256"] as? JsonPrimitive)?.contentOrNull?.lowercase().orEmpty(),
            note = (root["note"] as? JsonPrimitive)?.contentOrNull.orEmpty(),
        )
    }
}
