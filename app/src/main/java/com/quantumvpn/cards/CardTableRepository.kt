package com.quantumvpn.cards

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.provider.Settings
import com.quantumvpn.BuildConfig
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** A device-bound snapshot of the two-player table maintained by Quantum Control. */
data class CardTableSnapshot(
    val tableId: String,
    val ticket: String = "",
    val state: String,
    val seat: String,
    val name: String,
    val opponentName: String,
    val message: String,
) {
    val waiting: Boolean get() = state == "waiting"
    val ready: Boolean get() = state == "ready"
}

/**
 * Secure, deliberately small client for the card-table lobby.
 *
 * The panel stores only a PBKDF2 hash of the access code. The code is kept in
 * Compose state while joining and is never written to SharedPreferences, logs,
 * diagnostics, or an APK resource. The returned ticket is both short-lived and
 * bound to this device by the operator panel.
 */
class CardTableRepository(context: Context) {
    private val app = context.applicationContext

    suspend fun join(accessCode: String, displayName: String): Result<CardTableSnapshot> =
        request("/api/client/cards/join", "POST", JSONObject()
            .put("access_code", accessCode)
            .put("display_name", displayName)
            .toString())

    suspend fun state(ticket: String): Result<CardTableSnapshot> {
        if (ticket.isBlank()) return Result.failure(IllegalArgumentException("Нет билета игрового стола"))
        return request("/api/client/cards/state?ticket=${java.net.URLEncoder.encode(ticket, "UTF-8")}", "GET")
    }

    private suspend fun request(path: String, method: String, body: String? = null): Result<CardTableSnapshot> =
        withContext(Dispatchers.IO) {
            runCatching {
                val base = BuildConfig.PANEL_UPDATE_BASE_URL.trim().trimEnd('/')
                check(base.isNotBlank()) { "Игровая панель не настроена" }
                val connection = (URL(base + path).openConnection() as HttpURLConnection).apply {
                    requestMethod = method
                    connectTimeout = 10_000
                    readTimeout = 15_000
                    setRequestProperty("Accept", "application/json")
                    setRequestProperty("X-Device-Id", androidIdHash())
                    setRequestProperty("X-HWID", androidIdHash())
                    setRequestProperty("X-Device-Model", Build.MODEL.take(120))
                    if (body != null) {
                        doOutput = true
                        setRequestProperty("Content-Type", "application/json; charset=utf-8")
                    }
                }
                try {
                    if (body != null) connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
                    val stream = if (connection.responseCode in 200..299) connection.inputStream else connection.errorStream
                    val raw = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
                    if (connection.responseCode !in 200..299) {
                        val message = runCatching { JSONObject(raw).optString("message") }.getOrDefault("")
                        error(message.ifBlank { "Не удалось открыть стол (HTTP ${connection.responseCode})" })
                    }
                    parseSnapshot(raw)
                } finally {
                    connection.disconnect()
                }
            }
        }

    private fun parseSnapshot(raw: String): CardTableSnapshot {
        val payload = JSONObject(raw)
        val tableId = payload.optString("table_id")
        require(tableId.matches(Regex("[a-f0-9]{12}"))) { "Панель вернула неверный игровой стол" }
        return CardTableSnapshot(
            tableId = tableId,
            ticket = payload.optString("ticket"),
            state = payload.optString("state", "waiting"),
            seat = payload.optString("seat"),
            name = payload.optString("name"),
            opponentName = payload.optString("opponent_name"),
            message = payload.optString("message"),
        )
    }

    @SuppressLint("HardwareIds")
    private fun androidIdHash(): String {
        val raw = Settings.Secure.getString(app.contentResolver, Settings.Secure.ANDROID_ID).orEmpty()
        return MessageDigest.getInstance("SHA-256")
            .digest(raw.toByteArray())
            .joinToString("") { "%02x".format(it) }
            .take(16)
    }
}
