package com.quantumvpn.donations

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.provider.Settings
import com.quantumvpn.BuildConfig
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

data class DonationEntry(
    val amountRub: Int,
    val ts: Long,
    val label: String = "",
)

data class DonationSummary(
    val totalRub: Int = 0,
    val count: Int = 0,
    val recent: List<DonationEntry> = emptyList(),
    val mineServer: List<DonationEntry> = emptyList(),
)

/** Local history + optional sync to the operator panel (anonymous device hash). */
class DonationRepository(context: Context) {
    private val app = context.applicationContext
    private val prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun localHistory(): List<DonationEntry> {
        val raw = prefs.getString(KEY_HISTORY, "[]").orEmpty()
        return runCatching {
            val arr = JSONArray(raw)
            buildList {
                for (i in 0 until arr.length()) {
                    val o = arr.optJSONObject(i) ?: continue
                    add(
                        DonationEntry(
                            amountRub = o.optInt("amount_rub", 0),
                            ts = o.optLong("ts", 0L),
                            label = o.optString("label", ""),
                        ),
                    )
                }
            }.sortedByDescending { it.ts }
        }.getOrDefault(emptyList())
    }

    fun localTotalRub(): Int = localHistory().sumOf { it.amountRub.coerceAtLeast(0) }

    fun rememberLocal(amountRub: Int, label: String = ""): List<DonationEntry> {
        val amount = amountRub.coerceIn(1, 1_000_000)
        val next = listOf(DonationEntry(amount, System.currentTimeMillis(), label)) + localHistory()
        val trimmed = next.take(MAX_LOCAL)
        val arr = JSONArray()
        trimmed.forEach { entry ->
            arr.put(
                JSONObject()
                    .put("amount_rub", entry.amountRub)
                    .put("ts", entry.ts)
                    .put("label", entry.label),
            )
        }
        prefs.edit().putString(KEY_HISTORY, arr.toString()).apply()
        return trimmed
    }

    suspend fun fetchSummary(): DonationSummary = withContext(Dispatchers.IO) {
        val base = BuildConfig.PANEL_UPDATE_BASE_URL.trim().trimEnd('/')
        if (base.isBlank()) return@withContext DonationSummary()
        runCatching {
            val connection = open(base + "/api/client/donations", "GET")
            try {
                check(connection.responseCode in 200..299) { "HTTP ${connection.responseCode}" }
                parseSummary(connection.inputStream.bufferedReader().readText())
            } finally {
                connection.disconnect()
            }
        }.getOrDefault(DonationSummary())
    }

    suspend fun reportDonation(amountRub: Int, note: String = ""): Result<DonationSummary> =
        withContext(Dispatchers.IO) {
            runCatching {
                val base = BuildConfig.PANEL_UPDATE_BASE_URL.trim().trimEnd('/')
                check(base.isNotBlank()) { "Панель не настроена" }
                val amount = amountRub.coerceIn(1, 1_000_000)
                rememberLocal(amount, note)
                val body = JSONObject()
                    .put("amount_rub", amount)
                    .put("note", note.take(80))
                    .put("app_version", BuildConfig.VERSION_NAME)
                    .toString()
                    .toByteArray(Charsets.UTF_8)
                val connection = open(base + "/api/client/donations", "POST")
                try {
                    connection.doOutput = true
                    connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
                    connection.outputStream.use { it.write(body) }
                    check(connection.responseCode in 200..299) { "HTTP ${connection.responseCode}" }
                    parseSummary(connection.inputStream.bufferedReader().readText())
                } finally {
                    connection.disconnect()
                }
            }
        }

    private fun open(url: String, method: String): HttpURLConnection {
        return (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 12_000
            readTimeout = 20_000
            setRequestProperty("Accept", "application/json")
            setRequestProperty("x-device-model", Build.MODEL.take(120))
            setRequestProperty("x-hwid", androidIdHash())
            setRequestProperty("X-Device-Id", androidIdHash())
        }
    }

    private fun parseSummary(raw: String): DonationSummary {
        val root = JSONObject(raw)
        return DonationSummary(
            totalRub = root.optInt("total_rub", 0),
            count = root.optInt("count", 0),
            recent = parseList(root.optJSONArray("recent")),
            mineServer = parseList(root.optJSONArray("mine")),
        )
    }

    private fun parseList(arr: JSONArray?): List<DonationEntry> {
        if (arr == null) return emptyList()
        return buildList {
            for (i in 0 until arr.length()) {
                val o = arr.optJSONObject(i) ?: continue
                add(
                    DonationEntry(
                        amountRub = o.optInt("amount_rub", 0),
                        ts = o.optLong("ts", 0L) * 1000L,
                        label = o.optString("label", o.optString("note", "")),
                    ),
                )
            }
        }
    }

    @SuppressLint("HardwareIds")
    private fun androidIdHash(): String {
        val raw = Settings.Secure.getString(app.contentResolver, Settings.Secure.ANDROID_ID).orEmpty()
        return MessageDigest.getInstance("SHA-256")
            .digest(raw.toByteArray())
            .joinToString("") { "%02x".format(it) }
            .take(16)
    }

    companion object {
        const val YOOMONEY_BUTTON_URL =
            "https://yoomoney.ru/quickpay/fundraise/button?billNumber=1KF196EER0I.260922&"
        const val YOOMONEY_PAGE_URL =
            "https://yoomoney.ru/quickpay/fundraise/button?billNumber=1KF196EER0I.260922&sum=0"

        private const val PREFS = "quantum_donations"
        private const val KEY_HISTORY = "history_json"
        private const val MAX_LOCAL = 40

        fun formatRub(amount: Int): String = "%,d ₽".format(Locale("ru", "RU"), amount).replace(',', ' ')

        fun formatWhen(tsMillis: Long): String {
            if (tsMillis <= 0L) return "—"
            return SimpleDateFormat("dd.MM.yyyy HH:mm", Locale("ru", "RU")).format(Date(tsMillis))
        }
    }
}
