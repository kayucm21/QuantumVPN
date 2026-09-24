package com.quantumvpn.policy

import android.annotation.SuppressLint
import android.content.Context
import android.provider.Settings
import android.os.Build
import com.quantumvpn.BuildConfig
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/**
 * Polls RosPanel Client Control for the branded Android APK.
 * Base URL = BuildConfig.PANEL_UPDATE_BASE_URL (includes secret path).
 * Sends x-hwid (ANDROID_ID) so maintenance and access changes apply promptly.
 */
class ClientPolicyRepository(
    private val appContext: Context? = null,
    private val baseUrl: String = BuildConfig.PANEL_UPDATE_BASE_URL,
    private val scope: CoroutineScope,
) {
    private val mutable = MutableStateFlow(ClientPolicy())
    val policy: StateFlow<ClientPolicy> = mutable.asStateFlow()
    private var loop: Job? = null

    fun start(intervalMs: Long = 3_000L) {
        if (baseUrl.isBlank()) return
        if (loop?.isActive == true) return
        loop = scope.launch(Dispatchers.IO) {
            while (isActive) {
                refresh()
                delay(intervalMs)
            }
        }
    }

    fun stop() {
        loop?.cancel()
        loop = null
    }

    fun deviceSerial(): String = resolveAndroidId(appContext)

    suspend fun refresh(): ClientPolicy? = withContext(Dispatchers.IO) {
        if (baseUrl.isBlank()) return@withContext null
        try {
            val serial = deviceSerial()
            val url = URL("${baseUrl.trimEnd('/')}/api/client/policy?platform=android")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                connectTimeout = 12_000
                readTimeout = 20_000
                requestMethod = "GET"
                setRequestProperty("Accept", "application/json")
                if (serial.isNotBlank()) {
                    setRequestProperty("x-hwid", serial)
                    setRequestProperty("x-device-os", "android")
                    setRequestProperty("x-device-model", Build.MODEL.take(120))
                }
                instanceFollowRedirects = true
            }
            try {
                val code = conn.responseCode
                val stream = if (code in 200..299) conn.inputStream else conn.errorStream
                val body = stream?.use {
                    BufferedReader(InputStreamReader(it, StandardCharsets.UTF_8)).readText()
                }.orEmpty()
                if (code !in 200..299) return@withContext null
                val parsed = parsePolicy(body)
                mutable.value = parsed
                parsed
            } finally {
                conn.disconnect()
            }
        } catch (_: Exception) {
            null
        }
    }

    companion object {
        @SuppressLint("HardwareIds")
        fun resolveAndroidId(ctx: Context?): String {
            if (ctx == null) return ""
            return try {
                Settings.Secure.getString(ctx.contentResolver, Settings.Secure.ANDROID_ID).orEmpty()
            } catch (_: Exception) {
                ""
            }
        }

        fun parsePolicy(raw: String): ClientPolicy {
            val root = JSONObject(raw)
            val featuresObj = root.optJSONObject("features")
            val features = ClientFeatureFlags(
                vpnConnect = featuresObj?.optBoolean("vpn_connect", true) ?: true,
                killSwitch = featuresObj?.optBoolean("kill_switch", true) ?: true,
                splitTunnel = featuresObj?.optBoolean("split_tunnel", true) ?: true,
                routingEditor = featuresObj?.optBoolean("routing_editor", true) ?: true,
                importJson = featuresObj?.optBoolean("import_json", true) ?: true,
                autoConnect = featuresObj?.optBoolean("auto_connect", true) ?: true,
                adblock = featuresObj?.optBoolean("adblock", true) ?: true,
                vpnSchedule = featuresObj?.optBoolean("vpn_schedule", true) ?: true,
                autoFailover = featuresObj?.optBoolean("auto_failover", true) ?: true,
                safeMode = featuresObj?.optBoolean("safe_mode", true) ?: true,
                stealthMode = run {
                    val stealth = featuresObj?.optBoolean("stealth_mode", true) ?: true
                    val selfsteal = featuresObj?.optBoolean("selfsteal", true) ?: true
                    stealth || selfsteal
                },
                carrierBypass = featuresObj?.optBoolean("carrier_bypass", true) ?: true,
            )
            return ClientPolicy(
                platform = root.optString("platform", "android"),
                announce = root.optString("announce", ""),
                announceUntil = root.optLong("announce_until", 0L),
                minVersion = root.optString("min_version", ""),
                latestVersion = root.optString("latest_version", ""),
                versionCode = root.optLong("version_code", 0L),
                forceUpdate = root.optBoolean("force_update", false),
                updateUrl = root.optString("update_url", ""),
                sha256 = root.optString("sha256", ""),
                note = root.optString("note", ""),
                features = features,
                maintenance = root.optBoolean("maintenance", false),
                maintenanceMessage = root.optString("maintenance_message", ""),
                bannedSerials = stringList(root.optJSONArray("banned_serials")),
                bannedIps = stringList(root.optJSONArray("banned_ips")),
                banned = root.optBoolean("banned", false),
                adsListUrl = root.optString("ads_list_url", ""),
                adblockLevel = root.optString("adblock_level", ""),
            )
        }

        private fun stringList(arr: JSONArray?): List<String> {
            if (arr == null) return emptyList()
            val out = ArrayList<String>(arr.length())
            for (i in 0 until arr.length()) {
                val s = arr.optString(i, "")
                if (s.isNotBlank()) out.add(s)
            }
            return out
        }
    }
}
