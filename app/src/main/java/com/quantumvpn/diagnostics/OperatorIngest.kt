package com.quantumvpn.diagnostics

import android.content.Context
import com.quantumvpn.BuildConfig
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * Silent operator ingest for a private VDS/panel. Never exposed in user UI.
 * No-op unless [BuildConfig.OPERATOR_INGEST_URL] is configured at build time.
 */
object OperatorIngest {
    val configured: Boolean
        get() = BuildConfig.OPERATOR_INGEST_URL.isNotBlank()

    suspend fun postRedacted(
        context: Context,
        event: String,
        fields: Map<String, String>,
    ) {
        if (!configured) return
        withContext(Dispatchers.IO) {
            runCatching {
                val body = JSONObject().apply {
                    put("schema", 1)
                    put("event", event.take(64))
                    put("package", context.packageName)
                    put("version_name", BuildConfig.VERSION_NAME)
                    put("version_code", BuildConfig.VERSION_CODE)
                    put("ts", System.currentTimeMillis())
                    val payload = JSONObject()
                    fields.forEach { (k, v) ->
                        payload.put(k.take(40), SecretRedactor.redact(v).take(240))
                    }
                    put("fields", payload)
                }.toString()
                val connection = URL(BuildConfig.OPERATOR_INGEST_URL).openConnection() as HttpURLConnection
                try {
                    connection.requestMethod = "POST"
                    connection.connectTimeout = 4_000
                    connection.readTimeout = 4_000
                    connection.doOutput = true
                    connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
                    connection.setRequestProperty("X-Quantum-Operator", BuildConfig.OPERATOR_INGEST_TOKEN)
                    OutputStreamWriter(connection.outputStream, Charsets.UTF_8).use { it.write(body) }
                    connection.responseCode
                } finally {
                    connection.disconnect()
                }
            }
        }
    }
}
