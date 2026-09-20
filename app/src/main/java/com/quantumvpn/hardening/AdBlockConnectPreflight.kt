package com.quantumvpn.hardening

import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import com.quantumvpn.ui.UiSettingsStore
import kotlinx.coroutines.flow.first

/**
 * Перед подключением VPN выставляет рабочий профиль блокировки рекламы:
 * Maximum + AdGuard DoH, Safe mode выкл., попытка смягчить Strict Private DNS.
 *
 * Android не даёт обычному приложению менять Private DNS без WRITE_SECURE_SETTINGS —
 * тогда открываем системный экран Private DNS.
 */
object AdBlockConnectPreflight {
    data class Result(
        val settingsApplied: Boolean,
        val adBlockEnabled: Boolean,
        val level: AdBlockLevel,
        val onlineDns: Boolean,
        val safeModeOff: Boolean,
        val privateDnsMode: String?,
        val privateDnsFixed: Boolean,
        val openedPrivateDnsSettings: Boolean,
        val tip: String,
    )

    suspend fun prepare(
        context: Context,
        settingsStore: UiSettingsStore,
        openPrivateDnsSettingsIfStrict: Boolean = true,
    ): Result {
        val before = settingsStore.settings.first()
        settingsStore.setAdBlockEnabled(true)
        // Standard + filtered DNS protects the whole TUN session without the
        // compatibility regressions of the most aggressive domain lists.
        settingsStore.setAdBlockLevel(AdBlockLevel.Standard)
        settingsStore.setAdBlockOnlineDns(true)
        settingsStore.setAdBlockTrackersOnly(false)
        settingsStore.setSafeModeConnect(false)

        val dnsMode = readPrivateDnsMode(context)
        var fixed = false
        var opened = false
        if (isStrictPrivateDns(dnsMode)) {
            fixed = trySetPrivateDnsOpportunistic(context)
            if (!fixed && openPrivateDnsSettingsIfStrict) {
                opened = openPrivateDnsSettings(context)
            }
        }

        val tip = buildString {
            append("Ad-block: Стандарт + AdGuard DoH · Safe mode выкл.")
            when {
                fixed -> append(" · Private DNS → Автоматически")
                opened -> append(" · Откройте Private DNS: Автоматически или Выкл.")
                isStrictPrivateDns(dnsMode) ->
                    append(" · Private DNS Strict мешает — поставьте Автоматически/Выкл.")
                else -> Unit
            }
        }

        return Result(
            settingsApplied = !before.adBlockEnabled ||
                before.adBlockLevel != AdBlockLevel.Standard ||
                !before.adBlockOnlineDns ||
                before.safeModeConnect ||
                before.adBlockTrackersOnly,
            adBlockEnabled = true,
            level = AdBlockLevel.Standard,
            onlineDns = true,
            safeModeOff = true,
            privateDnsMode = dnsMode,
            privateDnsFixed = fixed,
            openedPrivateDnsSettings = opened,
            tip = tip,
        )
    }

    fun readPrivateDnsMode(context: Context): String? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return "off"
        return runCatching {
            Settings.Global.getString(context.contentResolver, "private_dns_mode")
        }.getOrNull()?.lowercase()
    }

    fun isStrictPrivateDns(mode: String?): Boolean =
        mode == "hostname" || mode == "provider_hostname"

    /** Требует WRITE_SECURE_SETTINGS — на обычных устройствах вернёт false. */
    fun trySetPrivateDnsOpportunistic(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return true
        return runCatching {
            val cr = context.contentResolver
            Settings.Global.putString(cr, "private_dns_mode", "opportunistic")
            val after = Settings.Global.getString(cr, "private_dns_mode")?.lowercase()
            after == "opportunistic" || after == "off"
        }.getOrDefault(false)
    }

    fun openPrivateDnsSettings(context: Context): Boolean {
        val flags = Intent.FLAG_ACTIVITY_NEW_TASK
        val candidates = listOf(
            Intent("android.settings.PRIVATE_DNS_SETTINGS").addFlags(flags),
            Intent(Settings.ACTION_WIRELESS_SETTINGS).addFlags(flags),
            Intent(Settings.ACTION_SETTINGS).addFlags(flags),
        )
        for (intent in candidates) {
            val ok = runCatching {
                context.startActivity(intent)
                true
            }.getOrDefault(false)
            if (ok) return true
        }
        return false
    }
}
