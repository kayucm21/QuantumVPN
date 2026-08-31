package com.quantumvpn.diagnostics

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.quantumvpn.vpn.VpnConnectionState
import com.quantumvpn.vpn.VpnSessionStats

data class WhySlowReport(
    val title: String,
    val points: List<String>,
) {
    val summary: String get() = (listOf(title) + points).joinToString("\n• ", postfix = "")
}

object WhySlowDiagnoser {
    fun diagnose(
        context: Context,
        vpnState: VpnConnectionState,
        stats: VpnSessionStats,
        killSwitch: Boolean,
        powerModeName: String,
    ): WhySlowReport {
        val points = mutableListOf<String>()
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val caps = cm.activeNetwork?.let(cm::getNetworkCapabilities)
        val metered = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == false
        val validated = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
        val wifi = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        val cell = caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true

        when (vpnState) {
            is VpnConnectionState.Connected -> points += "VPN активен (${vpnState.profileName})."
            is VpnConnectionState.Starting -> points += "VPN ещё подключается."
            is VpnConnectionState.Stopping -> points += "VPN отключается."
            is VpnConnectionState.Error -> points += "Ошибка VPN: ${vpnState.message.take(120)}"
            else -> points += "VPN выключен — замер без туннеля."
        }

        stats.pingMillis?.let { ping ->
            when {
                ping > 250 -> points += "Высокий пинг ${ping} ms — смените сервер или регион."
                ping > 120 -> points += "Пинг ${ping} ms выше комфортного."
                else -> points += "Пинг ${ping} ms в норме."
            }
        } ?: points.add("Пинг ещё не измерен — нажмите «Проверить пинг».")

        if (!validated) points += "Android не подтвердил валидность сети (captive / DNS)."
        if (metered) points += "Сеть тарифицируемая — возможны ограничения оператора."
        if (cell) points += "Сотовая сеть: джиттер выше, чем на Wi‑Fi."
        if (wifi) points += "Wi‑Fi активен."
        // Captive portal heuristic: Wi‑Fi without validated internet.
        if (wifi && !validated) {
            points += "Похоже на captive portal: откройте браузер и пройдите Wi‑Fi авторизацию, затем подключите VPN снова."
        }
        if (killSwitch) points += "Kill switch включён — при обрыве VPN интернет будет нулевым."
        if (powerModeName == "Battery") {
            points += "Режим батареи (MTU нормализован) — для скорости выберите «Скорость»."
        }
        stats.exitLocation?.let { points += "Выход: ${it.displayLabel}." }

        val title = when {
            points.any { "Высокий пинг" in it || "Ошибка" in it } -> "Похоже на узкое место"
            points.any { "не подтвердил" in it } -> "Проблема с сетью Android"
            else -> "Диагностика скорости"
        }
        return WhySlowReport(title, points)
    }
}
