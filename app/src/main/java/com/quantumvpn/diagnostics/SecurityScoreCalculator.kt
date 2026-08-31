package com.quantumvpn.diagnostics

import com.quantumvpn.ui.UiSettings
import com.quantumvpn.vpn.VpnConnectionState
import com.quantumvpn.vpn.VpnSessionStats

data class SecurityScore(
    val score: Int,
    val grade: String,
    val tips: List<String>,
) {
    val summary: String get() = "Безопасность $score/100 ($grade)"
}

object SecurityScoreCalculator {
    fun compute(
        vpnState: VpnConnectionState,
        settings: UiSettings,
        stats: VpnSessionStats,
    ): SecurityScore {
        var score = 40
        val tips = mutableListOf<String>()
        when (vpnState) {
            is VpnConnectionState.Connected -> score += 35
            is VpnConnectionState.Starting -> score += 10
            is VpnConnectionState.Error -> {
                score -= 10
                tips += "Устраните ошибку VPN перед оценкой защиты."
            }
            else -> tips += "Включите VPN, чтобы поднять оценку."
        }
        if (settings.blockNonVpnTraffic) score += 15 else tips += "Включите kill switch."
        if (settings.vpnHiding.blockLocalEndpoints) score += 5 else tips += "Включите блокировку localhost API."
        if (settings.appLockEnabled) score += 5 else tips += "Включите блокировку настроек."
        if (settings.dnsOverride.enabled) score += 5
        if (stats.externalIp != null) score += 5
        score = score.coerceIn(0, 100)
        val grade = when {
            score >= 90 -> "A"
            score >= 75 -> "B"
            score >= 60 -> "C"
            score >= 40 -> "D"
            else -> "E"
        }
        return SecurityScore(score, grade, tips.take(4))
    }
}
