package com.quantumvpn.ui

/** Lightweight, on-device privacy score used by the Horizon Glass dashboard. */
object PrivacyScore {
    fun calculate(
        vpnConnected: Boolean,
        adBlockEnabled: Boolean,
        killSwitchEnabled: Boolean,
        secureDnsEnabled: Boolean,
        autoFailoverEnabled: Boolean,
        unknownWifiProtection: Boolean,
    ): Int {
        var score = 0
        if (vpnConnected) score += 35
        if (adBlockEnabled) score += 15
        if (killSwitchEnabled) score += 15
        if (secureDnsEnabled) score += 15
        if (autoFailoverEnabled) score += 10
        if (unknownWifiProtection) score += 10
        return score.coerceIn(0, 100)
    }

    fun label(score: Int): String = when {
        score >= 85 -> "Отличная защита"
        score >= 65 -> "Хорошая защита"
        score >= 40 -> "Есть что усилить"
        else -> "Защита выключена"
    }
}
