package com.quantumvpn.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.telephony.TelephonyManager

/** Lightweight MCC/MNC hints for carrier-specific DPI mitigations. */
object CarrierDetector {
    data class Snapshot(
        val operatorNumeric: String?,
        val operatorName: String?,
        val isCellular: Boolean,
        val isTele2Family: Boolean,
        val suggestsStrongBypass: Boolean,
        val displayLabel: String?,
    )

    fun snapshot(context: Context): Snapshot {
        val tm = context.getSystemService(TelephonyManager::class.java)
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val caps = cm?.activeNetwork?.let(cm::getNetworkCapabilities)
        val isCellular = caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true
        val numeric = tm?.networkOperator?.takeIf { it.length >= 5 }
        val name = tm?.networkOperatorName?.takeIf { it.isNotBlank() }
        val tele2 = isTele2Family(numeric, name)
        val family = operatorFamily(numeric, name)
        val strong = tele2 || family in setOf("mts", "beeline", "megafon", "yota", "sber", "tele2")
        val label = when {
            !name.isNullOrBlank() -> name
            family == "tele2" -> "Т2/Tele2"
            family != null -> family.uppercase()
            isCellular -> "мобильная сеть"
            else -> null
        }
        return Snapshot(
            operatorNumeric = numeric,
            operatorName = name,
            isCellular = isCellular,
            isTele2Family = tele2,
            suggestsStrongBypass = isCellular && strong,
            displayLabel = label,
        )
    }

    /** Russia Tele2 / t2.ru and common rebrands. */
    fun isTele2Family(numeric: String?, name: String?): Boolean {
        if (numeric != null && numeric.startsWith("25020")) return true
        val n = name?.lowercase().orEmpty()
        return n.contains("tele2") ||
            n.contains("теле2") ||
            Regex("""(?:^|[^a-zа-я0-9])(?:t2|т2)(?:[^a-zа-я0-9]|$)""").containsMatchIn(n)
    }

    fun operatorFamily(numeric: String?, name: String?): String? {
        if (isTele2Family(numeric, name)) return "tele2"
        val n = name?.lowercase().orEmpty()
        when {
            n.contains("мтс") || n.contains("mts") -> return "mts"
            n.contains("билайн") || n.contains("beeline") -> return "beeline"
            n.contains("мегафон") || n.contains("megafon") -> return "megafon"
            n.contains("yota") || n.contains("йота") -> return "yota"
            n.contains("сбер") || n.contains("sber") -> return "sber"
        }
        if (numeric != null) {
            when {
                numeric.startsWith("25001") -> return "mts"
                numeric.startsWith("25002") -> return "megafon"
                numeric.startsWith("25099") -> return "beeline"
                numeric.startsWith("25020") -> return "tele2"
            }
        }
        return null
    }
}
