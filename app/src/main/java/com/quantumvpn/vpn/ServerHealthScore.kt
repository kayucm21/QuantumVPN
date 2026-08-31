package com.quantumvpn.vpn

/**
 * Lightweight server health score from ping samples (0..100, higher is better).
 */
object ServerHealthScore {
    fun score(pingMillis: Int?, failStreak: Int = 0): Int {
        if (pingMillis == null) return (20 - failStreak * 5).coerceAtLeast(0)
        val latency = when {
            pingMillis <= 40 -> 100
            pingMillis <= 80 -> 90
            pingMillis <= 120 -> 80
            pingMillis <= 180 -> 70
            pingMillis <= 250 -> 55
            pingMillis <= 400 -> 40
            else -> 25
        }
        return (latency - failStreak * 8).coerceIn(0, 100)
    }

    fun label(score: Int): String = when {
        score >= 85 -> "Отлично"
        score >= 70 -> "Хорошо"
        score >= 50 -> "Средне"
        score >= 30 -> "Слабо"
        else -> "Плохо"
    }
}
