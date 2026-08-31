package com.quantumvpn.routing

import java.util.Calendar

/**
 * Lightweight time-based routing hint for UI simulator and optional direct-hour overlay.
 */
object TimeRoutingEvaluator {
    data class Window(
        val weekdaysOnly: Boolean = true,
        val startHour: Int = 9,
        val endHour: Int = 18,
    )

    fun isDirectWindow(now: Calendar = Calendar.getInstance(), window: Window = Window()): Boolean {
        val hour = now.get(Calendar.HOUR_OF_DAY)
        val day = now.get(Calendar.DAY_OF_WEEK)
        val weekday = day in Calendar.MONDAY..Calendar.FRIDAY
        if (window.weekdaysOnly && !weekday) return false
        return hour in window.startHour until window.endHour
    }

    fun actionForDomain(
        domain: String,
        enabled: Boolean,
        window: Window = Window(),
    ): String? {
        if (!enabled) return null
        if (!isDirectWindow(window = window)) return null
        val ru = domain.endsWith(".ru") || domain.endsWith(".su") || domain.endsWith(".рф")
        return if (ru) "Напрямую (рабочие часы)" else null
    }
}
