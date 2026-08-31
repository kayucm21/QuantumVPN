package com.quantumvpn.ui

import com.quantumvpn.routing.TimeRoutingEvaluator

/**
 * Lightweight domain→route simulator for Settings (uses current preset text only).
 */
object RouteSimulator {
    data class Result(val domain: String, val action: String, val detail: String)

    fun simulate(
        domainRaw: String,
        presetTitle: String?,
        summary: String?,
        timeRoutingEnabled: Boolean = false,
    ): Result {
        val domain = domainRaw.trim().lowercase().removePrefix("http://").removePrefix("https://")
            .substringBefore('/').substringBefore(':')
        if (domain.isBlank()) {
            return Result("", "—", "Введите домен, например youtube.com")
        }
        val timeDirect = TimeRoutingEvaluator.actionForDomain(domain, timeRoutingEnabled)
        val ru = domain.endsWith(".ru") || domain.endsWith(".su") || domain.endsWith(".рф")
        val ad = listOf("doubleclick", "googlesyndication", "adservice", "adsystem")
            .any { it in domain }
        val action = when {
            timeDirect != null -> timeDirect
            ad && (presetTitle?.contains("реклам", true) == true ||
                presetTitle?.contains("Семей", true) == true) -> "Блокировать"
            ru && presetTitle?.contains("Россия напрямую", true) == true -> "Напрямую"
            ru && presetTitle?.contains("Россия через VPN", true) == true -> "Через VPN"
            presetTitle?.contains("Всё через VPN", true) == true -> "Через VPN"
            presetTitle?.contains("Только выбранные", true) == true -> "Напрямую (если нет правила)"
            else -> "Через VPN (по умолчанию профиля)"
        }
        return Result(
            domain = domain,
            action = action,
            detail = summary?.take(160) ?: (presetTitle ?: "Пресет не выбран"),
        )
    }

    fun simulateBatch(
        raw: String,
        presetTitle: String?,
        summary: String?,
        timeRoutingEnabled: Boolean = false,
    ): List<Result> =
        raw.lines()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .take(50)
            .map { line -> simulate(line, presetTitle, summary, timeRoutingEnabled) }
}
