package com.quantumvpn.routing

import android.net.Uri

object ShareRouting {
    private val DOMAIN = Regex("""^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}$""")

    fun extractDomain(text: String): String? {
        val line = text.trim().lineSequence().firstOrNull { it.isNotBlank() }?.trim().orEmpty()
        if (line.isBlank()) return null
        if (line.contains("[Interface]", ignoreCase = true)) return null
        val host = runCatching { Uri.parse(line).host }.getOrNull()
            ?.removePrefix("www.")
            ?.takeIf { DOMAIN.matches(it) }
        if (host != null) return host
        val bare = line.removePrefix("www.")
        return bare.takeIf { DOMAIN.matches(it) }
    }
}
