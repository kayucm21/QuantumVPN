package com.quantumvpn.routing

import java.net.IDN
import java.util.Locale

object HomographGuard {
  private val confusables = setOf(
      'а', 'е', 'о', 'р', 'с', 'у', 'х', 'і', 'ј', 'ѕ',
      'Α', 'Β', 'Ε', 'Η', 'Ι', 'Κ', 'Μ', 'Ν', 'Ο', 'Ρ', 'Τ', 'Υ', 'Χ',
  )

    fun warning(domain: String): String? {
        val trimmed = domain.trim().lowercase(Locale.ROOT)
        if (trimmed.isBlank()) return null
        val hasCyrillic = trimmed.any { it in '\u0400'..'\u04FF' }
        val hasLatin = trimmed.any { it in 'a'..'z' }
        if (hasCyrillic && hasLatin) {
            return "Смешанная кириллица и латиница — возможен homograph/IDN обман."
        }
        val ascii = runCatching {
            IDN.toUnicode(trimmed, IDN.ALLOW_UNASSIGNED)
        }.getOrDefault(trimmed)
        if (ascii != trimmed && trimmed.any { it in confusables }) {
            return "Домен содержит похожие символы (IDN/homograph)."
        }
        return null
    }
}
