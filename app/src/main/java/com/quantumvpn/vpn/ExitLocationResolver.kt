package com.quantumvpn.vpn

/**
 * Best-effort exit location for the Home "Browsing safely from" card.
 * Prefers live VPN geo lookup; falls back to clues in the server label.
 */
data class ExitLocation(
    val countryName: String,
    val countryCode: String? = null,
    val flagEmoji: String? = null,
) {
    val displayLabel: String
        get() = listOfNotNull(flagEmoji, countryName).joinToString(" ")
}

object ExitLocationResolver {
    fun fromGeo(countryName: String?, countryCode: String?): ExitLocation? {
        val name = countryName?.trim()?.takeIf { it.isNotEmpty() && !it.equals("Unknown", true) }
            ?: countryCode?.trim()?.takeIf { it.length == 2 }?.uppercase()
            ?: return null
        val code = countryCode?.trim()?.takeIf { it.length == 2 }?.uppercase()
        return ExitLocation(
            countryName = name,
            countryCode = code,
            flagEmoji = code?.let(::flagEmoji),
        )
    }

    fun fromServerLabel(label: String?): ExitLocation? {
        if (label.isNullOrBlank()) return null
        val text = label.trim()
        FLAG_EMOJI.find(text)?.value?.let { flag ->
            val withoutFlag = text.replace(flag, "").trim(' ', '-', '_', '|', '·', '•')
            val name = withoutFlag.takeIf { it.isNotEmpty() }
                ?: COUNTRY_BY_CODE[flagToCode(flag)]
                ?: "Сервер"
            return ExitLocation(countryName = name, countryCode = flagToCode(flag), flagEmoji = flag)
        }
        for ((pattern, code, name) in COUNTRY_PATTERNS) {
            if (pattern.containsMatchIn(text)) {
                return ExitLocation(countryName = name, countryCode = code, flagEmoji = flagEmoji(code))
            }
        }
        val iso = ISO_CODE.find(text)?.groupValues?.getOrNull(1)?.uppercase()
        if (iso != null) {
            val name = COUNTRY_BY_CODE[iso] ?: iso
            return ExitLocation(countryName = name, countryCode = iso, flagEmoji = flagEmoji(iso))
        }
        return null
    }

    fun flagEmoji(countryCode: String): String? {
        val code = countryCode.trim().uppercase()
        if (code.length != 2 || code.any { it !in 'A'..'Z' }) return null
        val first = 0x1F1E6 + (code[0] - 'A')
        val second = 0x1F1E6 + (code[1] - 'A')
        return String(intArrayOf(first, second), 0, 2)
    }

    private fun flagToCode(flag: String): String? {
        if (flag.length < 4) return null
        val first = Character.codePointAt(flag, 0)
        val second = Character.codePointAt(flag, 2)
        if (first !in 0x1F1E6..0x1F1FF || second !in 0x1F1E6..0x1F1FF) return null
        return "${'A' + (first - 0x1F1E6)}${'A' + (second - 0x1F1E6)}"
    }

    private val FLAG_EMOJI = Regex("""[\x{1F1E6}-\x{1F1FF}][\x{1F1E6}-\x{1F1FF}]""")
    private val ISO_CODE = Regex("""(?i)(?:^|[^A-Z])([A-Z]{2})(?:\d+)?(?:$|[^A-Z])""")

    private val COUNTRY_BY_CODE = mapOf(
        "AT" to "Австрия", "AU" to "Австралия", "BE" to "Бельгия", "BG" to "Болгария",
        "BR" to "Бразилия", "CA" to "Канада", "CH" to "Швейцария", "CZ" to "Чехия",
        "DE" to "Германия", "DK" to "Дания", "EE" to "Эстония", "ES" to "Испания",
        "FI" to "Финляндия", "FR" to "Франция", "GB" to "Великобритания", "UK" to "Великобритания",
        "HK" to "Гонконг", "IE" to "Ирландия", "IL" to "Израиль", "IN" to "Индия",
        "IT" to "Италия", "JP" to "Япония", "KR" to "Корея", "LT" to "Литва",
        "LV" to "Латвия", "MD" to "Молдова", "NL" to "Нидерланды", "NO" to "Норвегия",
        "PL" to "Польша", "PT" to "Португалия", "RO" to "Румыния", "RS" to "Сербия",
        "RU" to "Россия", "SE" to "Швеция", "SG" to "Сингапур", "TR" to "Турция",
        "UA" to "Украина", "US" to "США", "KZ" to "Казахстан", "GE" to "Грузия",
        "AZ" to "Азербайджан", "AM" to "Армения", "CN" to "Китай", "TW" to "Тайвань",
    )

    private data class Pattern(val pattern: Regex, val code: String, val name: String)

    private val COUNTRY_PATTERNS = listOf(
        Pattern(Regex("""(?i)sweden|швеци"""), "SE", "Швеция"),
        Pattern(Regex("""(?i)germany|german|deutschland|герман"""), "DE", "Германия"),
        Pattern(Regex("""(?i)netherlands|holland|нидерланд|голланди"""), "NL", "Нидерланды"),
        Pattern(Regex("""(?i)france|франци"""), "FR", "Франция"),
        Pattern(Regex("""(?i)finland|финлянд"""), "FI", "Финляндия"),
        Pattern(Regex("""(?i)poland|польш"""), "PL", "Польша"),
        Pattern(Regex("""(?i)turkey|турци"""), "TR", "Турция"),
        Pattern(Regex("""(?i)switzerland|швейцар"""), "CH", "Швейцария"),
        Pattern(Regex("""(?i)austria|австри"""), "AT", "Австрия"),
        Pattern(Regex("""(?i)canada|канад"""), "CA", "Канада"),
        Pattern(Regex("""(?i)\busa\b|\bus\b|united states|америк|сша"""), "US", "США"),
        Pattern(Regex("""(?i)united kingdom|\buk\b|britain|великобритан|англи"""), "GB", "Великобритания"),
        Pattern(Regex("""(?i)japan|япони"""), "JP", "Япония"),
        Pattern(Regex("""(?i)singapore|сингапур"""), "SG", "Сингапур"),
        Pattern(Regex("""(?i)hong\s*kong|гонконг"""), "HK", "Гонконг"),
        Pattern(Regex("""(?i)russia|росси"""), "RU", "Россия"),
        Pattern(Regex("""(?i)ukraine|украин"""), "UA", "Украина"),
        Pattern(Regex("""(?i)kazakhstan|казахстан"""), "KZ", "Казахстан"),
        Pattern(Regex("""(?i)latvia|латви"""), "LV", "Латвия"),
        Pattern(Regex("""(?i)lithuania|литв"""), "LT", "Литва"),
        Pattern(Regex("""(?i)estonia|эстони"""), "EE", "Эстония"),
        Pattern(Regex("""(?i)spain|испани"""), "ES", "Испания"),
        Pattern(Regex("""(?i)italy|итали"""), "IT", "Италия"),
        Pattern(Regex("""(?i)czech|чехи"""), "CZ", "Чехия"),
        Pattern(Regex("""(?i)romania|румын"""), "RO", "Румыния"),
        Pattern(Regex("""(?i)bulgaria|болгар"""), "BG", "Болгария"),
        Pattern(Regex("""(?i)serbia|серби"""), "RS", "Сербия"),
        Pattern(Regex("""(?i)moldova|молдов"""), "MD", "Молдова"),
        Pattern(Regex("""(?i)israel|израил"""), "IL", "Израиль"),
        Pattern(Regex("""(?i)india|инди"""), "IN", "Индия"),
        Pattern(Regex("""(?i)brazil|бразил"""), "BR", "Бразилия"),
        Pattern(Regex("""(?i)australia|австрал"""), "AU", "Австралия"),
        Pattern(Regex("""(?i)korea|коре"""), "KR", "Корея"),
        Pattern(Regex("""(?i)taiwan|тайван"""), "TW", "Тайвань"),
        Pattern(Regex("""(?i)china|китай"""), "CN", "Китай"),
        Pattern(Regex("""(?i)norway|норвег"""), "NO", "Норвегия"),
        Pattern(Regex("""(?i)denmark|дани"""), "DK", "Дания"),
        Pattern(Regex("""(?i)belgium|бельги"""), "BE", "Бельгия"),
        Pattern(Regex("""(?i)portugal|португал"""), "PT", "Португалия"),
        Pattern(Regex("""(?i)ireland|ирланд"""), "IE", "Ирландия"),
    )
}
