package com.quantumvpn.vpn

/**
 * Каталог мобильных игр для игрового режима.
 *
 * Игровой режим (GearUP-подобный fast path): трафик выбранных игр идёт
 * напрямую через сеть Android (outbound `direct`), минуя VPN-сервер, —
 * кратчайший маршрут и минимальный пинг. Остальные приложения работают
 * как раньше. Управление объединено по ADR-003: Android allowlist
 * (допуск в TUN) + runtime route-правило (назначение в sing-box).
 */
data class GameProfile(
    val id: String,
    val title: String,
    val packageNames: Set<String>,
    val detail: String,
)

object GameCatalog {
    val games = listOf(
        GameProfile(
            id = "pubg-mobile",
            title = "PUBG Mobile",
            packageNames = setOf(
                "com.tencent.ig",
                "com.pubg.krmobile",
                "com.vng.pubgmobile",
                "com.rekoo.pubgm",
            ),
            detail = "Королевская битва",
        ),
        GameProfile(
            id = "mlbb",
            title = "Mobile Legends",
            packageNames = setOf("com.mobile.legends"),
            detail = "MOBA 5v5",
        ),
        GameProfile(
            id = "codm",
            title = "Call of Duty: Mobile",
            packageNames = setOf("com.activision.callofduty.shooter"),
            detail = "Шутер",
        ),
        GameProfile(
            id = "free-fire",
            title = "Free Fire",
            packageNames = setOf(
                "com.dts.freefireth",
                "com.dts.freefiremax",
            ),
            detail = "Королевская битва",
        ),
        GameProfile(
            id = "brawl-stars",
            title = "Brawl Stars",
            packageNames = setOf("com.supercell.brawlstars"),
            detail = "Supercell",
        ),
        GameProfile(
            id = "clash-royale",
            title = "Clash Royale",
            packageNames = setOf("com.supercell.clashroyale"),
            detail = "Supercell",
        ),
        GameProfile(
            id = "clash-of-clans",
            title = "Clash of Clans",
            packageNames = setOf("com.supercell.clashofclans"),
            detail = "Supercell",
        ),
        GameProfile(
            id = "genshin",
            title = "Genshin Impact",
            packageNames = setOf("com.miHoYo.GenshinImpact"),
            detail = "Открытый мир",
        ),
        GameProfile(
            id = "hsr",
            title = "Honkai: Star Rail",
            packageNames = setOf(
                "com.HoYoverse.hkrpgoversea",
                "com.miHoYo.hkrpg",
            ),
            detail = "HoYoverse",
        ),
        GameProfile(
            id = "roblox",
            title = "Roblox",
            packageNames = setOf("com.roblox.client"),
            detail = "Платформа игр",
        ),
        GameProfile(
            id = "standoff2",
            title = "Standoff 2",
            packageNames = setOf("com.axlebolt.standoff2"),
            detail = "Шутер",
        ),
        GameProfile(
            id = "wild-rift",
            title = "Wild Rift",
            packageNames = setOf("com.riotgames.league.wildrift"),
            detail = "Riot MOBA",
        ),
        GameProfile(
            id = "minecraft",
            title = "Minecraft",
            packageNames = setOf("com.mojang.minecraftpe"),
            detail = "Песочница",
        ),
        GameProfile(
            id = "fc-mobile",
            title = "FC Mobile",
            packageNames = setOf("com.ea.gp.fifamobile"),
            detail = "Футбол",
        ),
        GameProfile(
            id = "efootball",
            title = "eFootball",
            packageNames = setOf("jp.konami.pesamobile"),
            detail = "Футбол",
        ),
        GameProfile(
            id = "tanks-blitz",
            title = "Tanks Blitz",
            packageNames = setOf("net.wargaming.wot.blitz"),
            detail = "Танки",
        ),
    )

    /**
     * Игры из каталога, установленные на устройстве.
     * Возвращает пары (профиль, установленные пакеты профиля).
     */
    fun detectInstalled(installed: List<InstalledApp>): List<Pair<GameProfile, Set<String>>> {
        val installedNames = installed.asSequence().map(InstalledApp::packageName).toSet()
        return games.mapNotNull { game ->
            val present = game.packageNames.intersect(installedNames)
            if (present.isEmpty()) null else game to present
        }
    }

    /** Все пакеты каталога одним множеством (для тестов и диагностики). */
    val allPackages: Set<String> = games.flatMap(GameProfile::packageNames).toSet()
}
