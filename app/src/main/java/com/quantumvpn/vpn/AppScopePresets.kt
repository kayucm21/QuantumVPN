package com.quantumvpn.vpn

/**
 * Named per-app include presets built from installed packages + known package lists.
 */
enum class AppScopePreset(val title: String, val detail: String) {
    Messengers("Мессенджеры", "Telegram/WhatsApp/Signal/Discord → VPN"),
    Social("Соцсети", "Telegram/WhatsApp/Discord/Signal/Instagram"),
    Streaming("Стриминг", "YouTube/Spotify и клиенты"),
    Work("Работа", "Notion + AI-ассистенты"),
    Browsers("Браузеры", "Chrome/Firefox/Edge/Brave…"),
    Games("Игры", "Steam/Epic/Riot/Blizzard по package"),
}

object AppScopePresets {
    private val socialPackages = setOf(
        "com.instagram.android", "com.instagram.lite",
        "com.whatsapp", "com.whatsapp.w4b",
        "com.discord",
        "org.thoughtcrime.securesms",
    ) + PopularAppSuggestions.packageNames.filter {
        it.contains("telegram", true) ||
            it.contains("zastogram", true) ||
            it.contains("nekogram", true) ||
            it.contains("nagram", true) ||
            it.contains("ayugram", true) ||
            it.contains("exteragram", true) ||
            it.contains("mercurygram", true) ||
            it.contains("cherrygram", true) ||
            it.contains("forkgram", true) ||
            it.contains("vidogram", true) ||
            it.contains("monogram", true) ||
            it.contains("nekox", true)
    }

    private val streamingPackages = setOf(
        "com.spotify.music",
        "com.suno.android",
    ) + PopularAppSuggestions.packageNames.filter {
        it.contains("youtube", true) || it.contains("youtu", true)
    }

    private val workPackages = setOf(
        "notion.id",
        "com.openai.chatgpt",
        "com.anthropic.claude",
        "com.google.android.apps.bard",
        "ai.perplexity.app.android",
        "com.microsoft.copilot",
        "com.deepseek.chat",
        "ai.x.grok",
        "com.slack",
        "us.zoom.videomeetings",
        "com.microsoft.teams",
        "com.google.android.apps.docs",
        "com.microsoft.office.outlook",
    )

    private val browserPackages = PopularAppSuggestions.packageNames.filter {
        it.contains("chrome", true) ||
            it.contains("firefox", true) ||
            it.contains("browser", true) ||
            it.contains("brave", true) ||
            it.contains("opera", true) ||
            it.contains("edge", true) ||
            it.contains("vivaldi", true) ||
            it.contains("duckduckgo", true) ||
            it.contains("cromite", true) ||
            it.contains("fenix", true) ||
            it.contains("fennec", true) ||
            it.contains("sbrowser", true) ||
            it.contains("yandex.browser", true)
    }.toSet()

    private val gamePackages = setOf(
        "com.valvesoftware.android.steam.community",
        "com.epicgames.portal",
        "com.riotgames.league.wildrift",
        "com.riotgames.leagueoflegends",
        "com.blizzard.wtcg.hearthstone",
        "com.activision.callofduty.shooter",
        "com.supercell.clashofclans",
        "com.supercell.clashroyale",
        "com.mojang.minecraftpe",
        "com.tencent.ig",
        "com.pubg.krmobile",
    )

    fun packagesFor(preset: AppScopePreset, installed: List<InstalledApp>): Set<String> {
        val installedNames = installed.asSequence().map(InstalledApp::packageName).toSet()
        val wanted = when (preset) {
            AppScopePreset.Messengers -> socialPackages.filter {
                it.contains("telegram", true) ||
                    it.contains("whatsapp", true) ||
                    it.contains("signal", true) ||
                    it.contains("discord", true) ||
                    it.contains("securesms", true)
            }.toSet() + installed
                .filter {
                    it.label.contains("Telegram", true) ||
                        it.label.contains("WhatsApp", true) ||
                        it.label.contains("Signal", true) ||
                        it.label.contains("Discord", true)
                }
                .map { it.packageName }
            AppScopePreset.Social -> socialPackages + installed
                .filter {
                    it.suggestion?.contains("Telegram", true) == true ||
                        it.label.contains("Telegram", true) ||
                        it.label.contains("WhatsApp", true) ||
                        it.label.contains("Discord", true) ||
                        it.label.contains("Instagram", true) ||
                        it.label.contains("Signal", true)
                }
                .map { it.packageName }
            AppScopePreset.Streaming -> streamingPackages + installed
                .filter {
                    it.suggestion?.contains("YouTube", true) == true ||
                        it.label.contains("YouTube", true) ||
                        it.label.contains("Spotify", true) ||
                        it.label.contains("Twitch", true) ||
                        it.label.contains("Netflix", true)
                }
                .map { it.packageName }
            AppScopePreset.Work -> workPackages + installed
                .filter {
                    it.label.contains("Slack", true) ||
                        it.label.contains("Zoom", true) ||
                        it.label.contains("Teams", true) ||
                        it.label.contains("Notion", true) ||
                        it.label.contains("Outlook", true) ||
                        it.suggestion in setOf(
                            "ChatGPT", "Claude", "Gemini", "Perplexity",
                            "Microsoft Copilot", "DeepSeek", "Grok", "Notion",
                        )
                }
                .map { it.packageName }
            AppScopePreset.Browsers -> browserPackages + installed
                .filter { it.suggestion == "Браузер" || it.suggestion?.contains("Chrome") == true }
                .map { it.packageName }
            AppScopePreset.Games -> gamePackages + installed
                .filter {
                    it.packageName.contains("steam", true) ||
                        it.packageName.contains("epicgames", true) ||
                        it.packageName.contains("riotgames", true) ||
                        it.label.contains("Steam", true) ||
                        it.label.contains("Epic", true)
                }
                .map { it.packageName }
        }
        return wanted.intersect(installedNames)
    }
}
