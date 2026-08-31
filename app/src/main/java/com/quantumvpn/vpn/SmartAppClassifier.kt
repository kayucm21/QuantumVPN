package com.quantumvpn.vpn

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ApplicationInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Классифицирует установленные приложения по категориям для умного сплит-туннелинга.
 */
object SmartAppClassifier {

    enum class AppCategory {
        MESSENGER,
        BANKING,
        BROWSER,
        SOCIAL,
        GAMING,
        STREAMING,
        WORK,
        OTHER
    }

    data class ClassifiedApp(
        val packageName: String,
        val appName: String,
        val category: AppCategory,
        val icon: android.graphics.drawable.Drawable? = null
    )

    /**
     * Возвращает список всех установленных приложений с категориями.
     * Работает в фоновом потоке.
     */
    suspend fun getClassifiedApps(context: Context): List<ClassifiedApp> =
        withContext(Dispatchers.IO) {
            val pm = context.packageManager
            val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
            apps.mapNotNull { appInfo ->
                val category = classifyApp(appInfo, pm)
                val appName = appInfo.loadLabel(pm).toString()
                val icon = runCatching { appInfo.loadIcon(pm) }.getOrNull()
                ClassifiedApp(
                    packageName = appInfo.packageName,
                    appName = appName,
                    category = category,
                    icon = icon
                )
            }.sortedBy { it.appName }
        }

    /**
     * Классифицирует одно приложение на основе Intent-фильтров и пакета.
     */
    private fun classifyApp(appInfo: ApplicationInfo, pm: PackageManager): AppCategory {
        val packageName = appInfo.packageName.lowercase()

        // Явные правила по пакетам (мессенджеры)
        val messengers = setOf(
            "com.whatsapp", "org.telegram.messenger", "com.viber.voip",
            "com.discord", "com.slack", "com.microsoft.teams",
            "im.qq.mobile", "com.tencent.mm", "com.facebook.orca",
            "com.google.android.apps.messaging", "jp.naver.line.android",
            "com.skype.raider", "com.imo.android.imoim", "com.tango"
        )
        if (messengers.any { packageName.contains(it) }) {
            return AppCategory.MESSENGER
        }

        // Банки и финансовые приложения
        val banking = setOf(
            "sberbank", "tinkoff", "alfabank", "vtb", "gazprombank",
            "raiffeisen", "openbank", "psbank", "sovcombank",
            "paypal", "google.pay", "wallet", "coinbase", "binance"
        )
        if (banking.any { packageName.contains(it) }) {
            return AppCategory.BANKING
        }

        // Браузеры
        val browsers = setOf(
            "chrome", "firefox", "opera", "browser", "samsung.browser",
            "brave", "edge", "vivaldi", "kiwi.browser"
        )
        if (browsers.any { packageName.contains(it) }) {
            return AppCategory.BROWSER
        }

        // Соцсети
        val social = setOf(
            "instagram", "facebook", "twitter", "reddit", "tumblr",
            "pinterest", "snapchat", "tiktok", "telegram", "vk",
            "linkedin", "weibo", "clubhouse"
        )
        if (social.any { packageName.contains(it) }) {
            return AppCategory.SOCIAL
        }

        // Игры
        val gaming = setOf(
            "game", "play", "mobile.legends", "pubg", "genshin",
            "clash", "candy", "minecraft", "roblox", "fortnite"
        )
        if (gaming.any { packageName.contains(it) }) {
            return AppCategory.GAMING
        }

        // Стриминг
        val streaming = setOf(
            "youtube", "netflix", "spotify", "apple.music", "tidal",
            "twitch", "vimeo", "soundcloud", "audiobook"
        )
        if (streaming.any { packageName.contains(it) }) {
            return AppCategory.STREAMING
        }

        // Рабочие приложения
        val work = setOf(
            "office", "outlook", "onedrive", "sharepoint", "zoom",
            "webex", "meet", "calendar", "drive", "docs", "sheets",
            "slack", "trello", "asana", "jira", "notion", "obsidian"
        )
        if (work.any { packageName.contains(it) }) {
            return AppCategory.WORK
        }

        // Intent categories are not exposed on ResolveInfo in modern Android SDKs.
        return AppCategory.OTHER
    }

    /**
     * Возвращает список приложений для заданной категории.
     */
    suspend fun getAppsByCategory(
        context: Context,
        category: AppCategory
    ): List<ClassifiedApp> =
        getClassifiedApps(context).filter { it.category == category }

    /**
     * Возвращает список приложений для нескольких категорий.
     */
    suspend fun getAppsByCategories(
        context: Context,
        categories: Set<AppCategory>
    ): List<ClassifiedApp> =
        getClassifiedApps(context).filter { it.category in categories }
}
