package com.quantumvpn.vpn

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.net.Uri
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class InstalledApp(
    val packageName: String,
    val label: String,
    val system: Boolean,
    val enabled: Boolean,
    val suggestion: String? = null,
)

class AppCatalog(context: Context) {
    private val appContext = context.applicationContext
    private val packageManager = appContext.packageManager

    suspend fun load(): List<InstalledApp> = withContext(Dispatchers.IO) {
        val browserPackages = installedBrowserPackages()
        val telegramPackages = installedTelegramPackages()
        val youtubePackages = installedYouTubePackages()
        installedApplications()
            .asSequence()
            .filterNot { it.packageName == appContext.packageName }
            .map { application ->
                InstalledApp(
                    packageName = application.packageName,
                    label = runCatching { application.loadLabel(packageManager).toString() }
                        .getOrDefault(application.packageName)
                        .ifBlank { application.packageName },
                    system = application.flags and (
                        ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP
                    ) != 0,
                    enabled = application.enabled,
                    suggestion = suggestedAppLabel(
                        packageName = application.packageName,
                        browserPackages = browserPackages,
                        telegramPackages = telegramPackages,
                        youtubePackages = youtubePackages,
                    ),
                )
            }
            .distinctBy(InstalledApp::packageName)
            .sortedWith(
                compareBy<InstalledApp> { it.label.lowercase() }
                    .thenBy(InstalledApp::packageName),
            )
            .toList()
    }

    private fun installedBrowserPackages(): Set<String> {
        return handlerPackages(
            Intent.makeMainSelectorActivity(Intent.ACTION_MAIN, Intent.CATEGORY_APP_BROWSER),
            Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com"))
                .addCategory(Intent.CATEGORY_BROWSABLE),
        )
    }

    private fun installedTelegramPackages(): Set<String> = handlerPackages(
        Intent(Intent.ACTION_VIEW, Uri.parse("tg://resolve?domain=telegram"))
            .addCategory(Intent.CATEGORY_BROWSABLE),
    )

    private fun installedYouTubePackages(): Set<String> = handlerPackages(
        Intent(Intent.ACTION_VIEW, Uri.parse("https://www.youtube.com/watch?v=dQw4w9WgXcQ"))
            .addCategory(Intent.CATEGORY_BROWSABLE),
        Intent(Intent.ACTION_VIEW, Uri.parse("https://youtu.be/dQw4w9WgXcQ"))
            .addCategory(Intent.CATEGORY_BROWSABLE),
        Intent(Intent.ACTION_VIEW, Uri.parse("vnd.youtube:dQw4w9WgXcQ"))
            .addCategory(Intent.CATEGORY_BROWSABLE),
    )

    private fun handlerPackages(vararg intents: Intent): Set<String> = intents
        .asSequence()
        .flatMap { intent -> resolveActivities(intent).asSequence() }
        .mapNotNull { it.activityInfo?.packageName }
        .toSet()

    @Suppress("DEPRECATION")
    private fun resolveActivities(intent: Intent): List<ResolveInfo> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.queryIntentActivities(
                intent,
                PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_ALL.toLong()),
            )
        } else {
            packageManager.queryIntentActivities(intent, PackageManager.MATCH_ALL)
        }

    @Suppress("DEPRECATION")
    private fun installedApplications(): List<ApplicationInfo> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getInstalledApplications(
                PackageManager.ApplicationInfoFlags.of(
                    PackageManager.MATCH_DISABLED_COMPONENTS.toLong(),
                ),
            )
        } else {
            packageManager.getInstalledApplications(PackageManager.MATCH_DISABLED_COMPONENTS)
        }
}

object PopularAppSuggestions {
    private val labelsByPackage = mapOf(
        "com.openai.chatgpt" to "ChatGPT",
        "com.anthropic.claude" to "Claude",
        "com.google.android.apps.bard" to "Gemini",
        "ai.perplexity.app.android" to "Perplexity",
        "com.microsoft.copilot" to "Microsoft Copilot",
        "com.deepseek.chat" to "DeepSeek",
        "ai.x.grok" to "Grok",
        "com.suno.android" to "Suno",
        "com.spotify.music" to "Spotify",
        "notion.id" to "Notion",
        "com.instagram.android" to "Instagram",
        "com.instagram.lite" to "Instagram Lite",
        "com.google.android.youtube" to "YouTube",
        "com.google.android.apps.youtube.music" to "YouTube Music",
        "app.revanced.android.youtube" to "YouTube ReVanced",
        "app.revanced.android.apps.youtube.music" to "YouTube Music ReVanced",
        "app.rvx.android.youtube" to "YouTube ReVanced Extended",
        "app.rvx.android.apps.youtube.music" to "YouTube Music ReVanced Extended",
        "com.vanced.android.youtube" to "YouTube Vanced",
        "com.vanced.android.apps.youtube.music" to "YouTube Music Vanced",
        "app.morphe.android.youtube" to "YouTube Morphe",
        "app.morphe.androoid.youtube" to "YouTube Morphe",
        "app.morphe.android.apps.youtube.music" to "YouTube Music Morphe",
        "org.telegram.messenger" to "Telegram",
        "org.telegram.messenger.beta" to "Telegram Beta",
        "org.telegram.messenger.web" to "Telegram Direct / FOSS",
        "org.thunderdog.challegram" to "Telegram X",
        "org.zastogram.messenger" to "ZaStoGram",
        "org.zastogram.messenger.beta" to "ZaStoGram Beta",
        "org.zastogram.messenger.web" to "ZaStoGram Direct",
        "tw.nekomimi.nekogram" to "Nekogram",
        "tw.nekomimi.nekogram.beta" to "Nekogram Beta",
        "nekox.messenger" to "NekoX",
        "xyz.nextalone.nagram" to "Nagram",
        "com.radolyn.ayugram" to "AyuGram",
        "com.exteragram.messenger" to "exteraGram",
        "it.belloworld.mercurygram" to "Mercurygram",
        "it.belloworld.mercurygram.beta" to "Mercurygram Beta",
        "uz.unnarsx.cherrygram" to "Cherrygram",
        "org.forkgram.messenger" to "Forkgram",
        "org.forkgram.classic" to "Forkgram Classic",
        "org.vidogram.messenger" to "Vidogram",
        "org.monogram" to "MonoGram",
        "com.whatsapp" to "WhatsApp",
        "com.whatsapp.w4b" to "WhatsApp Business",
        "com.discord" to "Discord",
        "org.thoughtcrime.securesms" to "Signal",
        "com.android.chrome" to "Chrome",
        "com.chrome.beta" to "Chrome Beta",
        "com.chrome.dev" to "Chrome Dev",
        "com.chrome.canary" to "Chrome Canary",
        "org.chromium.chrome" to "Chromium / Ultimatum",
        "org.chromium.chrome.dev" to "Chromium / Ultimatum Dev",
        "org.mozilla.firefox" to "Firefox",
        "org.mozilla.firefox_beta" to "Firefox Beta",
        "org.mozilla.fenix" to "Firefox Nightly",
        "org.mozilla.fennec_fdroid" to "Fennec F-Droid",
        "org.mozilla.focus" to "Firefox Focus",
        "com.microsoft.emmx" to "Microsoft Edge",
        "com.microsoft.emmx.beta" to "Microsoft Edge Beta",
        "com.microsoft.emmx.dev" to "Microsoft Edge Dev",
        "com.microsoft.emmx.canary" to "Microsoft Edge Canary",
        "com.brave.browser" to "Brave",
        "com.brave.browser_beta" to "Brave Beta",
        "com.brave.browser_nightly" to "Brave Nightly",
        "com.opera.browser" to "Opera",
        "com.opera.mini.native" to "Opera Mini",
        "com.opera.gx" to "Opera GX",
        "com.sec.android.app.sbrowser" to "Samsung Internet",
        "com.sec.android.app.sbrowser.beta" to "Samsung Internet Beta",
        "com.yandex.browser" to "Яндекс Браузер",
        "com.yandex.browser.beta" to "Яндекс Браузер Beta",
        "com.yandex.browser.lite" to "Яндекс Браузер Lite",
        "com.kiwibrowser.browser" to "Kiwi Browser",
        "com.duckduckgo.mobile.android" to "DuckDuckGo",
        "com.vivaldi.browser" to "Vivaldi",
        "com.vivaldi.browser.snapshot" to "Vivaldi Snapshot",
        "org.cromite.cromite" to "Cromite",
    )

    val packageNames: Set<String> = labelsByPackage.keys
    const val MIGRATION_REVISION: Int = 1
    val packagesAddedInCurrentRevision: Set<String> = setOf(
        "com.openai.chatgpt",
        "com.anthropic.claude",
        "com.google.android.apps.bard",
        "ai.perplexity.app.android",
        "com.microsoft.copilot",
        "com.deepseek.chat",
        "ai.x.grok",
        "com.suno.android",
        "com.spotify.music",
        "notion.id",
    )

    fun labelFor(packageName: String): String? = labelsByPackage[packageName]
}

private val nonBrowserPackages = setOf(
    // The Pyaterochka app exposes a generic web handler but is not a browser.
    "ru.pyaterochka.app.browser",
)

internal fun suggestedAppLabel(
    packageName: String,
    browserPackages: Set<String>,
    telegramPackages: Set<String> = emptySet(),
    youtubePackages: Set<String> = emptySet(),
): String? = PopularAppSuggestions.labelFor(packageName) ?: when {
    packageName in browserPackages && packageName !in nonBrowserPackages -> "Браузер"
    packageName in telegramPackages -> "Telegram-клиент"
    packageName in youtubePackages -> "YouTube-клиент"
    else -> null
}
