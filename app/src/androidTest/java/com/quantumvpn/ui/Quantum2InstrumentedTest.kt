package com.quantumvpn.ui

import android.graphics.Bitmap
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.requiredSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.test.platform.app.InstrumentationRegistry
import com.quantumvpn.diagnostics.DiagnosticState
import com.quantumvpn.policy.ClientPolicy
import com.quantumvpn.ui.theme.QuantumVpnTheme
import com.quantumvpn.updates.GitHubAsset
import com.quantumvpn.updates.GitHubRelease
import com.quantumvpn.updates.ReleaseMetadata
import com.quantumvpn.updates.UpdateCandidate
import com.quantumvpn.updates.UpdateState
import com.quantumvpn.vpn.VpnSessionStats
import com.quantumvpn.vpn.RuntimeOutboundItem
import com.quantumvpn.vpn.RuntimeSelectorGroup
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.File

/**
 * Screen-only release regressions. These do not clear storage, import a real
 * subscription, install APKs, start VPN, or change Android DNS/network settings.
 * They prove Compose behavior, not physical VPN/network/performance gates.
 */
class Quantum2InstrumentedTest {
    @get:Rule val compose = createComposeRule()

    @Test fun compactHomeKeepsConnectServerAndGamesAboveBottomNavigation() {
        compose.setContent {
            QuantumVpnTheme(darkTheme = true) {
                Column(Modifier.requiredSize(360.dp, 640.dp)) {
                    Box(Modifier.weight(1f)) { TestHome() }
                    V2BottomBar(V2Tab.Home) {}
                }
            }
        }
        saveFixtureScreenshot("home-compact")
        compose.onNodeWithTag("home-connect").assertIsDisplayed().assertHasClickAction()
        compose.onNodeWithTag("home-server").assertIsDisplayed().assertHasClickAction()
        compose.onNodeWithTag("home-games").assertIsDisplayed().assertHasClickAction()
        val nav = compose.onNodeWithTag("bottom-navigation").fetchSemanticsNode().boundsInRoot
        listOf("home-connect", "home-server", "home-games").forEach { tag ->
            val action = compose.onNodeWithTag(tag).fetchSemanticsNode().boundsInRoot
            assertTrue("$tag must not overlap the bottom navigation", action.bottom <= nav.top + 1f)
        }
    }

    @Test fun bottomNavigationReservesSystemButtonsAndHasFourTouchTargets() {
        var bottomInset = 0
        var scale = 1f
        var selected = V2Tab.Home
        compose.setContent {
            val density = LocalDensity.current
            val inset = WindowInsets.navigationBars.getBottom(density)
            SideEffect { bottomInset = inset.coerceAtMost(with(density) { 72.dp.roundToPx() }); scale = density.density }
            QuantumVpnTheme(darkTheme = true) {
                Column(Modifier.fillMaxSize()) {
                    Box(Modifier.weight(1f))
                    V2BottomBar(V2Tab.Home) { selected = it }
                }
            }
        }
        val nav = compose.onNodeWithTag("bottom-navigation").fetchSemanticsNode().boundsInRoot
        listOf(V2Tab.Home, V2Tab.Servers, V2Tab.Statistics, V2Tab.Settings).forEach { tab ->
            val button = compose.onNode(hasText(tab.title) and hasClickAction())
            button.assertIsDisplayed().assertHeightIsAtLeast(48.dp)
            val bounds = button.fetchSemanticsNode().boundsInRoot
            assertTrue("${tab.title} must stay above the system-button inset", bounds.bottom <= nav.bottom - bottomInset + 1f)
            button.performClick()
            compose.runOnIdle { assertEquals(tab, selected) }
        }
        assertTrue("No duplicated full-screen navigation gap", nav.height <= 112f * scale + bottomInset)
    }

    @Test fun largeSystemTextDoesNotRemoveHomeActions() {
        compose.setContent {
            val density = LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(density.density, 1.6f)) {
                QuantumVpnTheme(darkTheme = true) {
                    Box(Modifier.requiredSize(360.dp, 600.dp)) { TestHome() }
                }
            }
        }
        // An accessibility fallback may scroll; controls must remain reachable.
        compose.onNodeWithTag("home-connect").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("home-server").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("home-games").performScrollTo().assertIsDisplayed()
    }

    @Test fun disconnectedHomeDoesNotClaimDnsIsActiveOrInventPing() {
        compose.setContent { QuantumVpnTheme { TestHome() } }
        compose.onAllNodesWithText("42 мс").assertCountEquals(0)
        compose.onAllNodesWithText("58 мс").assertCountEquals(0)
        compose.onAllNodesWithText("ГОТОВ").assertCountEquals(0)
        compose.onNodeWithTag("home-ping").assertExists()
        compose.onNodeWithTag("home-dns").assertExists()
        compose.onNodeWithTag("home-routing").assertExists()
        compose.onAllNodes(hasText("Проверка…", substring = true)).assertCountEquals(1)
    }

    @Test fun serversDoNotCallAnUnmeasuredEndpointATimeout() {
        var favorite: Pair<String, String>? = null
        compose.setContent {
            QuantumVpnTheme {
                V2Servers(listOf(serverGroup()), "proxy", "Тестовый сервер", emptyMap(), { _, _ -> },
                    "fixture", emptyMap(), null, false, {},
                    onFavorite = { group, server -> favorite = group to server }, pingMeasured = false)
            }
        }
        saveFixtureScreenshot("servers-unmeasured")
        compose.onNodeWithText("Проверка…").assertExists()
        compose.onAllNodesWithText("Таймаут").assertCountEquals(0)
        compose.onAllNodesWithText("42 мс").assertCountEquals(0)
        compose.onNodeWithContentDescription("Добавить Тестовый сервер в избранное").performClick()
        compose.runOnIdle { assertEquals("proxy" to "Тестовый сервер", favorite) }
    }

    @Test fun emptyServerFiltersExplainTheEmptyStateWithoutDemoEndpoints() {
        compose.setContent {
            QuantumVpnTheme {
                V2Servers(emptyList(), null, null, emptyMap(), { _, _ -> }, null, emptyMap(), null, false, {})
            }
        }
        compose.onNodeWithText("Нет серверов. Обновите подписку и проверьте сеть.").assertIsDisplayed()
        compose.onAllNodesWithText("Москва").assertCountEquals(0)
        compose.onNode(hasText("Избранные") and hasClickAction()).performClick()
        compose.onNodeWithText("Добавьте сервер в избранное кнопкой ☆").assertIsDisplayed()
    }

    @Test fun emptyStatisticsDoNotClaimValidatedNetworkOrSuccessfulPing() {
        compose.setContent {
            QuantumVpnTheme {
                V2Statistics(VpnSessionStats(), false, emptyList(), emptyList(), DiagnosticState(), 0, false)
            }
        }
        saveFixtureScreenshot("statistics-empty")
        compose.onNodeWithText("Нет данных").assertExists()
        compose.onNodeWithText("График появится после получения данных").assertIsDisplayed()
        compose.onNodeWithTag("statistics-check").assertIsNotEnabled()
        compose.onAllNodesWithText("Проверена").assertCountEquals(0)
        compose.onAllNodesWithText("58 мс").assertCountEquals(0)
        compose.onNode(hasText("Неделя") and hasClickAction()).performClick()
        compose.onNodeWithText("↓ Загрузка · Неделя").assertExists()
    }

    @Test fun settingsHaveFourCompactGroupsAndWorkingSubpages() {
        var updateChecks = 0
        compose.setContent {
            QuantumVpnTheme {
                Box(Modifier.requiredSize(360.dp, 640.dp)) { TestSettings(onCheckUpdate = { updateChecks++ }) }
            }
        }
        saveFixtureScreenshot("settings-four-groups")
        listOf("connection", "notifications", "appearance", "help").forEach { group ->
            compose.onNodeWithTag("settings-$group").assertIsDisplayed().assertHasClickAction()
                .assertHeightIsAtLeast(48.dp)
        }
        compose.onNodeWithTag("settings-connection").performClick()
        compose.onNodeWithText("Аварийная защита").assertExists()
        compose.onNodeWithText("← Настройки").performClick()
        compose.onNodeWithTag("settings-notifications").performClick()
        compose.onNodeWithText("Центр уведомлений").assertExists()
        compose.onNodeWithText("← Настройки").performClick()
        compose.onNodeWithTag("settings-help").performClick()
        compose.onNodeWithText("Проверить обновление").performClick()
        compose.runOnIdle { assertEquals(1, updateChecks) }
    }

    @Test fun homeBellOpensNotificationCenterInsteadOfTheSettingsHub() {
        compose.setContent { QuantumVpnTheme { TestSettings(initialNotificationsOpen = true) } }
        compose.onNodeWithText("Центр уведомлений").assertIsDisplayed()
        compose.onNodeWithTag("settings-connection").assertDoesNotExist()
        compose.onNodeWithTag("settings-help").assertDoesNotExist()
    }

    @Test fun appearancePreservesLocalPhotoControlsAndReducedMotionPreference() {
        var settings by mutableStateOf(UiSettings(reduceMotion = true, touchBubblesEnabled = false))
        compose.setContent {
            QuantumVpnTheme {
                TestSettings(
                    settings = settings,
                    onStyle = { settings = settings.copy(appBackgroundStyle = it) },
                    onReduceMotion = { settings = settings.copy(reduceMotion = it) },
                    onTouchBubbles = { settings = settings.copy(touchBubblesEnabled = it) },
                )
            }
        }
        compose.onNodeWithTag("settings-appearance").performClick()
        saveFixtureScreenshot("appearance")
        listOf("background-aurora", "background-city", "background-custom", "background-upload").forEach { tag ->
            compose.onNodeWithTag(tag).assertExists().assertHasClickAction()
        }
        compose.onNodeWithTag("background-city").performScrollTo().performClick()
        compose.runOnIdle { assertEquals(AppBackgroundStyle.NightCity, settings.appBackgroundStyle) }
        compose.onNodeWithTag("appearance-animations").performScrollTo()
        compose.onNode(hasAnyAncestor(hasTestTag("appearance-animations")) and isToggleable()).performClick()
        compose.runOnIdle { assertFalse(settings.reduceMotion) }
        compose.onNodeWithTag("appearance-touch-effects").performScrollTo()
        compose.onNode(hasAnyAncestor(hasTestTag("appearance-touch-effects")) and isToggleable()).performClick()
        compose.runOnIdle { assertTrue(settings.touchBubblesEnabled) }
        compose.onNodeWithTag("appearance-preview").performScrollTo().assertHasClickAction().performClick()
        compose.runOnIdle { assertEquals("", settings.customBackgroundUri) }
    }

    @Test fun startupCannotLeaveWhileAnApkIsDownloadingEvenIfReadyFlagIsStale() {
        var finished = 0
        compose.setContent {
            QuantumVpnTheme {
                AuroraStartup2026(true, UpdateState.Downloading(candidate(), 25, 100), 3, true) { finished++ }
            }
        }
        saveFixtureScreenshot("startup-downloading")
        compose.onNodeWithContentDescription("Загрузка 25 процентов").assertExists()
        compose.runOnIdle { assertEquals(0, finished) }
    }

    @Test fun startupWaitsForSystemInstallHandoffInsteadOfOpeningHome() {
        var finished = false
        compose.setContent {
            QuantumVpnTheme {
                AuroraStartup2026(true, UpdateState.Ready(candidate()), 3, true) { finished = true }
            }
        }
        compose.onAllNodes(hasText("Android", substring = true)).fetchSemanticsNodes()
            .also { assertTrue("System install confirmation must be explained", it.isNotEmpty()) }
        compose.runOnIdle { assertFalse(finished) }
    }

    @Test fun unknownDownloadSizeDoesNotShowMadeUpPercentOrEta() {
        compose.setContent {
            QuantumVpnTheme {
                AuroraStartup2026(false, UpdateState.Downloading(candidate(), 1024, -1), 3, true) {}
            }
        }
        compose.onAllNodes(hasContentDescription("процентов", substring = true)).assertCountEquals(0)
        compose.onAllNodes(hasText("%", substring = true)).assertCountEquals(0)
        compose.onAllNodes(hasText("время уточняется", substring = true)).assertCountEquals(1)
    }

    @Test fun startupCompletesOnlyAfterInitializationAndSettledUpdate() {
        var initialized by mutableStateOf(false)
        var finished = 0
        compose.setContent {
            QuantumVpnTheme {
                AuroraStartup2026(initialized, UpdateState.UpToDate("vfixture", "fixture"), 0, true) { finished++ }
            }
        }
        compose.runOnIdle { assertEquals(0, finished); initialized = true }
        compose.waitForIdle()
        compose.runOnIdle { assertEquals(1, finished) }
    }

    @Composable
    private fun TestHome() = V2Home(
        policy = ClientPolicy(), connected = false, busy = false, hasProfile = true,
        server = "Тестовый сервер", ping = null, adBlock = true, privacyScore = 60,
        stats = VpnSessionStats(), onConnect = {}, onServers = {}, onSettings = {},
        onCards = {}, reduceMotion = true, onNotifications = {}, pingMeasured = false,
    )

    @Composable
    private fun TestSettings(
        settings: UiSettings = UiSettings(reduceMotion = true),
        onStyle: (AppBackgroundStyle) -> Unit = {},
        onReduceMotion: (Boolean) -> Unit = {},
        onTouchBubbles: (Boolean) -> Unit = {},
        onCheckUpdate: () -> Unit = {},
        initialNotificationsOpen: Boolean = false,
    ) = V2Settings(
        diagnostics = DiagnosticState(), policy = ClientPolicy(), privacyScore = 60, vpnConnected = false,
        theme = settings.themeMode, dynamicColor = settings.useDynamicColor,
        autoConnect = settings.autoConnectOnCellular, notifications = !settings.quietMode,
        protectUnknownWifi = settings.protectUnknownWifi, travelMode = settings.travelModeEnabled,
        backgroundStyle = settings.appBackgroundStyle, customBackgroundUri = settings.customBackgroundUri,
        touchBubblesEnabled = settings.touchBubblesEnabled, uiSettings = settings,
        onLargeText = {}, onHighContrast = {}, onReduceMotion = onReduceMotion, onHaptics = {},
        adBlock = settings.adBlockEnabled, killSwitch = settings.blockNonVpnTraffic,
        onTheme = {}, onDynamicColor = {}, onAutoConnect = {}, onNotifications = {},
        onProtectUnknownWifi = {}, onTravelMode = {}, onBackgroundStyle = onStyle,
        onCustomBackgroundUri = {}, onTouchBubbles = onTouchBubbles, onAdBlock = {}, onKillSwitch = {},
        onCheckUpdate = onCheckUpdate,
        initialNotificationsOpen = initialNotificationsOpen,
    )

    private fun candidate(): UpdateCandidate {
        val apk = GitHubAsset("fixture.apk", "https://example.invalid/fixture.apk", 100, null)
        return UpdateCandidate(
            release = GitHubRelease("vfixture", "Fixture", "", "https://example.invalid/fixture", false, true, listOf(apk)),
            metadata = ReleaseMetadata("fixture", 1, "com.quantumvpn", "fixture", "0".repeat(40), listOf("arm64-v8a"), apk.name, "0".repeat(64), 100),
            apkAsset = apk,
            checksumAsset = GitHubAsset("fixture.apk.sha256", "https://example.invalid/fixture.apk.sha256", 80, null),
        )
    }

    private fun serverGroup() = RuntimeSelectorGroup(
        tag = "proxy", type = "selector", selected = "Тестовый сервер", selectable = true,
        items = listOf(RuntimeOutboundItem("Тестовый сервер", "vless", "fixture.invalid:443", null, null)),
    )

    private fun saveFixtureScreenshot(name: String) {
        // Bitmap IO is deliberately off the main thread, outside Espresso's
        // idle registry. Capture the loaded backdrop, not its temporary placeholder.
        compose.waitUntil(10_000) {
            compose.onAllNodesWithTag("quantum2-wallpaper", useUnmergedTree = true)
                .fetchSemanticsNodes().isNotEmpty()
        }
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val directory = checkNotNull(context.getExternalFilesDir("quantum2-review"))
        check(directory.isDirectory || directory.mkdirs())
        // Only independent fixture screens are captured. No profile, credentials,
        // subscriber data or real-device diagnostic is put in these artifacts.
        File(directory, "$name.png").outputStream().use { output ->
            check(compose.onRoot().captureToImage().asAndroidBitmap().compress(Bitmap.CompressFormat.PNG, 100, output))
        }
    }
}
