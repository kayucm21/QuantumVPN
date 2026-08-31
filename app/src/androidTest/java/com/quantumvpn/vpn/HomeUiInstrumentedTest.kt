package com.quantumvpn.vpn

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import com.quantumvpn.MainActivity
import com.quantumvpn.QuantumVpnApplication
import com.quantumvpn.profiles.ProfileSource
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test

class HomeUiInstrumentedTest {
    @get:Rule
    val composeRule = createAndroidComposeRule<MainActivity>()

    private val container
        get() = (composeRule.activity.application as QuantumVpnApplication).container

    private var profileId: String? = null

    @Before
    fun prepareConnectedDashboard() = runBlocking {
        container.profileStore.initialize()
        container.profileStore.profiles.value.forEach { container.profileStore.delete(it.id) }
        val profile = container.profileStore.create("Daily VPN", PROFILE, ProfileSource.RawJson)
        profileId = profile.id
        container.uiSettingsStore.setActiveProfile(profile.id)
        container.appSelectionStore.replaceAllowlist(setOf("com.android.settings"))
        val generation = container.vpnController.nextGeneration()
        container.vpnController.publish(
            generation,
            VpnConnectionState.Connected(profile.id, profile.name, System.currentTimeMillis() - 65_000),
        )
        container.vpnController.publishGroups(
            generation,
            listOf(
                RuntimeSelectorGroup(
                    tag = "zapret-proxy",
                    type = "selector",
                    selected = "Moscow",
                    selectable = true,
                    items = listOf(
                        RuntimeOutboundItem(
                            tag = "Moscow",
                            type = "vless",
                            endpoint = "vpn.example:443",
                            pingMillis = 42,
                            pingMeasuredAtEpochSeconds = 1,
                        ),
                    ),
                ),
            ),
        )
        container.vpnController.publishPing(generation, 42)
        container.vpnController.publishExternalIp(generation, "203.0.113.9")
        container.vpnController.publishStatusStream(generation, true)
        container.vpnController.publishTraffic(generation, 1_024, 2_048, 4_096, 8_192)
    }

    @After
    fun cleanup() = runBlocking {
        container.vpnController.setHomeVisible(false)
        val generation = container.vpnController.nextGeneration()
        container.vpnController.publish(generation, VpnConnectionState.Stopped)
        profileId?.let { container.profileStore.delete(it) }
        container.uiSettingsStore.setActiveProfile(null)
        container.appSelectionStore.replaceAllowlist(emptySet())
    }

    @Test
    fun compactCardAndSelectorSheetExposeSessionData() {
        composeRule.onNodeWithText("Защищено").assertExists()
        composeRule.onNodeWithText("Daily VPN").assertExists()
        composeRule.onNodeWithText("IP 203.0.113.9", substring = true).assertExists()
        composeRule.onNodeWithText("42 ms", substring = true).assertExists()
        composeRule.onNodeWithText("↓ 8.0 KB").assertExists()
        composeRule.onNodeWithText("↑ 4.0 KB").assertExists()

        composeRule.onNodeWithText("Moscow").performClick()
        composeRule.onNodeWithText("Серверы").assertExists()
        composeRule.onAllNodesWithText("VLESS · vpn.example:443").assertCountEquals(2)
        composeRule.onNodeWithText("Проверить").assertExists()
    }

    @Test
    fun homeRendersEveryConnectionStateWithoutChangingScreens() {
        val profile = checkNotNull(profileId)
        var generation = container.vpnController.nextGeneration()
        container.vpnController.publish(generation, VpnConnectionState.Stopped)
        composeRule.onNodeWithText("Не защищено").assertExists()
        composeRule.onNodeWithText("Подключить").assertExists()

        generation = container.vpnController.nextGeneration()
        container.vpnController.publish(
            generation,
            VpnConnectionState.Starting(profile, "Проверка sing-box"),
        )
        composeRule.onNodeWithText("Подключение…").assertExists()
        composeRule.onNodeWithText("Проверка sing-box").assertExists()
        composeRule.onNodeWithText("Остановить").assertExists()

        container.vpnController.publish(generation, VpnConnectionState.Stopping(profile))
        composeRule.onNodeWithText("Отключение…").assertExists()
        composeRule.onNodeWithText("Остановить").assertExists()

        container.vpnController.publish(
            generation,
            VpnConnectionState.Error("DNS через VPN заблокирован token=home-secret"),
        )
        composeRule.onNodeWithText("Ошибка подключения").assertExists()
        composeRule.onNodeWithText("home-secret", substring = true).assertDoesNotExist()
        composeRule.onNodeWithText("Подключить").assertExists()

        container.vpnController.publish(
            generation,
            VpnConnectionState.Connected(profile, "Daily VPN", System.currentTimeMillis()),
        )
        composeRule.onNodeWithText("Защищено").assertExists()
        composeRule.onNodeWithText("Отключить").assertExists()
    }

    @Test
    fun homeBlocksConnectionUntilProfileIsSelected() {
        runBlocking { container.uiSettingsStore.setActiveProfile(null) }
        composeRule.waitUntil(10_000) {
            composeRule.onAllNodesWithText("Добавить подписку").fetchSemanticsNodes().isNotEmpty()
        }
        composeRule.onNodeWithText("Добавить подписку").assertExists()
    }

    private companion object {
        const val PROFILE = """
            {
              "inbounds":[{"type":"tun","tag":"tun-in","address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],"auto_route":true,"route_address":["0.0.0.0/0","::/0"]}],
              "outbounds":[
                {"type":"vless","tag":"Moscow","server":"vpn.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001"},
                {"type":"selector","tag":"zapret-proxy","outbounds":["Moscow"],"default":"Moscow"}
              ],
              "route":{"auto_detect_interface":true,"final":"zapret-proxy"}
            }
        """
    }
}
