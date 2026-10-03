package com.quantumvpn.ui

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import com.quantumvpn.policy.ClientPolicy
import com.quantumvpn.ui.theme.QuantumVpnTheme
import com.quantumvpn.vpn.VpnSessionStats
import com.quantumvpn.updates.UpdateState
import org.junit.Rule
import org.junit.Test

/** Independent screen tests: no live subscription/VPN connection or data clearing. */
class Aurora2026InstrumentedTest {
    @get:Rule val compose = createComposeRule()

    @Test fun connectServerAndGameActionsAreRealButtons() {
        var connect = 0
        var games = 0
        compose.setContent {
            QuantumVpnTheme(darkTheme = true) {
                V2Home(ClientPolicy(), false, false, true, "Тестовый сервер", 52, true, 60, VpnSessionStats(),
                    onConnect = { connect++ }, onServers = {}, onSettings = {}, onCards = { games++ },
                    reduceMotion = true, onNotifications = {}, pingMeasured = true)
            }
        }
        compose.onNodeWithText("Подключить").performClick()
        compose.runOnIdle { check(connect == 1) }
        compose.onNodeWithTag("home-games").performScrollTo().performClick()
        compose.runOnIdle { check(games == 1) }
    }

    @Test fun startupDoesNotShowSimulatedPercentAndFinishesOnlyWhenReady() {
        var finished = false
        compose.setContent {
            QuantumVpnTheme {
                AuroraStartup2026(false, UpdateState.Checking("Stable"), 0, true) { finished = true }
            }
        }
        compose.onNodeWithText("Проверяем обновления").assertIsDisplayed()
        compose.onAllNodes(hasText("86%", substring = true)).assertCountEquals(0)
        compose.runOnIdle { check(!finished) }
    }
}
