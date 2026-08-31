package com.quantumvpn.vpn

import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import com.quantumvpn.MainActivity
import com.quantumvpn.QuantumVpnApplication
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test

class AppPickerUiInstrumentedTest {
    @get:Rule
    val composeRule = createAndroidComposeRule<MainActivity>()

    private val container
        get() = (composeRule.activity.application as QuantumVpnApplication).container

    @Before
    fun clearSelection() = runBlocking {
        container.appSelectionStore.replaceAllowlist(emptySet())
        container.appSelectionStore.setMode(AppScopeMode.Include)
    }

    @After
    fun cleanSelection() = runBlocking {
        container.appSelectionStore.replaceAllowlist(emptySet())
        container.appSelectionStore.setMode(AppScopeMode.Include)
    }

    @Test
    fun userFindsSystemAppSelectsItAndSelectionSurvivesRecreation() {
        composeRule.waitUntil(timeoutMillis = 20_000) {
            runBlocking { container.appSelectionStore.selection.first().initialized }
        }
        composeRule.onNodeWithText("Маршруты").performClick()
        composeRule.onNodeWithText("Выбрать приложения").performClick()
        composeRule.onNodeWithTag("show-system-apps").performClick()
        composeRule.onNodeWithTag("app-search").performTextInput(SETTINGS_PACKAGE)
        composeRule.waitUntil(timeoutMillis = 20_000) {
            composeRule.onAllNodesWithTag("app-row-$SETTINGS_PACKAGE")
                .fetchSemanticsNodes()
                .isNotEmpty()
        }
        composeRule.onNodeWithTag("app-row-$SETTINGS_PACKAGE").assertExists().performClick()
        composeRule.waitUntil(timeoutMillis = 10_000) {
            runBlocking {
                SETTINGS_PACKAGE in container.appSelectionStore.selection.first().allowedPackages
            }
        }
        composeRule.onNodeWithContentDescription("Назад").performClick()
        composeRule.onNodeWithText("В Android TUN: 1").assertExists()

        composeRule.activityRule.scenario.recreate()
        composeRule.waitForIdle()
        composeRule.onNodeWithText("В Android TUN: 1").assertExists()
    }

    private companion object {
        const val SETTINGS_PACKAGE = "com.android.settings"
    }
}
