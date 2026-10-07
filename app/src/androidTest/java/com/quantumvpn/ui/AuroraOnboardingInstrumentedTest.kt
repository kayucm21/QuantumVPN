package com.quantumvpn.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.requiredSize
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.unit.dp
import com.quantumvpn.ui.theme.QuantumVpnTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

class AuroraOnboardingInstrumentedTest {
    @get:Rule val compose = createComposeRule()

    @Test fun welcomeRequiresNameAndReturnsNormalizedNicknameOnly() {
        var completed = ""
        compose.setContent { QuantumVpnTheme(darkTheme = true) {
            Box(Modifier.requiredSize(360.dp, 640.dp)) { AuroraNamedOnboarding2026 { completed = it } }
        } }
        compose.onNodeWithTag("onboarding-continue").assertIsDisplayed().performClick()
        compose.onNodeWithTag("onboarding-continue").performScrollTo().assertIsNotEnabled()
        compose.onNodeWithTag("onboarding-name").performTextInput("  Алексей   Иванов  ")
        compose.onNodeWithTag("onboarding-continue").performScrollTo().assertIsEnabled().performClick()
        compose.runOnIdle { assertEquals("Алексей Иванов", completed) }
    }

    @Test fun invalidNicknameCannotEnterApplication() {
        var callbacks = 0
        compose.setContent { QuantumVpnTheme(darkTheme = true) { AuroraNamedOnboarding2026 { callbacks++ } } }
        compose.onNodeWithTag("onboarding-continue").performScrollTo().performClick()
        compose.onNodeWithTag("onboarding-name").performTextInput("A")
        compose.onNodeWithTag("onboarding-continue").performScrollTo().assertIsNotEnabled()
        compose.runOnIdle { assertEquals(0, callbacks) }
    }
}
