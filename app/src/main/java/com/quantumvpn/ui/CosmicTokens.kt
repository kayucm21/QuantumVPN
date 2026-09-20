package com.quantumvpn.ui

import android.os.Build
import android.view.HapticFeedbackConstants
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/** Unified QuantumVPN design tokens (Home + tabs + settings). */
object CosmicTokens {
    val Void = Color(0xFF070714)
    val Deep = Color(0xFF100D28)
    val Panel = Color(0xD91A1B3A)
    val Neon = Color(0xFFC395FF)
    val NeonDim = Color(0xFF5D477F)
    val Orbit = Color(0xFF9E8CFF)
    val GlowRing = Color(0xFF54F4CF)
    val StatusYellow = Color(0xFFFFD54F)
    val StatusGreen = Color(0xFF54F4CF)
    val StatusRed = Color(0xFFFF6B7A)
    val MapTint = Color(0xFF34235B)
    val ConnectedGlow = Color(0xFF203E55)
    val IdleGlow = Color(0xFF14132B)
    val Card = Color(0xCC18233E)
    val VipBlue = Color(0xFF9E8CFF)
    val OnVoid = Color(0xFFF2F6FC)
    val OnVoidMuted = Color(0xFFB9B6D1)
    val Hairline = Color(0x33FFFFFF)

    object Space {
        val xs: Dp = 4.dp
        val sm: Dp = 8.dp
        val md: Dp = 12.dp
        val lg: Dp = 16.dp
        val xl: Dp = 24.dp
        val xxl: Dp = 32.dp
    }

    object Radius {
        val sm: Dp = 10.dp
        val md: Dp = 16.dp
        val lg: Dp = 22.dp
        val pill: Dp = 999.dp
    }

    object Motion {
        const val TabCrossfadeMs = 220
        const val SheetSpringDamping = 0.86f
        const val ConnectPulseMs = 1400
    }
}

object Haptics {
    @Composable
    fun rememberPerformer(enabled: Boolean = true): (Int) -> Unit {
        val view = LocalView.current
        return { type ->
            if (enabled) view.performHapticFeedback(type)
        }
    }

    val Click: Int = HapticFeedbackConstants.KEYBOARD_TAP
    val Confirm: Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            HapticFeedbackConstants.CONFIRM
        } else {
            HapticFeedbackConstants.LONG_PRESS
        }
    val Reject: Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            HapticFeedbackConstants.REJECT
        } else {
            HapticFeedbackConstants.LONG_PRESS
        }
}
