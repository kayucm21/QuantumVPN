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
    val Void = Color(0xFF06122A)
    val Deep = Color(0xFF0A1A3A)
    val Panel = Color(0xFF13284F)
    val Neon = Color(0xFF2F7BFF)
    val NeonDim = Color(0xFF1A4A9A)
    val Orbit = Color(0xFF5BA0FF)
    val GlowRing = Color(0xFF3D8BFF)
    val StatusYellow = Color(0xFFFFD54F)
    val StatusGreen = Color(0xFF4ADE80)
    val StatusRed = Color(0xFFFF6B7A)
    val MapTint = Color(0xFF1A3A6E)
    val ConnectedGlow = Color(0xFF0C2A55)
    val IdleGlow = Color(0xFF081830)
    val Card = Color(0xFF163056)
    val VipBlue = Color(0xFF2B6CFF)
    val OnVoid = Color(0xFFF2F6FC)
    val OnVoidMuted = Color(0xFF9BB0D0)
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
