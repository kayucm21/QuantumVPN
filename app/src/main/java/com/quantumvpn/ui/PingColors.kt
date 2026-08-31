package com.quantumvpn.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

object PingColors {
    fun colorForPing(pingMillis: Int?): Color? = when {
        pingMillis == null -> null
        pingMillis < 80 -> Color(0xFF2E7D32)
        pingMillis < 200 -> Color(0xFFF9A825)
        pingMillis < 2000 -> Color(0xFFE65100)
        else -> Color(0xFFC62828)
    }

    @Composable
    fun themedColor(pingMillis: Int?): Color =
        colorForPing(pingMillis) ?: MaterialTheme.colorScheme.onSurfaceVariant

    fun labelForPing(pingMillis: Int?): String = when {
        pingMillis == null -> "—"
        pingMillis >= 2000 -> "мёртвый"
        pingMillis < 80 -> "отличный"
        pingMillis < 200 -> "норма"
        else -> "медленный"
    }
}
