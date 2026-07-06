package com.quantumvpn.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

private val DarkColorScheme = darkColorScheme(
    primary = Color(0xFF6C63FF),
    secondary = Color(0xFF00D9FF),
    tertiary = Color(0xFFFF6584),
    background = Color(0xFF0A0E21),
    surface = Color(0xFF151A30),
    surfaceVariant = Color(0xFF1E2340),
    onPrimary = Color.White,
    onSecondary = Color.White,
    onBackground = Color.White,
    onSurface = Color.White,
    onSurfaceVariant = Color(0xFFB0B0C0),
    primaryContainer = Color(0xFF2A2D4E),
    secondaryContainer = Color(0xFF003544),
    error = Color(0xFFFF6B6B),
    onError = Color.White
)

private val LightColorScheme = lightColorScheme(
    primary = Color(0xFF6C63FF),
    secondary = Color(0xFF00B4D8),
    tertiary = Color(0xFFFF6584),
    background = Color(0xFFF5F5FA),
    surface = Color.White,
    surfaceVariant = Color(0xFFEEF0F5),
    onPrimary = Color.White,
    onSecondary = Color.White,
    onBackground = Color(0xFF1A1A2E),
    onSurface = Color(0xFF1A1A2E),
    onSurfaceVariant = Color(0xFF6B7280),
    primaryContainer = Color(0xFFE8E6FF),
    secondaryContainer = Color(0xFFD4F5FF),
    error = Color(0xFFE53935),
    onError = Color.White
)

@Composable
fun QuantumVPNTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}
