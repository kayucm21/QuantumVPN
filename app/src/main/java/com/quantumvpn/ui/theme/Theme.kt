package com.quantumvpn.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.sp
import com.quantumvpn.ui.AccentColor

/** Happ-inspired dark-first palette with selectable accents. */
private fun lightColors(primary: Color, primaryContainer: Color, onPrimaryContainer: Color) =
    lightColorScheme(
        primary = primary,
        onPrimary = Color.White,
        primaryContainer = primaryContainer,
        onPrimaryContainer = onPrimaryContainer,
        secondary = Color(0xFF3D8BFF),
        secondaryContainer = Color(0xFFD6E6FF),
        tertiary = Color(0xFF6B7C93),
        background = Color(0xFFF4F6F8),
        surface = Color(0xFFF4F6F8),
        surfaceVariant = Color(0xFFE6EBEF),
        outline = Color(0xFF9AA5B1),
    )

private fun darkColors(primary: Color, onPrimary: Color, primaryContainer: Color, onPrimaryContainer: Color) =
    darkColorScheme(
        primary = primary,
        onPrimary = onPrimary,
        primaryContainer = primaryContainer,
        onPrimaryContainer = onPrimaryContainer,
        secondary = Color(0xFF5BA0FF),
        secondaryContainer = Color(0xFF1A3A66),
        tertiary = Color(0xFFA8B4C4),
        background = Color(0xFF06122A),
        surface = Color(0xFF0A1A3A),
        surfaceVariant = Color(0xFF13284F),
        surfaceContainerHighest = Color(0xFF163056),
        outline = Color(0xFF5C6673),
        error = Color(0xFFFF6B7A),
    )

private fun accentTriplet(accent: AccentColor): Triple<Color, Color, Color> = when (accent) {
    AccentColor.Green -> Triple(Color(0xFF1FAF6B), Color(0xFFD5F5E5), Color(0xFF05301C))
    AccentColor.Blue -> Triple(Color(0xFF2F6FED), Color(0xFFD6E4FF), Color(0xFF0A1F4A))
    AccentColor.Teal -> Triple(Color(0xFF0F9E9A), Color(0xFFCCF5F3), Color(0xFF043533))
    AccentColor.Amber -> Triple(Color(0xFFC98500), Color(0xFFFFE8B8), Color(0xFF3A2700))
    AccentColor.Purple -> Triple(Color(0xFF8B5CF6), Color(0xFFEDE7FF), Color(0xFF2D1B69))
    AccentColor.Rose -> Triple(Color(0xFFF43F5E), Color(0xFFFFE4E8), Color(0xFF4C0519))
    AccentColor.Orange -> Triple(Color(0xFFF97316), Color(0xFFFFEDD5), Color(0xFF431407))
    AccentColor.Mint -> Triple(Color(0xFF14B8A6), Color(0xFFCCFBF1), Color(0xFF042F2E))
}

private fun darkAccent(accent: AccentColor): Triple<Color, Color, Color> = when (accent) {
    AccentColor.Green -> Triple(Color(0xFF2EE59D), Color(0xFF0F6B45), Color(0xFFB8FFDC))
    AccentColor.Blue -> Triple(Color(0xFF7EB6FF), Color(0xFF1A3A66), Color(0xFFD6E6FF))
    AccentColor.Teal -> Triple(Color(0xFF4ADAD4), Color(0xFF0A524F), Color(0xFFB8FFFB))
    AccentColor.Amber -> Triple(Color(0xFFFFC44D), Color(0xFF6B4700), Color(0xFFFFE8B8))
    AccentColor.Purple -> Triple(Color(0xFFA78BFA), Color(0xFF3B1F6E), Color(0xFFEDE7FF))
    AccentColor.Rose -> Triple(Color(0xFFFB7185), Color(0xFF6B0F1F), Color(0xFFFFE4E8))
    AccentColor.Orange -> Triple(Color(0xFFFB923C), Color(0xFF5E2E0A), Color(0xFFFFEDD5))
    AccentColor.Mint -> Triple(Color(0xFF2DD4BF), Color(0xFF075E54), Color(0xFFCCFBF1))
}

@Composable
fun QuantumVpnTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    oledBlack: Boolean = false,
    accent: AccentColor = AccentColor.Green,
    largeText: Boolean = false,
    highContrast: Boolean = false,
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit,
) {
    val light = accentTriplet(accent)
    val dark = darkAccent(accent)
    val useDynamic = dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
    val baseScheme = if (useDynamic) {
        val ctx = LocalContext.current
        if (darkTheme) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
    } else {
        null
    }
    var colorScheme = when {
        useDynamic && darkTheme && oledBlack -> baseScheme!!.copy(
            background = Color.Black,
            surface = Color.Black,
            surfaceVariant = Color(0xFF121212),
            surfaceContainerHighest = Color(0xFF1A1A1A),
        )
        useDynamic -> baseScheme!!
        darkTheme && oledBlack -> darkColors(
            primary = dark.first,
            onPrimary = Color(0xFF003820),
            primaryContainer = dark.second,
            onPrimaryContainer = dark.third,
        ).copy(
            background = Color.Black,
            surface = Color.Black,
            surfaceVariant = Color(0xFF121212),
            surfaceContainerHighest = Color(0xFF1A1A1A),
        )
        darkTheme -> darkColors(
            primary = dark.first,
            onPrimary = Color(0xFF003820),
            primaryContainer = dark.second,
            onPrimaryContainer = dark.third,
        )
        else -> lightColors(light.first, light.second, light.third)
    }
    if (highContrast) {
        colorScheme = colorScheme.copy(
            outline = if (darkTheme) Color(0xFFE8EEF5) else Color(0xFF1A1F27),
            onSurface = if (darkTheme) Color.White else Color(0xFF0B0D10),
            onSurfaceVariant = if (darkTheme) Color(0xFFE0E6ED) else Color(0xFF2A313C),
        )
    }
    val typography = if (largeText) {
        QuantumVpnTypography.copy(
            bodyLarge = QuantumVpnTypography.bodyLarge.copy(fontSize = 18.sp),
            bodyMedium = QuantumVpnTypography.bodyMedium.copy(fontSize = 16.sp),
            bodySmall = QuantumVpnTypography.bodySmall.copy(fontSize = 14.sp),
            titleMedium = QuantumVpnTypography.titleMedium.copy(fontSize = 20.sp),
            labelLarge = QuantumVpnTypography.labelLarge.copy(fontSize = 15.sp),
        )
    } else {
        QuantumVpnTypography
    }
    MaterialTheme(
        colorScheme = colorScheme,
        typography = typography,
        content = content,
    )
}
