package com.quantumvpn.ui

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import kotlin.math.cos
import kotlin.math.sin

/**
 * Pseudo-3D globe backdrop: shaded sphere, grid lines, optional exit pin.
 * Lightweight Canvas — no OpenGL / Filament.
 */
@Composable
fun Globe3DBackdrop(
    modifier: Modifier = Modifier,
    pulse: Boolean,
    reduceMotion: Boolean,
    countryCode: String? = null,
) {
    val transition = rememberInfiniteTransition(label = "globe3d")
    val spin = if (pulse && !reduceMotion) {
        transition.animateFloat(
            initialValue = 0f,
            targetValue = 360f,
            animationSpec = infiniteRepeatable(
                animation = tween(24_000, easing = LinearEasing),
                repeatMode = RepeatMode.Restart,
            ),
            label = "spin",
        ).value
    } else {
        18f
    }
    val breathe = if (pulse && !reduceMotion) {
        transition.animateFloat(
            initialValue = 0.96f,
            targetValue = 1.04f,
            animationSpec = infiniteRepeatable(
                animation = tween(2_400, easing = LinearEasing),
                repeatMode = RepeatMode.Reverse,
            ),
            label = "breathe",
        ).value
    } else {
        1f
    }
    val (pinLat, pinLon) = countryLatLon(countryCode)

    Canvas(modifier = modifier.fillMaxSize()) {
        val center = Offset(size.width * 0.5f, size.height * 0.38f)
        val radius = size.minDimension * 0.34f * breathe
        drawCircle(
            brush = Brush.radialGradient(
                colors = listOf(
                    CosmicTokens.Orbit.copy(alpha = 0.18f),
                    Color.Transparent,
                ),
                center = center,
                radius = radius * 1.45f,
            ),
            radius = radius * 1.45f,
            center = center,
        )
        drawCircle(
            brush = Brush.radialGradient(
                colors = listOf(
                    Color(0xFF1A5080),
                    Color(0xFF0A2848),
                    Color(0xFF041020),
                ),
                center = center + Offset(-radius * 0.22f, -radius * 0.18f),
                radius = radius * 1.1f,
            ),
            radius = radius,
            center = center,
        )
        drawCircle(
            brush = Brush.radialGradient(
                colors = listOf(
                    Color.White.copy(alpha = 0.35f),
                    Color.Transparent,
                ),
                center = center + Offset(-radius * 0.35f, -radius * 0.42f),
                radius = radius * 0.55f,
            ),
            radius = radius * 0.55f,
            center = center + Offset(-radius * 0.35f, -radius * 0.42f),
        )
        rotate(spin, center) {
            drawGlobeGraticule(center, radius)
            drawGlobeLandMasses(center, radius)
        }
        if (countryCode != null) {
            drawExitPin(center, radius, pinLat, pinLon, spin)
        }
    }
}

private fun DrawScope.drawGlobeGraticule(center: Offset, radius: Float) {
    val grid = Color.White.copy(alpha = 0.08f)
    for (i in -2..2) {
        val lat = i * 18f
        val y = center.y + radius * sin(Math.toRadians(lat.toDouble())).toFloat() * 0.92f
        val w = radius * cos(Math.toRadians(lat.toDouble())).toFloat().coerceAtLeast(0.15f)
        drawLine(grid, Offset(center.x - w, y), Offset(center.x + w, y), strokeWidth = 1.2f)
    }
    for (i in 0 until 6) {
        val lon = i * 30f
        val path = Path()
        var first = true
        for (step in -90..90 step 12) {
            val latRad = Math.toRadians(step.toDouble())
            val lonRad = Math.toRadians((lon + step * 0.05).toDouble())
            val x = center.x + radius * cos(latRad).toFloat() * sin(lonRad).toFloat()
            val y = center.y + radius * sin(latRad).toFloat()
            if (first) {
                path.moveTo(x, y)
                first = false
            } else {
                path.lineTo(x, y)
            }
        }
        drawPath(path, grid, style = Stroke(width = 1f))
    }
}

private fun DrawScope.drawGlobeLandMasses(center: Offset, radius: Float) {
    val land = Color(0xFF2A6B4A).copy(alpha = 0.55f)
    val blobs = listOf(
        Offset(-0.35f, -0.12f) to 0.22f,
        Offset(0.08f, -0.18f) to 0.28f,
        Offset(0.42f, 0.05f) to 0.18f,
        Offset(-0.08f, 0.28f) to 0.16f,
    )
    blobs.forEach { (rel, relR) ->
        drawCircle(
            color = land,
            radius = radius * relR,
            center = center + Offset(radius * rel.x, radius * rel.y),
        )
    }
}

private fun DrawScope.drawExitPin(
    center: Offset,
    radius: Float,
    lat: Float,
    lon: Float,
    spin: Float,
) {
    val latRad = Math.toRadians(lat.toDouble())
    val lonRad = Math.toRadians((lon - spin * 0.35f).toDouble())
    val x = center.x + radius * cos(latRad).toFloat() * sin(lonRad).toFloat()
    val y = center.y + radius * sin(latRad).toFloat()
    drawCircle(CosmicTokens.StatusGreen.copy(alpha = 0.35f), radius = 10f, center = Offset(x, y))
    drawCircle(CosmicTokens.StatusGreen, radius = 5f, center = Offset(x, y))
    drawCircle(Color.White, radius = 2f, center = Offset(x - 1.5f, y - 1.5f))
}
