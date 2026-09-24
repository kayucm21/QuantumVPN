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
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import kotlin.math.cos
import kotlin.math.sin
import kotlin.random.Random

/**
 * Living ORBIT globe: rotating Earth, glowing atmosphere, orbital rings, twinkling stars.
 */
@Composable
fun Globe3DBackdrop(
    modifier: Modifier = Modifier,
    pulse: Boolean,
    reduceMotion: Boolean,
    countryCode: String? = null,
) {
    val transition = rememberInfiniteTransition(label = "orbit-globe")
    val alive = pulse && !reduceMotion
    val spin = if (alive) {
        transition.animateFloat(
            initialValue = 0f,
            targetValue = 360f,
            animationSpec = infiniteRepeatable(tween(18_000, easing = LinearEasing), RepeatMode.Restart),
            label = "spin",
        ).value
    } else {
        22f
    }
    val orbitSpin = if (alive) {
        transition.animateFloat(
            initialValue = 0f,
            targetValue = 360f,
            animationSpec = infiniteRepeatable(tween(7_200, easing = LinearEasing), RepeatMode.Restart),
            label = "orbit",
        ).value
    } else {
        0f
    }
    val orbitSpin2 = if (alive) {
        transition.animateFloat(
            initialValue = 360f,
            targetValue = 0f,
            animationSpec = infiniteRepeatable(tween(10_400, easing = LinearEasing), RepeatMode.Restart),
            label = "orbit2",
        ).value
    } else {
        40f
    }
    val orbitSpin3 = if (alive) {
        transition.animateFloat(
            initialValue = 0f,
            targetValue = 360f,
            animationSpec = infiniteRepeatable(tween(5_600, easing = LinearEasing), RepeatMode.Restart),
            label = "orbit3",
        ).value
    } else {
        80f
    }
    val breathe = if (alive) {
        transition.animateFloat(
            initialValue = 0.97f,
            targetValue = 1.05f,
            animationSpec = infiniteRepeatable(tween(2_800, easing = LinearEasing), RepeatMode.Reverse),
            label = "breathe",
        ).value
    } else {
        1f
    }
    val auraPulse = if (alive) {
        transition.animateFloat(
            initialValue = 0.35f,
            targetValue = 0.85f,
            animationSpec = infiniteRepeatable(tween(1_600, easing = LinearEasing), RepeatMode.Reverse),
            label = "aura",
        ).value
    } else {
        0.5f
    }
    val twinkle = if (alive) {
        transition.animateFloat(
            initialValue = 0.25f,
            targetValue = 1f,
            animationSpec = infiniteRepeatable(tween(1_100, easing = LinearEasing), RepeatMode.Reverse),
            label = "twinkle",
        ).value
    } else {
        0.7f
    }
    val stars = remember {
        List(72) { i ->
            val rnd = Random(i * 97 + 13)
            StarSpec(
                x = rnd.nextFloat(),
                y = rnd.nextFloat(),
                size = 0.8f + rnd.nextFloat() * 2.4f,
                phase = rnd.nextFloat(),
            )
        }
    }
    val (pinLat, pinLon) = countryLatLon(countryCode)

    Canvas(modifier = modifier.fillMaxSize()) {
        // Deep space + twinkling stars.
        drawRect(
            brush = Brush.verticalGradient(
                listOf(Color(0xFF02060F), Color(0xFF06101C), Color(0xFF040B16)),
            ),
        )
        stars.forEachIndexed { index, star ->
            val blink = ((twinkle + star.phase) % 1f)
            val alpha = 0.25f + 0.75f * blink
            val p = Offset(size.width * star.x, size.height * star.y)
            drawCircle(Color.White.copy(alpha = alpha * 0.9f), radius = star.size, center = p)
            if (index % 7 == 0) {
                drawCircle(Color(0xFF3DE7FF).copy(alpha = alpha * 0.45f), radius = star.size * 2.2f, center = p)
            }
        }

        val center = Offset(size.width * 0.5f, size.height * 0.38f)
        val radius = size.minDimension * 0.34f * breathe

        // Outer cosmic aura.
        drawCircle(
            brush = Brush.radialGradient(
                colors = listOf(
                    Color(0xFF3DE7FF).copy(alpha = 0.22f * auraPulse),
                    Color(0xFF7B5CFF).copy(alpha = 0.12f * auraPulse),
                    Color.Transparent,
                ),
                center = center,
                radius = radius * 1.85f,
            ),
            radius = radius * 1.85f,
            center = center,
        )
        // Atmosphere rim.
        drawCircle(
            brush = Brush.radialGradient(
                colors = listOf(
                    Color(0xFF5CE1FF).copy(alpha = 0.55f),
                    Color(0xFF1A6B9A).copy(alpha = 0.2f),
                    Color.Transparent,
                ),
                center = center,
                radius = radius * 1.22f,
            ),
            radius = radius * 1.18f,
            center = center,
        )
        // Ocean body.
        drawCircle(
            brush = Brush.radialGradient(
                colors = listOf(
                    Color(0xFF2A8FCC),
                    Color(0xFF145A8A),
                    Color(0xFF0A2F52),
                    Color(0xFF041528),
                ),
                center = center + Offset(-radius * 0.28f, -radius * 0.22f),
                radius = radius * 1.15f,
            ),
            radius = radius,
            center = center,
        )
        // Specular highlight.
        drawCircle(
            brush = Brush.radialGradient(
                colors = listOf(Color.White.copy(alpha = 0.42f), Color.Transparent),
                center = center + Offset(-radius * 0.38f, -radius * 0.45f),
                radius = radius * 0.55f,
            ),
            radius = radius * 0.55f,
            center = center + Offset(-radius * 0.38f, -radius * 0.45f),
        )

        rotate(spin, center) {
            drawGlobeGraticule(center, radius)
            drawGlobeLandMasses(center, radius)
            drawCityLights(center, radius)
        }

        // Living orbital rings with bright arcs.
        rotate(orbitSpin, center) {
            drawOrbitRing(center, radius * 1.38f, radius * 0.38f, Color(0xFF3DE7FF), 3.2f, auraPulse)
        }
        rotate(orbitSpin2, center) {
            drawOrbitRing(center, radius * 1.18f, radius * 0.52f, Color(0xFF8B6CFF), 2.4f, auraPulse * 0.85f)
        }
        rotate(orbitSpin3 + 55f, center) {
            drawOrbitRing(center, radius * 1.08f, radius * 0.68f, Color(0xFF5CF0D0), 1.8f, auraPulse * 0.7f)
        }
        // Moving bead on the brightest ring.
        val beadAngle = Math.toRadians(orbitSpin.toDouble())
        val bead = Offset(
            center.x + cos(beadAngle).toFloat() * radius * 1.38f,
            center.y + sin(beadAngle).toFloat() * radius * 0.38f,
        )
        drawCircle(Color(0xFF3DE7FF).copy(alpha = 0.35f), radius = 14f, center = bead)
        drawCircle(Color.White, radius = 4.5f, center = bead)

        if (countryCode != null) {
            drawExitPin(center, radius, pinLat, pinLon, spin)
        }
    }
}

private data class StarSpec(val x: Float, val y: Float, val size: Float, val phase: Float)

private fun DrawScope.drawOrbitRing(
    center: Offset,
    rx: Float,
    ry: Float,
    color: Color,
    stroke: Float,
    glow: Float,
) {
    drawOval(
        color = color.copy(alpha = 0.22f + 0.35f * glow),
        topLeft = Offset(center.x - rx, center.y - ry),
        size = Size(rx * 2f, ry * 2f),
        style = Stroke(width = stroke + 4f, cap = StrokeCap.Round),
    )
    drawOval(
        color = color.copy(alpha = 0.55f + 0.35f * glow),
        topLeft = Offset(center.x - rx, center.y - ry),
        size = Size(rx * 2f, ry * 2f),
        style = Stroke(width = stroke, cap = StrokeCap.Round),
    )
}

private fun DrawScope.drawGlobeGraticule(center: Offset, radius: Float) {
    val grid = Color.White.copy(alpha = 0.12f)
    for (i in -3..3) {
        val lat = i * 15f
        val y = center.y + radius * sin(Math.toRadians(lat.toDouble())).toFloat() * 0.92f
        val w = radius * cos(Math.toRadians(lat.toDouble())).toFloat().coerceAtLeast(0.12f)
        drawLine(grid, Offset(center.x - w, y), Offset(center.x + w, y), strokeWidth = 1.1f)
    }
    for (i in 0 until 8) {
        val lon = i * 22.5f
        val path = Path()
        var first = true
        for (step in -90..90 step 10) {
            val latRad = Math.toRadians(step.toDouble())
            val lonRad = Math.toRadians((lon + step * 0.04).toDouble())
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
    val land = Color(0xFF3FA86A).copy(alpha = 0.72f)
    val landDark = Color(0xFF1F6B45).copy(alpha = 0.65f)
    val blobs = listOf(
        Offset(-0.38f, -0.14f) to 0.24f,
        Offset(0.05f, -0.2f) to 0.3f,
        Offset(0.4f, 0.02f) to 0.2f,
        Offset(-0.1f, 0.3f) to 0.18f,
        Offset(0.22f, 0.22f) to 0.14f,
        Offset(-0.48f, 0.12f) to 0.12f,
    )
    blobs.forEachIndexed { index, (rel, relR) ->
        drawCircle(
            color = if (index % 2 == 0) land else landDark,
            radius = radius * relR,
            center = center + Offset(radius * rel.x, radius * rel.y),
        )
    }
}

private fun DrawScope.drawCityLights(center: Offset, radius: Float) {
    val lights = listOf(
        Offset(-0.22f, -0.08f),
        Offset(0.12f, -0.16f),
        Offset(0.32f, 0.05f),
        Offset(-0.05f, 0.18f),
        Offset(0.18f, 0.28f),
        Offset(-0.4f, 0.05f),
        Offset(0.02f, -0.02f),
    )
    lights.forEach { rel ->
        val p = center + Offset(radius * rel.x, radius * rel.y)
        drawCircle(Color(0xFFFFE08A).copy(alpha = 0.55f), radius = 2.2f, center = p)
        drawCircle(Color(0xFFFFF6C8).copy(alpha = 0.9f), radius = 1.1f, center = p)
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
