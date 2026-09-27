package com.quantumvpn.ui

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.shape.RoundedCornerShape

/**
 * Shared dark aurora layer for the first screen a person sees in QuantumVPN.
 *
 * It intentionally uses Canvas rather than a video/image asset: the animation is small,
 * adapts to every display size and can be made still by the caller when motion is reduced.
 */
@Composable
internal fun AuroraGlassBackdrop(
    modifier: Modifier = Modifier,
    motionEnabled: Boolean = true,
) {
    val transition = rememberInfiniteTransition(label = "aurora-backdrop")
    val drift by transition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(11_000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart,
        ),
        label = "aurora-drift",
    )
    val shimmer by transition.animateFloat(
        initialValue = 0.25f,
        targetValue = 0.95f,
        animationSpec = infiniteRepeatable(
            animation = tween(2_600, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "aurora-shimmer",
    )
    val phase = if (motionEnabled) drift else 0.38f
    val light = if (motionEnabled) shimmer else 0.58f

    Canvas(modifier = modifier.fillMaxSize()) {
        val w = size.width
        val h = size.height
        drawRect(
            brush = Brush.verticalGradient(
                colors = listOf(
                    Color(0xFF050816),
                    Color(0xFF08142A),
                    Color(0xFF050714),
                ),
            ),
        )

        // Two very soft colour fields make the background feel alive without reducing contrast.
        val mintCenter = Offset(w * (0.08f + phase * 0.14f), h * 0.24f)
        drawCircle(
            brush = Brush.radialGradient(
                colors = listOf(
                    Color(0xFF32FFD0).copy(alpha = 0.15f * light),
                    Color(0xFF32FFD0).copy(alpha = 0.035f),
                    Color.Transparent,
                ),
                center = mintCenter,
                radius = w * 0.76f,
            ),
            center = mintCenter,
            radius = w * 0.76f,
        )
        val violetCenter = Offset(w * (0.92f - phase * 0.12f), h * 0.56f)
        drawCircle(
            brush = Brush.radialGradient(
                colors = listOf(
                    Color(0xFFC095FF).copy(alpha = 0.14f * (1.1f - light)),
                    Color(0xFF7959E8).copy(alpha = 0.035f),
                    Color.Transparent,
                ),
                center = violetCenter,
                radius = w * 0.84f,
            ),
            center = violetCenter,
            radius = w * 0.84f,
        )

        // Aurora bands. Their low alpha keeps text and buttons readable over the animation.
        repeat(3) { index ->
            val y = h * (0.17f + index * 0.09f)
            val offset = ((phase + index * 0.23f) % 1f) * w * 0.22f
            val band = Path().apply {
                moveTo(-w * 0.12f, y + offset * 0.08f)
                cubicTo(
                    w * 0.18f,
                    y - h * (0.10f + index * 0.015f),
                    w * 0.58f,
                    y + h * (0.12f + index * 0.02f),
                    w * 1.12f,
                    y - h * 0.05f,
                )
            }
            drawPath(
                path = band,
                color = (if (index % 2 == 0) Color(0xFF44F5C1) else Color(0xFFB990FF))
                    .copy(alpha = 0.12f + 0.05f * light),
                style = Stroke(
                    width = (1.2f + index * 0.55f) * density,
                    cap = StrokeCap.Round,
                ),
            )
        }

        // Sparse stars keep the layout recognisably "network / aurora", not a flat gradient.
        val points = listOf(
            0.09f to 0.13f, 0.23f to 0.29f, 0.78f to 0.15f, 0.91f to 0.32f,
            0.14f to 0.58f, 0.82f to 0.67f, 0.32f to 0.82f, 0.63f to 0.9f,
        )
        points.forEachIndexed { index, (x, y) ->
            val alpha = 0.22f + ((light + index * 0.11f) % 0.6f)
            val center = Offset(w * x, h * y)
            drawCircle(Color.White.copy(alpha = alpha), radius = 1.2f * density, center = center)
            if (index % 3 == 0) {
                drawCircle(Color(0xFF5EF8D1).copy(alpha = alpha * 0.34f), radius = 4.5f * density, center = center)
            }
        }
    }
}

/** A tinted glass container with a quiet highlight on its upper edge. */
@Composable
internal fun AuroraGlass(
    modifier: Modifier = Modifier,
    cornerRadius: Dp = 26.dp,
    tint: Color = Color(0xFF10213D),
    content: @Composable () -> Unit,
) {
    val shape = RoundedCornerShape(cornerRadius)
    Box(
        modifier = modifier
            .clip(shape)
            .background(
                brush = Brush.verticalGradient(
                    colors = listOf(
                        tint.copy(alpha = 0.82f),
                        Color(0xFF071328).copy(alpha = 0.78f),
                    ),
                ),
            )
            .border(
                width = 1.dp,
                color = Color.White.copy(alpha = 0.13f),
                shape = shape,
            ),
        content = { content() },
    )
}
