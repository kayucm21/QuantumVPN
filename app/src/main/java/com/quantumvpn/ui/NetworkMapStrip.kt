package com.quantumvpn.ui

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
import androidx.compose.ui.graphics.drawscope.clipRect
import androidx.compose.ui.unit.dp
import com.quantumvpn.vpn.ExitLocation

data class PlanetMarker(
    val countryCode: String?,
    val primary: Boolean = false,
    val dimmed: Boolean = false,
)

/**
 * Flat equirectangular world map with a real exit pin — not a decorative spinning globe.
 */
@Composable
internal fun NetworkMapStrip(
    location: ExitLocation?,
    active: Boolean,
    modifier: Modifier = Modifier,
    extraMarkers: List<PlanetMarker> = emptyList(),
    leakRisk: Boolean = false,
) {
    val ocean = Color(0xFF1A3A5C)
    val oceanDeep = Color(0xFF0E2438)
    val land = Color(0xFF3D6B4F)
    val landEdge = Color(0xFF2A4A38)
    val grid = Color.White.copy(alpha = 0.10f)
    val accent = MaterialTheme.colorScheme.primary
    val secondary = MaterialTheme.colorScheme.secondary
    val warning = MaterialTheme.colorScheme.error

    val transition = rememberInfiniteTransition(label = "map-pulse")
    val pulse by transition.animateFloat(
        initialValue = 0.45f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(1_400, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "pulse",
    )

    val target = countryLatLon(location?.countryCode)
    val latAnim = remember { Animatable(target.first) }
    val lonAnim = remember { Animatable(target.second) }
    LaunchedEffect(target.first, target.second) {
        latAnim.animateTo(target.first, tween(700))
        lonAnim.animateTo(target.second, tween(700))
    }

    Canvas(
        modifier = modifier
            .fillMaxWidth()
            .height(176.dp)
            .padding(horizontal = 2.dp),
    ) {
        clipRect {
            drawRect(
                brush = Brush.verticalGradient(listOf(ocean, oceanDeep)),
                size = size,
            )
            drawGraticule(grid)
            for (continent in WORLD_CONTINENTS) {
                val path = continentPath(continent, size)
                drawPath(path, land)
                drawPath(path, landEdge, style = Stroke(width = 1.2.dp.toPx()))
            }

            for (marker in extraMarkers.filterNot { it.primary }) {
                val ll = countryLatLon(marker.countryCode)
                val point = projectFlat(ll.first, ll.second, size)
                drawCircle(
                    color = secondary.copy(alpha = if (marker.dimmed) 0.35f else 0.75f),
                    radius = 3.5.dp.toPx(),
                    center = point,
                )
            }

            val pin = projectFlat(latAnim.value, lonAnim.value, size)
            if (active || location != null) {
                val you = Offset(size.width * 0.5f, size.height - 6.dp.toPx())
                drawLine(
                    color = accent.copy(alpha = 0.35f * pulse),
                    start = you,
                    end = pin,
                    strokeWidth = 1.5.dp.toPx(),
                    cap = StrokeCap.Round,
                )
                drawCircle(
                    color = (if (leakRisk) warning else accent).copy(alpha = 0.22f * pulse),
                    radius = 18.dp.toPx() * pulse,
                    center = pin,
                )
                drawCircle(
                    color = if (leakRisk) warning else accent,
                    radius = 7.dp.toPx(),
                    center = pin,
                )
                drawCircle(
                    color = Color.White,
                    radius = 2.6.dp.toPx(),
                    center = pin,
                )
            }

            drawRect(
                color = if (leakRisk) warning.copy(alpha = 0.55f) else Color.White.copy(alpha = 0.18f),
                style = Stroke(width = if (leakRisk) 2.5.dp.toPx() else 1.2.dp.toPx()),
            )
        }
    }
}

private fun DrawScope.drawGraticule(color: Color) {
    for (lon in -150..150 step 30) {
        val x = ((lon + 180f) / 360f) * size.width
        drawLine(color, Offset(x, 0f), Offset(x, size.height), strokeWidth = 1f)
    }
    for (lat in listOf(-60f, -30f, 0f, 30f, 60f)) {
        val y = ((90f - lat) / 180f) * size.height
        drawLine(color, Offset(0f, y), Offset(size.width, y), strokeWidth = 1f)
    }
}

private fun continentPath(points: List<Pair<Float, Float>>, size: Size): Path {
    val path = Path()
    points.forEachIndexed { index, (lat, lon) ->
        val p = projectFlat(lat, lon, size)
        if (index == 0) path.moveTo(p.x, p.y) else path.lineTo(p.x, p.y)
    }
    path.close()
    return path
}

private fun projectFlat(latDeg: Float, lonDeg: Float, size: Size): Offset {
    val x = ((lonDeg + 180f) / 360f) * size.width
    val y = ((90f - latDeg) / 180f) * size.height
    return Offset(x.coerceIn(0f, size.width), y.coerceIn(0f, size.height))
}

/** Simplified lat/lon rings for recognizable landmasses (equirectangular). */
private val WORLD_CONTINENTS: List<List<Pair<Float, Float>>> = listOf(
    // North America
    listOf(
        70f to -165f, 68f to -140f, 60f to -140f, 55f to -130f, 48f to -125f,
        32f to -117f, 25f to -110f, 15f to -95f, 7f to -80f, 15f to -75f,
        25f to -80f, 30f to -85f, 45f to -65f, 50f to -55f, 60f to -65f,
        70f to -90f, 72f to -120f, 70f to -165f,
    ),
    // South America
    listOf(
        12f to -75f, 5f to -60f, -5f to -35f, -25f to -45f, -55f to -70f,
        -50f to -75f, -20f to -70f, 0f to -80f, 12f to -75f,
    ),
    // Europe
    listOf(
        71f to 5f, 70f to 30f, 60f to 30f, 55f to 40f, 45f to 30f,
        36f to 25f, 36f to -10f, 43f to -10f, 50f to 0f, 58f to 5f, 71f to 5f,
    ),
    // Africa
    listOf(
        37f to -10f, 35f to 10f, 32f to 32f, 12f to 50f, -5f to 40f,
        -35f to 25f, -35f to 18f, 0f to 10f, 5f to -5f, 15f to -15f, 37f to -10f,
    ),
    // Asia
    listOf(
        75f to 40f, 70f to 100f, 65f to 160f, 55f to 160f, 45f to 145f,
        35f to 140f, 20f to 120f, 8f to 100f, 5f to 75f, 25f to 60f,
        40f to 45f, 55f to 40f, 75f to 40f,
    ),
    // Australia
    listOf(
        -10f to 115f, -12f to 135f, -25f to 150f, -40f to 145f,
        -35f to 115f, -20f to 112f, -10f to 115f,
    ),
    // Greenland
    listOf(
        83f to -55f, 75f to -20f, 60f to -45f, 70f to -55f, 83f to -55f,
    ),
)

internal fun countryLatLon(countryCode: String?): Pair<Float, Float> {
    val code = countryCode?.uppercase()
    return when (code) {
        "US" -> 39f to -98f
        "CA" -> 56f to -106f
        "MX" -> 23f to -102f
        "BR" -> -14f to -51f
        "AR" -> -34f to -64f
        "CL" -> -35f to -71f
        "GB" -> 54f to -2f
        "IE" -> 53f to -8f
        "IS" -> 65f to -18f
        "SE" -> 62f to 15f
        "NO" -> 62f to 10f
        "FI" -> 64f to 26f
        "DK" -> 56f to 10f
        "EE" -> 59f to 25f
        "LV" -> 57f to 25f
        "LT" -> 55f to 24f
        "DE" -> 51f to 10f
        "NL" -> 52f to 5f
        "BE" -> 50f to 4f
        "FR" -> 46f to 2f
        "CH" -> 47f to 8f
        "AT" -> 47f to 14f
        "PL" -> 52f to 19f
        "CZ" -> 50f to 15f
        "ES" -> 40f to -3f
        "PT" -> 39f to -8f
        "IT" -> 42f to 12f
        "TR" -> 39f to 35f
        "RO" -> 46f to 25f
        "BG" -> 43f to 25f
        "RS" -> 44f to 21f
        "GR" -> 39f to 22f
        "RU" -> 55f to 55f
        "UA" -> 49f to 32f
        "KZ" -> 48f to 67f
        "IL" -> 31f to 35f
        "AE" -> 24f to 54f
        "SA" -> 24f to 45f
        "IN" -> 22f to 79f
        "SG" -> 1f to 104f
        "TH" -> 15f to 101f
        "VN" -> 16f to 108f
        "CN" -> 35f to 105f
        "HK" -> 22f to 114f
        "TW" -> 24f to 121f
        "KR" -> 36f to 128f
        "JP" -> 36f to 138f
        "AU" -> -25f to 134f
        "NZ" -> -41f to 174f
        "ZA" -> -29f to 24f
        "EG" -> 26f to 30f
        "NG" -> 10f to 8f
        else -> {
            val seed = (code?.sumOf { it.code } ?: 0) % 360
            val lon = seed - 180f
            val lat = ((seed * 17) % 120) - 60f
            lat to lon
        }
    }
}
