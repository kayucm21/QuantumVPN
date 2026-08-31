package com.quantumvpn.ui

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.quantumvpn.R
import kotlinx.coroutines.delay
import kotlin.math.roundToInt

/**
 * Cold-start splash: animated brand mark (rotating arc ring + gentle pulse),
 * greeting, dynamic status line, then a determinate percent bar.
 * Progress climbs toward 92% until [ready], then finishes at 100% before [onFinished].
 */
@Composable
fun StartupSplashScreen(
    ready: Boolean,
    onFinished: () -> Unit,
) {
    val progress = remember { Animatable(0f) }
    var percent by remember { mutableIntStateOf(0) }
    val brand = MaterialTheme.colorScheme.primary
    val bg = MaterialTheme.colorScheme.background
    val surface = MaterialTheme.colorScheme.surfaceVariant
    val onBg = MaterialTheme.colorScheme.onBackground
    val onSurface = MaterialTheme.colorScheme.onSurfaceVariant

    val infinite = rememberInfiniteTransition(label = "splash-anim")
    val rotation by infinite.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1100, easing = LinearEasing),
            repeatMode = RepeatMode.Restart,
        ),
        label = "ring-rotation",
    )
    val pulse by infinite.animateFloat(
        initialValue = 1f,
        targetValue = 1.07f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 900, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "icon-pulse",
    )

    LaunchedEffect(ready) {
        val startedAt = System.currentTimeMillis()
        if (!ready) {
            while (progress.value < 0.92f) {
                val next = (progress.value + 0.018f).coerceAtMost(0.92f)
                progress.snapTo(next)
                percent = (next * 100f).roundToInt()
                delay(40)
            }
            return@LaunchedEffect
        }
        val elapsed = System.currentTimeMillis() - startedAt
        if (elapsed < 900L) delay(900L - elapsed)
        progress.animateTo(
            targetValue = 1f,
            animationSpec = tween(durationMillis = 320, easing = LinearEasing),
        )
        percent = 100
        delay(180)
        onFinished()
    }

    val status = when {
        percent >= 92 -> "Почти готово…"
        percent >= 60 -> "Загрузка профилей…"
        percent >= 30 -> "Подготовка ядра…"
        else -> "Запуск QuantumVPN…"
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(bg)
            .semantics { contentDescription = "Загрузка QuantumVPN $percent%" },
        contentAlignment = Alignment.Center,
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
            modifier = Modifier.padding(horizontal = 32.dp),
        ) {
            Box(
                modifier = Modifier.size(150.dp),
                contentAlignment = Alignment.Center,
            ) {
                Canvas(modifier = Modifier.fillMaxSize()) {
                    val stroke = 4.dp.toPx()
                    drawArc(
                        color = brand,
                        startAngle = rotation - 90f,
                        sweepAngle = 90f,
                        useCenter = false,
                        style = Stroke(width = stroke, cap = StrokeCap.Round),
                        topLeft = Offset(stroke / 2f, stroke / 2f),
                        size = Size(size.width - stroke, size.height - stroke),
                    )
                }
                Box(
                    modifier = Modifier
                        .size(112.dp)
                        .scale(pulse)
                        .clip(RoundedCornerShape(28.dp))
                        .background(surface),
                    contentAlignment = Alignment.Center,
                ) {
                    Image(
                        painter = painterResource(R.drawable.ic_launcher_mark),
                        contentDescription = null,
                        modifier = Modifier.size(88.dp),
                    )
                }
            }
            Spacer(modifier = Modifier.height(30.dp))
            Text(
                text = "Добро пожаловать",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.SemiBold,
                color = onBg,
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = "QuantumVPN",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = brand,
            )
            Spacer(modifier = Modifier.height(10.dp))
            Text(
                text = status,
                style = MaterialTheme.typography.bodyMedium,
                color = onSurface,
            )
            Spacer(modifier = Modifier.height(28.dp))
            LinearProgressIndicator(
                progress = { progress.value },
                modifier = Modifier
                    .width(220.dp)
                    .height(6.dp)
                    .clip(RoundedCornerShape(99.dp)),
                color = brand,
                trackColor = surface,
                strokeCap = StrokeCap.Round,
            )
            Spacer(modifier = Modifier.height(14.dp))
            Text(
                text = "$percent%",
                fontSize = 22.sp,
                fontWeight = FontWeight.Medium,
                color = brand,
            )
        }
    }
}
