package com.quantumvpn.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.Surface
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
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.CheckCircle
import com.quantumvpn.R
import com.quantumvpn.updates.UpdateState
import kotlinx.coroutines.delay
import kotlin.math.roundToInt
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween

/**
 * Cold-start splash: dark radial gradient, glowing brand badge with a rotating
 * gradient ring, greeting, dynamic status line and a determinate percent bar.
 *
 * Progress climbs toward 92% until [ready], then finishes at 100% before [onFinished].
 * All shapes are drawn with Canvas/brushes — no bitmaps besides the launcher mark,
 * so the cold start stays cheap.
 */
@Composable
fun StartupSplashScreen(
    ready: Boolean,
    updateState: UpdateState,
    availableServers: Int,
    onFinished: () -> Unit,
) {
    V2StartupSplash(
        ready = ready,
        updateState = updateState,
        availableServers = availableServers,
        onFinished = onFinished,
    )
    return

    val progress = remember { Animatable(0f) }
    var percent by remember { mutableIntStateOf(0) }
    val brand = MaterialTheme.colorScheme.primary
    val bg = MaterialTheme.colorScheme.background
    val deep = MaterialTheme.colorScheme.primaryContainer
    val onBg = MaterialTheme.colorScheme.onBackground
    val onSurface = MaterialTheme.colorScheme.onSurfaceVariant

    val infinite = rememberInfiniteTransition(label = "splash-anim")
    val rotation by infinite.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1400, easing = LinearEasing),
            repeatMode = RepeatMode.Restart,
        ),
        label = "ring-rotation",
    )
    val counter by infinite.animateFloat(
        initialValue = 360f,
        targetValue = 0f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1900, easing = LinearEasing),
            repeatMode = RepeatMode.Restart,
        ),
        label = "ring-counter",
    )
    val pulse by infinite.animateFloat(
        initialValue = 1f,
        targetValue = 1.12f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1000, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "icon-pulse",
    )
    val haloAlpha by infinite.animateFloat(
        initialValue = 0.35f,
        targetValue = 0.7f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1200, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "halo-alpha",
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
    val fadeOut by animateFloatAsState(
        targetValue = if (percent >= 100) 0f else 1f,
        animationSpec = tween(durationMillis = 180),
        label = "splash-fade",
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.radialGradient(
                    colors = listOf(
                        deep.copy(alpha = 0.55f),
                        bg,
                        bg.copy(alpha = 0.92f),
                    ),
                    center = Offset(0.5f, 0.42f),
                    radius = 1300f,
                ),
            )
            .semantics { contentDescription = "Загрузка QuantumVPN $percent%" },
        contentAlignment = Alignment.Center,
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
            modifier = Modifier
                .padding(horizontal = 32.dp)
                .alpha(fadeOut),
        ) {
            Box(
                modifier = Modifier.size(180.dp),
                contentAlignment = Alignment.Center,
            ) {
                // Пульсирующее мягкое гало позади бейджа.
                Box(
                    modifier = Modifier
                        .size(142.dp)
                        .scale(pulse)
                        .alpha(haloAlpha)
                        .background(
                            Brush.radialGradient(
                                colors = listOf(brand.copy(alpha = 0.9f), Color.Transparent),
                            ),
                            CircleShape,
                        ),
                )
                // Два встречно вращающихся градиентных обода.
                Canvas(
                    modifier = Modifier
                        .fillMaxSize()
                        .alpha(0.95f),
                ) {
                    val stroke = 5.dp.toPx()
                    val glowStroke = 10.dp.toPx()
                    val inset = glowStroke / 2f
                    val sweep = Brush.sweepGradient(
                        colors = listOf(
                            Color.Transparent,
                            brand,
                            deep.copy(alpha = 0.9f),
                            Color.Transparent,
                        ),
                    )
                    drawArc(
                        brush = sweep,
                        startAngle = rotation - 90f,
                        sweepAngle = 120f,
                        useCenter = false,
                        style = Stroke(width = glowStroke, cap = StrokeCap.Round),
                        topLeft = Offset(inset, inset),
                        size = Size(size.width - glowStroke, size.height - glowStroke),
                    )
                    drawArc(
                        color = brand,
                        startAngle = counter + 70f,
                        sweepAngle = 70f,
                        useCenter = false,
                        style = Stroke(width = stroke, cap = StrokeCap.Round),
                        topLeft = Offset(stroke / 2f, stroke / 2f),
                        size = Size(size.width - stroke, size.height - stroke),
                    )
                }
                Box(
                    modifier = Modifier
                        .size(118.dp)
                        .scale(1f + (pulse - 1f) * 0.45f)
                        .clip(RoundedCornerShape(30.dp))
                        .background(
                            Brush.linearGradient(
                                colors = listOf(
                                    MaterialTheme.colorScheme.surface,
                                    MaterialTheme.colorScheme.surfaceVariant,
                                ),
                            ),
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    Image(
                        painter = painterResource(R.drawable.ic_launcher_mark),
                        contentDescription = null,
                        modifier = Modifier.size(86.dp),
                    )
                }
            }
            Spacer(modifier = Modifier.height(34.dp))
            Text(
                text = "QuantumVPN",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                color = onBg,
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = "VPN, который пропускает только необходимое",
                style = MaterialTheme.typography.bodyMedium,
                color = onSurface,
                modifier = Modifier.alpha(0.85f),
            )
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = status,
                style = MaterialTheme.typography.bodySmall,
                color = onSurface,
                modifier = Modifier.alpha(0.7f),
            )
            Spacer(modifier = Modifier.height(26.dp))
            LinearProgressIndicator(
                progress = { progress.value },
                modifier = Modifier
                    .width(224.dp)
                    .height(7.dp)
                    .clip(RoundedCornerShape(99.dp)),
                color = brand,
                trackColor = MaterialTheme.colorScheme.surface,
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

/** Liquid Glass Orbit splash: globe + horizontal progress, update check before UI. */
@Composable
private fun V2StartupSplash(
    ready: Boolean,
    updateState: UpdateState,
    availableServers: Int,
    onFinished: () -> Unit,
) {
    val progress = remember { Animatable(0f) }
    val infinite = rememberInfiniteTransition(label = "splash-glow")
    val glow by infinite.animateFloat(
        initialValue = 0.35f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(900, easing = LinearEasing), RepeatMode.Reverse),
        label = "glow",
    )
    val shimmer by infinite.animateFloat(
        initialValue = -0.35f,
        targetValue = 1.35f,
        animationSpec = infiniteRepeatable(tween(1600, easing = LinearEasing), RepeatMode.Restart),
        label = "shimmer",
    )
    LaunchedEffect(ready) {
        if (!ready) {
            while (progress.value < .86f) {
                progress.snapTo((progress.value + .018f).coerceAtMost(.86f)); delay(40)
            }
        } else {
            progress.animateTo(1f, tween(280)); delay(160); onFinished()
        }
    }
    val displayedProgress = when (updateState) {
        is UpdateState.Downloading -> if (updateState.totalBytes > 0) {
            (updateState.downloadedBytes.toFloat() / updateState.totalBytes).coerceIn(0f, 1f)
        } else progress.value
        is UpdateState.Ready -> 1f
        else -> progress.value
    }
    val pct = (displayedProgress * 100).roundToInt()
    val status = when (updateState) {
        is UpdateState.Checking -> "Проверяем обновление…"
        is UpdateState.RetryingViaVpn -> "Повтор через обычную сеть (без VPN)…"
        is UpdateState.Downloading -> {
            val downloaded = updateState.downloadedBytes / 1024f / 1024f
            val total = updateState.totalBytes / 1024f / 1024f
            val speed = formatUpdateSpeed(updateState.speedBytesPerSecond)
            val eta = formatUpdateEta(updateState.etaSeconds)
            "Обновление ${updateState.candidate.metadata.versionName}: %.0f%% · %.1f / %.1f МБ\n$speed · $eta".format(displayedProgress * 100, downloaded, total)
        }
        is UpdateState.Ready -> "Готово · Android запросит установку…"
        is UpdateState.Available -> "Найдено обновление · передаём системе…"
        is UpdateState.Failure -> "Сбой · откройте ссылку в браузере или повторите"
        else -> when {
            availableServers <= 0 -> "Загружаем серверы…"
            !ready -> "Загружаем серверы…"
            else -> "Готово"
        }
    }
    val step = when (updateState) {
        is UpdateState.Ready -> 3
        is UpdateState.Downloading, is UpdateState.Available -> 2
        is UpdateState.Checking, is UpdateState.RetryingViaVpn -> 1
        else -> when {
            ready -> 3
            availableServers > 0 -> 2
            else -> 1
        }
    }
    Box(
        modifier = Modifier
            .fillMaxSize()
            .semantics { contentDescription = "Загрузка QuantumVPN $pct%" },
    ) {
        AuroraGlassBackdrop(Modifier.fillMaxSize(), motionEnabled = true)
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 24.dp, vertical = 34.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                AuroraBrandMark(connected = ready, modifier = Modifier.size(42.dp))
                Column(modifier = Modifier.padding(start = 10.dp)) {
                    Text("QuantumVPN", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 24.sp)
                    Text("Защита соединения", color = Color(0xFFB2C5DA), fontSize = 13.sp)
                }
            }
            Spacer(Modifier.height(28.dp))
            Text("Готовим защищённый канал", color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 21.sp)
            Text(
                "Проверяем сеть, обновления и доступные серверы",
                color = Color(0xFFB6C7D8),
                fontSize = 13.sp,
                modifier = Modifier.padding(top = 6.dp),
            )
            Spacer(Modifier.weight(0.65f))
            AuroraStartupEmblem(
                progress = displayedProgress,
                glow = glow,
                shimmer = shimmer,
            )
            Spacer(Modifier.weight(0.55f))
            AuroraGlass(
                modifier = Modifier.fillMaxWidth(),
                cornerRadius = 24.dp,
                tint = Color(0xFF102842),
            ) {
                Column(modifier = Modifier.padding(horizontal = 18.dp, vertical = 16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(status, color = Color(0xFFD8E4EF), fontSize = 14.sp, maxLines = 2)
                        Text("$pct%", color = Color(0xFF58F6CE), fontWeight = FontWeight.Bold, fontSize = 17.sp)
                    }
                    Spacer(Modifier.height(12.dp))
                    Box(
                        Modifier
                            .fillMaxWidth()
                            .height(9.dp)
                            .clip(RoundedCornerShape(999.dp))
                            .background(Color(0xFF23415C).copy(alpha = 0.72f)),
                    ) {
                        Box(
                            Modifier
                                .fillMaxWidth(displayedProgress.coerceIn(0.02f, 1f))
                                .height(9.dp)
                                .clip(RoundedCornerShape(999.dp))
                                .background(
                                    Brush.horizontalGradient(
                                        listOf(
                                            Color(0xFF54F4CF).copy(alpha = glow),
                                            Color(0xFF75FFD9),
                                            Color(0xFFC395FF).copy(alpha = glow),
                                        ),
                                    ),
                                ),
                        )
                        Canvas(Modifier.fillMaxSize()) {
                            val x = size.width * shimmer
                            drawCircle(
                                brush = Brush.radialGradient(
                                    colors = listOf(Color.White.copy(alpha = 0.65f), Color.Transparent),
                                    center = Offset(x, size.height / 2f),
                                    radius = size.width * 0.15f,
                                ),
                                radius = size.width * 0.15f,
                                center = Offset(x, size.height / 2f),
                            )
                        }
                    }
                }
            }
            Spacer(Modifier.height(22.dp))
            AuroraStartupSteps(step = step)
            Spacer(Modifier.height(12.dp))
            Text("Больше свободы. Больше возможностей. Везде с вами.", color = Color(0xFF93AABE), fontSize = 11.sp)
        }
    }
}

private fun formatUpdateSpeed(bytesPerSecond: Long): String = when {
    bytesPerSecond < 16L * 1024L -> "Считаем скорость…"
    bytesPerSecond < 1024L * 1024L -> "${bytesPerSecond / 1024L} КБ/с"
    else -> "%.1f МБ/с".format(bytesPerSecond / 1024f / 1024f)
}

private fun formatUpdateEta(seconds: Long?): String {
    if (seconds == null) return "время уточняется"
    return when {
        seconds < 60L -> "осталось ${seconds.coerceAtLeast(1L)} с"
        seconds < 3600L -> "осталось ${seconds / 60L} мин"
        else -> "осталось ${seconds / 3600L} ч"
    }
}

@Composable
private fun AuroraStartupEmblem(
    progress: Float,
    glow: Float,
    shimmer: Float,
) {
    Box(
        modifier = Modifier.size(206.dp),
        contentAlignment = Alignment.Center,
    ) {
        Canvas(Modifier.fillMaxSize()) {
            val center = Offset(size.width / 2f, size.height / 2f)
            val ringRadius = size.minDimension * 0.45f
            drawCircle(
                brush = Brush.radialGradient(
                    listOf(Color(0xFF55F6CD).copy(alpha = 0.25f * glow), Color.Transparent),
                    center = center,
                    radius = ringRadius * 1.3f,
                ),
                center = center,
                radius = ringRadius * 1.3f,
            )
            drawArc(
                color = Color.White.copy(alpha = 0.18f),
                startAngle = -90f,
                sweepAngle = 360f,
                useCenter = false,
                topLeft = Offset(center.x - ringRadius, center.y - ringRadius),
                size = Size(ringRadius * 2f, ringRadius * 2f),
                style = Stroke(width = 7.dp.toPx(), cap = StrokeCap.Round),
            )
            drawArc(
                brush = Brush.sweepGradient(
                    listOf(
                        Color(0xFF54F4CF),
                        Color(0xFFC395FF),
                        Color(0xFF54F4CF),
                    ),
                    center = center,
                ),
                startAngle = -90f,
                sweepAngle = (progress.coerceIn(0.02f, 1f) * 360f),
                useCenter = false,
                topLeft = Offset(center.x - ringRadius, center.y - ringRadius),
                size = Size(ringRadius * 2f, ringRadius * 2f),
                style = Stroke(width = 7.dp.toPx(), cap = StrokeCap.Round),
            )
            val orbitX = center.x + ringRadius * 0.93f * (shimmer * 2f - 1f)
            drawCircle(Color(0xFFEEFFFF), radius = 3.dp.toPx(), center = Offset(orbitX, center.y - ringRadius * 0.34f))
        }
        Box(
            modifier = Modifier
                .size(126.dp)
                .clip(RoundedCornerShape(38.dp))
                .background(
                    Brush.radialGradient(
                        listOf(Color(0xFF173E57), Color(0xFF0B1C35), Color(0xFF071224)),
                    ),
                ),
            contentAlignment = Alignment.Center,
        ) {
            Canvas(Modifier.size(72.dp)) {
                val w = size.width
                val h = size.height
                val shield = androidx.compose.ui.graphics.Path().apply {
                    moveTo(w * 0.5f, h * 0.08f)
                    lineTo(w * 0.84f, h * 0.23f)
                    lineTo(w * 0.78f, h * 0.67f)
                    quadraticBezierTo(w * 0.5f, h * 0.9f, w * 0.22f, h * 0.67f)
                    lineTo(w * 0.16f, h * 0.23f)
                    close()
                }
                drawPath(shield, Color(0xFF5CF5D0), style = Stroke(width = 4.dp.toPx(), cap = StrokeCap.Round))
                drawRoundRect(
                    color = Color(0xFF5CF5D0),
                    topLeft = Offset(w * 0.31f, h * 0.45f),
                    size = Size(w * 0.38f, h * 0.28f),
                    cornerRadius = androidx.compose.ui.geometry.CornerRadius(7.dp.toPx(), 7.dp.toPx()),
                )
                drawArc(
                    color = Color(0xFF5CF5D0),
                    startAngle = 180f,
                    sweepAngle = 180f,
                    useCenter = false,
                    topLeft = Offset(w * 0.36f, h * 0.25f),
                    size = Size(w * 0.28f, h * 0.31f),
                    style = Stroke(width = 4.dp.toPx(), cap = StrokeCap.Round),
                )
                drawCircle(Color(0xFF082034), radius = 4.dp.toPx(), center = Offset(w * 0.5f, h * 0.58f))
            }
        }
    }
}

@Composable
private fun AuroraStartupSteps(step: Int) {
    val items = listOf("Сеть", "Серверы", "Готово")
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceEvenly,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        items.forEachIndexed { index, label ->
            val active = index + 1 <= step
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Box(
                    modifier = Modifier
                        .size(30.dp)
                        .clip(CircleShape)
                        .background(if (active) Color(0xFF42EFC5).copy(alpha = 0.2f) else Color.White.copy(alpha = 0.08f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        if (active) "✓" else "${index + 1}",
                        color = if (active) Color(0xFF5CF5D0) else Color(0xFF92A8BC),
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                    )
                }
                Text(label, color = if (active) Color(0xFFD6FDF4) else Color(0xFF92A8BC), fontSize = 12.sp, modifier = Modifier.padding(top = 5.dp))
            }
        }
    }
}
