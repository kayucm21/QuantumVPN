package com.quantumvpn.ui

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
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
import kotlinx.coroutines.delay
import kotlin.math.roundToInt

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
    onFinished: () -> Unit,
) {
    V2StartupSplash(ready = ready, onFinished = onFinished)
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

/** Aurora C splash: violet/mint glass, kept separate from the former blue loader. */
@Composable
private fun V2StartupSplash(ready: Boolean, onFinished: () -> Unit) {
    val progress = remember { Animatable(0f) }
    val infinite = rememberInfiniteTransition(label = "v2-splash")
    val pulse by infinite.animateFloat(
        initialValue = 0.92f, targetValue = 1.08f,
        animationSpec = infiniteRepeatable(tween(1100, easing = LinearEasing), RepeatMode.Reverse), label = "pulse",
    )
    LaunchedEffect(ready) {
        if (!ready) {
            while (progress.value < .86f) {
                progress.snapTo((progress.value + .025f).coerceAtMost(.86f)); delay(45)
            }
        } else {
            progress.animateTo(1f, tween(260)); delay(180); onFinished()
        }
    }
    val pct = (progress.value * 100).roundToInt()
    Box(
        Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Color(0xFF120D2A), Color(0xFF0A1225), Color(0xFF070714)))),
        contentAlignment = Alignment.Center,
    ) {
        Globe3DBackdrop(Modifier.fillMaxSize(), pulse = true, reduceMotion = false, countryCode = null)
        Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(28.dp)) {
            Surface(
                shape = CircleShape,
                color = Color(0xCC1A1B3A),
                border = androidx.compose.foundation.BorderStroke(3.dp, Color(0xFFC395FF)),
                modifier = Modifier.size(188.dp).scale(pulse),
            ) {
                Column(Modifier.fillMaxSize(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
                    Icon(Icons.Default.Lock, null, tint = Color(0xFF54F4CF), modifier = Modifier.size(72.dp))
                    Text("Quantum", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 28.sp)
                    Text("VPN", color = Color(0xFF54F4CF), fontWeight = FontWeight.Bold, fontSize = 28.sp)
                }
            }
            Spacer(Modifier.height(22.dp))
            Text("Защита соединения", color = Color.White.copy(alpha = .86f), fontSize = 18.sp)
            Spacer(Modifier.height(18.dp))
            Box(Modifier.size(104.dp), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(
                    progress = { progress.value },
                    color = Color(0xFF54F4CF),
                    trackColor = Color(0xFF33445B),
                    strokeWidth = 9.dp,
                    modifier = Modifier.fillMaxSize(),
                )
                Text("$pct%", color = Color.White, fontSize = 26.sp, fontWeight = FontWeight.Bold)
            }
            Spacer(Modifier.height(16.dp))
            Text(
                when {
                    pct < 35 -> "Проверяем сеть…"
                    pct < 78 -> "Загружаем серверы…"
                    pct < 100 -> "Готовим защиту…"
                    else -> "Готово"
                },
                color = CosmicTokens.OnVoidMuted,
                fontSize = 15.sp,
            )
            Spacer(Modifier.height(20.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                SplashStep("Сеть", pct >= 20)
                SplashStep("Серверы", pct >= 55)
                SplashStep("Готово", pct >= 100)
            }
        }
    }
}

@Composable
private fun SplashStep(label: String, done: Boolean) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Surface(
            shape = CircleShape,
            color = if (done) Color(0xFF54F4CF).copy(alpha = .16f) else Color(0xFF18283B),
            border = androidx.compose.foundation.BorderStroke(2.dp, if (done) Color(0xFF54F4CF) else Color(0xFF40546B)),
            modifier = Modifier.size(38.dp),
        ) {
            Box(contentAlignment = Alignment.Center) {
                if (done) Icon(Icons.Default.CheckCircle, null, tint = Color(0xFF54F4CF), modifier = Modifier.size(23.dp))
            }
        }
        Spacer(Modifier.height(6.dp))
        Text(label, color = if (done) Color.White else Color(0xFF8294A9), fontSize = 12.sp)
    }
}
