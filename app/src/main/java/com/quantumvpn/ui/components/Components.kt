package com.quantumvpn.ui.components

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.quantumvpn.data.ConnectionState
import com.quantumvpn.data.VPNState
import kotlin.math.cos
import kotlin.math.sin

@Composable
fun PowerButton(
    isConnected: Boolean,
    isConnecting: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.2f,
        targetValue = 0.6f,
        animationSpec = infiniteRepeatable(
            animation = tween(1500, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulseAlpha"
    )

    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 1.3f,
        animationSpec = infiniteRepeatable(
            animation = tween(1500, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulseScale"
    )

    val rotation by rememberInfiniteTransition(label = "rotation").animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(8000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "rotation"
    )

    val buttonColor = when {
        isConnected -> Color(0xFF00E676)
        isConnecting -> Color(0xFFFFAB00)
        else -> Color(0xFF6C63FF)
    }

    val glowColor = when {
        isConnected -> Color(0xFF00E676)
        isConnecting -> Color(0xFFFFAB00)
        else -> Color(0xFF6C63FF)
    }

    Box(
        modifier = modifier.size(200.dp),
        contentAlignment = Alignment.Center
    ) {
        // Outer glow ring
        if (isConnected || isConnecting) {
            Canvas(
                modifier = Modifier
                    .fillMaxSize()
                    .offset(
                        x = ((pulseScale - 1f) * 50).dp,
                        y = ((pulseScale - 1f) * 50).dp
                    )
            ) {
                drawCircle(
                    color = glowColor.copy(alpha = pulseAlpha * 0.3f),
                    radius = size.minDimension / 2
                )
            }
        }

        // Rotating ring
        Canvas(
            modifier = Modifier
                .fillMaxSize()
                .offset(
                    x = ((pulseScale - 1f) * 25).dp,
                    y = ((pulseScale - 1f) * 25).dp
                )
        ) {
            val stroke = Stroke(width = 3.dp.toPx(), cap = StrokeCap.Round)
            val radius = size.minDimension / 2 - 10.dp.toPx()

            for (i in 0..11) {
                val angle = Math.toRadians((i * 30 + rotation).toDouble())
                val x = center.x + radius * cos(angle).toFloat()
                val y = center.y + radius * sin(angle).toFloat()
                drawCircle(
                    color = glowColor.copy(alpha = 0.6f),
                    radius = 2.dp.toPx(),
                    center = Offset(x, y)
                )
            }
        }

        // Main button
        Box(
            modifier = Modifier
                .size(160.dp)
                .shadow(
                    elevation = if (isConnected) 24.dp else 12.dp,
                    shape = CircleShape,
                    ambientColor = glowColor.copy(alpha = 0.5f),
                    spotColor = glowColor
                )
                .clip(CircleShape)
                .background(
                    Brush.radialGradient(
                        colors = listOf(
                            buttonColor.copy(alpha = 0.3f),
                            buttonColor.copy(alpha = 0.1f),
                            Color.Transparent
                        )
                    )
                )
                .clickable { onClick() },
            contentAlignment = Alignment.Center
        ) {
            Box(
                modifier = Modifier
                    .size(120.dp)
                    .shadow(
                        elevation = 8.dp,
                        shape = CircleShape,
                        ambientColor = glowColor
                    )
                    .clip(CircleShape)
                    .background(
                        Brush.verticalGradient(
                            colors = listOf(
                                buttonColor,
                                buttonColor.copy(alpha = 0.8f)
                            )
                        )
                    ),
                contentAlignment = Alignment.Center
            ) {
                AnimatedContent(
                    targetState = when {
                        isConnecting -> Icons.Filled.Sync
                        isConnected -> Icons.Filled.Link
                        else -> Icons.Filled.PowerSettingsNew
                    },
                    transitionSpec = {
                        fadeIn(tween(300)) + scaleIn(tween(300)) togetherWith
                                fadeOut(tween(300)) + scaleOut(tween(300))
                    },
                    label = "icon"
                ) { icon ->
                    Icon(
                        imageVector = icon,
                        contentDescription = if (isConnected) "Disconnect" else "Connect",
                        tint = Color.White,
                        modifier = Modifier.size(48.dp)
                    )
                }
            }
        }
    }
}

@Composable
fun StatusCard(
    vpnState: VPNState,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = when {
                    vpnState.isConnected -> "Connected"
                    vpnState.isConnecting -> "Connecting..."
                    else -> "Disconnected"
                },
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                color = when {
                    vpnState.isConnected -> Color(0xFF00E676)
                    vpnState.isConnecting -> Color(0xFFFFAB00)
                    else -> MaterialTheme.colorScheme.onSurface
                }
            )

            if (vpnState.currentServer != null) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "${vpnState.currentServer.flag} ${vpnState.currentServer.name}",
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = vpnState.currentServer.protocol.displayName,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                )
            }

            if (vpnState.isConnected) {
                Spacer(modifier = Modifier.height(16.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceEvenly
                ) {
                    SpeedItem(
                        label = "↓ Download",
                        speed = vpnState.downloadSpeed
                    )
                    SpeedItem(
                        label = "↑ Upload",
                        speed = vpnState.uploadSpeed
                    )
                }
            }
        }
    }
}

@Composable
fun SpeedItem(
    label: String,
    speed: Long,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = formatSpeed(speed),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.primary
        )
    }
}

@Composable
fun ServerItem(
    name: String,
    country: String,
    countryCode: String,
    flag: String,
    protocol: String,
    ping: Long,
    isSelected: Boolean,
    onClick: () -> Unit,
    onPingClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier
            .fillMaxWidth()
            .clickable { onClick() },
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isSelected) {
                MaterialTheme.colorScheme.primaryContainer
            } else {
                MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f)
            }
        ),
        border = if (isSelected) {
            CardDefaults.outlinedCardBorder().takeIf { true }
        } else {
            null
        }
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = flag,
                fontSize = 32.sp
            )

            Spacer(modifier = Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = name,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = "$country • $protocol",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            if (ping >= 0) {
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = when {
                        ping < 100 -> Color(0xFF00E676).copy(alpha = 0.2f)
                        ping < 300 -> Color(0xFFFFAB00).copy(alpha = 0.2f)
                        else -> Color(0xFFFF6B6B).copy(alpha = 0.2f)
                    }
                ) {
                    Text(
                        text = "${ping}ms",
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                        style = MaterialTheme.typography.labelMedium,
                        color = when {
                            ping < 100 -> Color(0xFF00E676)
                            ping < 300 -> Color(0xFFFFAB00)
                            else -> Color(0xFFFF6B6B)
                        }
                    )
                }
            }

            IconButton(onClick = onPingClick) {
                Icon(
                    imageVector = Icons.Outlined.Speed,
                    contentDescription = "Test Ping",
                    tint = MaterialTheme.colorScheme.primary
                )
            }

            if (isSelected) {
                Icon(
                    imageVector = Icons.Filled.CheckCircle,
                    contentDescription = "Selected",
                    tint = Color(0xFF00E676),
                    modifier = Modifier.size(24.dp)
                )
            }
        }
    }
}

@Composable
fun StatItem(
    icon: ImageVector,
    label: String,
    value: String,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(
            imageVector = icon,
            contentDescription = label,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(24.dp)
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = value,
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold
        )
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

private fun formatSpeed(bytes: Long): String {
    return when {
        bytes < 1024 -> "$bytes B/s"
        bytes < 1024 * 1024 -> "${bytes / 1024} KB/s"
        else -> "${bytes / (1024 * 1024)} MB/s"
    }
}
