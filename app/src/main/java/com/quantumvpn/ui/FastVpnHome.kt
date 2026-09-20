package com.quantumvpn.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.interaction.MutableInteractionSource
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
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.IconButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.ripple
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.math.max
import com.quantumvpn.vpn.VpnConnectionState
import com.quantumvpn.vpn.VpnSessionStats

data class HomeTopServerPing(
    val tag: String,
    val label: String,
    val pingMillis: Int?,
    val selected: Boolean = false,
)

/** Priority-VPN style home (RU): status, speeds, power, server, adblock. */
@Composable
@Suppress("UNUSED_PARAMETER")
fun FastVpnHomeContent(
    title: String = "QuantumVPN",
    vpnState: VpnConnectionState,
    sessionStats: VpnSessionStats,
    sessionTimerLabel: String,
    serverFlag: String?,
    serverLabel: String,
    serverPingLabel: String? = null,
    recentFlags: List<String> = emptyList(),
    onRecentFlag: (Int) -> Unit = {},
    subscriptionLabel: String,
    connectEnabled: Boolean,
    reduceMotion: Boolean = false,
    leakLabel: String? = null,
    leakOk: Boolean? = null,
    onLeakCheck: () -> Unit = {},
    onBestServer: (() -> Unit)? = null,
    bestServerBusy: Boolean = false,
    onOpenMenu: () -> Unit,
    onToggleConnect: () -> Unit,
    onSwipeLeft: () -> Unit = {},
    onSwipeRight: () -> Unit = {},
    onOpenServers: () -> Unit,
    onOpenSubscription: () -> Unit,
    carrierBypassEnabled: Boolean = true,
    lastDisconnectLine: String? = null,
    operatorHint: String? = null,
    onPanicReset: (() -> Unit)? = null,
    beginnerMode: Boolean = false,
    compactHome: Boolean = false,
    hideExitIp: Boolean = false,
    exitIp: String? = null,
    preConnectIp: String? = null,
    protocolLabel: String? = null,
    connectEtaMillis: Long? = null,
    securityScoreSummary: String? = null,
    killSwitchOn: Boolean = false,
    onToggleKillSwitch: () -> Unit = {},
    alwaysOnActive: Boolean = false,
    lockdownActive: Boolean = false,
    showBatteryTip: Boolean = false,
    networkChangedTip: String? = null,
    captivePortal: Boolean = false,
    onOpenCaptivePortal: () -> Unit = {},
    onLiveCheck: () -> Unit = {},
    onMessengersOnly: () -> Unit = {},
    onSpeedTest: () -> Unit = {},
    speedTestBusy: Boolean = false,
    lastSpeedTestDetail: String? = null,
    onWhySlow: () -> Unit = {},
    onJammerTest: () -> Unit = {},
    onApplyJammer: () -> Unit = {},
    onHardReconnect: () -> Unit = {},
    onSnoozeReconnect: () -> Unit = {},
    reconnectCountdownLabel: String? = null,
    onApplyRoutingPreset: ((com.quantumvpn.routing.RoutingPreset) -> Unit)? = null,
    onCopyExitIp: () -> Unit = {},
    pingSamples: List<Long> = emptyList(),
    adBlockEnabled: Boolean = true,
    adBlockActive: Boolean = false,
    adBlockRuleCount: Int = 0,
    adBlockOnlineDns: Boolean = true,
    adBlockLevel: com.quantumvpn.hardening.AdBlockLevel =
        com.quantumvpn.hardening.AdBlockLevel.Maximum,
    onToggleAdBlock: (Boolean) -> Unit = {},
    onOpenAdBlockSettings: () -> Unit = {},
    adBlockedApprox: Int = 0,
    adBlockedSessionTotal: Long = 0L,
    protocolRecommendation: String? = null,
    stealthMode: Boolean = false,
    homeVisualTheme: HomeVisualTheme = HomeVisualTheme.Globe3d,
    hideMap: Boolean = false,
    exitCountryCode: String? = null,
    topServerPings: List<HomeTopServerPing> = emptyList(),
    onSelectTopServer: (String) -> Unit = {},
    modifier: Modifier = Modifier,
) {
    val connected = vpnState is VpnConnectionState.Connected
    val busy = vpnState is VpnConnectionState.Starting || vpnState is VpnConnectionState.Stopping
    val statusTitle = when (vpnState) {
        is VpnConnectionState.Connected -> "Подключено"
        is VpnConnectionState.Starting -> "Подключение…"
        is VpnConnectionState.Stopping -> "Отключение…"
        is VpnConnectionState.Error -> "Не удалось подключить"
        VpnConnectionState.Stopped -> "Отключено"
    }
    val statusColor = when (vpnState) {
        is VpnConnectionState.Connected -> CosmicTokens.StatusGreen
        is VpnConnectionState.Starting, is VpnConnectionState.Stopping -> CosmicTokens.Orbit
        is VpnConnectionState.Error -> CosmicTokens.StatusYellow
        VpnConnectionState.Stopped -> Color.White.copy(alpha = 0.75f)
    }
    val errorHint = (vpnState as? VpnConnectionState.Error)?.message
        ?.takeIf { it.isNotBlank() }
        ?.let { raw ->
            // Prefer humanized service message; fall back for any leftover eng/libbox text.
            if (raw.any { it in '\u0400'..'\u04FF' }) raw else friendlyVpnErrorHint(raw)
        }
    val down = sessionStats.samples.lastOrNull()?.downloadBytesPerSecond ?: 0L
    val up = sessionStats.samples.lastOrNull()?.uploadBytesPerSecond ?: 0L
    // Block ads when user enabled it and VPN session is active.
    val adBlockOn = adBlockEnabled && adBlockActive
    val pad = if (compactHome) 14.dp else 20.dp

    // This is the primary production home now. Keep the former dense dashboard
    // below while its advanced controls are migrated into dedicated tabs.
    ModernHomeContent(
        title = title,
        vpnState = vpnState,
        sessionTimerLabel = sessionTimerLabel,
        serverFlag = serverFlag,
        serverLabel = serverLabel,
        serverPingLabel = serverPingLabel,
        connectEnabled = connectEnabled,
        reduceMotion = reduceMotion,
        adBlockEnabled = adBlockEnabled,
        adBlockActive = adBlockOn,
        adBlockRuleCount = adBlockRuleCount,
        adBlockOnlineDns = adBlockOnlineDns,
        adBlockLevel = adBlockLevel,
        adBlockedSessionTotal = adBlockedSessionTotal,
        onOpenMenu = onOpenMenu,
        onToggleConnect = onToggleConnect,
        onOpenServers = onOpenServers,
        onToggleAdBlock = onToggleAdBlock,
        onOpenAdBlockSettings = onOpenAdBlockSettings,
    )
    return

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    listOf(Color(0xFF0A1628), CosmicTokens.Deep, CosmicTokens.Void, Color(0xFF02060C)),
                ),
            ),
    ) {
        if (!hideMap) {
            when (homeVisualTheme) {
                HomeVisualTheme.Globe3d -> Globe3DBackdrop(
                    modifier = Modifier.fillMaxSize(),
                    pulse = connected && !reduceMotion,
                    reduceMotion = reduceMotion,
                    countryCode = exitCountryCode,
                )
                HomeVisualTheme.Classic -> WorldMapBackdrop(
                    modifier = Modifier.fillMaxSize(),
                    pulse = connected && !reduceMotion,
                )
            }
        }
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = pad),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp, bottom = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Spacer(modifier = Modifier.size(48.dp))
                Text(
                    title,
                    color = Color.White,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 20.sp,
                )
                IconButton(
                    onClick = onOpenMenu,
                    modifier = Modifier.semantics { contentDescription = "Настройки" },
                ) {
                    Surface(
                        shape = CircleShape,
                        color = Color.White.copy(alpha = 0.12f),
                        modifier = Modifier.size(40.dp),
                    ) {
                        Box(contentAlignment = Alignment.Center, modifier = Modifier.fillMaxSize()) {
                            GridMenuIcon(tint = Color.White, modifier = Modifier.size(18.dp))
                        }
                    }
                }
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                if (connected) {
                    Icon(
                        Icons.Default.CheckCircle,
                        null,
                        tint = CosmicTokens.StatusGreen,
                        modifier = Modifier.size(18.dp).padding(end = 4.dp),
                    )
                }
                Text(statusTitle, color = statusColor, fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
            }
            Text(
                if (connected || busy) sessionTimerLabel else "00:00:00",
                color = Color.White.copy(alpha = 0.9f),
                fontWeight = FontWeight.Medium,
                fontSize = 28.sp,
                modifier = Modifier.padding(top = 4.dp),
            )

            Spacer(modifier = Modifier.height(14.dp))
            if (!beginnerMode) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceEvenly,
                ) {
                    SpeedColumn(title = "Загрузка", value = formatRate(down))
                    SpeedColumn(title = "Отдача", value = formatRate(up))
                }
            }

            if (!beginnerMode && connected && sessionStats.samples.size >= 2) {
                Spacer(modifier = Modifier.height(10.dp))
                TrafficAreaChart(
                    samples = sessionStats.samples,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(76.dp)
                        .padding(horizontal = 4.dp),
                )
            }

            if (!beginnerMode && (
                !protocolLabel.isNullOrBlank() ||
                    (!hideExitIp && !exitIp.isNullOrBlank()) ||
                    !serverPingLabel.isNullOrBlank()
                )
            ) {
                Spacer(modifier = Modifier.height(10.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    protocolLabel?.takeIf { it.isNotBlank() }?.let { proto ->
                        HomeInfoChip(label = proto.uppercase())
                    }
                    if (stealthMode) {
                        HomeInfoChip(label = "STEALTH", highlight = true)
                    }
                    if (!hideExitIp && !exitIp.isNullOrBlank()) {
                        HomeInfoChip(
                            label = "IP $exitIp",
                            onClick = onCopyExitIp,
                        )
                    }
                    serverPingLabel?.takeIf { it.isNotBlank() }?.let { ping ->
                        HomeInfoChip(label = ping)
                    }
                }
            }
            if (!beginnerMode && pingSamples.size >= 2) {
                Spacer(modifier = Modifier.height(8.dp))
                PingSparkline(
                    samples = pingSamples.map { it.toFloat() },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(28.dp)
                        .padding(horizontal = 8.dp),
                )
            }

            if (!beginnerMode && !preConnectIp.isNullOrBlank() && !exitIp.isNullOrBlank() && preConnectIp != exitIp && !hideExitIp) {
                Text(
                    "Было $preConnectIp → $exitIp",
                    color = Color.White.copy(alpha = 0.55f),
                    fontSize = 12.sp,
                    modifier = Modifier.padding(top = 4.dp),
                )
            }
            if (!beginnerMode) {
                securityScoreSummary?.takeIf { it.isNotBlank() }?.let { score ->
                    Text(
                        "Trust: $score",
                        color = CosmicTokens.Orbit,
                        fontSize = 12.sp,
                        modifier = Modifier.padding(top = 4.dp),
                    )
                }
            }

            reconnectCountdownLabel?.takeIf { it.isNotBlank() }?.let { countdown ->
                Spacer(modifier = Modifier.height(8.dp))
                Surface(
                    onClick = onSnoozeReconnect,
                    shape = RoundedCornerShape(14.dp),
                    color = CosmicTokens.Card.copy(alpha = 0.85f),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        countdown,
                        color = Color.White.copy(alpha = 0.85f),
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(vertical = 8.dp, horizontal = 12.dp),
                        fontSize = 13.sp,
                    )
                }
            }

            Spacer(modifier = Modifier.height(if (compactHome) 18.dp else 28.dp))
            FastPowerButton(
                connected = connected,
                busy = busy,
                enabled = connectEnabled,
                reduceMotion = reduceMotion,
                globe3d = homeVisualTheme == HomeVisualTheme.Globe3d,
                onClick = onToggleConnect,
                onSwipeLeft = onSwipeLeft,
                onSwipeRight = onSwipeRight,
            )
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                when {
                    busy && vpnState is VpnConnectionState.Starting -> "Идёт подключение…"
                    busy -> "Идёт отключение…"
                    connected -> "Нажмите, чтобы отключить"
                    else -> "Нажмите, чтобы подключить"
                },
                color = Color.White.copy(alpha = 0.75f),
                fontSize = 14.sp,
            )
            if (onBestServer != null) {
                Spacer(modifier = Modifier.height(8.dp))
                Surface(
                    onClick = onBestServer,
                    shape = RoundedCornerShape(14.dp),
                    color = Color.White.copy(alpha = 0.12f),
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        if (bestServerBusy) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(14.dp),
                                strokeWidth = 2.dp,
                                color = Color.White,
                            )
                        }
                        Text(
                            "Лучший сервер",
                            color = Color.White.copy(alpha = 0.85f),
                            fontSize = 13.sp,
                        )
                    }
                }
            }
            if (!errorHint.isNullOrBlank()) {
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    errorHint,
                    color = Color.White.copy(alpha = 0.7f),
                    fontSize = 13.sp,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            if (captivePortal) {
                Spacer(modifier = Modifier.height(8.dp))
                Surface(
                    onClick = onOpenCaptivePortal,
                    shape = RoundedCornerShape(14.dp),
                    color = CosmicTokens.StatusYellow.copy(alpha = 0.25f),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        "Wi‑Fi требует вход — открыть браузер",
                        color = Color.White,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(vertical = 10.dp, horizontal = 12.dp),
                        fontSize = 13.sp,
                    )
                }
            }

            if (!beginnerMode && topServerPings.isNotEmpty()) {
                Spacer(modifier = Modifier.height(12.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    topServerPings.forEach { item ->
                        val pingLabel = item.pingMillis?.let { "${it} ms" } ?: "…"
                        Surface(
                            onClick = { onSelectTopServer(item.tag) },
                            shape = RoundedCornerShape(20.dp),
                            color = if (item.selected) {
                                CosmicTokens.Orbit.copy(alpha = 0.35f)
                            } else {
                                Color.White.copy(alpha = 0.12f)
                            },
                        ) {
                            Text(
                                "${item.label} · $pingLabel",
                                color = Color.White.copy(alpha = 0.9f),
                                fontSize = 12.sp,
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(18.dp))
            ServerSelectCard(
                flag = serverFlag,
                label = serverLabel,
                pingLabel = serverPingLabel,
                onClick = onOpenServers,
            )
            Spacer(modifier = Modifier.height(18.dp))
            if (!beginnerMode || adBlockEnabled) {
                AdBlockBar(
                    enabled = adBlockOn,
                    configured = adBlockEnabled,
                    ruleCount = adBlockRuleCount,
                    onlineDns = adBlockOnlineDns,
                    level = adBlockLevel,
                    blockedApprox = adBlockedApprox,
                    blockedSessionTotal = adBlockedSessionTotal,
                    onToggle = onToggleAdBlock,
                    onOpenSettings = onOpenAdBlockSettings,
                )
            }
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

/** Clean four-tab home matching the released QuantumVPN visual system. */
@Composable
private fun ModernHomeContent(
    title: String,
    vpnState: VpnConnectionState,
    sessionTimerLabel: String,
    serverFlag: String?,
    serverLabel: String,
    serverPingLabel: String?,
    connectEnabled: Boolean,
    reduceMotion: Boolean,
    adBlockEnabled: Boolean,
    adBlockActive: Boolean,
    adBlockRuleCount: Int,
    adBlockOnlineDns: Boolean,
    adBlockLevel: com.quantumvpn.hardening.AdBlockLevel,
    adBlockedSessionTotal: Long,
    onOpenMenu: () -> Unit,
    onToggleConnect: () -> Unit,
    onOpenServers: () -> Unit,
    onToggleAdBlock: (Boolean) -> Unit,
    onOpenAdBlockSettings: () -> Unit,
) {
    val connected = vpnState is VpnConnectionState.Connected
    val busy = vpnState is VpnConnectionState.Starting || vpnState is VpnConnectionState.Stopping
    val stateText = when {
        connected -> "Защита включена"
        busy -> "Подключение…"
        else -> "Безопасное соединение"
    }
    Box(
        modifier = Modifier.fillMaxSize().background(
            Brush.verticalGradient(listOf(Color(0xFF071B2A), Color(0xFF04111E), Color(0xFF02070D))),
        ),
    ) {
        Globe3DBackdrop(
            modifier = Modifier.fillMaxSize(),
            pulse = connected && !reduceMotion,
            reduceMotion = reduceMotion,
            countryCode = null,
        )
        Column(
            modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 18.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column {
                    Text(title, color = Color.White, fontSize = 25.sp, fontWeight = FontWeight.Bold)
                    Text("Ваш безопасный интернет", color = CosmicTokens.OnVoidMuted, fontSize = 13.sp)
                }
                IconButton(onClick = onOpenMenu) {
                    Surface(shape = CircleShape, color = CosmicTokens.Card, modifier = Modifier.size(42.dp)) {
                        Box(contentAlignment = Alignment.Center) { GridMenuIcon(Color.White, Modifier.size(18.dp)) }
                    }
                }
            }
            Spacer(Modifier.height(38.dp))
            Surface(
                shape = CircleShape,
                color = if (connected) CosmicTokens.StatusGreen.copy(alpha = 0.15f) else CosmicTokens.Card.copy(alpha = 0.85f),
                border = androidx.compose.foundation.BorderStroke(2.dp, if (connected) CosmicTokens.StatusGreen else Color.White.copy(alpha = 0.20f)),
                modifier = Modifier.size(218.dp),
            ) {
                Column(
                    modifier = Modifier.fillMaxSize(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                ) {
                    Text(if (connected) "✓" else "◉", color = if (connected) CosmicTokens.StatusGreen else Color.White, fontSize = 50.sp)
                    Text(stateText, color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 17.sp)
                    Text(if (connected || busy) sessionTimerLabel else "Нажмите для подключения", color = CosmicTokens.OnVoidMuted, fontSize = 12.sp)
                }
            }
            Spacer(Modifier.height(22.dp))
            FastPowerButton(
                connected = connected, busy = busy, enabled = connectEnabled, reduceMotion = reduceMotion,
                globe3d = true, onClick = onToggleConnect, onSwipeLeft = {}, onSwipeRight = {},
            )
            Spacer(Modifier.height(24.dp))
            ServerSelectCard(serverFlag, serverLabel, serverPingLabel, onOpenServers)
            Spacer(Modifier.height(12.dp))
            AdBlockBar(
                enabled = adBlockActive, configured = adBlockEnabled, ruleCount = adBlockRuleCount,
                onlineDns = adBlockOnlineDns, level = adBlockLevel, blockedSessionTotal = adBlockedSessionTotal,
                onToggle = onToggleAdBlock, onOpenSettings = onOpenAdBlockSettings,
            )
            Spacer(Modifier.height(22.dp))
        }
    }
}

/** Four-square menu icon (Priority-style). */
@Composable
private fun GridMenuIcon(tint: Color, modifier: Modifier = Modifier) {
    Canvas(modifier = modifier.size(24.dp)) {
        val gap = size.width * 0.16f
        val cell = (size.width - gap) / 2f
        val radius = CornerRadius(2.dp.toPx(), 2.dp.toPx())
        listOf(
            Offset(0f, 0f),
            Offset(cell + gap, 0f),
            Offset(0f, cell + gap),
            Offset(cell + gap, cell + gap),
        ).forEach { origin ->
            drawRoundRect(
                color = tint,
                topLeft = origin,
                size = Size(cell, cell),
                cornerRadius = radius,
            )
        }
    }
}

/** Short user-facing hint; never dump raw libbox/TUN stack on Home. */
internal fun friendlyVpnErrorHint(raw: String): String {
    val text = raw.lowercase()
    return when {
        "configure tun" in text || "tun-in" in text || "tun interface" in text ->
            "Не удалось создать VPN-туннель. Отключите другой VPN / Always-on в системе и разрешите QuantumVPN."
        "permission" in text || "not prepared" in text || "prepare" in text ->
            "Нужно разрешение VPN в Android. Нажмите ещё раз и подтвердите."
        "revoke" in text ->
            "Разрешение VPN отозвано. Включите VPN снова и подтвердите запрос системы."
        "no network" in text || "network" in text && "unavailable" in text ->
            "Нет сети. Проверьте Wi‑Fi или мобильный интернет."
        else ->
            "Подключение не удалось. Проверьте сервер и сеть, затем попробуйте снова."
    }
}

@Composable
private fun SpeedColumn(title: String, value: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(title, color = Color.White.copy(alpha = 0.55f), fontSize = 13.sp)
        Text(value, color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 18.sp, modifier = Modifier.padding(top = 4.dp))
    }
}

/** Filled live traffic chart (download/upload) — Material 3 Expressive dashboard. */
@Composable
private fun TrafficAreaChart(
    samples: List<com.quantumvpn.vpn.TrafficSample>,
    modifier: Modifier = Modifier,
) {
    val primary = MaterialTheme.colorScheme.primary
    val secondary = MaterialTheme.colorScheme.secondary
    Canvas(
        modifier = modifier
            .clip(RoundedCornerShape(16.dp))
            .background(CosmicTokens.Card.copy(alpha = 0.55f))
            .padding(12.dp),
    ) {
        if (samples.size < 2) return@Canvas
        val peak = samples.fold(1L) { acc, s -> max(acc, max(s.downloadBytesPerSecond, s.uploadBytesPerSecond)) }
        val w = size.width
        val h = size.height
        fun pathOf(value: (com.quantumvpn.vpn.TrafficSample) -> Long): Path {
            val p = Path()
            samples.forEachIndexed { i, s ->
                val x = w * i / (samples.size - 1)
                val y = h * (1f - value(s).toFloat() / peak.toFloat())
                if (i == 0) p.moveTo(x, y) else p.lineTo(x, y)
            }
            return p
        }
        val down = pathOf { it.downloadBytesPerSecond }
        down.lineTo(w, h)
        down.lineTo(0f, h)
        down.close()
        drawPath(
            down,
            Brush.verticalGradient(
                listOf(primary.copy(alpha = 0.45f), primary.copy(alpha = 0.04f)),
            ),
        )
        drawPath(
            pathOf { it.downloadBytesPerSecond },
            primary,
            style = Stroke(2.dp.toPx(), cap = StrokeCap.Round),
        )
        drawPath(
            pathOf { it.uploadBytesPerSecond },
            secondary,
            style = Stroke(2.dp.toPx(), cap = StrokeCap.Round),
        )
    }
}

private fun levelLabel(level: com.quantumvpn.hardening.AdBlockLevel): String = when (level) {
    com.quantumvpn.hardening.AdBlockLevel.Light -> "Лёгкий"
    com.quantumvpn.hardening.AdBlockLevel.Standard -> "Стандарт"
    com.quantumvpn.hardening.AdBlockLevel.Hard -> "Жёсткий"
    com.quantumvpn.hardening.AdBlockLevel.Maximum -> "Максимум"
}

@Composable
private fun AdBlockBar(
    enabled: Boolean,
    configured: Boolean,
    ruleCount: Int,
    onlineDns: Boolean,
    level: com.quantumvpn.hardening.AdBlockLevel,
    blockedApprox: Int = 0,
    blockedSessionTotal: Long = 0L,
    onToggle: (Boolean) -> Unit,
    onOpenSettings: () -> Unit,
) {
    Surface(
        onClick = onOpenSettings,
        shape = RoundedCornerShape(18.dp),
        color = CosmicTokens.Card.copy(alpha = 0.88f),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                Icons.Default.Warning,
                null,
                tint = when {
                    enabled -> CosmicTokens.StatusGreen
                    configured -> Color.White.copy(alpha = 0.75f)
                    else -> Color.White.copy(alpha = 0.55f)
                },
                modifier = Modifier.size(22.dp),
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text("Блокировка рекламы", color = Color.White, fontWeight = FontWeight.Medium, fontSize = 15.sp)
                Text(
                    when {
                        enabled && onlineDns ->
                            "DNS + маршрут · ~$ruleCount · ${levelLabel(level)} · AdGuard"
                        enabled ->
                            "DNS + маршрут · ~$ruleCount · ${levelLabel(level)} · локальные списки"
                        configured ->
                            "Включена · активируется с VPN"
                        else ->
                            "Выключена в настройках"
                    },
                    color = Color.White.copy(alpha = 0.55f),
                    fontSize = 12.sp,
                )
                if (enabled) {
                    Text(
                        "$blockedApprox блок./мин · всего $blockedSessionTotal",
                        color = CosmicTokens.Orbit,
                        fontSize = 11.sp,
                    )
                }
            }
            Switch(
                checked = configured,
                onCheckedChange = onToggle,
                colors = SwitchDefaults.colors(
                    checkedThumbColor = Color.White,
                    checkedTrackColor = CosmicTokens.StatusGreen,
                    uncheckedThumbColor = Color.White.copy(alpha = 0.7f),
                    uncheckedTrackColor = Color.White.copy(alpha = 0.2f),
                ),
            )
        }
    }
}

@Composable
private fun ServerSelectCard(flag: String?, label: String, pingLabel: String?, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(28.dp),
        color = CosmicTokens.Card.copy(alpha = 0.92f),
        modifier = Modifier.fillMaxWidth().semantics { contentDescription = "Выбрать сервер" },
    ) {
        Row(modifier = Modifier.padding(horizontal = 18.dp, vertical = 16.dp), verticalAlignment = Alignment.CenterVertically) {
            AnimatedContent(
                targetState = flag ?: "🌐",
                transitionSpec = { fadeIn(tween(280)) togetherWith fadeOut(tween(180)) },
                label = "flag",
            ) { emoji -> Text(emoji, fontSize = 22.sp, modifier = Modifier.padding(end = 12.dp)) }
            Column(modifier = Modifier.weight(1f)) {
                Text(label, color = Color.White, fontWeight = FontWeight.Medium, fontSize = 17.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                if (!pingLabel.isNullOrBlank()) Text(pingLabel, color = CosmicTokens.Orbit, fontSize = 12.sp, maxLines = 1)
            }
            Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null, tint = Color.White.copy(alpha = 0.7f))
        }
    }
}

@Composable
private fun SubscriptionSelectCard(label: String, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(28.dp),
        color = CosmicTokens.VipBlue,
        modifier = Modifier.fillMaxWidth().semantics { contentDescription = "Выбрать подписку" },
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 18.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center,
        ) {
            Text("👑", fontSize = 20.sp)
            Spacer(modifier = Modifier.width(10.dp))
            Column {
                Text("ВЫБРАТЬ ПОДПИСКУ", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 15.sp)
                Text(label, color = Color.White.copy(alpha = 0.85f), fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

@Composable
private fun FastPowerButton(
    connected: Boolean,
    busy: Boolean,
    enabled: Boolean,
    reduceMotion: Boolean,
    globe3d: Boolean = false,
    onClick: () -> Unit,
    onSwipeLeft: () -> Unit,
    onSwipeRight: () -> Unit,
) {
    val ring = if (connected) CosmicTokens.GlowRing else CosmicTokens.GlowRing.copy(alpha = 0.85f)
    val transition = rememberInfiniteTransition(label = "pwr")
    val animate = !reduceMotion
    val spin = if (busy && animate) {
        transition.animateFloat(0f, 360f, infiniteRepeatable(tween(1200, easing = LinearEasing), RepeatMode.Restart), "spin").value
    } else 0f
    val pulse = if (connected && !busy && animate) {
        transition.animateFloat(0.92f, 1.06f, infiniteRepeatable(tween(1600, easing = LinearEasing), RepeatMode.Reverse), "pulse").value
    } else 1f
    var drag by remember { mutableFloatStateOf(0f) }
    val interaction = remember { MutableInteractionSource() }
    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier
            .size(168.dp)
            .pointerInput(enabled) {
                if (!enabled) return@pointerInput
                detectHorizontalDragGestures(
                    onDragEnd = {
                        when {
                            drag > 80f -> onSwipeRight()
                            drag < -80f -> onSwipeLeft()
                        }
                        drag = 0f
                    },
                    onHorizontalDrag = { _, amount -> drag += amount },
                )
            },
    ) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val stroke = 10.dp.toPx()
            val radius = size.minDimension / 2f - stroke
            drawCircle(
                brush = Brush.radialGradient(
                    listOf(
                        if (connected) CosmicTokens.StatusGreen.copy(alpha = 0.35f * pulse)
                        else CosmicTokens.Orbit.copy(alpha = 0.22f),
                        Color.Transparent,
                    ),
                ),
                radius = radius * 1.25f * pulse,
            )
            rotate(spin) {
                if (globe3d) {
                    drawCircle(
                        color = CosmicTokens.Orbit.copy(alpha = 0.25f),
                        radius = radius * 1.08f,
                        style = Stroke(width = stroke * 0.45f),
                    )
                }
                drawArc(
                    color = ring,
                    startAngle = -90f,
                    sweepAngle = if (busy) 270f else 360f,
                    useCenter = false,
                    topLeft = Offset(stroke, stroke),
                    size = Size(size.width - stroke * 2, size.height - stroke * 2),
                    style = Stroke(width = stroke, cap = StrokeCap.Round),
                )
            }
        }
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .size(118.dp)
                .clip(CircleShape)
                .background(
                    if (globe3d) {
                        Brush.radialGradient(
                            listOf(
                                if (connected) Color(0xFF5CFFD0).copy(alpha = 0.95f) else Color(0xFF3A7BD5),
                                if (connected) Color(0xFF0B9B52) else Color(0xFF0D2240),
                                Color(0xFF041020),
                            ),
                        )
                    } else {
                        Brush.verticalGradient(
                            listOf(
                                if (connected) Color(0xFF1FE07A) else Color(0xFF1A3A5C),
                                if (connected) Color(0xFF0B9B52) else Color(0xFF0D2240),
                            ),
                        )
                    },
                )
                .clickable(
                    enabled = enabled,
                    interactionSource = interaction,
                    indication = ripple(bounded = true, color = Color.White),
                    onClick = onClick,
                ),
        ) {
            if (busy) {
                CircularProgressIndicator(color = Color.White, strokeWidth = 3.dp, modifier = Modifier.size(36.dp))
            } else {
                Canvas(modifier = Modifier.size(48.dp)) {
                    val stroke = 5.dp.toPx()
                    drawArc(
                        color = Color.White,
                        startAngle = -40f,
                        sweepAngle = 260f,
                        useCenter = false,
                        topLeft = Offset(stroke, stroke),
                        size = Size(size.width - stroke * 2, size.height - stroke * 2),
                        style = Stroke(width = stroke, cap = StrokeCap.Round),
                    )
                    drawLine(
                        Color.White,
                        Offset(size.width / 2f, stroke * 0.4f),
                        Offset(size.width / 2f, size.height * 0.48f),
                        strokeWidth = stroke,
                        cap = StrokeCap.Round,
                    )
                }
            }
        }
    }
}

@Composable
private fun WorldMapBackdrop(modifier: Modifier = Modifier, pulse: Boolean) {
    val transition = rememberInfiniteTransition(label = "map")
    val drift = if (pulse) {
        transition.animateFloat(0f, 1f, infiniteRepeatable(tween(12_000, easing = LinearEasing), RepeatMode.Restart), "drift").value
    } else 0.35f
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawCircle(
            brush = Brush.radialGradient(
                listOf(Color(0xFF123A5C).copy(alpha = 0.55f), Color.Transparent),
                center = Offset(w * 0.55f, h * 0.42f),
                radius = w * 0.55f,
            ),
        )
        val continents = listOf(
            Path().apply {
                moveTo(w * 0.18f, h * 0.32f)
                cubicTo(w * 0.28f, h * 0.22f, w * 0.38f, h * 0.30f, w * 0.42f, h * 0.40f)
                cubicTo(w * 0.36f, h * 0.48f, w * 0.22f, h * 0.46f, w * 0.18f, h * 0.32f)
                close()
            },
            Path().apply {
                moveTo(w * 0.48f, h * 0.28f)
                cubicTo(w * 0.58f, h * 0.18f, w * 0.72f, h * 0.26f, w * 0.78f, h * 0.38f)
                cubicTo(w * 0.70f, h * 0.48f, w * 0.52f, h * 0.44f, w * 0.48f, h * 0.28f)
                close()
            },
        )
        continents.forEachIndexed { i, path ->
            drawPath(path, Color(0xFF1E4D73).copy(alpha = 0.28f + 0.08f * ((drift + i * 0.2f) % 1f)))
        }
    }
}

private fun formatRate(bytesPerSec: Long): String {
    if (bytesPerSec < 1024) return "$bytesPerSec B/s"
    val kb = bytesPerSec / 1024.0
    if (kb < 1024) return String.format("%.1f KB/s", kb)
    return String.format("%.2f MB/s", kb / 1024.0)
}

@Composable
private fun HomeInfoChip(label: String, onClick: (() -> Unit)? = null, highlight: Boolean = false) {
    val shape = RoundedCornerShape(20.dp)
    val colors = if (highlight) {
        CosmicTokens.Orbit.copy(alpha = 0.35f)
    } else {
        Color.White.copy(alpha = 0.12f)
    }
    val textColor = if (highlight) Color.White else Color.White.copy(alpha = 0.9f)
    if (onClick != null) {
        Surface(onClick = onClick, shape = shape, color = colors) {
            Text(
                label,
                color = textColor,
                fontSize = 12.sp,
                modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    } else {
        Surface(shape = shape, color = colors) {
            Text(
                label,
                color = textColor,
                fontSize = 12.sp,
                modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun PingSparkline(samples: List<Float>, modifier: Modifier = Modifier) {
    val valid = samples.filter { it > 0f }
    if (valid.size < 2) return
    val max = valid.maxOrNull()?.coerceAtLeast(1f) ?: return
    Canvas(modifier = modifier) {
        val step = size.width / (valid.size - 1).coerceAtLeast(1)
        val path = Path()
        valid.forEachIndexed { index, ping ->
            val x = index * step
            val y = size.height - (ping / max) * size.height
            if (index == 0) path.moveTo(x, y) else path.lineTo(x, y)
        }
        drawPath(
            path = path,
            color = CosmicTokens.Orbit.copy(alpha = 0.85f),
            style = Stroke(width = 2.dp.toPx(), cap = StrokeCap.Round),
        )
    }
}
