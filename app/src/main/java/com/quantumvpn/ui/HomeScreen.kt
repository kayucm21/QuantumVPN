package com.quantumvpn.ui

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.ripple
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.quantumvpn.diagnostics.DiagnosticState
import com.quantumvpn.profiles.ProfileMetadata
import com.quantumvpn.profiles.ProfileSource
import com.quantumvpn.profiles.ProfileStore
import com.quantumvpn.routing.HappRoutingCatalog
import com.quantumvpn.routing.RoutingPreset
import androidx.compose.material3.FilterChip
import androidx.compose.foundation.horizontalScroll
import com.quantumvpn.vpn.ExitLocationResolver
import com.quantumvpn.vpn.forServerUi
import com.quantumvpn.vpn.RuntimeOutboundItem
import com.quantumvpn.vpn.RuntimeSelectorGroup
import com.quantumvpn.vpn.TrafficSample
import com.quantumvpn.vpn.VpnConnectionState
import com.quantumvpn.vpn.VpnSessionStats
import com.quantumvpn.vpn.primaryGroup
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlin.math.max

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun HomeScreen(
    contentPadding: PaddingValues,
    profiles: List<ProfileMetadata>,
    activeProfile: ProfileMetadata?,
    onSelectProfile: (String) -> Unit,
    onAddProfile: () -> Unit,
    vpnState: VpnConnectionState,
    selectorGroups: List<RuntimeSelectorGroup>,
    profileSelectorGroups: List<RuntimeSelectorGroup>,
    sessionStats: VpnSessionStats,
    routingPreset: RoutingPreset?,
    routingLoading: Boolean,
    happCatalog: HappRoutingCatalog,
    onApplyRoutingPreset: (RoutingPreset) -> Unit,
    onSetHappRoutingEnabled: (Boolean) -> Unit,
    onSelectHappRoutingProfile: (String) -> Unit,
    onStart: (String) -> Unit,
    onStop: () -> Unit,
    onSelectOutbound: (String, String, String) -> Unit,
    onSelectProfileServer: (String, String) -> Unit,
    onMeasurePing: () -> Unit,
    onMeasureGroup: (String) -> Unit,
    profileStore: ProfileStore,
    recentServers: List<com.quantumvpn.vpn.RecentServer> = emptyList(),
    onRecentServer: (com.quantumvpn.vpn.RecentServer) -> Unit = {},
    blockNonVpnTraffic: Boolean = false,
    routingSummary: String? = null,
    onImportClipboard: () -> Unit = {},
    onRefreshSubscriptions: () -> Unit = {},
    onSpeedTest: () -> Unit = {},
    onWhySlow: () -> Unit = {},
    diagnostics: DiagnosticState? = null,
    subscriptionQuota: com.quantumvpn.importer.SubscriptionUserInfo? = null,
    reduceMotion: Boolean = false,
    securityScoreSummary: String? = null,
    securityTips: List<String> = emptyList(),
    lastDisconnectReason: String? = null,
    compactHome: Boolean = false,
    hideExitIp: Boolean = false,
    showSessionTimer: Boolean = true,
    hapticsEnabled: Boolean = true,
    onCopyExitIp: () -> Unit = {},
    onPanicDisconnect: () -> Unit = {},
    onRaceDns: () -> Unit = {},
    onBestPingHint: () -> Unit = {},
    connectEtaMillis: Long? = null,
    serverMode: com.quantumvpn.ui.ServerMode = com.quantumvpn.ui.ServerMode.Standard,
    captivePortal: Boolean = false,
    onOpenCaptivePortal: () -> Unit = {},
    onLiveCheck: () -> Unit = {},
    onMessengersOnly: () -> Unit = {},
    alwaysOnActive: Boolean = false,
    privateDnsActive: Boolean = false,
    showBatteryTip: Boolean = false,
    trustedWifiTip: String? = null,
    onHardReconnect: () -> Unit = {},
    dnsModeLabel: String = "DNS",
    onToggleKillSwitch: () -> Unit = {},
    onOpenDnsSettings: () -> Unit = {},
    adBlockEnabled: Boolean = true,
    adBlockActive: Boolean = false,
    adBlockRuleCount: Int = 0,
    adBlockOnlineDns: Boolean = true,
    adBlockLevel: com.quantumvpn.hardening.AdBlockLevel =
        com.quantumvpn.hardening.AdBlockLevel.Maximum,
    onToggleAdBlock: (Boolean) -> Unit = {},
    onOpenAdBlockSettings: () -> Unit = {},
    confirmDisconnect: Boolean = false,
    networkTransportLabel: String? = null,
    meteredNetwork: Boolean = false,
    lockdownActive: Boolean = false,
    networkValidated: Boolean = true,
    hideQuota: Boolean = false,
    networkChangedTip: String? = null,
    onSnoozeReconnect: () -> Unit = {},
    homeLoading: Boolean = false,
    showCoachMark: Boolean = false,
    onDismissCoachMark: () -> Unit = {},
    showTipsCarousel: Boolean = false,
    onDismissTipsCarousel: () -> Unit = {},
    onSmokeTest10s: () -> Unit = {},
    onSwapLastServer: () -> Unit = {},
    onOpenMenu: () -> Unit = {},
    onOpenServers: () -> Unit = {},
    carrierBypassEnabled: Boolean = true,
    lastDisconnectLine: String? = null,
    operatorHint: String? = null,
    onPanicReset: () -> Unit = {},
    beginnerMode: Boolean = false,
    homeVisualTheme: HomeVisualTheme = HomeVisualTheme.Globe3d,
    stealthMode: Boolean = false,
    hideMap: Boolean = false,
    onJammerTest: () -> Unit = {},
    onApplyJammer: () -> Unit = {},
    lastSpeedTestDetail: String? = null,
    speedTestBusy: Boolean = false,
    protocolLabel: String? = null,
    preConnectIp: String? = null,
    reconnectCountdownLabel: String? = null,
    protocolRecommendation: String? = null,
) {
    var serverSheetOpen by rememberSaveable { mutableStateOf(false) }
    var profileSheetOpen by rememberSaveable { mutableStateOf(false) }
    var routingSheetOpen by rememberSaveable { mutableStateOf(false) }
    var confirmStopOpen by rememberSaveable { mutableStateOf(false) }
    var connectMenuOpen by rememberSaveable { mutableStateOf(false) }
    var leakLabel by remember { mutableStateOf<String?>(null) }
    var leakOk by remember { mutableStateOf<Boolean?>(null) }
    var leakBusy by remember { mutableStateOf(false) }
    var bestBusy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val connected = vpnState as? VpnConnectionState.Connected
    val haptics = Haptics.rememberPerformer(hapticsEnabled)
    var connectArmedAt by remember { mutableStateOf(0L) }
    var connectTick by remember { mutableStateOf(0L) }
    var sessionTick by remember { mutableStateOf(0L) }
    val trafficHistory = rememberTrafficHistory(autoUpdate = true)
    LaunchedEffect(vpnState) {
        if (vpnState is VpnConnectionState.Connected) {
            trafficHistory.startAutoUpdate()
        } else {
            trafficHistory.stopAutoUpdate()
            trafficHistory.clear()
        }
    }
    // Fast Home is the only layout; beginner/homeLayoutMode no longer branch UI.
    LaunchedEffect(vpnState) {
        if (vpnState is VpnConnectionState.Starting) {
            while (true) {
                connectTick = System.currentTimeMillis()
                delay(200)
            }
        } else {
            connectTick = 0L
        }
    }
    LaunchedEffect(vpnState, sessionStats.connectedAtEpochMillis, showSessionTimer) {
        if (showSessionTimer && vpnState is VpnConnectionState.Connected &&
            sessionStats.connectedAtEpochMillis != null
        ) {
            while (true) {
                sessionTick = System.currentTimeMillis()
                delay(1_000)
            }
        } else {
            sessionTick = 0L
        }
    }
    val gap = if (compactHome) 6.dp else 12.dp
    val sectionGap = if (compactHome) 10.dp else 20.dp
    val displayGroups = when {
        connected != null && selectorGroups.any { it.items.isNotEmpty() } -> selectorGroups
        else -> profileSelectorGroups
    }.forServerUi()
    val currentGroup = displayGroups.primaryGroup()
    val currentServer = currentGroup?.items?.firstOrNull { it.tag == currentGroup.selected }
        ?: currentGroup?.items?.firstOrNull()
    val canChangeProfile = vpnState is VpnConnectionState.Stopped || vpnState is VpnConnectionState.Error
    val canChangeServer = activeProfile != null && displayGroups.any { it.items.isNotEmpty() }
    val accent = MaterialTheme.colorScheme.primary
    val protected = connected != null
    val bg = MaterialTheme.colorScheme.background
    val location = currentServer?.tag?.let { ExitLocationResolver.fromServerLabel(it) }
        ?: sessionStats.exitLocation
    val sessionTimerLabel = run {
        val started = sessionStats.connectedAtEpochMillis
        if (connected != null && started != null && sessionTick > 0L) {
            val sec = ((sessionTick - started).coerceAtLeast(0L) / 1000L)
            "%d:%02d:%02d".format(sec / 3600, (sec % 3600) / 60, sec % 60)
        } else {
            "0:00:00"
        }
    }
    val serverLabel = location?.countryName
        ?: currentServer?.tag
        ?: "Выберите сервер"
    val subscriptionLabel = buildString {
        append(activeProfile?.name ?: "Добавить подписку")
        if (!hideQuota && !beginnerMode && subscriptionQuota != null) {
            val q = subscriptionQuota.summaryRu
            if (q.isNotBlank()) append(" · ").append(q)
        }
    }
    val topServerPings = remember(displayGroups, currentGroup) {
        val group = currentGroup ?: return@remember emptyList()
        group.items
            .sortedBy { it.pingMillis ?: Int.MAX_VALUE }
            .take(3)
            .map { item ->
                HomeTopServerPing(
                    tag = item.tag,
                    label = item.tag.take(22),
                    pingMillis = item.pingMillis,
                    selected = item.tag == group.selected,
                )
            }
    }
    LaunchedEffect(activeProfile?.id, currentGroup?.tag, vpnState) {
        val group = currentGroup ?: return@LaunchedEffect
        if (group.items.isEmpty()) return@LaunchedEffect
        if (group.items.any { it.pingMillis == null }) {
            if (vpnState is VpnConnectionState.Connected) {
                onMeasureGroup(group.tag)
            }
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .padding(contentPadding),
    ) {
        if (homeLoading) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .background(CosmicTokens.Void)
                    .padding(20.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                HomeLoadingSkeleton()
                Text(
                    "Загрузка…",
                    color = Color.White.copy(alpha = 0.7f),
                    modifier = Modifier.padding(top = 12.dp),
                )
            }
        } else if (profiles.isEmpty()) {
            ManagedWelcomeScreen(onContinue = onAddProfile)
        } else {
            FastVpnHomeContent(
                vpnState = vpnState,
                sessionStats = sessionStats,
                sessionTimerLabel = sessionTimerLabel,
                serverFlag = location?.flagEmoji,
                serverLabel = serverLabel,
                serverPingLabel = when {
                    sessionStats.pingMillis != null -> formatPing(sessionStats.pingMillis)
                    currentServer?.pingMillis != null -> formatPing(currentServer.pingMillis.toLong())
                    else -> null
                },
                recentFlags = recentServers.mapNotNull { it.flagEmoji }.distinct().take(5),
                onRecentFlag = { index ->
                    recentServers.mapNotNull { it.flagEmoji }.distinct().getOrNull(index)?.let { flag ->
                        recentServers.firstOrNull { it.flagEmoji == flag }?.let(onRecentServer)
                    }
                },
                subscriptionLabel = subscriptionLabel,
                connectEnabled = activeProfile != null || vpnState is VpnConnectionState.Connected ||
                    vpnState is VpnConnectionState.Starting || vpnState is VpnConnectionState.Stopping,
                reduceMotion = reduceMotion,
                leakLabel = if (leakBusy) "Проверка…" else leakLabel,
                leakOk = leakOk,
                onLeakCheck = {
                    if (leakBusy) return@FastVpnHomeContent
                    leakBusy = true
                    leakLabel = "Проверка…"
                    scope.launch {
                        val result = runCatching {
                            com.quantumvpn.diagnostics.LeakChecker.run(context)
                        }.getOrNull()
                        leakBusy = false
                        if (result == null) {
                            leakOk = false
                            leakLabel = "Ошибка проверки"
                            return@launch
                        }
                        val ok = result.vpnActive && result.httpsOk && result.dnsResolvesGoogle &&
                            result.notes.none { "IPv4 и IPv6" in it }
                        leakOk = ok
                        leakLabel = if (ok) "Утечек нет" else "Есть риски"
                    }
                },
                onBestServer = {
                    val group = currentGroup ?: return@FastVpnHomeContent
                    if (bestBusy) return@FastVpnHomeContent
                    bestBusy = true
                    scope.launch {
                        try {
                            if (vpnState is VpnConnectionState.Connected) {
                                onMeasureGroup(group.tag)
                                delay(1_800)
                            }
                            val best = com.quantumvpn.vpn.ServerFailover.nextBest(
                                groups = displayGroups,
                                pingByTag = com.quantumvpn.vpn.SessionPingCache.snapshot(),
                                excludeTag = null,
                                mode = serverMode,
                            ) ?: group.items
                                .mapNotNull { item ->
                                    val ping = item.pingMillis ?: return@mapNotNull null
                                    com.quantumvpn.vpn.ServerFailover.Candidate(group.tag, item.tag, ping)
                                }
                                .minByOrNull { it.pingMillis }
                            if (best == null) {
                                onBestPingHint()
                                return@launch
                            }
                            haptics(Haptics.Confirm)
                            when (vpnState) {
                                is VpnConnectionState.Connected ->
                                    onSelectOutbound(vpnState.profileId, best.groupTag, best.outboundTag)
                                else -> {
                                    onSelectProfileServer(best.groupTag, best.outboundTag)
                                    activeProfile?.id?.let(onStart)
                                }
                            }
                        } finally {
                            bestBusy = false
                        }
                    }
                },
                bestServerBusy = bestBusy,
                onOpenMenu = onOpenMenu,
                onToggleConnect = {
                    val now = System.currentTimeMillis()
                    if (now - connectArmedAt < 700L) return@FastVpnHomeContent
                    connectArmedAt = now
                    haptics(if (vpnState is VpnConnectionState.Connected) Haptics.Reject else Haptics.Confirm)
                    when (vpnState) {
                        VpnConnectionState.Stopped,
                        is VpnConnectionState.Error,
                        -> activeProfile?.id?.let(onStart) ?: onAddProfile()
                        is VpnConnectionState.Connected -> {
                            if (confirmDisconnect) confirmStopOpen = true else onStop()
                        }
                        is VpnConnectionState.Starting,
                        is VpnConnectionState.Stopping,
                        -> onStop()
                    }
                },
                onSwipeLeft = {
                    if (vpnState is VpnConnectionState.Connected) {
                        haptics(Haptics.Reject)
                        if (confirmDisconnect) confirmStopOpen = true else onStop()
                    }
                },
                onSwipeRight = {
                    if (vpnState is VpnConnectionState.Connected) {
                        haptics(Haptics.Confirm)
                        onHardReconnect()
                    } else if (vpnState is VpnConnectionState.Stopped || vpnState is VpnConnectionState.Error) {
                        haptics(Haptics.Confirm)
                        activeProfile?.id?.let(onStart) ?: onAddProfile()
                    }
                },
                onOpenServers = onOpenServers,
                onOpenSubscription = {
                    if (canChangeProfile || profiles.isNotEmpty()) profileSheetOpen = true
                    else onAddProfile()
                },
                carrierBypassEnabled = carrierBypassEnabled,
                lastDisconnectLine = lastDisconnectLine ?: lastDisconnectReason,
                operatorHint = operatorHint,
                onPanicReset = onPanicReset,
                beginnerMode = beginnerMode,
                compactHome = compactHome,
                hideExitIp = hideExitIp,
                exitIp = sessionStats.externalIp,
                preConnectIp = preConnectIp,
                protocolLabel = protocolLabel ?: currentServer?.type,
                connectEtaMillis = connectEtaMillis,
                securityScoreSummary = securityScoreSummary,
                killSwitchOn = blockNonVpnTraffic,
                onToggleKillSwitch = onToggleKillSwitch,
                alwaysOnActive = alwaysOnActive,
                lockdownActive = lockdownActive,
                showBatteryTip = showBatteryTip,
                networkChangedTip = networkChangedTip,
                captivePortal = captivePortal,
                onOpenCaptivePortal = onOpenCaptivePortal,
                onLiveCheck = onLiveCheck,
                onMessengersOnly = onMessengersOnly,
                onSpeedTest = onSpeedTest,
                speedTestBusy = speedTestBusy,
                lastSpeedTestDetail = lastSpeedTestDetail,
                onWhySlow = onWhySlow,
                onJammerTest = onJammerTest,
                onApplyJammer = onApplyJammer,
                onHardReconnect = onHardReconnect,
                onSnoozeReconnect = onSnoozeReconnect,
                reconnectCountdownLabel = reconnectCountdownLabel,
                onApplyRoutingPreset = onApplyRoutingPreset,
                onCopyExitIp = onCopyExitIp,
                pingSamples = sessionStats.pingSamples,
                adBlockEnabled = adBlockEnabled,
                adBlockActive = adBlockActive,
                adBlockRuleCount = adBlockRuleCount,
                adBlockOnlineDns = adBlockOnlineDns,
                adBlockLevel = adBlockLevel,
                onToggleAdBlock = onToggleAdBlock,
                onOpenAdBlockSettings = onOpenAdBlockSettings,
                adBlockedApprox = sessionStats.adBlockedPerMinute,
                adBlockedSessionTotal = sessionStats.adBlockedSessionTotal,
                protocolRecommendation = protocolRecommendation,
                stealthMode = stealthMode,
                homeVisualTheme = homeVisualTheme,
                hideMap = hideMap,
                exitCountryCode = sessionStats.exitCountryCode,
                topServerPings = topServerPings,
                onSelectTopServer = { tag ->
                    val group = currentGroup ?: return@FastVpnHomeContent
                    when (vpnState) {
                        is VpnConnectionState.Connected ->
                            onSelectOutbound(vpnState.profileId, group.tag, tag)
                        else -> onSelectProfileServer(group.tag, tag)
                    }
                },
                modifier = Modifier.fillMaxSize(),
            )
            if (showCoachMark || showTipsCarousel) {
                Column(
                    modifier = Modifier
                        .align(Alignment.TopCenter)
                        .padding(top = 56.dp, start = 16.dp, end = 16.dp),
                ) {
                    if (showCoachMark) {
                        CoachMarkBanner(
                            screen = CoachMarkScreen.Home,
                            onDismiss = onDismissCoachMark,
                            modifier = Modifier.padding(bottom = 8.dp),
                        )
                    }
                    if (showTipsCarousel) {
                        TipsCarousel(
                            onDismiss = onDismissTipsCarousel,
                            modifier = Modifier.padding(bottom = 8.dp),
                        )
                    }
                }
            }
        }

    }

    if (confirmStopOpen) {
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { confirmStopOpen = false },
            title = { Text("Отключить VPN?") },
            text = { Text("Трафик снова пойдёт через обычную сеть Android.") },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmStopOpen = false
                        onStop()
                    },
                ) { Text("Отключить") }
            },
            dismissButton = {
                TextButton(onClick = { confirmStopOpen = false }) { Text("Отмена") }
            },
        )
    }

    if (profileSheetOpen) {
        ModalBottomSheet(onDismissRequest = { profileSheetOpen = false }) {
            ProfileSelectorSheet(
                profiles = profiles,
                activeProfileId = activeProfile?.id,
                onSelect = {
                    if (canChangeProfile) {
                        onSelectProfile(it)
                        profileSheetOpen = false
                    }
                },
                onAddProfile = {
                    profileSheetOpen = false
                    onAddProfile()
                },
            )
        }
    }
    if (serverSheetOpen && canChangeServer) {
        ModalBottomSheet(onDismissRequest = { serverSheetOpen = false }) {
            ServerSelectorSheet(
                groups = displayGroups,
                sessionPingMillis = sessionStats.pingMillis,
                connected = connected != null,
                profileId = activeProfile?.id,
                profileStore = profileStore,
                onSelect = { group, item ->
                    if (connected != null) {
                        onSelectOutbound(connected.profileId, group.tag, item.tag)
                    } else {
                        onSelectProfileServer(group.tag, item.tag)
                    }
                    serverSheetOpen = false
                },
                onMeasureGroupLive = onMeasureGroup,
            )
        }
    }
    if (routingSheetOpen && activeProfile != null) {
        ModalBottomSheet(onDismissRequest = { routingSheetOpen = false }) {
            if (happCatalog.profiles.isNotEmpty()) {
                HappRoutingSheet(
                    catalog = happCatalog,
                    onEnabledChange = onSetHappRoutingEnabled,
                    onSelect = {
                        onSelectHappRoutingProfile(it)
                        routingSheetOpen = false
                    },
                )
            } else {
                RoutingPresetSheet(
                    selected = routingPreset,
                    onSelect = {
                        onApplyRoutingPreset(it)
                        routingSheetOpen = false
                    },
                )
            }
        }
    }
}

/** First-run screen for the built-in subscription; no manual link import. */
@Composable
private fun ManagedWelcomeScreen(onContinue: () -> Unit) {
    Box(
        modifier = Modifier.fillMaxSize().background(
            Brush.verticalGradient(listOf(Color(0xFF061A29), Color(0xFF03101C), Color(0xFF01060B))),
        ),
    ) {
        Globe3DBackdrop(Modifier.fillMaxSize(), pulse = true, reduceMotion = false, countryCode = null)
        Column(
            modifier = Modifier.fillMaxSize().padding(horizontal = 28.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Surface(
                shape = CircleShape,
                color = CosmicTokens.StatusGreen.copy(alpha = 0.16f),
                border = androidx.compose.foundation.BorderStroke(2.dp, CosmicTokens.StatusGreen),
                modifier = Modifier.size(160.dp),
            ) {
                Column(
                    modifier = Modifier.fillMaxSize(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                ) {
                    Icon(Icons.Default.Lock, contentDescription = null, tint = CosmicTokens.StatusGreen, modifier = Modifier.size(54.dp))
                    Text("QuantumVPN", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 18.sp)
                }
            }
            Spacer(Modifier.height(32.dp))
            Text("Защищённый интернет", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 28.sp, textAlign = TextAlign.Center)
            Spacer(Modifier.height(10.dp))
            Text(
                "Встроенное подключение готово. Выберите сервер и включите защиту в один тап.",
                color = CosmicTokens.OnVoidMuted,
                fontSize = 16.sp,
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(30.dp))
            Button(
                onClick = onContinue,
                colors = ButtonDefaults.buttonColors(containerColor = CosmicTokens.StatusGreen, contentColor = Color(0xFF04120D)),
                modifier = Modifier.fillMaxWidth().height(56.dp),
            ) { Text("Продолжить", fontWeight = FontWeight.Bold, fontSize = 17.sp) }
            Spacer(Modifier.height(12.dp))
            Text("Без ручного импорта ссылок", color = CosmicTokens.OnVoidMuted, fontSize = 12.sp)
        }
    }
}

@Composable
private fun HappConnectButton(
    vpnState: VpnConnectionState,
    enabled: Boolean,
    accent: Color,
    onSwipeLeft: () -> Unit = {},
    onSwipeRight: () -> Unit = {},
    onClick: () -> Unit,
) {
    val busy = vpnState is VpnConnectionState.Starting || vpnState is VpnConnectionState.Stopping
    val connected = vpnState is VpnConnectionState.Connected
    val ringColor = when {
        vpnState is VpnConnectionState.Error -> MaterialTheme.colorScheme.error
        connected -> accent
        busy -> accent.copy(alpha = 0.7f)
        else -> MaterialTheme.colorScheme.outline.copy(alpha = 0.45f)
    }
    val fillColor = when {
        connected -> accent
        busy -> MaterialTheme.colorScheme.surfaceVariant
        else -> MaterialTheme.colorScheme.surfaceContainerHighest
    }
    val iconTint = when {
        connected -> MaterialTheme.colorScheme.onPrimary
        else -> MaterialTheme.colorScheme.onSurface
    }
    val spin = if (busy) {
        val transition = rememberInfiniteTransition(label = "connect-spin")
        transition.animateFloat(
            initialValue = 0f,
            targetValue = 360f,
            animationSpec = infiniteRepeatable(
                animation = tween(1_200, easing = LinearEasing),
                repeatMode = RepeatMode.Restart,
            ),
            label = "spin",
        ).value
    } else {
        0f
    }
    var dragTotal by remember { mutableStateOf(0f) }
    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier
            .size(168.dp)
            .semantics {
                contentDescription = when {
                    connected -> "Отключить VPN"
                    busy -> "Остановить подключение"
                    else -> "Подключить VPN"
                }
            }
            .pointerInput(enabled) {
                if (!enabled) return@pointerInput
                detectHorizontalDragGestures(
                    onDragEnd = {
                        when {
                            dragTotal > 72f -> onSwipeRight()
                            dragTotal < -72f -> onSwipeLeft()
                        }
                        dragTotal = 0f
                    },
                    onHorizontalDrag = { _, amount -> dragTotal += amount },
                )
            }
            .clip(CircleShape)
            .clickable(
                enabled = enabled,
                indication = ripple(bounded = true, radius = 84.dp),
                interactionSource = remember { MutableInteractionSource() },
                onClick = onClick,
            ),
    ) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val stroke = 5.dp.toPx()
            val inset = stroke / 2
            rotate(spin) {
                drawArc(
                    color = ringColor,
                    startAngle = if (busy) -90f else 0f,
                    sweepAngle = if (busy) 270f else 360f,
                    useCenter = false,
                    topLeft = Offset(inset, inset),
                    size = Size(size.width - stroke, size.height - stroke),
                    style = Stroke(width = stroke, cap = StrokeCap.Round),
                )
            }
        }
        Surface(
            modifier = Modifier.size(132.dp),
            shape = CircleShape,
            color = fillColor,
            shadowElevation = if (connected) 10.dp else 4.dp,
        ) {
            Box(contentAlignment = Alignment.Center, modifier = Modifier.fillMaxSize()) {
                if (busy) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(36.dp),
                        strokeWidth = 3.dp,
                        color = accent,
                    )
                } else {
                    Icon(
                        imageVector = if (connected) Icons.Default.Lock else Icons.Default.PlayArrow,
                        contentDescription = null,
                        tint = iconTint,
                        modifier = Modifier.size(56.dp),
                    )
                }
            }
        }
    }
}

@Composable
private fun SelectorCard(
    label: String,
    value: String,
    trailing: String? = null,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.large)
            .clickable(enabled = enabled, onClick = onClick),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.75f),
        shape = MaterialTheme.shapes.large,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    label,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    value,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            if (trailing != null) {
                Text(
                    trailing,
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(end = 8.dp),
                )
            }
            Text("›", style = MaterialTheme.typography.headlineSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun ProfileSelectorSheet(
    profiles: List<ProfileMetadata>,
    activeProfileId: String?,
    onSelect: (String) -> Unit,
    onAddProfile: () -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxWidth(),
        contentPadding = PaddingValues(start = 20.dp, end = 20.dp, bottom = 32.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        item {
            Text("Подписки", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
            Spacer(modifier = Modifier.height(8.dp))
        }
        items(profiles, key = { it.id }) { profile ->
            val selected = profile.id == activeProfileId
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onSelect(profile.id) }
                    .padding(vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = selected, onClick = { onSelect(profile.id) })
                Column(modifier = Modifier.weight(1f).padding(start = 4.dp)) {
                    Text(profile.name, fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Medium)
                    Text(
                        when (profile.source) {
                            ProfileSource.Subscription, ProfileSource.Url, ProfileSource.Link -> "Подписка"
                            ProfileSource.Qr -> "QR"
                            ProfileSource.File -> "Файл"
                            ProfileSource.Clipboard -> "Буфер"
                            ProfileSource.RawJson -> "Импорт"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
        item {
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedButton(onClick = onAddProfile, modifier = Modifier.fillMaxWidth()) {
                Text("Добавить подписку")
            }
        }
    }
}

@Composable
private fun SessionFacts(stats: VpnSessionStats, connectedAt: Long, onMeasurePing: () -> Unit) {
    var now by remember(connectedAt) { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(connectedAt) {
        while (true) {
            delay(1_000)
            now = System.currentTimeMillis()
        }
    }
    val elapsed = ((now - connectedAt) / 1000L).coerceAtLeast(0L)
    val hours = elapsed / 3600
    val minutes = (elapsed % 3600) / 60
    val seconds = elapsed % 60
    val totalBytes = (stats.downloadTotalBytes + stats.uploadTotalBytes).coerceAtLeast(0L)
    val mbPerHour = if (elapsed >= 30L) {
        (totalBytes.toDouble() / 1_000_000.0) / (elapsed.toDouble() / 3600.0)
    } else {
        null
    }
    Column(modifier = Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                "Сессия %02d:%02d:%02d".format(hours, minutes, seconds),
                style = MaterialTheme.typography.labelLarge,
            )
            TextButton(onClick = onMeasurePing) { Text("Пинг") }
            Text(
                formatPing(stats.pingMillis),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.primary,
            )
        }
        mbPerHour?.let { rate ->
            Text(
                "Расход ~%.1f МБ/ч".format(rate),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun PingSparkline(samples: List<Long>) {
    val line = MaterialTheme.colorScheme.primary
    val grid = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f)
    Canvas(
        modifier = Modifier
            .fillMaxWidth()
            .height(48.dp)
            .clip(MaterialTheme.shapes.medium)
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f))
            .padding(8.dp),
    ) {
        drawLine(grid, Offset(0f, size.height), Offset(size.width, size.height))
        if (samples.size < 2) return@Canvas
        val peak = max(1L, samples.maxOrNull() ?: 1L)
        val path = Path()
        samples.forEachIndexed { index, value ->
            val x = size.width * index / max(1, samples.size - 1)
            val y = size.height * (1f - value.toFloat() / peak.toFloat())
            if (index == 0) path.moveTo(x, y) else path.lineTo(x, y)
        }
        drawPath(path, line, style = Stroke(2.dp.toPx(), cap = StrokeCap.Round))
    }
}

@Composable
private fun TrafficTotals(stats: VpnSessionStats) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
        Text("↓ ${formatBytes(stats.downloadTotalBytes)}", color = MaterialTheme.colorScheme.primary)
        Text("↑ ${formatBytes(stats.uploadTotalBytes)}", color = MaterialTheme.colorScheme.secondary)
    }
}

@Composable
private fun TrafficChart(samples: List<TrafficSample>) {
    val downloadColor = MaterialTheme.colorScheme.primary
    val uploadColor = MaterialTheme.colorScheme.secondary
    val gridColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f)
    Canvas(
        modifier = Modifier
            .fillMaxWidth()
            .height(96.dp)
            .clip(MaterialTheme.shapes.medium)
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f))
            .padding(8.dp),
    ) {
        drawLine(gridColor, start = Offset(0f, size.height), end = Offset(size.width, size.height))
        if (samples.size < 2) return@Canvas
        val peak = max(1L, samples.maxOf { max(it.downloadBytesPerSecond, it.uploadBytesPerSecond) })
        fun pathOf(value: (TrafficSample) -> Long): Path = Path().apply {
            samples.forEachIndexed { index, sample ->
                val x = size.width * index / max(1, samples.size - 1)
                val y = size.height * (1f - value(sample).toFloat() / peak.toFloat())
                if (index == 0) moveTo(x, y) else lineTo(x, y)
            }
        }
        drawPath(pathOf(TrafficSample::downloadBytesPerSecond), downloadColor, style = Stroke(2.dp.toPx(), cap = StrokeCap.Round))
        drawPath(pathOf(TrafficSample::uploadBytesPerSecond), uploadColor, style = Stroke(2.dp.toPx(), cap = StrokeCap.Round))
    }
}

@Composable
private fun ServerSelectorSheet(
    groups: List<RuntimeSelectorGroup>,
    sessionPingMillis: Long?,
    connected: Boolean,
    profileId: String?,
    profileStore: ProfileStore,
    onSelect: (RuntimeSelectorGroup, RuntimeOutboundItem) -> Unit,
    onMeasureGroupLive: (String) -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var pinging by remember { mutableStateOf(false) }
    var offlinePings by remember { mutableStateOf<Map<String, Int?>>(emptyMap()) }
    val hasServers = groups.any { it.items.isNotEmpty() }

    fun pingLabel(item: RuntimeOutboundItem, selected: Boolean): String {
        val live = item.pingMillis?.toLong()
        val offline = offlinePings[item.tag]?.toLong()
        val session = sessionPingMillis.takeIf { selected && connected }
        return formatPing(live ?: offline ?: session)
    }

    fun runPing(group: RuntimeSelectorGroup) {
        if (pinging || group.items.isEmpty()) return
        if (connected) {
            onMeasureGroupLive(group.tag)
            return
        }
        val id = profileId ?: return
        pinging = true
        scope.launch {
            offlinePings = runCatching {
                measureOfflinePings(
                    context = context,
                    profileStore = profileStore,
                    profileId = id,
                    group = group,
                )
            }.getOrDefault(emptyMap())
            pinging = false
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxWidth(),
        contentPadding = PaddingValues(start = 20.dp, end = 20.dp, bottom = 32.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        item {
            Text("Серверы", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
            Spacer(modifier = Modifier.height(8.dp))
        }
        groups.filter { it.items.isNotEmpty() }.forEach { group ->
            if (groups.size > 1) {
                item(key = "header-${group.tag}") {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(group.tag, modifier = Modifier.weight(1f), style = MaterialTheme.typography.titleMedium)
                        if (hasServers) {
                            TextButton(
                                onClick = { runPing(group) },
                                enabled = !pinging,
                            ) {
                                Text(if (pinging) "…" else "Проверить")
                            }
                        }
                    }
                }
            } else if (hasServers) {
                item(key = "ping-${group.tag}") {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        if (pinging) {
                            CircularProgressIndicator(
                                modifier = Modifier
                                    .padding(end = 8.dp)
                                    .height(18.dp)
                                    .size(18.dp),
                                strokeWidth = 2.dp,
                            )
                        }
                        TextButton(
                            onClick = { runPing(group) },
                            enabled = !pinging,
                        ) {
                            Text("Проверить пинг")
                        }
                    }
                }
            }
            items(group.items, key = { "${group.tag}-${it.tag}" }) { item ->
                val selected = group.selected == item.tag
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable(enabled = group.selectable) { onSelect(group, item) }
                        .padding(vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(
                        selected = selected,
                        onClick = if (group.selectable) ({ onSelect(group, item) }) else null,
                    )
                    Column(modifier = Modifier.weight(1f)) {
                        Text(item.tag, fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal)
                        Text(
                            listOfNotNull(item.type.uppercase(), item.endpoint).joinToString(" · "),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    Text(
                        pingLabel(item, selected),
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
            }
        }
    }
}

@Composable
private fun HappRoutingSheet(
    catalog: HappRoutingCatalog,
    onEnabledChange: (Boolean) -> Unit,
    onSelect: (String) -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxWidth(),
        contentPadding = PaddingValues(start = 20.dp, end = 20.dp, bottom = 32.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        item {
            Text("Маршрутизация", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
            Spacer(modifier = Modifier.height(12.dp))
            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Включить маршрутизацию", fontWeight = FontWeight.SemiBold)
                }
                androidx.compose.material3.Switch(
                    checked = catalog.enabled,
                    onCheckedChange = onEnabledChange,
                )
            }
            Spacer(modifier = Modifier.height(12.dp))
            Text("Профили", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary)
        }
        items(catalog.profiles, key = { it.name }) { profile ->
            val selected = catalog.enabled && catalog.activeName == profile.name
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(enabled = catalog.enabled) { onSelect(profile.name) }
                    .padding(vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(
                    selected = selected,
                    onClick = if (catalog.enabled) ({ onSelect(profile.name) }) else null,
                    enabled = catalog.enabled,
                )
                Text(profile.name, modifier = Modifier.weight(1f).padding(start = 4.dp), fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Medium)
            }
        }
    }
}

@Composable
private fun RoutingPresetSheet(
    selected: RoutingPreset?,
    onSelect: (RoutingPreset) -> Unit,
) {
    val presets = listOf(
        RoutingPreset.AllThroughVpn,
        RoutingPreset.BypassLan,
        RoutingPreset.OnlySelectedSites,
        RoutingPreset.RussiaDirect,
        RoutingPreset.RussiaVpn,
        RoutingPreset.BlockAds,
        RoutingPreset.FamilyProtect,
        RoutingPreset.Streaming,
        RoutingPreset.Gaming,
        RoutingPreset.Work,
        RoutingPreset.Custom,
    )
    LazyColumn(
        modifier = Modifier.fillMaxWidth(),
        contentPadding = PaddingValues(start = 20.dp, end = 20.dp, bottom = 32.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        item {
            Text("Маршрутизация", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
            Spacer(modifier = Modifier.height(8.dp))
        }
        items(presets, key = { it.name }) { preset ->
            val isSelected = preset == selected
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onSelect(preset) }
                    .padding(vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = isSelected, onClick = { onSelect(preset) })
                Column(modifier = Modifier.weight(1f).padding(start = 4.dp)) {
                    Text(preset.title, fontWeight = if (isSelected) FontWeight.SemiBold else FontWeight.Medium)
                    Text(preset.detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}

internal fun formatPing(millis: Long?): String = when (millis) {
    null -> "—"
    else -> "${millis} ms"
}

internal fun connectionQualityLabel(pingMillis: Long?): String? {
    val ping = pingMillis ?: return null
    return when {
        ping < 50 -> "Качество: отлично (<50 ms)"
        ping < 100 -> "Качество: хорошо (<100 ms)"
        ping < 200 -> "Качество: норма (<200 ms)"
        ping < 400 -> "Качество: слабо"
        else -> "Качество: плохо"
    }
}

internal fun pingJitterLabel(samples: List<Long>): String? {
    if (samples.size < 3) return null
    val recent = samples.takeLast(12)
    val avg = recent.average()
    val variance = recent.map { (it - avg) * (it - avg) }.average()
    val jitter = kotlin.math.sqrt(variance)
    return "Джиттер ~${jitter.toInt()} ms · avg ${avg.toInt()} ms"
}

internal fun formatBytes(value: Long): String {
    if (value < 1024) return "$value B"
    val units = arrayOf("KB", "MB", "GB", "TB")
    var size = value.toDouble()
    var unit = -1
    while (size >= 1024 && unit < units.lastIndex) {
        size /= 1024
        unit++
    }
    return "%.1f %s".format(java.util.Locale.US, size, units[unit])
}

private fun VpnConnectionState.statusSubtitle(): String = when (this) {
    VpnConnectionState.Stopped -> "Нажмите «Подключить»"
    is VpnConnectionState.Starting -> "Подключение…"
    is VpnConnectionState.Connected -> "Трафик защищён"
    is VpnConnectionState.Stopping -> "Отключение…"
    is VpnConnectionState.Error -> "Ошибка подключения"
}

private fun VpnConnectionState.actionHint(needsProfile: Boolean): String = when {
    needsProfile -> "Добавьте подписку"
    this is VpnConnectionState.Connected -> "Подключено"
    this is VpnConnectionState.Starting -> "Подключение"
    this is VpnConnectionState.Stopping -> "Отключение"
    this is VpnConnectionState.Error -> "Повторить"
    else -> "Подключить"
}
