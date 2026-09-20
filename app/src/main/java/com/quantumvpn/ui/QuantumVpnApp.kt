package com.quantumvpn.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.quantumvpn.BuildConfig
import com.quantumvpn.importer.qrImportScanOptions
import com.quantumvpn.policy.ClientPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.journeyapps.barcodescanner.ScanContract
import com.quantumvpn.diagnostics.DiagnosticState
import com.quantumvpn.profiles.ImportPreviewState
import com.quantumvpn.profiles.ProfileMetadata
import com.quantumvpn.profiles.ProfileSource
import com.quantumvpn.profiles.ProfileStore
import com.quantumvpn.profiles.ProfilesUiState
import com.quantumvpn.profiles.ProfilesViewModel
import com.quantumvpn.routing.RoutingUiState
import com.quantumvpn.routing.RoutingViewModel
import com.quantumvpn.updates.UpdateCandidate
import com.quantumvpn.updates.UpdateChannel
import com.quantumvpn.updates.UpdateState
import com.quantumvpn.vpn.AppScopeMode
import com.quantumvpn.vpn.RuntimeSelectorGroup
import com.quantumvpn.vpn.VpnConnectionState
import com.quantumvpn.vpn.VpnSessionStats
import com.quantumvpn.vpn.primaryGroup
import java.text.DateFormat
import java.util.Date
import com.quantumvpn.ui.components.QvBottomBar
import com.quantumvpn.ui.components.QvTabItem

private enum class AppTab(
    val id: String,
    val title: String,
    val icon: ImageVector,
) {
    Home("home", "Главная", Icons.Default.Home),
    Servers("servers", "Серверы", Icons.AutoMirrored.Filled.List),
    Statistics("statistics", "Статистика", Icons.Default.Menu),
    Settings("settings", "Настройки", Icons.Default.Settings),
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QuantumVpnApp(
    profilesViewModel: ProfilesViewModel,
    state: ProfilesUiState,
    profileStore: ProfileStore,
    routingViewModel: RoutingViewModel,
    routingState: RoutingUiState,
    vpnState: VpnConnectionState,
    selectorGroups: List<RuntimeSelectorGroup>,
    sessionStats: VpnSessionStats,
    diagnostics: DiagnosticState,
    vpnMessage: String?,
    onVpnMessageConsumed: () -> Unit,
    onVpnStart: (String) -> Unit,
    onVpnStop: () -> Unit,
    onHardReconnect: () -> Unit = {},
    onSelectOutbound: (String, String, String) -> Unit,
    onMeasurePing: () -> Unit,
    onMeasureGroup: (String) -> Unit,
    onHomeSelected: (Boolean) -> Unit,
    onDiagnosticsSelected: (Boolean) -> Unit,
    onCreateDiagnosticShare: suspend () -> Intent,
    onClearDnsCache: () -> Unit,
    updateState: UpdateState,
    onCheckUpdate: (UpdateChannel) -> Unit,
    onDownloadUpdate: () -> Unit,
    onInstallUpdate: () -> Unit,
    onCancelUpdate: () -> Unit,
    initialShortcut: String? = null,
    onShortcutConsumed: () -> Unit = {},
) {
    // V2 owns the complete user-visible shell. Legacy screens remain temporarily
    // in source only as a rollback aid while the new shell is device-tested.
    val useV2 = true
    if (useV2) {
        QuantumVpnAppV2(
            state = state,
            viewModel = profilesViewModel,
            vpnState = vpnState,
            selectorGroups = state.homeSelectorGroups.ifEmpty { selectorGroups },
            sessionStats = sessionStats,
            diagnostics = diagnostics,
            onVpnStart = onVpnStart,
            onVpnStop = onVpnStop,
            onSelectServer = profilesViewModel::selectActiveServer,
            onHomeSelected = onHomeSelected,
            onMeasurePing = onMeasurePing,
            onMeasureGroup = onMeasureGroup,
            updateState = updateState,
            onCheckUpdate = { onCheckUpdate(UpdateChannel.Stable) },
            onDownloadUpdate = onDownloadUpdate,
            onInstallUpdate = onInstallUpdate,
            onCancelUpdate = onCancelUpdate,
        )
    } else {
    val context = LocalContext.current
    var selectedTab by rememberSaveable { mutableStateOf(AppTab.Home) }
    var gridMenuOpen by rememberSaveable { mutableStateOf(false) }
    var pendingSettingsDestination by remember { mutableStateOf<SettingsDestination?>(null) }
    var pendingUnlockSuccess by remember { mutableStateOf<(() -> Unit)?>(null) }
    var showWhatsNew by rememberSaveable { mutableStateOf(false) }
    val adBlockRuleCount = remember(
        state.settings.adBlockEnabled,
        state.settings.adBlockLevel,
        state.settings.adBlockTrackersOnly,
        state.settings.adBlockWhitelist,
        state.settings.adBlockOnlineDns,
    ) {
        com.quantumvpn.hardening.AdBlockHardening.ruleCount(
            com.quantumvpn.hardening.AdBlockOptions(
                enabled = state.settings.adBlockEnabled,
                level = state.settings.adBlockLevel,
                trackersOnly = state.settings.adBlockTrackersOnly,
                whitelistSuffixes = state.settings.adBlockWhitelist
                    .split(',', ' ', '\n', ';')
                    .map { it.trim().lowercase() }
                    .filter { it.isNotBlank() },
                useOnlineFilterDns = state.settings.adBlockOnlineDns,
                categories = state.settings.adBlockCategories,
            ),
        )
    }
    val adBlockActive = vpnState is VpnConnectionState.Connected
    val credentialLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            pendingUnlockSuccess?.invoke()
        } else if (pendingUnlockSuccess != null) {
            profilesViewModel.showTip("Действие отменено.")
        }
        pendingUnlockSuccess = null
    }
    fun confirmDevice(title: String, subtitle: String, onSuccess: () -> Unit) {
        val activity = context as? androidx.fragment.app.FragmentActivity
        if (state.settings.biometricLockEnabled && activity != null) {
            DeviceUnlock.authenticate(
                activity = activity,
                preferBiometric = true,
                title = title,
                subtitle = subtitle,
                onSuccess = onSuccess,
                onFailure = {
                    val keyguard = context.getSystemService(android.app.KeyguardManager::class.java)
                    @Suppress("DEPRECATION")
                    val intent = keyguard?.createConfirmDeviceCredentialIntent(title, subtitle)
                    if (intent != null) {
                        pendingUnlockSuccess = onSuccess
                        credentialLauncher.launch(intent)
                    } else {
                        onSuccess()
                    }
                },
            )
            return
        }
        val keyguard = context.getSystemService(android.app.KeyguardManager::class.java)
        @Suppress("DEPRECATION")
        val intent = keyguard?.createConfirmDeviceCredentialIntent(title, subtitle)
        if (intent != null) {
            pendingUnlockSuccess = onSuccess
            credentialLauncher.launch(intent)
        } else {
            onSuccess()
        }
    }
    fun guardedStop() {
        if (state.settings.requireUnlockToDisconnect) {
            confirmDevice("QuantumVPN", "Подтвердите отключение VPN", onVpnStop)
        } else {
            onVpnStop()
        }
    }
    fun guardedStart(profileId: String) {
        val app = context.applicationContext as? com.quantumvpn.QuantumVpnApplication
        val repo = app?.container?.clientPolicyRepository
        val policy = repo?.policy?.value ?: com.quantumvpn.policy.ClientPolicy()
        val block = policy.blockReason(
            com.quantumvpn.BuildConfig.VERSION_CODE.toLong(),
            deviceSerial = repo?.deviceSerial().orEmpty(),
        )
        if (block != null) {
            profilesViewModel.showTip(block)
            return
        }
        onVpnStart(profileId)
    }
    fun guardedSelectServer(groupTag: String, outboundTag: String) {
        val select = {
            profilesViewModel.selectActiveServer(groupTag, outboundTag)
        }
        if (state.settings.requireUnlockToChangeServer) {
            confirmDevice("QuantumVPN", "Подтвердите смену сервера") {
                select()
            }
        } else {
            select()
        }
    }
    fun openTab(tab: AppTab) {
        if (tab == AppTab.Settings && (state.settings.appLockEnabled || state.settings.biometricLockEnabled)) {
            confirmDevice("QuantumVPN", "Подтвердите доступ к настройкам") {
                selectedTab = tab
            }
        } else {
            selectedTab = tab
        }
    }
    LaunchedEffect(state.initialized, state.settings.lastSeenChangelogVersion) {
        if (!state.initialized) return@LaunchedEffect
        val latest = LocalChangelog.entries.firstOrNull()?.version.orEmpty()
        if (latest.isNotBlank() && latest != state.settings.lastSeenChangelogVersion) {
            showWhatsNew = true
        }
    }
    LaunchedEffect(initialShortcut, state.initialized) {
        if (!state.initialized || initialShortcut.isNullOrBlank()) return@LaunchedEffect
        when (initialShortcut) {
            "connect" -> {
                selectedTab = AppTab.Home
                val profileId = state.settings.activeProfileId
                if (profileId != null) guardedStart(profileId)
                else profilesViewModel.showTip("Сначала выберите профиль.")
                onShortcutConsumed()
            }
            "disconnect" -> {
                guardedStop()
                onShortcutConsumed()
            }
            "servers" -> {
                selectedTab = AppTab.Servers
                onShortcutConsumed()
            }
            "speedtest" -> {
                selectedTab = AppTab.Home
                profilesViewModel.runSpeedTest()
                onShortcutConsumed()
            }
            "dns" -> {
                selectedTab = AppTab.Settings
                profilesViewModel.raceDnsLatency()
                onShortcutConsumed()
            }
            "import" -> {
                selectedTab = AppTab.Settings
                profilesViewModel.installManagedSubscription()
                onShortcutConsumed()
            }
            else -> onShortcutConsumed()
        }
    }
    var dismissedUpdateTag by rememberSaveable { mutableStateOf<String?>(null) }
    val recentServers by profilesViewModel.recentServers.collectAsState()
    val favoriteKeys by profilesViewModel.favoriteKeys.collectAsState()
    val pinnedKeys by profilesViewModel.pinnedKeys.collectAsState()
    val quarantinedKeys by profilesViewModel.quarantinedServerKeys.collectAsState()
    val reliabilityScores by profilesViewModel.reliabilityScores.collectAsState()
    val reliabilityEntries by profilesViewModel.reliabilityEntries.collectAsState()
    val switchHistory by profilesViewModel.switchHistory.collectAsState()
    val lastDisconnectReason by profilesViewModel.lastDisconnectReason.collectAsState()
    val serverNotes by profilesViewModel.serverNotes.collectAsState()
    val connectEtaMillis by profilesViewModel.connectEtaMillis.collectAsState()
    val securityScore = remember(vpnState, state.settings, sessionStats) {
        com.quantumvpn.diagnostics.SecurityScoreCalculator.compute(
            vpnState = vpnState,
            settings = state.settings,
            stats = sessionStats,
        )
    }
    var failoverKey by rememberSaveable { mutableStateOf<String?>(null) }
    var failoverTried by rememberSaveable { mutableStateOf(listOf<String>()) }
    var failoverCount by rememberSaveable { mutableStateOf(0) }
    var lastFailoverAt by rememberSaveable { mutableStateOf(0L) }
    var lastNetworkTransport by rememberSaveable { mutableStateOf<String?>(null) }
    var networkChangedTip by rememberSaveable { mutableStateOf<String?>(null) }
    var preConnectIp by rememberSaveable { mutableStateOf<String?>(null) }
    var reconnectCountdownLabel by remember { mutableStateOf<String?>(null) }
    var lastConnectedSnapshot by remember {
        mutableStateOf<Pair<VpnConnectionState.Connected, VpnSessionStats>?>(null)
    }
    var smokeStopAt by remember { mutableStateOf(0L) }
    LaunchedEffect(sessionStats.externalIp, vpnState) {
        val ip = sessionStats.externalIp?.takeIf { it.isNotBlank() } ?: return@LaunchedEffect
        val note = when (vpnState) {
            is VpnConnectionState.Connected -> "VPN"
            else -> "сеть"
        }
        runCatching {
            (context.applicationContext as? com.quantumvpn.QuantumVpnApplication)
                ?.container
                ?.exitIpTimelineStore
                ?.append(ip, note)
        }
    }
    LaunchedEffect(vpnState, state.settings.qoeMonitorEnabled, sessionStats.pingMillis) {
        if (!state.settings.qoeMonitorEnabled) return@LaunchedEffect
        if (vpnState !is VpnConnectionState.Connected) return@LaunchedEffect
        while (true) {
            kotlinx.coroutines.delay(5 * 60 * 1000L)
            if (vpnState !is VpnConnectionState.Connected) break
            val ping = sessionStats.pingMillis ?: continue
            if (ping <= 350) continue
            profilesViewModel.logEvent("qoe", "high_ping_$ping")
            if (!state.settings.autoFailoverEnabled ||
                !com.quantumvpn.policy.ClientFeatureGate.features().autoFailover
            ) {
                profilesViewModel.showTip("QoE: пинг ${ping} ms — попробуйте «Лучший сервер»")
                continue
            }
            if (state.settings.snoozeReconnectUntilEpochMillis > System.currentTimeMillis()) continue
            val profileId = state.settings.activeProfileId ?: continue
            val groups = state.homeSelectorGroups
            val current = groups.primaryGroup()?.selected
            val next = com.quantumvpn.vpn.ServerFailover.nextBest(
                groups = groups,
                pingByTag = com.quantumvpn.vpn.SessionPingCache.snapshot(),
                excludeTag = current,
                reliabilityByTag = reliabilityScores,
                mode = state.settings.serverMode,
            ) ?: continue
            profilesViewModel.selectActiveServer(next.groupTag, next.outboundTag)
            guardedStart(profileId)
            val quietNight = state.settings.quietNightReconnect &&
                java.util.Calendar.getInstance().get(java.util.Calendar.HOUR_OF_DAY) in 0..6
            if (!quietNight) {
                profilesViewModel.showTip("QoE failover → ${next.outboundTag} (${next.pingMillis} ms)")
            }
        }
    }
    LaunchedEffect(state.settings.stealthUntilEpochMillis) {
        val until = state.settings.stealthUntilEpochMillis
        if (until <= 0L) return@LaunchedEffect
        val left = until - System.currentTimeMillis()
        if (left <= 0) {
            profilesViewModel.setStealthUntil(0L)
            profilesViewModel.setIncognitoSession(false)
            return@LaunchedEffect
        }
        profilesViewModel.setIncognitoSession(true)
        kotlinx.coroutines.delay(left)
        profilesViewModel.setStealthUntil(0L)
        profilesViewModel.setIncognitoSession(false)
        profilesViewModel.showTip("Stealth 30 мин завершён")
    }
    LaunchedEffect(vpnState) {
        when (vpnState) {
            is VpnConnectionState.Connected -> profilesViewModel.recordConnectSuccessForAdaptiveDpi()
            is VpnConnectionState.Error -> profilesViewModel.recordConnectFailureForAdaptiveDpi()
            else -> Unit
        }
    }
    LaunchedEffect(vpnState) {
        while (true) {
            val until = state.settings.snoozeReconnectUntilEpochMillis
            val left = until - System.currentTimeMillis()
            reconnectCountdownLabel = if (left > 0) {
                "Reconnect на паузе: ${(left / 1000).coerceAtLeast(1)} с"
            } else {
                null
            }
            if (left <= 0) break
            kotlinx.coroutines.delay(1_000)
        }
    }
    LaunchedEffect(smokeStopAt) {
        if (smokeStopAt <= 0L) return@LaunchedEffect
        val wait = smokeStopAt - System.currentTimeMillis()
        if (wait > 0) kotlinx.coroutines.delay(wait)
        guardedStop()
        smokeStopAt = 0L
        profilesViewModel.showTip("Smoke-тест 10 с завершён.")
    }
    LaunchedEffect(diagnostics.network?.transport) {
        val transport = diagnostics.network?.transport?.takeIf { it.isNotBlank() } ?: return@LaunchedEffect
        val prev = lastNetworkTransport
        if (prev != null && prev != transport) {
            networkChangedTip = "Сеть сменилась: $prev → $transport"
        }
        lastNetworkTransport = transport
    }
    LaunchedEffect(vpnState, sessionStats) {
        when (val stateNow = vpnState) {
            is VpnConnectionState.Connected -> {
                lastConnectedSnapshot = stateNow to sessionStats
            }
            is VpnConnectionState.Stopped, is VpnConnectionState.Error -> {
                val snap = lastConnectedSnapshot
                if (snap != null) {
                    val (conn, stats) = snap
                    val durationSec = stats.connectedAtEpochMillis?.let {
                        ((System.currentTimeMillis() - it).coerceAtLeast(0L) / 1000L)
                    } ?: 0L
                    profilesViewModel.recordSessionTraffic(
                        profileName = conn.profileName,
                        downloadBytes = stats.downloadTotalBytes,
                        uploadBytes = stats.uploadTotalBytes,
                        durationSec = durationSec,
                    )
                    lastConnectedSnapshot = null
                }
            }
            else -> Unit
        }
    }
    LaunchedEffect(vpnState) {
        val error = vpnState as? VpnConnectionState.Error ?: return@LaunchedEffect
        val code = error.code.ifBlank { "VPN-000" }
        profilesViewModel.noteDisconnectReason("$code · ${error.message}")
        profilesViewModel.recordConnectFail()
        if (!state.settings.autoFailoverEnabled ||
            !com.quantumvpn.policy.ClientFeatureGate.features().autoFailover
        ) return@LaunchedEffect
        if (state.settings.snoozeReconnectUntilEpochMillis > System.currentTimeMillis()) {
            profilesViewModel.showTip("Failover на паузе (snooze).")
            return@LaunchedEffect
        }
        if (state.settings.failoverCooldownUntilEpochMillis > System.currentTimeMillis()) {
            profilesViewModel.showTip("Failover cooldown активен.")
            return@LaunchedEffect
        }
        val now = System.currentTimeMillis()
        if (now - lastFailoverAt < 12_000L) return@LaunchedEffect
        if (failoverCount >= 3) {
            profilesViewModel.startFailoverCooldown(30)
            profilesViewModel.showTip("Failover: лимит 3 попыток. Cooldown 30 мин.")
            return@LaunchedEffect
        }
        val key = "${error.code}:${error.message}"
        if (failoverKey == key && failoverCount == 0) return@LaunchedEffect
        failoverKey = key
        val profileId = state.settings.activeProfileId ?: return@LaunchedEffect
        val groups = state.homeSelectorGroups
        val current = groups.primaryGroup()?.selected
        val exclude = failoverTried.toSet() + setOfNotNull(current)
        val primary = groups.primaryGroup()
        val failedType = primary?.items?.firstOrNull { it.tag == current }?.type
        val candidates = com.quantumvpn.vpn.ServerFailover.candidates(
            groups = groups,
            pingByTag = com.quantumvpn.vpn.SessionPingCache.snapshot(),
            excludeTags = exclude,
        )
        val typeByTag = primary?.items?.associate { it.tag to it.type }.orEmpty()
        val next = com.quantumvpn.vpn.ProtocolSwitchHint.preferAlternate(
            candidates = candidates,
            typeByTag = typeByTag,
            failedType = failedType,
            reliabilityByTag = reliabilityScores,
            mode = state.settings.serverMode,
        ) ?: candidates.minByOrNull { it.pingMillis }
        if (next == null) {
            profilesViewModel.showTip("Failover: нет другого сервера с пингом.")
            return@LaunchedEffect
        }
        failoverTried = (exclude + next.outboundTag).toList()
        failoverCount += 1
        lastFailoverAt = now
        profilesViewModel.selectActiveServer(next.groupTag, next.outboundTag)
        guardedStart(profileId)
        val quietNight = state.settings.quietNightReconnect &&
            java.util.Calendar.getInstance().get(java.util.Calendar.HOUR_OF_DAY) in 0..6
        val tip = "Failover ${failoverCount}/3 → ${next.outboundTag} (${next.pingMillis} ms)" +
            (failedType?.let { " · смена протокола с $it" }.orEmpty())
        if (!quietNight) profilesViewModel.showTip(tip)
        profilesViewModel.logEvent("failover", "${next.outboundTag}#$failoverCount")
    }
    LaunchedEffect(vpnState) {
        val connected = vpnState as? VpnConnectionState.Connected ?: return@LaunchedEffect
        failoverKey = null
        failoverTried = emptyList()
        failoverCount = 0
        val attempt = diagnostics.connectionAttempt
        val duration = attempt?.totalDurationMillis
            ?: sessionStats.connectedAtEpochMillis?.let {
                (connected.connectedAtEpochMillis - it).takeIf { d -> d > 0 }
            }
        duration?.let { profilesViewModel.recordConnectDuration(it) }
        profilesViewModel.recordConnectSuccess()
    }
    LaunchedEffect(vpnState, state.settings.autoLockOnDisconnect) {
        if (!state.settings.autoLockOnDisconnect) return@LaunchedEffect
        if (vpnState is VpnConnectionState.Stopped || vpnState is VpnConnectionState.Error) {
            profilesViewModel.logEvent("security", "auto-lock-on-disconnect")
        }
    }
    LaunchedEffect(vpnState, sessionStats.connectedAtEpochMillis, state.settings.idleRemindEnabled) {
        if (!state.settings.idleRemindEnabled) return@LaunchedEffect
        val started = sessionStats.connectedAtEpochMillis ?: return@LaunchedEffect
        if (vpnState !is VpnConnectionState.Connected) return@LaunchedEffect
        while (true) {
            val hours = (System.currentTimeMillis() - started) / 3_600_000L
            if (hours >= 4L) {
                profilesViewModel.showTip("VPN работает уже ${hours}ч. Можно отключить, если не нужен.")
                break
            }
            kotlinx.coroutines.delay(30 * 60_000L)
        }
    }
    val homeSelected = selectedTab == AppTab.Home
    DisposableEffect(homeSelected) {
        onHomeSelected(homeSelected)
        onDispose { if (homeSelected) onHomeSelected(false) }
    }

    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val profilesSorted = remember(state.profiles, state.settings.subscriptionPriorityIds) {
        val priority = state.settings.subscriptionPriorityIds
            .split(',')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
        if (priority.isEmpty()) {
            state.profiles
        } else {
            state.profiles.sortedBy { profile ->
                val idx = priority.indexOf(profile.id)
                if (idx >= 0) idx else priority.size + 1
            }
        }
    }
    LaunchedEffect(state.message) {
        state.message?.let {
            snackbarHostState.showSnackbar(it)
            profilesViewModel.consumeMessage()
        }
    }
    LaunchedEffect(Unit) {
        val app = context.applicationContext as? com.quantumvpn.QuantumVpnApplication ?: return@LaunchedEffect
        app.container.clientPolicyRepository.policy.collect { policy ->
            val announce = policy.activeAnnounce()
            if (announce.isNotBlank()) {
                profilesViewModel.showTip(announce)
            }
            val serial = app.container.clientPolicyRepository.deviceSerial()
            val block = policy.blockReason(
                com.quantumvpn.BuildConfig.VERSION_CODE.toLong(),
                deviceSerial = serial,
            )
            if (block != null && vpnState is VpnConnectionState.Connected) {
                onVpnStop()
                profilesViewModel.showTip(block)
            }
            if (!policy.features.adblock && state.settings.adBlockEnabled) {
                profilesViewModel.setAdBlockEnabled(false)
            }
        }
    }
    LaunchedEffect(state.undoMessage) {
        val undo = state.undoMessage ?: return@LaunchedEffect
        val result = snackbarHostState.showSnackbar(
            message = undo,
            actionLabel = "Отменить",
            duration = SnackbarDuration.Long,
        )
        if (result == SnackbarResult.ActionPerformed) {
            profilesViewModel.undoLastAction()
        } else {
            profilesViewModel.consumeUndoOffer()
        }
    }
    state.subscriptionDiff?.let { diff ->
        SubscriptionDiffDialog(
            diff = diff,
            onDismiss = profilesViewModel::dismissSubscriptionDiff,
            onUndo = profilesViewModel::undoLastAction,
        )
    }
    LaunchedEffect(vpnMessage) {
        vpnMessage?.let {
            snackbarHostState.showSnackbar(it)
            onVpnMessageConsumed()
        }
    }
    var lastExitIp by rememberSaveable { mutableStateOf<String?>(null) }
    LaunchedEffect(sessionStats.externalIp, vpnState, state.settings.notifyExitIpChange) {
        val ip = sessionStats.externalIp
        if (!state.settings.notifyExitIpChange) {
            lastExitIp = ip
            return@LaunchedEffect
        }
        if (vpnState is VpnConnectionState.Connected &&
            !ip.isNullOrBlank() &&
            lastExitIp != null &&
            lastExitIp != ip
        ) {
            snackbarHostState.showSnackbar("Exit IP сменился: $ip")
            profilesViewModel.logEvent("exit_ip", "IP $ip")
        }
        if (!ip.isNullOrBlank()) lastExitIp = ip
        if (vpnState !is VpnConnectionState.Connected) lastExitIp = null
    }
    LaunchedEffect(routingState.undoMessage) {
        routingState.undoMessage?.let { msg ->
            val result = snackbarHostState.showSnackbar(
                message = msg,
                actionLabel = "Отменить",
                duration = SnackbarDuration.Long,
            )
            if (result == SnackbarResult.ActionPerformed) {
                routingViewModel.undoRoutingChange()
            } else {
                routingViewModel.consumeRoutingUndo()
            }
        }
    }
    LaunchedEffect(routingState.message) {
        routingState.message?.let {
            snackbarHostState.showSnackbar(it)
            routingViewModel.consumeMessage()
        }
    }
    LaunchedEffect(updateState) {
        if (updateState == UpdateState.Idle || updateState is UpdateState.Checking) {
            dismissedUpdateTag = null
        }
    }
    val availableUpdate = (updateState as? UpdateState.Available)?.candidate
    if (availableUpdate != null && dismissedUpdateTag != availableUpdate.release.tag) {
        UpdateAvailableDialog(
            candidate = availableUpdate,
            onDownload = {
                dismissedUpdateTag = availableUpdate.release.tag
                onDownloadUpdate()
            },
            onLater = {
                dismissedUpdateTag = availableUpdate.release.tag
                onCancelUpdate()
            },
        )
    }
    when (val currentUpdate = updateState) {
        is UpdateState.Downloading -> {
            UpdateDownloadingDialog(
                candidate = currentUpdate.candidate,
                downloadedBytes = currentUpdate.downloadedBytes,
                totalBytes = currentUpdate.totalBytes,
                onCancel = onCancelUpdate,
            )
        }
        is UpdateState.Ready -> {
            if (dismissedUpdateTag != currentUpdate.candidate.release.tag) {
                UpdateReadyDialog(
                    candidate = currentUpdate.candidate,
                    onInstall = onInstallUpdate,
                    onLater = {
                        dismissedUpdateTag = currentUpdate.candidate.release.tag
                        onCancelUpdate()
                    },
                )
            }
        }
        is UpdateState.RetryingViaVpn -> {
            UpdateProgressNotice(
                title = "Повтор через VPN",
                body = "Прямой доступ к обновлению недоступен — пробуем через VPN.",
            )
        }
        else -> Unit
    }
    LaunchedEffect(state.importCompletion) {
        if (state.importCompletion != null) {
            profilesViewModel.consumeImportCompletion()
        }
    }

    if (!state.settings.onboardingCompleted && state.initialized) {
        OnboardingScreen(
            contentPadding = PaddingValues(0.dp),
            onFinished = profilesViewModel::completeOnboarding,
            onImport = {
                profilesViewModel.completeOnboarding()
                selectedTab = AppTab.Settings
            },
        )
        return
    }

    if (showWhatsNew) {
        val latest = LocalChangelog.entries.first()
        androidx.compose.material3.AlertDialog(
            onDismissRequest = {
                showWhatsNew = false
                profilesViewModel.markChangelogSeen(latest.version)
            },
            title = { Text("Что нового в ${latest.version}") },
            text = {
                Column {
                    latest.bullets.forEach { line ->
                        Text("• $line", modifier = Modifier.padding(bottom = 4.dp))
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showWhatsNew = false
                        profilesViewModel.markChangelogSeen(latest.version)
                    },
                ) { Text("Понятно") }
            },
        )
    }

    Scaffold(
        // Each primary screen owns its heading, matching the four-tab app shell.
        topBar = {},
        bottomBar = {
            QvBottomBar(
                tabs = AppTab.entries.map { tab ->
                    QvTabItem(id = tab.id, title = tab.title, icon = tab.icon)
                },
                selectedId = selectedTab.id,
                onSelect = { id ->
                    AppTab.entries.firstOrNull { it.id == id }?.let(::openTab)
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
        containerColor = if (selectedTab == AppTab.Home) {
            CosmicTokens.Void
        } else {
            MaterialTheme.colorScheme.background
        },
    ) { contentPadding ->
        BackHandler(enabled = selectedTab != AppTab.Home) {
            selectedTab = AppTab.Home
        }
        when (selectedTab) {
            AppTab.Home -> HomeScreen(
                contentPadding = contentPadding,
                profiles = profilesSorted,
                activeProfile = profilesSorted.firstOrNull {
                    it.id == state.settings.activeProfileId
                } ?: state.profiles.firstOrNull {
                    it.id == state.settings.activeProfileId
                },
                onSelectProfile = profilesViewModel::selectProfile,
                onAddProfile = profilesViewModel::installManagedSubscription,
                vpnState = vpnState,
                selectorGroups = selectorGroups,
                profileSelectorGroups = state.homeSelectorGroups,
                sessionStats = sessionStats,
                routingPreset = routingState.inspection?.preset,
                routingLoading = routingState.loading,
                happCatalog = routingState.happCatalog,
                onApplyRoutingPreset = routingViewModel::applyPreset,
                onSetHappRoutingEnabled = routingViewModel::setHappRoutingEnabled,
                onSelectHappRoutingProfile = routingViewModel::selectHappRoutingProfile,
                onStart = { activeProfileId ->
                    if (vpnState !is VpnConnectionState.Connected) {
                        preConnectIp = sessionStats.externalIp ?: preConnectIp
                    }
                    guardedStart(activeProfileId)
                },
                onStop = { guardedStop() },
                onSelectOutbound = { profileId, groupTag, outboundTag ->
                    onSelectOutbound(profileId, groupTag, outboundTag)
                    profilesViewModel.recordRecentServer(profileId, groupTag, outboundTag)
                },
                onSelectProfileServer = profilesViewModel::selectActiveServer,
                onMeasurePing = onMeasurePing,
                onMeasureGroup = onMeasureGroup,
                profileStore = profileStore,
                recentServers = recentServers,
                onRecentServer = { recent ->
                    profilesViewModel.selectProfile(recent.profileId)
                    profilesViewModel.selectActiveServer(recent.groupTag, recent.outboundTag)
                },
                blockNonVpnTraffic = state.settings.blockNonVpnTraffic,
                routingSummary = routingState.inspection?.summary,
                onImportClipboard = {
                    profilesViewModel.installManagedSubscription()
                },
                onRefreshSubscriptions = profilesViewModel::refreshAllSubscriptions,
                onSpeedTest = profilesViewModel::runSpeedTest,
                onWhySlow = {
                    val report = com.quantumvpn.diagnostics.WhySlowDiagnoser.diagnose(
                        context = context,
                        vpnState = vpnState,
                        stats = sessionStats,
                        killSwitch = state.settings.blockNonVpnTraffic,
                        powerModeName = state.settings.powerMode.name,
                    )
                    profilesViewModel.logEvent("diagnose", report.summary.replace('\n', ' '))
                    profilesViewModel.showTip(report.summary)
                },
                diagnostics = diagnostics,
                subscriptionQuota = state.subscriptionQuota,
                reduceMotion = state.settings.reduceMotion,
                securityScoreSummary = securityScore.summary,
                securityTips = securityScore.tips,
                lastDisconnectReason = lastDisconnectReason,
                compactHome = state.settings.compactHome,
                hideExitIp = state.settings.hideExitIp,
                showSessionTimer = state.settings.showSessionTimer,
                hapticsEnabled = state.settings.hapticsEnabled,
                connectEtaMillis = connectEtaMillis,
                serverMode = state.settings.serverMode,
                captivePortal = diagnostics.network?.captivePortal == true,
                onOpenCaptivePortal = {
                    runCatching {
                        context.startActivity(
                            Intent(Intent.ACTION_VIEW, android.net.Uri.parse("http://connectivitycheck.gstatic.com/generate_204"))
                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                        )
                    }
                },
                onLiveCheck = profilesViewModel::liveCheckActiveServer,
                onMessengersOnly = {
                    if (!com.quantumvpn.policy.ClientFeatureGate.features().splitTunnel) {
                        profilesViewModel.showTip("Split tunnel отключён оператором.")
                        return@HomeScreen
                    }
                    val app = context.applicationContext as? com.quantumvpn.QuantumVpnApplication
                    if (app == null) {
                        profilesViewModel.showTip("Не удалось применить пресет")
                        return@HomeScreen
                    }
                    scope.launch {
                        val installed = withContext(Dispatchers.IO) {
                            app.container.appCatalog.load()
                        }
                        val packages = com.quantumvpn.vpn.AppScopePresets.packagesFor(
                            com.quantumvpn.vpn.AppScopePreset.Messengers,
                            installed,
                        )
                        app.container.appSelectionStore.setMode(com.quantumvpn.vpn.AppScopeMode.Include)
                        app.container.appSelectionStore.replaceAllowlist(packages)
                        profilesViewModel.showTip("Per-app: только мессенджеры → VPN (${packages.size})")
                    }
                },
                alwaysOnActive = diagnostics.vpnPolicy?.alwaysOn == true,
                lockdownActive = diagnostics.vpnPolicy?.lockdown == true,
                privateDnsActive = diagnostics.network?.privateDnsActive == true,
                showBatteryTip = vpnState is VpnConnectionState.Error ||
                    vpnState is VpnConnectionState.Stopped,
                trustedWifiTip = remember(state.settings.trustedWifiSsids, state.settings.autoConnectTrustedWifi) {
                    val ssid = com.quantumvpn.vpn.WifiSsidReader.currentSsid(context) ?: return@remember null
                    val trusted = state.settings.trustedWifiSsids
                        .split(',')
                        .map { it.trim() }
                        .filter { it.isNotEmpty() }
                    when {
                        trusted.any { it.equals(ssid, ignoreCase = true) } ->
                            if (state.settings.autoConnectTrustedWifi) {
                                "Wi‑Fi «$ssid»: доверенная сеть, автоподключение включено."
                            } else {
                                "Wi‑Fi «$ssid»: в доверенных. Включите автоподключение в Настройках."
                            }
                        trusted.isEmpty() ->
                            "Wi‑Fi «$ssid»: добавьте SSID в доверенные (Ещё → Подключение)."
                        else ->
                            "Wi‑Fi «$ssid»: не в доверенных — трафик как обычно."
                    }
                },
                onHardReconnect = onHardReconnect,
                dnsModeLabel = when (state.settings.dnsMode) {
                    com.quantumvpn.config.DnsMode.Automatic -> "DNS авто"
                    com.quantumvpn.config.DnsMode.Android -> "DNS Android"
                    com.quantumvpn.config.DnsMode.Secure -> "DNS DoH"
                    com.quantumvpn.config.DnsMode.FromJson -> "DNS JSON"
                },
                onToggleKillSwitch = {
                    profilesViewModel.setBlockNonVpnTraffic(!state.settings.blockNonVpnTraffic)
                },
                onOpenDnsSettings = { openTab(AppTab.Settings) },
                adBlockEnabled = state.settings.adBlockEnabled,
                adBlockActive = adBlockActive,
                adBlockRuleCount = adBlockRuleCount,
                adBlockOnlineDns = state.settings.adBlockOnlineDns,
                adBlockLevel = state.settings.adBlockLevel,
                onToggleAdBlock = profilesViewModel::setAdBlockEnabled,
                onOpenAdBlockSettings = {
                    pendingSettingsDestination = SettingsDestination.AdBlock
                    openTab(AppTab.Settings)
                },
                confirmDisconnect = state.settings.confirmDisconnect,
                networkTransportLabel = diagnostics.network?.transport?.let { raw ->
                    when (raw.lowercase()) {
                        "wifi" -> "Сеть: Wi‑Fi"
                        "cellular", "cell", "mobile" -> "Сеть: LTE/моб."
                        "ethernet" -> "Сеть: Ethernet"
                        "none", "unknown", "" -> null
                        else -> "Сеть: $raw"
                    }
                },
                meteredNetwork = diagnostics.network?.metered == true,
                networkValidated = diagnostics.network?.validated != false,
                hideQuota = state.settings.hideQuota,
                networkChangedTip = networkChangedTip,
                onSnoozeReconnect = {
                    profilesViewModel.snoozeReconnectFifteenMinutes()
                    profilesViewModel.showTip("Reconnect/failover на паузе 15 мин.")
                },
                homeLoading = !state.initialized,
                showCoachMark = CoachMarkScreen.Home.name !in state.settings.dismissedCoachMarkScreens &&
                    !state.settings.coachMarksDismissed,
                onDismissCoachMark = { profilesViewModel.dismissCoachMark(CoachMarkScreen.Home) },
                showTipsCarousel = !state.settings.tipsCarouselDismissed && state.initialized,
                onDismissTipsCarousel = profilesViewModel::dismissTipsCarousel,
                onSwapLastServer = profilesViewModel::swapToPreviousServer,
                onSmokeTest10s = {
                    val profileId = state.settings.activeProfileId
                    if (profileId == null) {
                        profilesViewModel.showTip("Сначала выберите профиль.")
                    } else {
                        guardedStart(profileId)
                        smokeStopAt = System.currentTimeMillis() + 10_000L
                        profilesViewModel.showTip("Smoke-тест: 10 с подключения.")
                    }
                },
                onCopyExitIp = {
                    val ip = sessionStats.externalIp
                    if (ip.isNullOrBlank() || state.settings.hideExitIp) {
                        profilesViewModel.showTip("Exit IP скрыт или ещё не получен.")
                    } else {
                        val cm = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE)
                            as android.content.ClipboardManager
                        cm.setPrimaryClip(android.content.ClipData.newPlainText("exit-ip", ip))
                        profilesViewModel.showTip("Exit IP скопирован.")
                    }
                },
                onPanicDisconnect = {
                    onVpnStop()
                    profilesViewModel.noteDisconnectReason("Panic disconnect")
                    profilesViewModel.showTip("Panic: VPN отключён.")
                },
                onRaceDns = profilesViewModel::raceDnsLatency,
                onBestPingHint = {
                    profilesViewModel.showTip("Нет серверов с известным пингом. Откройте список и нажмите «Проверить».")
                },
                onOpenMenu = { gridMenuOpen = true },
                onOpenServers = { openTab(AppTab.Servers) },
                carrierBypassEnabled = state.settings.carrierBypassEnabled,
                lastDisconnectLine = lastDisconnectReason,
                operatorHint = remember(context) {
                    val snap = com.quantumvpn.vpn.CarrierDetector.snapshot(context)
                    when {
                        snap.isCellular && snap.displayLabel != null ->
                            "Оператор: ${snap.displayLabel} · обход DPI для всех сетей"
                        snap.isCellular -> "Мобильная сеть · обход DPI включён"
                        else -> null
                    }
                },
                onPanicReset = profilesViewModel::panicResetNetworkOverlays,
                beginnerMode = state.settings.beginnerMode,
                homeVisualTheme = state.settings.homeVisualTheme,
                stealthMode = state.settings.stealthMode,
                hideMap = state.settings.hideMap,
                onJammerTest = profilesViewModel::runJammerTest,
                onApplyJammer = profilesViewModel::applyJammerRecommendation,
                lastSpeedTestDetail = state.settings.lastSpeedTestDetail.ifBlank { null },
                speedTestBusy = state.busy,
                protocolLabel = null,
                preConnectIp = preConnectIp,
                reconnectCountdownLabel = reconnectCountdownLabel,
                protocolRecommendation = remember(context) {
                    val snap = com.quantumvpn.vpn.CarrierDetector.snapshot(context)
                    when {
                        snap.isCellular && snap.suggestsStrongBypass ->
                            "Рекомендуем: Hysteria2 или VLESS+Reality"
                        snap.isCellular ->
                            "Рекомендуем: VLESS+Reality / Hysteria"
                        else -> "Wi‑Fi: любой стабильный протокол (Reality / Hysteria)"
                    }
                },
            )
            AppTab.Servers -> ServersScreen(
                contentPadding = contentPadding,
                profiles = profilesSorted,
                activeProfile = profilesSorted.firstOrNull {
                    it.id == state.settings.activeProfileId
                } ?: state.profiles.firstOrNull {
                    it.id == state.settings.activeProfileId
                },
                selectorGroups = selectorGroups,
                profileSelectorGroups = state.homeSelectorGroups,
                vpnState = vpnState,
                profileStore = profileStore,
                onSelectProfile = profilesViewModel::selectProfile,
                onAddProfile = profilesViewModel::installManagedSubscription,
                onSelectServer = { groupTag, outboundTag ->
                    guardedSelectServer(groupTag, outboundTag)
                },
                onSelectOutboundLive = { profileId, groupTag, outboundTag ->
                    onSelectOutbound(profileId, groupTag, outboundTag)
                    profilesViewModel.recordRecentServer(profileId, groupTag, outboundTag)
                },
                onMeasureGroupLive = onMeasureGroup,
                sortByPing = state.settings.sortServersByPing,
                favoriteKeys = favoriteKeys,
                pinnedKeys = pinnedKeys,
                onToggleFavorite = profilesViewModel::toggleFavoriteServer,
                onTogglePin = profilesViewModel::togglePinnedServer,
                switchHistory = switchHistory,
                serverNotes = serverNotes,
                onSetServerNote = profilesViewModel::setServerNote,
                hideDeadDefault = state.settings.hideDeadServersDefault,
                autoPingOnOpen = state.settings.autoPingOnServersOpen,
                quarantinedKeys = quarantinedKeys,
                showCoachMark = CoachMarkScreen.Servers.name !in state.settings.dismissedCoachMarkScreens &&
                    !state.settings.coachMarksDismissed,
                onDismissCoachMark = { profilesViewModel.dismissCoachMark(CoachMarkScreen.Servers) },
                onRefreshSubscriptions = profilesViewModel::refreshAllSubscriptions,
                onRecordProbeFailure = profilesViewModel::recordServerProbeFailure,
                onRecordProbeSuccess = profilesViewModel::recordServerProbeSuccess,
                reliabilityScores = reliabilityScores,
                reliabilityEntries = reliabilityEntries,
                serverMode = state.settings.serverMode,
                compactActions = true,
            )
            AppTab.Statistics -> StatisticsScreen(
                contentPadding = contentPadding,
                sessionStats = sessionStats,
                vpnState = vpnState,
            )
            AppTab.Settings -> SettingsScreen(
                contentPadding = contentPadding,
                state = state,
                vpnState = vpnState,
                sessionStats = sessionStats,
                diagnostics = diagnostics,
                viewModel = profilesViewModel,
                routingState = routingState,
                routingViewModel = routingViewModel,
                onDiagnosticsSelected = onDiagnosticsSelected,
                onCreateDiagnosticShare = onCreateDiagnosticShare,
                onClearDnsCache = onClearDnsCache,
                updateState = updateState,
                onCheckUpdate = onCheckUpdate,
                onDownloadUpdate = onDownloadUpdate,
                onInstallUpdate = onInstallUpdate,
                onCancelUpdate = onCancelUpdate,
                showCoachMark = CoachMarkScreen.Settings.name !in state.settings.dismissedCoachMarkScreens &&
                    !state.settings.coachMarksDismissed,
                onDismissCoachMark = { profilesViewModel.dismissCoachMark(CoachMarkScreen.Settings) },
                showAppsCoachMark = CoachMarkScreen.Apps.name !in state.settings.dismissedCoachMarkScreens &&
                    !state.settings.coachMarksDismissed,
                onDismissAppsCoachMark = { profilesViewModel.dismissCoachMark(CoachMarkScreen.Apps) },
                initialDestination = pendingSettingsDestination,
                onInitialDestinationConsumed = { pendingSettingsDestination = null },
            )
        }
    }

    if (gridMenuOpen) {
        androidx.compose.material3.ModalBottomSheet(
            onDismissRequest = { gridMenuOpen = false },
            containerColor = CosmicTokens.Deep,
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp, vertical = 8.dp)
                    .padding(bottom = 28.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    "Меню",
                    color = CosmicTokens.OnVoid,
                    style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier.padding(bottom = 8.dp),
                )
                listOf(
                    AppTab.Servers to "Выбор сервера и пинг",
                    AppTab.Statistics to "Трафик и качество сети",
                    AppTab.Settings to "Настройки приложения",
                ).forEach { (tab, subtitle) ->
                    Surface(
                        onClick = {
                            gridMenuOpen = false
                            openTab(tab)
                        },
                        color = CosmicTokens.Card.copy(alpha = 0.9f),
                        shape = MaterialTheme.shapes.large,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Icon(tab.icon, contentDescription = null, tint = CosmicTokens.Orbit)
                            Column(modifier = Modifier.padding(start = 14.dp).weight(1f)) {
                                Text(tab.title, color = CosmicTokens.OnVoid, fontWeight = FontWeight.SemiBold)
                                Text(subtitle, color = CosmicTokens.OnVoidMuted, style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                }
            }
        }
    }
    }
}

@Composable
internal fun UpdateAvailableDialog(
    candidate: UpdateCandidate,
    onDownload: () -> Unit,
    onLater: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onLater,
        title = { Text("Доступно обновление ${candidate.metadata.versionName}") },
        text = {
            Column(
                modifier = Modifier
                    .heightIn(max = 360.dp)
                    .verticalScroll(rememberScrollState())
                    .testTag("update-release-notes"),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("Изменения", style = MaterialTheme.typography.titleMedium)
                ReleaseNotesMarkdown(
                    candidate.release.body.ifBlank {
                        "Автор релиза не добавил список изменений."
                    },
                )
            }
        },
        confirmButton = {
            Button(onClick = onDownload) { Text("Скачать") }
        },
        dismissButton = {
            TextButton(onClick = onLater) { Text("Позже") }
        },
        modifier = Modifier.testTag("update-available-dialog"),
    )
}

@Composable
internal fun UpdateDownloadingDialog(
    candidate: UpdateCandidate,
    downloadedBytes: Long,
    totalBytes: Long,
    onCancel: () -> Unit,
) {
    val progress = if (totalBytes > 0) {
        (downloadedBytes.toFloat() / totalBytes.toFloat()).coerceIn(0f, 1f)
    } else {
        0f
    }
    AlertDialog(
        onDismissRequest = {},
        title = { Text("Загрузка ${candidate.metadata.versionName}") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    candidate.release.title.ifBlank { "Обновление QuantumVPN" },
                    style = MaterialTheme.typography.bodyMedium,
                )
                androidx.compose.material3.LinearProgressIndicator(
                    progress = { progress },
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(
                    "${formatUpdateBytes(downloadedBytes)} / ${formatUpdateBytes(totalBytes)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onCancel) { Text("Отмена") }
        },
        modifier = Modifier.testTag("update-downloading-dialog"),
    )
}

@Composable
internal fun UpdateReadyDialog(
    candidate: UpdateCandidate,
    onInstall: () -> Unit,
    onLater: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onLater,
        title = { Text("Готово к установке ${candidate.metadata.versionName}") },
        text = {
            Column(
                modifier = Modifier
                    .heightIn(max = 360.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    "Обновление загружено и проверено. Android потребует подтверждение установки.",
                )
                ReleaseNotesMarkdown(
                    candidate.release.body.ifBlank {
                        "Автор релиза не добавил список изменений."
                    },
                )
            }
        },
        confirmButton = {
            Button(onClick = onInstall) { Text("Установить") }
        },
        dismissButton = {
            TextButton(onClick = onLater) { Text("Позже") }
        },
        modifier = Modifier.testTag("update-ready-dialog"),
    )
}

@Composable
private fun UpdateProgressNotice(title: String, body: String) {
    AlertDialog(
        onDismissRequest = {},
        title = { Text(title) },
        text = { Text(body) },
        confirmButton = {},
    )
}

private fun formatUpdateBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    if (bytes < 1024 * 1024) return "%.1f KB".format(bytes / 1024.0)
    return "%.1f MB".format(bytes / (1024.0 * 1024.0))
}

@Composable
private fun ProfilesScreen(
    contentPadding: PaddingValues,
    state: ProfilesUiState,
    viewModel: ProfilesViewModel,
) {
    var deleteTarget by remember { mutableStateOf<ProfileMetadata?>(null) }
    var renameTarget by remember { mutableStateOf<ProfileMetadata?>(null) }
    var urlDialogOpen by remember { mutableStateOf(false) }
    var cameraDenied by remember { mutableStateOf(false) }
    val context = LocalContext.current
    val fileLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let(viewModel::importDocument)
    }
    val qrLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.takeIf(String::isNotBlank)?.let(viewModel::importQr)
    }
    val launchQrScanner = {
        qrLauncher.launch(qrImportScanOptions())
    }
    val cameraPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) launchQrScanner() else cameraDenied = true
    }
    val requestQr = {
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED
        ) {
            launchQrScanner()
        } else {
            cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }
    val groups = remember(state.profiles) { profileGroups(state.profiles) }
    var refreshing by remember { mutableStateOf(false) }
    @OptIn(ExperimentalMaterial3Api::class)
    androidx.compose.material3.pulltorefresh.PullToRefreshBox(
        isRefreshing = refreshing,
        onRefresh = {
            refreshing = true
            viewModel.refreshAllSubscriptions()
            refreshing = false
        },
        modifier = Modifier.fillMaxSize(),
    ) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(contentPadding)
            .testTag("profiles-list"),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                com.quantumvpn.ui.components.QvHubHeader(
                    title = "Подписка QuantumVPN",
                    subtitle = "Серверы получаются через защищённый API",
                )
                ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        "Встроенная конфигурация",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(
                        "Конфигурация и серверы обновляются из защищённого API. " +
                            "Ручной импорт ссылок, файлов и QR-кодов отключён.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Button(
                        onClick = {
                            if (state.profiles.isEmpty()) {
                                viewModel.installManagedSubscription()
                            } else {
                                viewModel.refreshAllSubscriptions()
                            }
                        },
                        enabled = !state.busy,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(if (state.profiles.isEmpty()) "Получить конфигурацию" else "Обновить серверы")
                    }
                }
                }
            }
        }

        if (state.busy) {
            item {
                Box(
                    Modifier
                        .fillMaxWidth()
                        .semantics { contentDescription = "Операция с профилем выполняется" },
                    contentAlignment = Alignment.Center,
                ) {
                    CircularProgressIndicator()
                }
            }
        }

        if (state.profiles.isEmpty()) {
            item {
                Column(
                    modifier = Modifier.testTag("profiles-empty"),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        "Профилей пока нет",
                        style = MaterialTheme.typography.headlineSmall,
                        modifier = Modifier.semantics { heading() },
                    )
                    Text(
                        "Получите встроенную защищённую конфигурацию выше.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        } else {
            groups.forEach { group ->
                item(key = "group-${group.title}") {
                    Text(
                        "${group.title} · ${group.profiles.size}",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier
                            .padding(top = 4.dp)
                            .semantics { heading() },
                    )
                }
                items(group.profiles, key = ProfileMetadata::id) { profile ->
                    ProfileCard(
                        profile = profile,
                        active = profile.id == state.settings.activeProfileId,
                        enabled = !state.busy,
                        onSelect = { viewModel.selectProfile(profile.id) },
                        onRename = { renameTarget = profile },
                        onDelete = { deleteTarget = profile },
                        onRefresh = { viewModel.refreshSubscription(profile.id) },
                        refreshable = profile.id in state.refreshableProfileIds,
                    )
                }
            }
        }
    }
    }

    deleteTarget?.let { profile ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text("Удалить профиль?") },
            text = { Text("${profile.name} и его backup будут удалены безвозвратно.") },
            confirmButton = {
                TextButton(
                    onClick = {
                        viewModel.deleteProfile(profile.id)
                        deleteTarget = null
                    },
                ) { Text("Удалить") }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) { Text("Отмена") }
            },
        )
    }

    renameTarget?.let { profile ->
        RenameDialog(
            initialName = profile.name,
            onDismiss = { renameTarget = null },
            onRename = { name ->
                viewModel.renameProfile(profile.id, name)
                renameTarget = null
            },
        )
    }

    if (urlDialogOpen) {
        UrlImportDialog(
            onDismiss = { urlDialogOpen = false },
            onImport = { url ->
                urlDialogOpen = false
                viewModel.importUrl(url)
            },
        )
    }

    if (cameraDenied) {
        AlertDialog(
            onDismissRequest = { cameraDenied = false },
            title = { Text("Камера недоступна") },
            text = { Text("Разрешение камеры нужно только на время открытия QR-сканера.") },
            confirmButton = {
                TextButton(onClick = { cameraDenied = false }) { Text("Понятно") }
            },
        )
    }

    state.importPreview?.let { preview ->
        ImportPreviewDialog(
            preview = preview,
            busy = state.busy,
            onDismiss = viewModel::dismissImportPreview,
            onCreate = viewModel::confirmImport,
            onAppend = viewModel::confirmAppend,
            onRefresh = viewModel::confirmRefresh,
        )
    }

}

@Composable
private fun UrlImportDialog(
    onDismiss: () -> Unit,
    onImport: (String) -> Unit,
) {
    var url by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Импорт по URL") },
        text = {
            OutlinedTextField(
                value = url,
                onValueChange = { url = it.take(4096) },
                label = { Text("URL подписки или share-ссылка") },
                singleLine = true,
            )
        },
        confirmButton = {
            TextButton(onClick = { onImport(url) }, enabled = url.isNotBlank()) {
                Text("Загрузить preview")
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } },
    )
}

@Composable
private fun ImportPreviewDialog(
    preview: ImportPreviewState,
    busy: Boolean,
    onDismiss: () -> Unit,
    onCreate: (String) -> Unit,
    onAppend: (String) -> Unit,
    onRefresh: (Boolean) -> Unit,
) {
    var name by remember(preview) { mutableStateOf(preview.suggestedName) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (preview.isRefresh) "Обновление подписки" else "Предпросмотр импорта") },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(preview.sourceDescription, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(
                    if (preview.serverCount > 0) "Серверов: ${preview.serverCount}" else "Готовый sing-box JSON",
                )
                if (preview.serverLabels.isNotEmpty()) {
                    Text(
                        preview.serverLabels.joinToString(" • "),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (!preview.isRefresh) {
                    OutlinedTextField(
                        value = name,
                        onValueChange = { name = it.take(80) },
                        label = { Text("Название профиля") },
                        singleLine = true,
                    )
                }
                preview.activityWarning?.let {
                    Text(it, color = MaterialTheme.colorScheme.error)
                }
                if (preview.selectionChanged) {
                    Text(
                        "Текущий server tag исчез: будет выбран первый доступный сервер.",
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                if (preview.activeRefresh) {
                    Text(
                        "Профиль сейчас подключён. Перезапуск возможен только отдельным подтверждением ниже.",
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
                if (!preview.isRefresh && preview.isSingleManaged && preview.appendTargets.isNotEmpty()) {
                    HorizontalDivider()
                    Text("Или добавить сервер в managed-группу:")
                    preview.appendTargets.take(4).forEach { profile ->
                        TextButton(onClick = { onAppend(profile.id) }, enabled = !busy) {
                            Text(profile.name)
                        }
                    }
                }
            }
        },
        confirmButton = {
            if (preview.isRefresh) {
                Column(horizontalAlignment = Alignment.End) {
                    if (preview.activeRefresh) {
                        TextButton(onClick = { onRefresh(true) }, enabled = !busy) {
                            Text("Сохранить и переподключить")
                        }
                    }
                    TextButton(onClick = { onRefresh(false) }, enabled = !busy) {
                        Text(if (preview.activeRefresh) "Сохранить без перезапуска" else "Обновить")
                    }
                }
            } else {
                TextButton(onClick = { onCreate(name) }, enabled = name.isNotBlank() && !busy) {
                    Text("Новый профиль")
                }
            }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !busy) { Text("Отмена") } },
    )
}

@Composable
private fun ProfileCard(
    profile: ProfileMetadata,
    active: Boolean,
    enabled: Boolean,
    onSelect: () -> Unit,
    onRename: () -> Unit,
    onDelete: () -> Unit,
    onRefresh: () -> Unit,
    refreshable: Boolean,
) {
    val updatedAt = remember(profile.updatedAtEpochMillis) {
        DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
            .format(Date(profile.updatedAtEpochMillis))
    }
    ElevatedCard(
        modifier = Modifier
            .fillMaxWidth()
            .semantics {
                contentDescription = buildString {
                    append(profile.name)
                    append(". Источник: ")
                    append(profile.source.displayName())
                    append(". Обновлено: ")
                    append(updatedAt)
                    if (active) append(". Активный профиль")
                }
            },
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(profile.name, fontWeight = FontWeight.SemiBold)
                    Text(
                        profile.source.displayName(),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        "Обновлено: $updatedAt",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (active) Text("Активен", color = MaterialTheme.colorScheme.primary)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                if (!active) {
                    TextButton(onClick = onSelect, enabled = enabled) { Text("Выбрать") }
                }
                TextButton(onClick = onRename, enabled = enabled) { Text("Имя") }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                if (refreshable) {
                    TextButton(onClick = onRefresh, enabled = enabled) { Text("Обновить") }
                }
                TextButton(onClick = onDelete, enabled = enabled) { Text("Удалить") }
            }
        }
    }
}

private data class ProfileGroup(
    val title: String,
    val profiles: List<ProfileMetadata>,
)

private fun profileGroups(profiles: List<ProfileMetadata>): List<ProfileGroup> {
    val subscriptions = profiles.filter { it.source in setOf(ProfileSource.Url, ProfileSource.Subscription) }
    val imported = profiles.filter { it.source in setOf(ProfileSource.Clipboard, ProfileSource.Link, ProfileSource.Qr) }
    val files = profiles.filter { it.source in setOf(ProfileSource.File, ProfileSource.RawJson) }
    return listOf(
        ProfileGroup("Подписки", subscriptions),
        ProfileGroup("Импортированные", imported),
        ProfileGroup("Файлы и JSON", files),
    ).filter { it.profiles.isNotEmpty() }
}

private fun ProfileSource.displayName(): String = when (this) {
    ProfileSource.RawJson -> "JSON"
    ProfileSource.File -> "Системный файл"
    ProfileSource.Clipboard -> "Буфер обмена"
    ProfileSource.Link -> "Ссылка"
    ProfileSource.Qr -> "QR-код"
    ProfileSource.Url -> "URL-подписка"
    ProfileSource.Subscription -> "Подписка"
}

@Composable
private fun RenameDialog(
    initialName: String,
    onDismiss: () -> Unit,
    onRename: (String) -> Unit,
) {
    var name by remember(initialName) { mutableStateOf(initialName) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Переименовать") },
        text = {
            OutlinedTextField(
                value = name,
                onValueChange = { name = it.take(80) },
                label = { Text("Название") },
                singleLine = true,
            )
        },
        confirmButton = {
            TextButton(onClick = { onRename(name) }, enabled = name.isNotBlank()) {
                Text("Сохранить")
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } },
    )
}
