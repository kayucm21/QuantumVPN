package com.quantumvpn

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.content.ActivityNotFoundException
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.provider.Settings
import android.os.Build
import android.os.Bundle
import androidx.fragment.app.FragmentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import android.view.WindowManager
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.LaunchedEffect
import androidx.core.content.ContextCompat
import androidx.core.content.IntentCompat
import androidx.core.net.toUri
import com.quantumvpn.profiles.ProfilesViewModel
import com.quantumvpn.routing.RoutingViewModel
import com.quantumvpn.ui.QuantumVpnApp
import com.quantumvpn.ui.StartupSplashScreen
import com.quantumvpn.ui.ThemeMode
import com.quantumvpn.ui.theme.QuantumVpnTheme
import com.quantumvpn.updates.UpdateChannel
import com.quantumvpn.vpn.VpnBatteryExemption
import com.quantumvpn.vpn.VpnConnectionState
import com.quantumvpn.vpn.VpnController
import com.quantumvpn.vpn.VpnScheduleAlarms
import com.quantumvpn.widget.VpnToggleWidget
import com.quantumvpn.widget.VpnWideWidget
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

class MainActivity : FragmentActivity() {
    companion object {
        const val SHORTCUT_EXTRA = "com.quantumvpn.shortcut"
    }

    private val vpnController: VpnController
        get() = (application as QuantumVpnApplication).container.vpnController
    private var pendingProfileId: String? = null
    private var activityStarted = false
    private var homeSelected = false
    private var diagnosticsSelected = false
    private var pendingUpdateInstall = false
    private var pendingShortcut by mutableStateOf<String?>(null)
    private var lastSubscriptionRefreshMs = 0L
    private val updateController
        get() = (application as QuantumVpnApplication).container.updateController
    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val profileId = pendingProfileId
        pendingProfileId = null
        if (result.resultCode == Activity.RESULT_OK && profileId != null) {
            vpnController.start(profileId)
            maybeRequestBatteryExemption()
        } else {
            vpnController.publishMessage("Android не выдал разрешение VPN.")
        }
    }
    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) {
        continueVpnPermissionRequest()
    }
    private val updateInstallerLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        updateController.onInstallerFinished(result.resultCode == Activity.RESULT_OK)
    }
    private val unknownSourceLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) {
        val shouldContinue = pendingUpdateInstall
        pendingUpdateInstall = false
        if (shouldContinue && canRequestPackageInstalls()) {
            launchUpdateInstaller()
        } else if (shouldContinue) {
            updateController.failInstallation("Android не разрешил установку из этого источника.")
        }
    }
    private val profilesViewModel: ProfilesViewModel by viewModels {
        (application as QuantumVpnApplication).container.profilesViewModelFactory
    }
    private val routingViewModel: RoutingViewModel by viewModels {
        (application as QuantumVpnApplication).container.routingViewModelFactory
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        setContent {
            val state by profilesViewModel.state.collectAsState()
            val vpnState by vpnController.state.collectAsState()
            val selectorGroups by vpnController.selectorGroups.collectAsState()
            val sessionStats by vpnController.sessionStats.collectAsState()
            val diagnostics by vpnController.diagnostics.collectAsState()
            val routingState by routingViewModel.state.collectAsState()
            val vpnMessage by vpnController.message.collectAsState()
            val updateState by updateController.state.collectAsState()
            val systemDark = isSystemInDarkTheme()
            LaunchedEffect(
                state.settings.scheduleNightAutoConnect,
                state.settings.scheduleMorningDisconnect,
                state.settings.subscriptionRefreshHours,
            ) {
                VpnScheduleAlarms.reschedule(this@MainActivity)
                com.quantumvpn.vpn.SubscriptionRefreshAlarms.reschedule(this@MainActivity)
            }
            LaunchedEffect(vpnState) {
                VpnToggleWidget.requestUpdate(this@MainActivity)
                VpnWideWidget.requestUpdate(this@MainActivity)
            }
            LaunchedEffect(Unit) {
                // При старте приложения сразу выставляем Maximum + AdGuard + Safe mode off.
                profilesViewModel.prepareAdBlockBeforeConnect(
                    context = this@MainActivity,
                    openPrivateDnsSettingsIfStrict = false,
                )
            }
            var startupServersChecked by remember { mutableStateOf(false) }
            LaunchedEffect(state.initialized, state.profiles.size) {
                if (state.initialized && state.profiles.isEmpty() && state.importPreview == null) {
                    profilesViewModel.installManagedSubscription()
                }
            }
            LaunchedEffect(state.importPreview?.sourceUrl, state.importPreview?.isRefresh) {
                val preview = state.importPreview
                if (preview != null && !preview.isRefresh &&
                    preview.sourceUrl == com.quantumvpn.profiles.ManagedSubscriptionEndpoint.url
                ) {
                    profilesViewModel.confirmImport(preview.suggestedName)
                }
            }
            LaunchedEffect(state.homeSelectorGroups) {
                if (state.homeSelectorGroups.any { it.items.isNotEmpty() }) startupServersChecked = true
            }
            LaunchedEffect(Unit) {
                kotlinx.coroutines.delay(15_000)
                startupServersChecked = true
            }
            var splashDone by remember { mutableStateOf(false) }
            LaunchedEffect(splashDone) {
                if (splashDone) {
                    kotlinx.coroutines.delay(750)
                    updateController.checkOnce(UpdateChannel.Stable, autoDownload = false)
                }
            }
            val darkTheme = if (!splashDone) {
                true
            } else {
                when (state.settings.themeMode) {
                    ThemeMode.System -> systemDark
                    ThemeMode.Light -> false
                    ThemeMode.Dark -> true
                }
            }
            SideEffect {
                val systemBarStyle = if (darkTheme) {
                    SystemBarStyle.dark(Color.TRANSPARENT)
                } else {
                    SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT)
                }
                enableEdgeToEdge(
                    statusBarStyle = systemBarStyle,
                    navigationBarStyle = systemBarStyle,
                )
            }
            QuantumVpnTheme(
                darkTheme = darkTheme,
                oledBlack = state.settings.oledBlack,
                accent = state.settings.accentColor,
                largeText = state.settings.largeText,
                highContrast = state.settings.highContrast,
                dynamicColor = state.settings.useDynamicColor,
            ) {
                LaunchedEffect(state.settings.flagSecure) {
                    if (state.settings.flagSecure) {
                        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    } else {
                        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    }
                }
                var previousVpn by remember { mutableStateOf<VpnConnectionState?>(null) }
                LaunchedEffect(vpnState, state.settings.connectSoundEnabled, state.settings.quietMode) {
                    val prev = previousVpn
                    previousVpn = vpnState
                    if (!state.settings.connectSoundEnabled || state.settings.quietMode || prev == null) {
                        return@LaunchedEffect
                    }
                    val tone = when {
                        vpnState is VpnConnectionState.Connected &&
                            prev !is VpnConnectionState.Connected ->
                            android.media.ToneGenerator.TONE_PROP_ACK
                        vpnState is VpnConnectionState.Stopped &&
                            prev is VpnConnectionState.Connected ->
                            android.media.ToneGenerator.TONE_PROP_NACK
                        vpnState is VpnConnectionState.Error ->
                            android.media.ToneGenerator.TONE_CDMA_ALERT_CALL_GUARD
                        else -> return@LaunchedEffect
                    }
                    runCatching {
                        val gen = android.media.ToneGenerator(
                            android.media.AudioManager.STREAM_NOTIFICATION,
                            60,
                        )
                        gen.startTone(tone, 160)
                        kotlinx.coroutines.delay(200)
                        gen.release()
                    }
                }
                LaunchedEffect(vpnState, state.settings.keepScreenOnWhileConnecting) {
                    val keep = state.settings.keepScreenOnWhileConnecting &&
                        vpnState is VpnConnectionState.Starting
                    if (keep) {
                        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                    } else {
                        window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                    }
                }
                if (!splashDone) {
                    StartupSplashScreen(
                        ready = state.initialized && startupServersChecked,
                        updateState = updateState,
                        availableServers = state.homeSelectorGroups.sumOf { it.items.size },
                        onFinished = { splashDone = true },
                    )
                } else {
                    QuantumVpnApp(
                        profilesViewModel = profilesViewModel,
                        state = state,
                        profileStore = (application as QuantumVpnApplication).container.profileStore,
                        routingViewModel = routingViewModel,
                        routingState = routingState,
                        vpnState = vpnState,
                        selectorGroups = selectorGroups,
                        sessionStats = sessionStats,
                        diagnostics = diagnostics,
                        vpnMessage = vpnMessage,
                        onVpnMessageConsumed = vpnController::consumeMessage,
                        onVpnStart = ::requestVpnStart,
                        onVpnStop = vpnController::stop,
                        onHardReconnect = {
                            vpnController.restartIfConnected("Жёсткий reconnect из Home")
                        },
                        onSelectOutbound = vpnController::selectOutbound,
                        onMeasurePing = vpnController::measurePing,
                        onMeasureGroup = vpnController::measureGroup,
                        onHomeSelected = ::setHomeSelected,
                        onDiagnosticsSelected = ::setDiagnosticsSelected,
                        onCreateDiagnosticShare = {
                            (application as QuantumVpnApplication).container.diagnosticExporter.createShareIntent()
                        },
                        onClearDnsCache = vpnController::clearDnsCache,
                        updateState = updateState,
                        onCheckUpdate = { channel -> updateController.check(channel) },
                        onDownloadUpdate = updateController::download,
                        onInstallUpdate = ::requestUpdateInstall,
                        onCancelUpdate = updateController::cancelAndDelete,
                        initialShortcut = pendingShortcut,
                        onShortcutConsumed = { pendingShortcut = null },
                    )
                }
            }
        }
        if (savedInstanceState == null) {
            handleExternalImport(intent)
            handleWidgetToggle(intent)
            handleShortcut(intent)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleExternalImport(intent)
        handleWidgetToggle(intent)
        handleShortcut(intent)
    }

    override fun onStart() {
        super.onStart()
        activityStarted = true
        updateVisibleStreams()
    }

    override fun onResume() {
        super.onResume()
        val now = System.currentTimeMillis()
        // Тихо обновляем подписки каждый раз при открытии приложения
        // (с защитой от частых resume при кратковременном фоне).
        if (now - lastSubscriptionRefreshMs > 20_000L) {
            lastSubscriptionRefreshMs = now
            profilesViewModel.refreshAllSubscriptionsQuietly(silent = true)
        }
    }

    override fun onStop() {
        activityStarted = false
        updateVisibleStreams()
        super.onStop()
    }

    private fun setHomeSelected(selected: Boolean) {
        homeSelected = selected
        updateVisibleStreams()
    }

    private fun setDiagnosticsSelected(selected: Boolean) {
        diagnosticsSelected = selected
        updateVisibleStreams()
    }

    private fun updateVisibleStreams() {
        vpnController.setHomeVisible(activityStarted && homeSelected)
        vpnController.setDiagnosticsVisible(activityStarted && diagnosticsSelected)
    }

    private fun handleExternalImport(intent: Intent) {
        if (intent.action == Intent.ACTION_SEND && intent.type == "text/plain") {
            val uri = intent.externalImportUri()
            val text = intent.getStringExtra(Intent.EXTRA_TEXT)
            if (uri == null && !text.isNullOrBlank()) {
                routingViewModel.addDomainRuleFromShare(text)
                intent.removeExtra(Intent.EXTRA_TEXT)
                return
            }
        }
        val uri = intent.externalImportUri() ?: return
        profilesViewModel.importDocument(uri)
    }

    private fun handleWidgetToggle(intent: Intent) {
        if (!intent.getBooleanExtra(VpnToggleWidget.EXTRA_WIDGET_TOGGLE, false)) return
        intent.removeExtra(VpnToggleWidget.EXTRA_WIDGET_TOGGLE)
        when (vpnController.state.value) {
            is VpnConnectionState.Connected,
            is VpnConnectionState.Starting,
            -> vpnController.stop()
            is VpnConnectionState.Stopping -> Unit
            else -> {
                val profileId = profilesViewModel.state.value.settings.activeProfileId
                if (profileId != null) {
                    requestVpnStart(profileId)
                } else {
                    vpnController.publishMessage("Сначала выберите профиль на главном экране.")
                }
            }
        }
    }

    private fun handleShortcut(intent: Intent) {
        if (intent.action == "android.service.quicksettings.action.QS_TILE_PREFERENCES") {
            pendingShortcut = "servers"
            return
        }
        val action = intent.getStringExtra(SHORTCUT_EXTRA) ?: return
        intent.removeExtra(SHORTCUT_EXTRA)
        pendingShortcut = action
    }

    private fun requestVpnStart(profileId: String) {
        pendingProfileId = profileId
        lifecycleScope.launch {
            val preflight = profilesViewModel.prepareAdBlockBeforeConnect(
                context = this@MainActivity,
                openPrivateDnsSettingsIfStrict = true,
            )
            if (preflight.openedPrivateDnsSettings && !preflight.privateDnsFixed) {
                vpnController.publishMessage(
                    "Private DNS Strict мешает блокировке рекламы. " +
                        "Поставьте «Автоматически» или «Выкл.» и снова нажмите Подключить.",
                )
                // Не стартуем VPN, пока пользователь не сменит Private DNS.
                pendingProfileId = null
                return@launch
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                ContextCompat.checkSelfPermission(
                    this@MainActivity,
                    Manifest.permission.POST_NOTIFICATIONS,
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            } else {
                continueVpnPermissionRequest()
            }
        }
    }

    private fun continueVpnPermissionRequest() {
        val profileId = pendingProfileId ?: return
        val permissionIntent = vpnController.permissionIntent()
        if (permissionIntent == null) {
            pendingProfileId = null
            vpnController.start(profileId)
            maybeRequestBatteryExemption()
        } else {
            vpnPermissionLauncher.launch(permissionIntent)
        }
    }

    private fun maybeRequestBatteryExemption() {
        val intent = VpnBatteryExemption.requestIntent(this) ?: return
        runCatching { startActivity(intent) }
    }

    private fun requestUpdateInstall() {
        if (!canRequestPackageInstalls()) {
            pendingUpdateInstall = true
            try {
                unknownSourceLauncher.launch(
                    Intent(
                        Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                        "package:$packageName".toUri(),
                    ),
                )
            } catch (_: ActivityNotFoundException) {
                pendingUpdateInstall = false
                updateController.failInstallation("Android не открыл настройку установки из источника.")
            } catch (_: SecurityException) {
                pendingUpdateInstall = false
                updateController.failInstallation("Android запретил открыть настройку установки.")
            }
            return
        }
        launchUpdateInstaller()
    }

    private fun canRequestPackageInstalls(): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.O || packageManager.canRequestPackageInstalls()

    private fun launchUpdateInstaller() {
        try {
            updateInstallerLauncher.launch(updateController.createInstallIntent())
        } catch (_: ActivityNotFoundException) {
            updateController.failInstallation("Системный установщик APK не найден.")
        } catch (_: SecurityException) {
            updateController.failInstallation("Android запретил запуск системной установки.")
        } catch (error: Exception) {
            updateController.failInstallation(error.message ?: "Не удалось открыть системную установку.")
        }
    }
}

private fun Intent.externalImportUri(): Uri? {
    if (action != Intent.ACTION_VIEW && action != Intent.ACTION_SEND) return null
    val streamUri = IntentCompat.getParcelableExtra(this, Intent.EXTRA_STREAM, Uri::class.java)
    val clipUri = clipData
        ?.takeIf { it.itemCount == 1 }
        ?.getItemAt(0)
        ?.uri
    val uri = if (action == Intent.ACTION_VIEW) {
        data ?: streamUri ?: clipUri
    } else {
        streamUri ?: clipUri ?: data
    }
    return uri?.takeIf { it.scheme in setOf("content", "file", "android.resource") }
}
