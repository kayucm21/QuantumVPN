package com.quantumvpn

import android.content.Context
import com.quantumvpn.config.LibboxConfigValidator
import com.quantumvpn.updates.PanelFirstUpdateSource
import com.quantumvpn.updates.PanelUpdateSource
import com.quantumvpn.diagnostics.DiagnosticExporter
import com.quantumvpn.diagnostics.AppCrashStore
import com.quantumvpn.vpn.BootstrapCache
import com.quantumvpn.vpn.BootstrapResolver
import com.quantumvpn.importer.AndroidImportReader
import com.quantumvpn.importer.HttpSubscriptionFetcher
import com.quantumvpn.importer.SubscriptionSourceStore
import com.quantumvpn.policy.ClientPolicyRepository
import com.quantumvpn.diagnostics.EventJournalStore
import com.quantumvpn.diagnostics.ExitIpTimelineStore
import com.quantumvpn.diagnostics.ConnectDurationStore
import com.quantumvpn.diagnostics.DisconnectReasonStore
import com.quantumvpn.diagnostics.SessionTrafficHistoryStore
import com.quantumvpn.diagnostics.ReliabilityReportStore
import com.quantumvpn.diagnostics.SettingsAuditStore
import com.quantumvpn.diagnostics.SpeedTestHistoryStore
import com.quantumvpn.importer.SubscriptionSourceHealthStore
import com.quantumvpn.importer.SubscriptionQuotaStore
import com.quantumvpn.vpn.FavoriteServersStore
import com.quantumvpn.vpn.PinnedServersStore
import com.quantumvpn.vpn.RecentServersStore
import com.quantumvpn.vpn.SessionSwitchHistoryStore
import com.quantumvpn.vpn.WifiAutoConnectCoordinator
import com.quantumvpn.vpn.DeadServerQuarantineStore
import com.quantumvpn.vpn.ServerReliabilityStore
import com.quantumvpn.vpn.VpnScheduleAlarms
import com.quantumvpn.vpn.VpnScheduleCoordinator
import com.quantumvpn.profiles.LastKnownGoodStore
import com.quantumvpn.profiles.ProfileBackupExporter
import com.quantumvpn.profiles.ProfileBackupImporter
import com.quantumvpn.profiles.ProfileStore
import com.quantumvpn.profiles.ProfilesViewModel
import com.quantumvpn.routing.RuleSetAssetManager
import com.quantumvpn.routing.HappRoutingProfileStore
import com.quantumvpn.routing.RoutingViewModel
import com.quantumvpn.ui.UiSettingsStore
import com.quantumvpn.updates.UpdateController
import com.quantumvpn.updates.AppUpdateVpnFallback
import com.quantumvpn.updates.AndroidUpdateInstallIntentFactory
import com.quantumvpn.updates.FtpAwareHttpClient
import com.quantumvpn.updates.FtpUpdateSource
import com.quantumvpn.updates.GitHubUpdateSource
import com.quantumvpn.updates.PreferFtpThenGitHubSource
import com.quantumvpn.vpn.AndroidPackageAvailability
import com.quantumvpn.vpn.AppCatalog
import com.quantumvpn.vpn.AppSelectionStore
import com.quantumvpn.vpn.GameModeStore
import com.quantumvpn.vpn.AppsViewModel
import com.quantumvpn.vpn.NamedAppSetsStore
import com.quantumvpn.vpn.ServerNotesStore
import com.quantumvpn.vpn.LibboxRuntime
import com.quantumvpn.vpn.IcmpPingProbe
import com.quantumvpn.vpn.VpnAppScopePreflight
import com.quantumvpn.vpn.VpnController
import com.quantumvpn.vpn.ProxyBootstrapper
import com.quantumvpn.vpn.VpnExternalIpProbe
import com.quantumvpn.vpn.VpnHealthPipeline
import com.quantumvpn.vpn.VpnNetworkProvider
import com.quantumvpn.security.KillSwitch
import com.quantumvpn.security.BiometricAuth
import com.quantumvpn.scheduling.VpnScheduler
import com.quantumvpn.recovery.AutoReconnect
import com.quantumvpn.state.LastConnectionState
import com.quantumvpn.protection.OperatorBypassProtection
import androidx.datastore.preferences.preferencesDataStore
import com.quantumvpn.notifications.VpnNotificationManager
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob

private val Context.dataStore by preferencesDataStore(name = "settings")

class AppContainer(
    context: Context,
    val appCrashStore: AppCrashStore,
) {
    val appContext: Context = context.applicationContext
    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    val clientPolicyRepository = ClientPolicyRepository(appContext = appContext, scope = appScope)
    val libboxRuntime = LibboxRuntime(appContext)
    val configValidator = LibboxConfigValidator()
    val profileStore = ProfileStore(
        root = File(appContext.filesDir, "profiles"),
        validator = configValidator,
    )
    val uiSettingsStore = UiSettingsStore(appContext)
    val importReader = AndroidImportReader(appContext)
    val subscriptionFetcher = HttpSubscriptionFetcher(
        deviceSerialProvider = {
            ClientPolicyRepository.resolveAndroidId(appContext)
        },
    )
    val subscriptionSourceStore = SubscriptionSourceStore(
        File(appContext.noBackupFilesDir, "subscriptions"),
    )
    val happRoutingProfileStore = HappRoutingProfileStore(
        File(appContext.noBackupFilesDir, "happ-routing"),
    )
    val olcrtcEngineStore = com.quantumvpn.olcrtc.OlcrtcEngineStore(
        File(appContext.noBackupFilesDir, "olcrtc-engines"),
    )
    val bootstrapCache = BootstrapCache(File(appContext.noBackupFilesDir, "network"))
    val appSelectionStore = AppSelectionStore(appContext)
    val gameModeStore = GameModeStore(appContext)
    val namedAppSetsStore = NamedAppSetsStore(appContext)
    val appCatalog = AppCatalog(appContext)
    val vpnAppScopePreflight = VpnAppScopePreflight(
        ownPackageName = appContext.packageName,
        packageAvailability = AndroidPackageAvailability(appContext.packageManager),
    )
    val vpnController = VpnController(appContext, appCrashStore.read())
    val diagnosticExporter = DiagnosticExporter(
        context = appContext,
        settingsStore = uiSettingsStore,
        vpnController = vpnController,
        crashStore = appCrashStore,
    ).also(DiagnosticExporter::cleanupStaleFiles)
    private val ftpUpdateSource = if (BuildConfig.FTP_UPDATES_ENABLED) {
        FtpUpdateSource(
            host = BuildConfig.FTP_UPDATE_HOST,
            username = BuildConfig.FTP_UPDATE_USER,
            password = BuildConfig.FTP_UPDATE_PASSWORD,
            remoteDir = BuildConfig.FTP_UPDATE_DIR,
            applicationId = appContext.packageName,
        )
    } else {
        null
    }
    // RosPanel-backed auto-update: the operator publishes a release on the panel and the
    // app pulls it. Falls back to the existing FTP/GitHub composite when the panel has no
    // release published (or is unreachable).
    val panelUpdateSource = if (BuildConfig.PANEL_UPDATE_BASE_URL.isNotBlank()) {
        PanelUpdateSource(
            baseUrl = BuildConfig.PANEL_UPDATE_BASE_URL,
            applicationId = appContext.packageName,
            currentVersionName = BuildConfig.VERSION_NAME,
            currentVersionCode = BuildConfig.VERSION_CODE.toLong(),
            deviceId = ClientPolicyRepository.resolveAndroidId(appContext),
        )
    } else {
        null
    }
    val compositeSource = PreferFtpThenGitHubSource(
        ftp = ftpUpdateSource,
        github = GitHubUpdateSource(BuildConfig.UPDATE_REPOSITORY, appContext.packageName),
    )
    // In-app / FTP updates disabled — APKs are distributed manually.
    val updateController = UpdateController(
        context = appContext,
        repository = BuildConfig.UPDATE_REPOSITORY,
        currentVersionName = BuildConfig.VERSION_NAME,
        currentVersionCode = BuildConfig.VERSION_CODE.toLong(),
        source = PanelFirstUpdateSource(panelUpdateSource, compositeSource),
        http = com.quantumvpn.updates.PanelHttpsClient(),
        vpnFallback = AppUpdateVpnFallback(appContext, uiSettingsStore, vpnController),
        installIntentFactory = AndroidUpdateInstallIntentFactory(appContext),
    )
    val recentServersStore = RecentServersStore(appContext)
    val favoriteServersStore = FavoriteServersStore(appContext)
    val pinnedServersStore = PinnedServersStore(appContext)
    val reliabilityReportStore = ReliabilityReportStore(appContext)
    val deadServerQuarantineStore = DeadServerQuarantineStore(appContext)
    val serverReliabilityStore = ServerReliabilityStore(appContext)
    val lastKnownGoodStore = LastKnownGoodStore(appContext)
    val subscriptionSourceHealthStore = SubscriptionSourceHealthStore(appContext)
    val exitIpTimelineStore = ExitIpTimelineStore(appContext)
    val eventJournalStore = EventJournalStore(appContext)
    val disconnectReasonStore = DisconnectReasonStore(appContext)
    val sessionSwitchHistoryStore = SessionSwitchHistoryStore(appContext)
    val subscriptionQuotaStore = SubscriptionQuotaStore(appContext)
    val speedTestHistoryStore = SpeedTestHistoryStore(appContext)
    val connectDurationStore = ConnectDurationStore(appContext)
    val serverNotesStore = ServerNotesStore(appContext)
    val sessionTrafficHistoryStore = SessionTrafficHistoryStore(appContext)
    val settingsAuditStore = SettingsAuditStore(appContext)
    val profileBackupExporter = ProfileBackupExporter(
        context = appContext,
        profileStore = profileStore,
        subscriptionSourceStore = subscriptionSourceStore,
    )
    val profileBackupImporter = ProfileBackupImporter(
        context = appContext,
        profileStore = profileStore,
        subscriptionSourceStore = subscriptionSourceStore,
    )
    val wifiAutoConnect = WifiAutoConnectCoordinator(
        context = appContext,
        settingsStore = uiSettingsStore,
        vpnController = vpnController,
        eventJournal = eventJournalStore,
    )
    val vpnSchedule = VpnScheduleCoordinator(
        context = appContext,
        settingsStore = uiSettingsStore,
        vpnController = vpnController,
        eventJournal = eventJournalStore,
    )
    val ruleSetAssetManager = RuleSetAssetManager(appContext)
    val proxyBootstrapper = ProxyBootstrapper(BootstrapResolver(), bootstrapCache)
    private val vpnNetworkProvider = VpnNetworkProvider(appContext)
    val vpnHealthPipeline = VpnHealthPipeline(vpnNetworkProvider)
    val vpnExternalIpProbe = VpnExternalIpProbe(vpnNetworkProvider)
    val icmpPingProbe = IcmpPingProbe()
    
    // Новые компоненты v5.0.0
    val killSwitch = KillSwitch(appContext, appContext.dataStore)
    val biometricAuth = BiometricAuth(appContext, appContext.dataStore)
    val vpnScheduler = VpnScheduler(appContext, appContext.dataStore)
    val autoReconnect = AutoReconnect(appContext, appContext.dataStore)
    val lastConnectionState = LastConnectionState(appContext, appContext.dataStore)
    val operatorBypassProtection = OperatorBypassProtection(appContext, appContext.dataStore)
    val notificationManager = VpnNotificationManager(appContext, appContext.dataStore)

    val profilesViewModelFactory: ProfilesViewModel.Factory
        get() = ProfilesViewModel.Factory(
            profileStore,
            uiSettingsStore,
            configValidator,
            importReader,
            subscriptionFetcher,
            subscriptionSourceStore,
            vpnController,
            bootstrapCache,
            ruleSetAssetManager,
            happRoutingProfileStore,
            olcrtcEngineStore,
            recentServersStore,
            favoriteServersStore,
            pinnedServersStore,
            profileBackupImporter,
            eventJournalStore,
            sessionSwitchHistoryStore,
            subscriptionQuotaStore,
            disconnectReasonStore,
            speedTestHistoryStore,
            connectDurationStore,
            serverNotesStore,
            sessionTrafficHistoryStore,
            settingsAuditStore,
            reliabilityReportStore,
            deadServerQuarantineStore,
            serverReliabilityStore,
            lastKnownGoodStore,
            subscriptionSourceHealthStore,
            importClipboardClear = { importReader.clearClipboardSafely() },
        )

    val appsViewModelFactory: AppsViewModel.Factory
        get() = AppsViewModel.Factory(
            appSelectionStore,
            appCatalog,
            namedAppSetsStore,
            gameModeStore,
            vpnController,
        )

    val routingViewModelFactory: RoutingViewModel.Factory
        get() = RoutingViewModel.Factory(
            profileStore,
            uiSettingsStore,
            ruleSetAssetManager,
            vpnController,
            happRoutingProfileStore,
        )
}
