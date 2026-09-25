package com.quantumvpn.ui

import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Build
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import com.quantumvpn.routing.RoutingUiState
import com.quantumvpn.routing.RoutingViewModel
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import com.quantumvpn.vpn.AppsViewModel
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import com.quantumvpn.BuildConfig
import com.quantumvpn.QuantumVpnApplication
import com.quantumvpn.config.DnsMode
import com.quantumvpn.config.DnsOverride
import com.quantumvpn.diagnostics.DiagnosticAttemptOutcome
import com.quantumvpn.diagnostics.DiagnosticState
import com.quantumvpn.diagnostics.DiagnosticStageStatus
import com.quantumvpn.diagnostics.DiagnosticStopOutcome
import com.quantumvpn.diagnostics.LeakChecker
import com.quantumvpn.diagnostics.MemoryUsageProbe
import com.quantumvpn.diagnostics.WhySlowDiagnoser
import com.quantumvpn.hardening.TunMtuMode
import com.quantumvpn.profiles.ProfilesUiState
import com.quantumvpn.profiles.ProfilesViewModel
import com.quantumvpn.updates.UpdateChannel
import com.quantumvpn.updates.UpdateOperation
import com.quantumvpn.updates.UpdateState
import com.quantumvpn.vpn.VpnConnectionState
import com.quantumvpn.vpn.VpnSessionStats
import com.quantumvpn.vpn.WifiSsidReader
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import android.Manifest
import android.provider.Settings as AndroidSettings

enum class SettingsDestination {
    Main,
    Connection,
    Network,
    Appearance,
    Privacy,
    Schedule,
    VpnHiding,
    CarrierBypass,
    Diagnostics,
    Apps,
    Journal,
    Changelog,
    Faq,
    RouteSim,
    Checklist,
    Developer,
    ThreatModel,
    PrivacyPromise,
    ErrorGlossary,
    OemQuirks,
    A11yStatement,
    AuditLog,
    About,
    Updates,
    OperatorHelp,
    Backlog,
    HealthDashboard,
    SystemWizards,
        AdBlock,
        Routing,
    }

@Composable
fun SettingsScreen(
    contentPadding: PaddingValues,
    state: ProfilesUiState,
    vpnState: VpnConnectionState,
    sessionStats: VpnSessionStats = VpnSessionStats(),
    diagnostics: DiagnosticState,
        viewModel: ProfilesViewModel,
        routingState: RoutingUiState,
        routingViewModel: RoutingViewModel,
        onDiagnosticsSelected: (Boolean) -> Unit,
    onCreateDiagnosticShare: suspend () -> Intent,
    onClearDnsCache: () -> Unit,
    updateState: UpdateState,
    onCheckUpdate: (UpdateChannel) -> Unit,
    onDownloadUpdate: () -> Unit,
    onInstallUpdate: () -> Unit,
    onCancelUpdate: () -> Unit,
    showCoachMark: Boolean = false,
    onDismissCoachMark: () -> Unit = {},
    showAppsCoachMark: Boolean = false,
    onDismissAppsCoachMark: () -> Unit = {},
    initialDestination: SettingsDestination? = null,
    onInitialDestinationConsumed: () -> Unit = {},
) {
    var destination by rememberSaveable { mutableStateOf(SettingsDestination.Main) }
    val settingsListState = remember { LazyListState() }
    androidx.compose.runtime.LaunchedEffect(initialDestination) {
        if (initialDestination != null) {
            destination = initialDestination
            onInitialDestinationConsumed()
        }
    }
    val goBack = { destination = SettingsDestination.Main }
    BackHandler(enabled = destination != SettingsDestination.Main, onBack = goBack)

    when (destination) {
        SettingsDestination.Main -> SettingsHubMain(
            contentPadding = contentPadding,
            state = state,
            viewModel = viewModel,
            lazyListState = settingsListState,
            onOpen = { destination = it },
            showCoachMark = showCoachMark,
            onDismissCoachMark = onDismissCoachMark,
        )
        SettingsDestination.VpnHiding -> VpnHidingSettings(
            contentPadding = contentPadding,
            state = state,
            viewModel = viewModel,
            onBack = goBack,
        )
        SettingsDestination.CarrierBypass -> CarrierBypassSettings(
            contentPadding = contentPadding,
            state = state,
            viewModel = viewModel,
            onBack = goBack,
        )
        SettingsDestination.Connection -> ConnectionSettingsPage(
            contentPadding = contentPadding,
            state = state,
            viewModel = viewModel,
            onBack = goBack,
        )
        SettingsDestination.Network -> NetworkSettingsPage(
            contentPadding = contentPadding,
            state = state,
            viewModel = viewModel,
            onClearDnsCache = onClearDnsCache,
            onOpen = { destination = it },
            onBack = goBack,
        )
        SettingsDestination.Appearance -> AppearanceSettingsPage(
            contentPadding = contentPadding,
            state = state,
            viewModel = viewModel,
            onBack = goBack,
        )
        SettingsDestination.Privacy -> PrivacySettingsPage(
            contentPadding = contentPadding,
            state = state,
            viewModel = viewModel,
            onBack = goBack,
            onOpenPrivacyPromise = { destination = SettingsDestination.PrivacyPromise },
        )
        SettingsDestination.Schedule -> ScheduleSettingsPage(
            contentPadding = contentPadding,
            state = state,
            viewModel = viewModel,
            onBack = goBack,
        )
        SettingsDestination.Updates -> UpdatesSettingsPage(
            contentPadding = contentPadding,
            state = state,
            viewModel = viewModel,
            updateState = updateState,
            onCheckUpdate = onCheckUpdate,
            onDownloadUpdate = onDownloadUpdate,
            onInstallUpdate = onInstallUpdate,
            onCancelUpdate = onCancelUpdate,
            onBack = goBack,
        )
        SettingsDestination.OperatorHelp -> OperatorHelpPage(
            contentPadding = contentPadding,
            state = state,
            onBack = goBack,
        )
        SettingsDestination.HealthDashboard -> HealthDashboardPage(
            contentPadding = contentPadding,
            state = state,
            vpnState = vpnState,
            sessionStats = sessionStats,
            diagnostics = diagnostics,
            viewModel = viewModel,
            onBack = goBack,
        )
        SettingsDestination.SystemWizards -> SystemWizardsPage(
            contentPadding = contentPadding,
            onBack = goBack,
        )
        SettingsDestination.AdBlock -> AdBlockSettingsPage(
            contentPadding = contentPadding,
            state = state,
            viewModel = viewModel,
            onBack = goBack,
        )
        SettingsDestination.Apps -> {
            val context = LocalContext.current
            val appsViewModel = remember {
                (context.applicationContext as QuantumVpnApplication)
                    .container
                    .appsViewModelFactory
                    .create(AppsViewModel::class.java)
            }
            val appsState by appsViewModel.state.collectAsState()
            AppPickerScreen(
                state = appsState,
                viewModel = appsViewModel,
                onBack = goBack,
                showCoachMark = showAppsCoachMark,
                onDismissCoachMark = onDismissAppsCoachMark,
            )
        }
        SettingsDestination.Diagnostics -> DiagnosticsSettings(
            contentPadding = contentPadding,
            vpnState = vpnState,
            diagnostics = diagnostics,
            onSelected = onDiagnosticsSelected,
            onCreateDiagnosticShare = onCreateDiagnosticShare,
            onClearDnsCache = onClearDnsCache,
            onBack = goBack,
        )
        SettingsDestination.Journal -> EventJournalSettings(
            contentPadding = contentPadding,
            viewModel = viewModel,
            onBack = goBack,
        )
        SettingsDestination.Changelog -> ChangelogSettings(
            contentPadding = contentPadding,
            onBack = goBack,
        )
        SettingsDestination.Faq -> FaqSettings(
            contentPadding = contentPadding,
            onBack = goBack,
        )
        SettingsDestination.RouteSim -> RouteSimulatorSettings(
            contentPadding = contentPadding,
            onBack = goBack,
        )
        SettingsDestination.Checklist -> ChecklistSettings(
            contentPadding = contentPadding,
            state = state,
            vpnState = vpnState,
            onBack = goBack,
        )
        SettingsDestination.Developer -> DeveloperSettingsPage(
            contentPadding = contentPadding,
            onOpen = { destination = it },
            onBack = goBack,
        )
        SettingsDestination.ThreatModel -> TextPagesSettings(
            contentPadding = contentPadding,
            title = "Модель угроз",
            paragraphs = LocalThreatModel.paragraphs,
            onBack = goBack,
        )
        SettingsDestination.PrivacyPromise -> TextPagesSettings(
            contentPadding = contentPadding,
            title = "Что мы не собираем",
            paragraphs = LocalPrivacyPromise.bullets.map { "• $it" },
            onBack = goBack,
        )
        SettingsDestination.ErrorGlossary -> ErrorGlossarySettings(
            contentPadding = contentPadding,
            onBack = goBack,
        )
        SettingsDestination.OemQuirks -> OemQuirksSettings(
            contentPadding = contentPadding,
            onBack = goBack,
        )
        SettingsDestination.A11yStatement -> TextPagesSettings(
            contentPadding = contentPadding,
            title = "Доступность",
            paragraphs = LocalAccessibilityStatement.paragraphs,
            onBack = goBack,
        )
        SettingsDestination.AuditLog -> AuditLogSettings(
            contentPadding = contentPadding,
            viewModel = viewModel,
            onBack = goBack,
        )
        SettingsDestination.About -> AboutSettings(
            contentPadding = contentPadding,
            onBack = goBack,
        )
        SettingsDestination.Backlog -> BacklogScreen(
            contentPadding = contentPadding,
            onBack = goBack,
        )
        SettingsDestination.Routing -> RoutingScreen(
            contentPadding = contentPadding,
            routingState = routingState,
            routingViewModel = routingViewModel,
            showCoachMark = showCoachMark,
            onDismissCoachMark = onDismissCoachMark,
        )
    }
}

@Composable
private fun DnsOverrideDialog(
    current: DnsOverride,
    onDismiss: () -> Unit,
    onSave: (String, String) -> Unit,
) {
    var hostname by rememberSaveable(current.hostname) { mutableStateOf(current.hostname) }
    var ipv4Address by rememberSaveable(current.ipv4Address) { mutableStateOf(current.ipv4Address) }
    val validationMessage = DnsOverride.validationMessage(hostname, ipv4Address)

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("DNS-переопределение") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = hostname,
                    onValueChange = { hostname = it },
                    label = { Text("Точный домен") },
                    singleLine = true,
                    isError = DnsOverride.validationMessage(hostname, DnsOverride.DEFAULT_IPV4_ADDRESS) != null,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("dns-override-hostname")
                        .semantics { contentDescription = "Домен DNS-переопределения" },
                )
                OutlinedTextField(
                    value = ipv4Address,
                    onValueChange = { ipv4Address = it },
                    label = { Text("IPv4-адрес") },
                    singleLine = true,
                    isError = DnsOverride.validationMessage(DnsOverride.DEFAULT_HOSTNAME, ipv4Address) != null,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("dns-override-ipv4")
                        .semantics { contentDescription = "IPv4 DNS-переопределения" },
                )
                Text(
                    validationMessage
                        ?: "HTTPS продолжит проверять исходное имя домена и его сертификат.",
                    style = MaterialTheme.typography.bodySmall,
                    color = if (validationMessage == null) {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    } else {
                        MaterialTheme.colorScheme.error
                    },
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onSave(hostname, ipv4Address) },
                enabled = validationMessage == null,
            ) { Text("Сохранить") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Отмена") }
        },
    )
}

@Composable
internal fun UpdateControls(
    state: UpdateState,
    channel: UpdateChannel,
    onCheck: (UpdateChannel) -> Unit,
    onDownload: () -> Unit,
    onInstall: () -> Unit,
    onCancel: () -> Unit,
) {
    when (state) {
        UpdateState.Idle -> Button(
            onClick = { onCheck(channel) },
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
        ) { Text("Проверить обновления") }

        is UpdateState.Checking -> {
            Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(modifier = Modifier.padding(end = 12.dp))
                Text("Проверка канала ${state.channel}…")
            }
            OutlinedButton(onClick = onCancel) { Text("Отмена") }
        }

        is UpdateState.RetryingViaVpn -> {
            Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(modifier = Modifier.padding(end = 12.dp))
                Text(
                    when (state.operation) {
                        UpdateOperation.Check -> "Панель обновлений недоступна напрямую. Повторяем проверку…"
                        UpdateOperation.Download -> "Загрузка с панели прервана. Повторяем попытку…"
                    },
                )
            }
            OutlinedButton(onClick = onCancel) { Text("Отмена") }
        }

        is UpdateState.UpToDate -> {
            val source = if (state.checkedTag.startsWith("v") || state.checkedTag.contains("ftp", ignoreCase = true)) {
                "Проверено · ${state.checkedTag}"
            } else {
                "Проверено · ${state.checkedTag}"
            }
            Text("$source · установлена ${state.currentVersion}.")
            Text(
                "Источник: операторская панель VDS.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(onClick = { onCheck(channel) }) { Text("Проверить ещё раз") }
        }

        is UpdateState.Available -> {
            ReleaseSummary(
                state.candidate.metadata.versionName,
                state.candidate.metadata.coreTag,
                state.candidate.metadata.abi.single(),
            )
            Button(
                onClick = onDownload,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            ) { Text("Скачать и проверить APK") }
        }

        is UpdateState.Downloading -> {
            val progress = if (state.totalBytes > 0) {
                (state.downloadedBytes.toFloat() / state.totalBytes.toFloat()).coerceIn(0f, 1f)
            } else {
                0f
            }
            ReleaseSummary(
                state.candidate.metadata.versionName,
                state.candidate.metadata.coreTag,
                state.candidate.metadata.abi.single(),
            )
            LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth())
            Text(
                "${formatUpdateBytes(state.downloadedBytes)} / ${formatUpdateBytes(state.totalBytes)}",
                style = MaterialTheme.typography.bodySmall,
            )
            OutlinedButton(onClick = onCancel) { Text("Отменить и удалить") }
        }

        is UpdateState.Ready -> {
            ReleaseSummary(
                state.candidate.metadata.versionName,
                state.candidate.metadata.coreTag,
                state.candidate.metadata.abi.single(),
            )
            Text("SHA-256, package, version и подпись проверены.")
            Button(
                onClick = onInstall,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            ) { Text("Открыть системную установку") }
            OutlinedButton(onClick = onCancel) { Text("Удалить APK") }
        }

        is UpdateState.Failure -> {
            Text(state.message, color = MaterialTheme.colorScheme.error)
            if (state.candidate != null) {
                Button(onClick = onDownload) { Text("Повторить загрузку") }
            }
            OutlinedButton(onClick = { onCheck(channel) }) { Text("Проверить заново") }
        }
    }
}

@Composable
private fun ReleaseSummary(versionName: String, coreTag: String, abi: String) {
    Text("Доступна версия $versionName", fontWeight = FontWeight.SemiBold)
    Text("Core $coreTag · $abi", style = MaterialTheme.typography.bodySmall)
}

private fun formatUpdateBytes(value: Long): String = when {
    value >= 1024 * 1024 -> "%.1f МБ".format(value / (1024.0 * 1024.0))
    value >= 1024 -> "%.1f КБ".format(value / 1024.0)
    else -> "$value Б"
}

@Composable
private fun CarrierBypassSettings(
    contentPadding: PaddingValues,
    state: ProfilesUiState,
    viewModel: ProfilesViewModel,
    onBack: () -> Unit,
) {
    val settings = state.settings
    SettingsSubpage(contentPadding, "Обход DPI", onBack) {
        SettingsCard(title = "Операторы и глушилки") {
            Text(
                "На runtime: record_fragment + fragment на TLS-прокси (не на Reality). " +
                    "Глобальный route tls_fragment отключён — он рвал весь HTTPS. " +
                    "Сохранённый JSON профиля не меняется.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            VpnHidingSwitchRow(
                title = "Обход DPI и лимитов",
                subtitle = "Всегда включён на всех операторах (глушилки). Выключить нельзя.",
                checked = true,
                onCheckedChange = { enabled ->
                    if (enabled) viewModel.setCarrierBypassEnabled(true)
                    else viewModel.setCarrierBypassEnabled(true)
                },
                testTag = "carrier-bypass-enabled",
            )
            HorizontalDivider()
            VpnHidingSwitchRow(
                title = "На Wi‑Fi мягче",
                subtitle = "Агрессивный → Оператор на Wi‑Fi",
                checked = settings.softerBypassOnWifi,
                onCheckedChange = viewModel::setSofterBypassOnWifi,
                testTag = "softer-wifi",
            )
            HorizontalDivider()
            VpnHidingSwitchRow(
                title = "Adaptive DPI",
                subtitle = "Усиливать обход после фейлов connect",
                checked = settings.adaptiveDpiEnabled,
                onCheckedChange = viewModel::setAdaptiveDpiEnabled,
                testTag = "adaptive-dpi",
            )
            HorizontalDivider()
            Text("Пресет", fontWeight = FontWeight.Medium)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                com.quantumvpn.hardening.BypassPreset.entries.forEach { preset ->
                    FilterChip(
                        selected = settings.bypassPreset == preset,
                        onClick = { viewModel.setBypassPreset(preset) },
                        label = {
                            Text(
                                when (preset) {
                                    com.quantumvpn.hardening.BypassPreset.Soft -> "Мягкий"
                                    com.quantumvpn.hardening.BypassPreset.Standard -> "Стандарт"
                                    com.quantumvpn.hardening.BypassPreset.Tele2 -> "Оператор"
                                    com.quantumvpn.hardening.BypassPreset.Aggressive -> "Агрессивный"
                                },
                            )
                        },
                        enabled = settings.carrierBypassEnabled,
                    )
                }
            }
            HorizontalDivider()
            VpnHidingSwitchRow(
                title = "Всегда усиленный режим",
                subtitle = "Переключает пресет на «Агрессивный» (uTLS + TFO). Выкл → Стандарт.",
                checked = settings.carrierBypassAlwaysAggressive,
                onCheckedChange = viewModel::setCarrierBypassAlwaysAggressive,
                testTag = "carrier-bypass-aggressive",
                enabled = settings.carrierBypassEnabled,
            )
        }
        Text(
            "WireGuard без TLS не получает fragment — для Т2 лучше VLESS/Reality или другой TLS-прокси. " +
                "Safe mode временно отключает обход.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun VpnHidingSettings(
    contentPadding: PaddingValues,
    state: ProfilesUiState,
    viewModel: ProfilesViewModel,
    onBack: () -> Unit,
) {
    val options = state.settings.vpnHiding
    SettingsSubpage(contentPadding, "Скрытие VPN", onBack) {
        SettingsCard(title = "Возможности rootless-режима") {
            Text(
                "Защита закрывает локальные proxy/API и уменьшает технические признаки. " +
                    "Обычное приложение не может скрыть созданные Android TRANSPORT_VPN и TUN-интерфейс.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                "Здесь нет фонового сканирования, таймеров или дополнительного процесса.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        SettingsCard(title = "Защита от активных чекеров") {
            VpnHidingSwitchRow(
                title = "Блокировать localhost endpoints",
                subtitle = "Удаляет Clash/V2Ray API и запрещает дополнительные SOCKS/HTTP/mixed inbounds в runtime.",
                checked = options.blockLocalEndpoints,
                onCheckedChange = viewModel::setVpnHidingBlockLocalEndpoints,
                testTag = "vpn-hiding-local-endpoints",
            )
            if (!options.blockLocalEndpoints) {
                Text(
                    "Защита отключена: raw JSON сможет открыть локальный controller или proxy для других приложений.",
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Text(
                "Обход через Network.bindSocket не разрешается: VpnService.Builder.allowBypass() не используется.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        SettingsCard(title = "Сетевые параметры") {
            VpnHidingSwitchRow(
                title = "Нейтральное имя VPN-сессии",
                subtitle = "Показывает «Системная сеть» вместо имени клиента в доступных Android-представлениях.",
                checked = options.neutralSessionName,
                onCheckedChange = viewModel::setVpnHidingNeutralSessionName,
                testTag = "vpn-hiding-session-name",
            )
            HorizontalDivider()
            Text("MTU TUN", fontWeight = FontWeight.Medium)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                TunMtuMode.entries.forEach { mode ->
                    FilterChip(
                        selected = options.tunMtuMode == mode,
                        onClick = { viewModel.setVpnHidingTunMtuMode(mode) },
                        label = { Text(mode.displayName()) },
                        modifier = Modifier.testTag("vpn-hiding-mtu-${mode.name}"),
                    )
                }
            }
            Text(
                options.tunMtuMode.description(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        Text(
            "Изменение параметров контролируемо перезапускает активное подключение. " +
                "Сохранённый JSON профиля не переписывается.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun VpnHidingSwitchRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    testTag: String,
    enabled: Boolean = true,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 64.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f).padding(end = 12.dp)) {
            Text(title, fontWeight = FontWeight.Medium)
            Text(
                subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            enabled = enabled,
            modifier = Modifier
                .testTag(testTag)
                .semantics { contentDescription = title },
        )
    }
}

@Composable
private fun DiagnosticsSettings(
    contentPadding: PaddingValues,
    vpnState: VpnConnectionState,
    diagnostics: DiagnosticState,
    onSelected: (Boolean) -> Unit,
    onCreateDiagnosticShare: suspend () -> Intent,
    onClearDnsCache: () -> Unit,
    onBack: () -> Unit,
) {
    DisposableEffect(Unit) {
        onSelected(true)
        onDispose { onSelected(false) }
    }
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var timelineExpanded by rememberSaveable { mutableStateOf(false) }
    var stopTimelineExpanded by rememberSaveable { mutableStateOf(false) }
    var crashExpanded by rememberSaveable { mutableStateOf(false) }
    var logsExpanded by rememberSaveable { mutableStateOf(false) }
    var overlayExpanded by rememberSaveable { mutableStateOf(false) }
    var exporting by remember { mutableStateOf(false) }
    var exportError by remember { mutableStateOf<String?>(null) }
    var sendingReport by remember { mutableStateOf(false) }
    var reportStatus by remember { mutableStateOf<String?>(null) }

    SettingsSubpage(contentPadding, "Диагностика", onBack) {
        Column(
            modifier = Modifier.testTag("diagnostics-screen"),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("Текущее состояние", style = MaterialTheme.typography.titleMedium)
                Text(vpnState.diagnosticLabel(), fontWeight = FontWeight.SemiBold)
            }
        }
        OutlinedButton(
            enabled = !exporting,
            onClick = {
                scope.launch {
                    exporting = true
                    exportError = null
                    try {
                        val shareIntent = onCreateDiagnosticShare()
                        context.startActivity(
                            Intent.createChooser(shareIntent, "Передать диагностику"),
                        )
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (_: ActivityNotFoundException) {
                        exportError = "Не найдено приложение для передачи файла."
                    } catch (_: SecurityException) {
                        exportError = "Android запретил передачу файла."
                    } catch (_: Throwable) {
                        exportError = "Не удалось создать диагностический файл."
                    } finally {
                        exporting = false
                    }
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .testTag("export-diagnostics"),
        ) {
            if (exporting) {
                CircularProgressIndicator(
                    modifier = Modifier.padding(end = 8.dp),
                    strokeWidth = 2.dp,
                )
            }
            Text("Экспортировать диагностику")
        }
        exportError?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Text(
            "Создаёт временный redacted diagnostic JSON и открывает системное окно отправки.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("Добровольный отчёт об ошибке", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Отправка происходит только после нажатия кнопки. Передаются модель устройства, версия приложения, последняя ошибка и до 80 очищенных строк журнала. Подписки, ключи и ссылки удаляются.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedButton(
                    enabled = !sendingReport,
                    onClick = {
                        scope.launch {
                            sendingReport = true
                            reportStatus = null
                            val result = com.quantumvpn.diagnostics.VoluntaryDiagnosticReporter(context).send(diagnostics)
                            reportStatus = if (result.isSuccess) "Отчёт отправлен." else "Не удалось отправить отчёт."
                            sendingReport = false
                        }
                    },
                    modifier = Modifier.fillMaxWidth().testTag("send-voluntary-diagnostic"),
                ) { Text(if (sendingReport) "Отправка…" else "Отправить отчёт") }
                reportStatus?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            }
        }
        val app = context.applicationContext as? QuantumVpnApplication
        val exitEvents by (app?.container?.exitIpTimelineStore?.events
            ?: kotlinx.coroutines.flow.flowOf(emptyList())).collectAsState(initial = emptyList())
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("Кому виден мой IP", style = MaterialTheme.typography.titleMedium)
                if (exitEvents.isEmpty()) {
                    Text(
                        "Пока нет смен Exit IP. Появятся после подключения.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodySmall,
                    )
                } else {
                    exitEvents.take(12).forEach { event ->
                        Text(
                            "${java.text.SimpleDateFormat("dd.MM HH:mm", java.util.Locale.getDefault()).format(java.util.Date(event.epochMillis))} · ${event.ip} · ${event.note}",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    OutlinedButton(
                        onClick = {
                            scope.launch {
                                app?.container?.exitIpTimelineStore?.clear()
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text("Очистить таймлайн IP")
                    }
                }
            }
        }
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("Последняя ошибка", style = MaterialTheme.typography.titleMedium)
                val failure = diagnostics.lastFailure
                if (failure == null) {
                    Text("Ошибок текущего запуска нет.")
                } else {
                    Text(
                        "${failure.supportCode} · ${failure.type.title}",
                        modifier = Modifier.testTag("diagnostic-error-type"),
                        color = MaterialTheme.colorScheme.error,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(failure.message, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    failure.technicalDetail?.let { detail ->
                        Text(
                            "Технически: $detail",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("Время остановки", style = MaterialTheme.typography.titleMedium)
                val attempt = diagnostics.stopAttempt
                if (attempt == null) {
                    Text("Замеры появятся после следующей остановки VPN.")
                } else {
                    Text(
                        if (attempt.outcome == DiagnosticStopOutcome.Running) {
                            "Остановка выполняется"
                        } else {
                            "Остановлено за ${formatDiagnosticDuration(attempt.totalDurationMillis)}"
                        },
                        fontWeight = FontWeight.SemiBold,
                    )
                    attempt.stages.lastOrNull { it.status == DiagnosticStageStatus.Running }?.let { stage ->
                        Text(
                            "Сейчас: ${stage.label}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    attempt.slowestCompletedStage?.let { stage ->
                        Text(
                            "Самый долгий этап: ${stage.label} — ${formatDiagnosticDuration(stage.durationMillis)}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.testTag("diagnostic-stop-slowest-stage"),
                        )
                    }
                    OutlinedButton(
                        onClick = { stopTimelineExpanded = !stopTimelineExpanded },
                        modifier = Modifier.testTag("diagnostic-stop-timeline-toggle"),
                    ) {
                        Text(
                            if (stopTimelineExpanded) {
                                "Скрыть этапы"
                            } else {
                                "Показать этапы (${attempt.stages.size})"
                            },
                        )
                    }
                    if (stopTimelineExpanded) {
                        Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
                            attempt.stages.forEach { stage ->
                                Text(
                                    "${stage.status.symbol()} ${stage.label} — " +
                                        (stage.durationMillis?.let(::formatDiagnosticDuration)
                                            ?: "выполняется") +
                                        (stage.detail?.let { " · $it" } ?: ""),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = if (stage.status == DiagnosticStageStatus.Failed) {
                                        MaterialTheme.colorScheme.error
                                    } else {
                                        MaterialTheme.colorScheme.onSurfaceVariant
                                    },
                                )
                            }
                        }
                    }
                }
                Text(
                    "TUN закрывается до клиентов и libbox; каждый этап измеряется отдельно.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("Время подключения", style = MaterialTheme.typography.titleMedium)
                val attempt = diagnostics.connectionAttempt
                if (attempt == null) {
                    Text("Замеры появятся после следующей попытки подключения.")
                } else {
                    Text(
                        attempt.outcome.diagnosticLabel(attempt.totalDurationMillis),
                        fontWeight = FontWeight.SemiBold,
                        color = if (attempt.outcome == DiagnosticAttemptOutcome.Failed) {
                            MaterialTheme.colorScheme.error
                        } else {
                            MaterialTheme.colorScheme.onSurface
                        },
                    )
                    Text(
                        "Триггер: ${attempt.trigger}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    attempt.stages.lastOrNull { it.status == DiagnosticStageStatus.Running }?.let { stage ->
                        Text(
                            "Сейчас: ${stage.label}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    attempt.slowestCompletedStage?.let { stage ->
                        Text(
                            "Самый долгий этап: ${stage.label} — ${formatDiagnosticDuration(stage.durationMillis)}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.testTag("diagnostic-slowest-stage"),
                        )
                    }
                    OutlinedButton(
                        onClick = { timelineExpanded = !timelineExpanded },
                        modifier = Modifier.testTag("diagnostic-timeline-toggle"),
                    ) {
                        Text(if (timelineExpanded) "Скрыть этапы" else "Показать этапы (${attempt.stages.size})")
                    }
                    if (timelineExpanded) {
                        Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
                            attempt.stages.forEach { stage ->
                                Text(
                                    "${stage.status.symbol()} ${stage.label} — " +
                                        (stage.durationMillis?.let(::formatDiagnosticDuration) ?: "выполняется") +
                                        (stage.detail?.let { " · $it" } ?: ""),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = if (stage.status == DiagnosticStageStatus.Failed) {
                                        MaterialTheme.colorScheme.error
                                    } else {
                                        MaterialTheme.colorScheme.onSurfaceVariant
                                    },
                                )
                            }
                        }
                    }
                    if (diagnostics.previousConnectionAttempts.isNotEmpty()) {
                        Text("Предыдущие попытки", fontWeight = FontWeight.SemiBold)
                        diagnostics.previousConnectionAttempts.takeLast(2).asReversed().forEach { previous ->
                            Text(
                                "${previous.trigger}: " +
                                    previous.outcome.diagnosticLabel(previous.totalDurationMillis) +
                                    (previous.failure?.let { " · ${it.supportCode}" } ?: "") +
                                    (previous.slowestCompletedStage?.let { " · ${it.label}" } ?: ""),
                                style = MaterialTheme.typography.bodySmall,
                                color = if (previous.outcome == DiagnosticAttemptOutcome.Failed) {
                                    MaterialTheme.colorScheme.error
                                } else {
                                    MaterialTheme.colorScheme.onSurfaceVariant
                                },
                            )
                        }
                    }
                }
                Text(
                    "Замеры делаются только на событиях запуска: без таймера, polling и фонового трафика.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("Предыдущий crash приложения", style = MaterialTheme.typography.titleMedium)
                val crash = diagnostics.previousCrash
                if (crash == null) {
                    Text("Сохранённого Kotlin/Java crash нет.")
                } else {
                    Text(
                        crash.exceptionType,
                        color = MaterialTheme.colorScheme.error,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.testTag("diagnostic-previous-crash"),
                    )
                    Text(formatDiagnosticTimestamp(crash.occurredAtEpochMillis))
                    crash.message?.let {
                        Text(it, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    if (crash.stack.isNotEmpty()) {
                        OutlinedButton(onClick = { crashExpanded = !crashExpanded }) {
                            Text(if (crashExpanded) "Скрыть стек" else "Показать короткий стек")
                        }
                    }
                    if (crashExpanded) {
                        Text(
                            crash.stack.joinToString("\n") { frame ->
                                "${frame.className}.${frame.methodName}:${frame.lineNumber}"
                            },
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                        )
                    }
                }
                Text(
                    "Хранится только один redacted Kotlin/Java crash без сетевого runtime-лога. " +
                        "На API 30+ Android отдельно сообщает тип последнего native crash/ANR без тяжёлого trace.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                diagnostics.previousProcessExit?.let { exit ->
                    HorizontalDivider()
                    Text("Предыдущее завершение процесса", fontWeight = FontWeight.SemiBold)
                    Text(
                        "${exit.reason} · status ${exit.status}",
                        color = if (exit.reason == "native_crash" || exit.reason == "anr") {
                            MaterialTheme.colorScheme.error
                        } else {
                            MaterialTheme.colorScheme.onSurface
                        },
                    )
                    Text(
                        "${formatDiagnosticTimestamp(exit.occurredAtEpochMillis)} · " +
                            "PSS ${exit.pssKilobytes} KiB · RSS ${exit.rssKilobytes} KiB",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    exit.description?.let {
                        Text(it, style = MaterialTheme.typography.bodySmall)
                    }
                }
                if (Build.VERSION.SDK_INT < 30) {
                    Text(
                        "История native crash/ANR через Android доступна начиная с API 30.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("Среда", style = MaterialTheme.typography.titleMedium)
                Text("QuantumVPN ${BuildConfig.VERSION_NAME}")
                Text("Core ${BuildConfig.CORE_TAG} · ${BuildConfig.CORE_COMMIT.take(12)}")
                Text(
                    "Android patch ${BuildConfig.CORE_PATCH_SHA256.take(12)}",
                    style = MaterialTheme.typography.bodySmall,
                )
                Text("Android ${Build.VERSION.RELEASE} · API ${Build.VERSION.SDK_INT}")
                val vpnPolicy = diagnostics.vpnPolicy
                when {
                    vpnPolicy == null -> Text(
                        "Always-on/Lockdown: статус появится при запуске VPN.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    !vpnPolicy.statusAvailable -> Text(
                        "Always-on/Lockdown: Android API < 29 не даёт публичный статус.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    vpnPolicy.alwaysOn || vpnPolicy.lockdown -> Text(
                        "Always-on: ${vpnPolicy.alwaysOn.yesNo()} · Lockdown: ${vpnPolicy.lockdown.yesNo()}. " +
                            "Эти режимы пока не поддерживаются; отключите их в Android.",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                    else -> Text(
                        "Always-on: нет · Lockdown: нет",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("Сеть Android", style = MaterialTheme.typography.titleMedium)
                val network = diagnostics.network
                if (network == null) {
                    Text("Состояние появится при подключении или экспорте отчёта.")
                } else {
                    Text(
                        "${network.transport} · ${network.interfaceName ?: "интерфейс не определён"}",
                    )
                    Text(
                        "Validated: ${network.validated.yesNo()} · Metered: ${network.metered.yesNo()}",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Text(
                        "Private DNS: ${network.privateDnsMode} · active: ${network.privateDnsActive.yesNo()}",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("Последние логи", style = MaterialTheme.typography.titleMedium)
                Text(
                    if (diagnostics.logStreamActive) {
                        "Поток core активен только пока открыт этот экран."
                    } else {
                        "Поток core не активен; в памяти сохранены только bounded строки текущего запуска."
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    "Core: получено ${diagnostics.coreLogStats.receivedLines}, " +
                        "схлопнуто ${diagnostics.coreLogStats.coalescedLines}, " +
                        "отброшено ${diagnostics.coreLogStats.droppedLines}.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedButton(
                    onClick = { logsExpanded = !logsExpanded },
                    modifier = Modifier.testTag("diagnostic-logs-toggle"),
                ) {
                    Text(if (logsExpanded) "Скрыть (${diagnostics.logs.size})" else "Показать (${diagnostics.logs.size})")
                }
                if (logsExpanded) {
                    if (diagnostics.logs.isEmpty()) {
                        Text("Строк логов пока нет.")
                    } else {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(max = 360.dp)
                                .verticalScroll(rememberScrollState()),
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            diagnostics.logs.forEach { line ->
                                Text(
                                    "${line.levelName}/${line.category.code}: ${line.message}" +
                                        if (line.repeatCount > 1) " ×${line.repeatCount}" else "",
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace,
                                )
                            }
                        }
                    }
                }
            }
        }
        diagnostics.effectiveOverlay?.let { overlay ->
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text("Effective overlay", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Только структура managed-оверлея без адресов, правил сопоставления и credentials.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    OutlinedButton(onClick = { overlayExpanded = !overlayExpanded }) {
                        Text(if (overlayExpanded) "Скрыть" else "Показать")
                    }
                    if (overlayExpanded) {
                        Text(
                            overlay,
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                        )
                    }
                }
            }
        }
        MemoryUsageCard()
        OutlinedButton(onClick = onClearDnsCache) { Text("Очистить DNS-кэш и перезапустить core") }
        Text(
            "Runtime-лог на диск не пишется; временный export удаляется при следующем запуске.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        }
    }
}

@Composable
private fun MemoryUsageCard() {
    val context = LocalContext.current
    val snapshot = remember { MemoryUsageProbe.snapshot(context) }
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text("Память", style = MaterialTheme.typography.titleMedium)
            Text(
                "Процесс: heap ${snapshot.heapUsagePercent}% · PSS ${snapshot.formatMb(snapshot.totalPssMb)}",
                style = MaterialTheme.typography.bodyMedium,
            )
            LinearProgressIndicator(
                progress = { snapshot.heapUsagePercent / 100f },
                modifier = Modifier.fillMaxWidth(),
            )
            Text(
                "Java heap: ${snapshot.formatMb(snapshot.heapUsedMb)} / ${snapshot.formatMb(snapshot.heapMaxMb)}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                "Native heap: ${snapshot.formatMb(snapshot.nativeHeapUsedMb)} / ${snapshot.formatMb(snapshot.nativeHeapMaxMb)}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                "Устройство: ${snapshot.deviceUsagePercent}% занято · свободно ${snapshot.formatMb(snapshot.deviceAvailMb)}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (snapshot.lowMemory) {
                Text(
                    "⚠ Система в состоянии нехватки памяти (low memory).",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
    }
}

@Composable
private fun ChangelogSettings(
    contentPadding: PaddingValues,
    onBack: () -> Unit,
) {
    SettingsSubpage(contentPadding, "Что нового", onBack) {
        LocalChangelog.entries.forEach { entry ->
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(entry.version, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    entry.bullets.forEach { bullet ->
                        Text("• $bullet", style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }
    }
}

@Composable
private fun FaqSettings(
    contentPadding: PaddingValues,
    onBack: () -> Unit,
) {
    SettingsSubpage(contentPadding, "FAQ", onBack) {
        LocalFaq.items.forEach { item ->
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(item.q, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    Text(item.a, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}

@Composable
private fun RouteSimulatorSettings(
    contentPadding: PaddingValues,
    onBack: () -> Unit,
) {
    var domain by rememberSaveable { mutableStateOf("") }
    var presetTitle by rememberSaveable { mutableStateOf("Всё через VPN") }
    val presets = listOf(
        "Всё через VPN",
        "Россия напрямую",
        "Россия через VPN",
        "Только выбранные сайты",
        "Блок рекламы",
        "Семейный фильтр",
        "Стриминг",
        "Игры",
        "Работа",
    )
    SettingsSubpage(contentPadding, "Симулятор маршрута", onBack) {
        Text(
            "Упрощённая оценка по пресету (не полный движок правил).",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            presets.forEach { title ->
                FilterChip(
                    selected = presetTitle == title,
                    onClick = { presetTitle = title },
                    label = { Text(title) },
                )
            }
        }
        OutlinedTextField(
            value = domain,
            onValueChange = { domain = it },
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 80.dp),
            minLines = 1,
            maxLines = 8,
            label = { Text("Домен или список (по строке)") },
            placeholder = { Text("youtube.com\ngoogle.com") },
        )
        val batch = remember(domain, presetTitle) {
            if (domain.contains('\n')) {
                RouteSimulator.simulateBatch(domain, presetTitle, presetTitle, timeRoutingEnabled = false)
            } else {
                listOf(RouteSimulator.simulate(domain, presetTitle, presetTitle))
            }
        }
        batch.filter { it.domain.isNotBlank() }.forEach { result ->
            Text("${result.domain} → ${result.action}", fontWeight = FontWeight.SemiBold)
            Text(result.detail, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun ChecklistSettings(
    contentPadding: PaddingValues,
    state: ProfilesUiState,
    vpnState: VpnConnectionState,
    onBack: () -> Unit,
) {
    val items = remember(vpnState, state.settings) {
        com.quantumvpn.diagnostics.SecurityChecklist.items(vpnState, state.settings)
    }
    SettingsSubpage(contentPadding, "Чеклист безопасности", onBack) {
        Text(
            com.quantumvpn.diagnostics.SecurityChecklist.summary(items),
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.primary,
        )
        items.forEach { item ->
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(
                        "${if (item.ok) "OK" else "TODO"} · ${item.title}",
                        fontWeight = FontWeight.SemiBold,
                        color = if (item.ok) {
                            MaterialTheme.colorScheme.primary
                        } else {
                            MaterialTheme.colorScheme.error
                        },
                    )
                    if (!item.ok) {
                        Text(item.hint, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

@Composable
private fun PrivacySwitchRow(
    title: String,
    detail: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(title)
            Text(
                detail,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
private fun LeakStatusRow(label: String, ok: Boolean, detail: String? = null) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label)
        Text(
            buildString {
                append(if (ok) "OK" else "FAIL")
                detail?.takeIf { it.isNotBlank() }?.let { append(" · ").append(it) }
            },
            color = if (ok) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
            fontWeight = FontWeight.SemiBold,
        )
    }
}

@Composable
private fun EventJournalSettings(
    contentPadding: PaddingValues,
    viewModel: ProfilesViewModel,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val events by viewModel.journalEvents.collectAsState(initial = emptyList())
    var kindFilter by rememberSaveable { mutableStateOf<String?>(null) }
    val kinds = remember(events) { events.map { it.kind }.distinct().sorted() }
    val filtered = events.filter { kindFilter == null || it.kind == kindFilter }
    SettingsSubpage(contentPadding, "Журнал событий", onBack) {
        OutlinedButton(
            onClick = {
                val csv = buildString {
                    appendLine("epoch_ms,kind,message")
                    filtered.forEach { event ->
                        val msg = event.message.replace('"', '\'').replace('\n', ' ')
                        appendLine("${event.epochMillis},${event.kind},\"$msg\"")
                    }
                }
                val share = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_SUBJECT, "QuantumVPN journal")
                    putExtra(Intent.EXTRA_TEXT, csv)
                }
                runCatching {
                    context.startActivity(Intent.createChooser(share, "Экспорт журнала"))
                }
            },
            enabled = filtered.isNotEmpty(),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Экспорт CSV…")
        }
        OutlinedButton(
            onClick = viewModel::clearEventJournal,
            enabled = events.isNotEmpty(),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Очистить журнал")
        }
        if (kinds.isNotEmpty()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                FilterChip(
                    selected = kindFilter == null,
                    onClick = { kindFilter = null },
                    label = { Text("Все") },
                )
                kinds.forEach { kind ->
                    FilterChip(
                        selected = kindFilter == kind,
                        onClick = { kindFilter = if (kindFilter == kind) null else kind },
                        label = { Text(kind) },
                    )
                }
            }
        }
        if (filtered.isEmpty()) {
            Text(
                if (events.isEmpty()) {
                    "Пока пусто. События появятся после подключения, обновления подписок, спидтеста или диагностики."
                } else {
                    "Нет событий этого типа."
                },
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            filtered.forEach { event ->
                ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier.padding(14.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        Text(
                            "${event.kind} · ${formatDiagnosticTimestamp(event.epochMillis)}",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary,
                        )
                        Text(event.message, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }
    }
}

@Composable
private fun TextPagesSettings(
    contentPadding: PaddingValues,
    title: String,
    paragraphs: List<String>,
    onBack: () -> Unit,
) {
    SettingsSubpage(contentPadding, title, onBack) {
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                paragraphs.forEach { Text(it) }
            }
        }
    }
}

@Composable
private fun ErrorGlossarySettings(
    contentPadding: PaddingValues,
    onBack: () -> Unit,
) {
    SettingsSubpage(contentPadding, "Глоссарий ошибок", onBack) {
        LocalErrorGlossary.entries.forEach { entry ->
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(entry.code, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary)
                    Text(entry.meaning)
                    Text(entry.action, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}

@Composable
private fun OemQuirksSettings(
    contentPadding: PaddingValues,
    onBack: () -> Unit,
) {
    SettingsSubpage(contentPadding, "OEM-советы", onBack) {
        LocalOemQuirks.entries.forEach { entry ->
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(entry.oem, fontWeight = FontWeight.SemiBold)
                    Text(entry.tip, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}

@Composable
private fun AuditLogSettings(
    contentPadding: PaddingValues,
    viewModel: ProfilesViewModel,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val events by viewModel.settingsAuditEvents.collectAsState(initial = emptyList())
    SettingsSubpage(contentPadding, "Аудит настроек", onBack) {
        OutlinedButton(
            onClick = {
                val text = events.joinToString("\n") { e ->
                    "${e.epochMillis}\t${e.key}=${e.value}"
                }.ifBlank { "empty" }
                runCatching {
                    context.startActivity(
                        Intent.createChooser(
                            Intent(Intent.ACTION_SEND).apply {
                                type = "text/plain"
                                putExtra(Intent.EXTRA_TEXT, text)
                            },
                            "Аудит настроек",
                        ),
                    )
                }
            },
            enabled = events.isNotEmpty(),
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Экспорт…") }
        OutlinedButton(
            onClick = viewModel::clearSettingsAudit,
            enabled = events.isNotEmpty(),
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Очистить") }
        if (events.isEmpty()) {
            Text("Пока пусто. Изменения kill switch / DNS / lock появятся здесь.")
        } else {
            events.take(40).forEach { event ->
                Text(
                    "${formatDiagnosticTimestamp(event.epochMillis)} · ${event.key}=${event.value}",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

@Composable
private fun AboutSettings(
    contentPadding: PaddingValues,
    onBack: () -> Unit,
) {
    SettingsSubpage(contentPadding, "О приложении", onBack) {
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("QuantumVPN", style = MaterialTheme.typography.headlineSmall)
                Text("Версия ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
                val context = androidx.compose.ui.platform.LocalContext.current
                val trust = remember { com.quantumvpn.security.TrustDiagnostics.report(context) }
                trust.apkSha256?.let { hash ->
                    Text(
                        "APK SHA-256: ${hash.take(20)}…",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                    )
                }
                Text("Источник установки: ${trust.installSource}", style = MaterialTheme.typography.bodySmall)
                Text(
                    if (trust.rooted) "Root: обнаружен (информационно)" else "Root: не обнаружен",
                    style = MaterialTheme.typography.bodySmall,
                    color = if (trust.rooted) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    if (trust.tampered) "Подпись APK: не удалось проверить" else "Подпись APK: OK",
                    style = MaterialTheme.typography.bodySmall,
                )
                Text(
                    "Собственный Android VPN-клиент на ядре sing-box-extended. " +
                        "Подключает весь трафик устройства через выбранный профиль, " +
                        "поддерживает подписки, WireGuard и обычный sing-box JSON.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("Ядро", style = MaterialTheme.typography.titleMedium)
                Text(BuildConfig.CORE_TAG)
                Text(BuildConfig.CORE_COMMIT, style = MaterialTheme.typography.bodySmall)
                Text(
                    "Ядро встроено в APK и обновляется только вместе с приложением.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("Возможности", style = MaterialTheme.typography.titleMedium)
                Text("• Весь трафик устройства идёт через VPN")
                Text("• Профили и подписки выбираются до подключения")
                Text("• Подписки обновляются при запуске; маршруты — встроенные rule-set")
                Text("• Профили и URL подписок шифруются на устройстве (Android Keystore)")
                Text("• Скорость ↓/↑ отображается в уведомлении")
                Text("• Обновления только из стабильного канала")
            }
        }
    }
}

@Composable
internal fun SettingsSubpage(
    contentPadding: PaddingValues,
    title: String,
    onBack: () -> Unit,
    content: @Composable () -> Unit,
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(contentPadding),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item(key = "header") {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 56.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                IconButton(onClick = onBack) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Назад")
                }
                Text(
                    title,
                    style = MaterialTheme.typography.headlineSmall,
                    modifier = Modifier.semantics { heading() },
                )
            }
        }
        item(key = "content") {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp), content = { content() })
        }
    }
}

@Composable
private fun SettingsCard(
    title: String,
    content: @Composable ColumnScope.() -> Unit,
) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(
                title,
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.semantics { heading() },
            )
            content()
        }
    }
}

@Composable
private fun SettingsLinkRow(
    title: String,
    subtitle: String,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 72.dp)
            .clickable(onClick = onClick)
            .semantics { contentDescription = "$title. $subtitle" }
            .padding(horizontal = 18.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(title, fontWeight = FontWeight.Medium)
            Text(
                subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Text("›", style = MaterialTheme.typography.headlineSmall)
    }
}

private fun ThemeMode.displayName(): String = when (this) {
    ThemeMode.System -> "Системная"
    ThemeMode.Light -> "Светлая"
    ThemeMode.Dark -> "Тёмная"
}

private fun DnsMode.displayName(): String = when (this) {
    DnsMode.Automatic -> "Автоматически"
    DnsMode.Android -> "DNS Android"
    DnsMode.Secure -> "Защищённый через VPN"
    DnsMode.FromJson -> "Из JSON"
}

private fun DnsMode.description(): String = when (this) {
    DnsMode.Automatic -> "DNS профиля → DNS Android → DoH. Переход только после подтверждённой ошибки."
    DnsMode.Android -> "Системный resolver и Private DNS Android остаются источником истины."
    DnsMode.Secure -> "Стандартный DNS выбранных приложений идёт в DoH через proxy."
    DnsMode.FromJson -> "DNS профиля используется как есть; если его нет — local DNS Android без DoH."
}

private fun TunMtuMode.displayName(): String = when (this) {
    TunMtuMode.CoreDefault -> "По профилю"
    TunMtuMode.Normalize1500 -> "Нормализовать 1500"
}

private fun TunMtuMode.description(): String = when (this) {
    TunMtuMode.CoreDefault ->
        "Используется MTU профиля; для WireGuard без tun.mtu — MTU endpoint, " +
            "для остальных — Android-default ядра."
    TunMtuMode.Normalize1500 ->
        "Используется по умолчанию: runtime ограничивает TUN до MTU 1500. " +
            "Для userspace WireGuard выбирается меньшее из 1500 и MTU endpoint. JSON не меняется."
}

private fun VpnConnectionState.diagnosticLabel(): String = when (this) {
    VpnConnectionState.Stopped -> "VPN выключен"
    is VpnConnectionState.Starting -> "Подключение: $message"
    is VpnConnectionState.Connected -> "Подключено: $profileName"
    is VpnConnectionState.Stopping -> "Отключение"
    is VpnConnectionState.Error -> "Ошибка VPN"
}

private fun DiagnosticAttemptOutcome.diagnosticLabel(totalDurationMillis: Long?): String = when (this) {
    DiagnosticAttemptOutcome.Running -> "Подключение выполняется"
    DiagnosticAttemptOutcome.Connected -> "Подключено за ${formatDiagnosticDuration(totalDurationMillis)}"
    DiagnosticAttemptOutcome.Failed -> "Ошибка через ${formatDiagnosticDuration(totalDurationMillis)}"
    DiagnosticAttemptOutcome.Cancelled -> "Попытка отменена через ${formatDiagnosticDuration(totalDurationMillis)}"
}

private fun DiagnosticStageStatus.symbol(): String = when (this) {
    DiagnosticStageStatus.Running -> "…"
    DiagnosticStageStatus.Success -> "✓"
    DiagnosticStageStatus.Recovered -> "↻"
    DiagnosticStageStatus.Failed -> "×"
    DiagnosticStageStatus.Cancelled -> "—"
}

private fun formatDiagnosticDuration(value: Long?): String = when {
    value == null -> "не измерено"
    value < 1_000 -> "$value мс"
    else -> "%.2f с".format(value / 1_000.0)
}

private fun formatDiagnosticTimestamp(epochMillis: Long): String =
    DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM).format(Date(epochMillis))

private fun formatSettingsBytes(value: Long): String = when {
    value < 1024 -> "$value B"
    value < 1024 * 1024 -> "%.1f KB".format(value / 1024.0)
    value < 1024L * 1024 * 1024 -> "%.1f MB".format(value / (1024.0 * 1024))
    else -> "%.2f GB".format(value / (1024.0 * 1024 * 1024))
}

private fun Boolean.yesNo(): String = if (this) "да" else "нет"
