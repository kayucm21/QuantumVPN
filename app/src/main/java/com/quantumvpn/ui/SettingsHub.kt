package com.quantumvpn.ui

import android.Manifest
import android.content.Intent
import android.provider.Settings as AndroidSettings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.quantumvpn.BuildConfig
import com.quantumvpn.config.DnsMode
import com.quantumvpn.diagnostics.DiagnosticState
import com.quantumvpn.profiles.ProfilesUiState
import com.quantumvpn.profiles.ProfilesViewModel
import com.quantumvpn.ui.components.QvDivider
import com.quantumvpn.ui.components.QvHubHeader
import com.quantumvpn.ui.components.QvNavRow
import com.quantumvpn.ui.components.QvSection
import com.quantumvpn.ui.components.QvToggleRow
import com.quantumvpn.updates.UpdateChannel
import com.quantumvpn.updates.UpdateState
import com.quantumvpn.vpn.VpnConnectionState
import com.quantumvpn.vpn.VpnSessionStats
import com.quantumvpn.vpn.WifiSsidReader

@Composable
internal fun SettingsHubMain(
    contentPadding: PaddingValues,
    state: ProfilesUiState,
    viewModel: ProfilesViewModel,
    lazyListState: LazyListState = rememberLazyListState(),
    onOpen: (SettingsDestination) -> Unit,
    showCoachMark: Boolean = false,
    onDismissCoachMark: () -> Unit = {},
) {
    var query by rememberSaveable { mutableStateOf("") }
    fun match(vararg terms: String): Boolean {
        val q = query.trim()
        if (q.isEmpty()) return true
        return terms.any { it.contains(q, ignoreCase = true) }
    }
    val links = listOf(
        Triple("Подключение", "Kill switch, failover, Wi‑Fi и safe mode", SettingsDestination.Connection),
        Triple("Сеть и обход", "DNS, DPI, скрытие VPN", SettingsDestination.Network),
        Triple("Приложения", "Per-app VPN", SettingsDestination.Apps),
        Triple("Внешний вид", "Тема, акцент, OLED, текст", SettingsDestination.Appearance),
        Triple("Приватность", "App lock, biometric, скриншоты", SettingsDestination.Privacy),
        Triple("Расписание", "Ночь / утро / работа", SettingsDestination.Schedule),
        Triple("Диагностика", "Экспорт, утечки, журнал", SettingsDestination.Diagnostics),
        Triple("Здоровье VPN", "Reliability, score, обрывы", SettingsDestination.HealthDashboard),
        Triple("Always-on и батарея", "Мастер системных настроек", SettingsDestination.SystemWizards),
        Triple("Блокировка рекламы", "Уровни, трекеры, whitelist", SettingsDestination.AdBlock),
        Triple("Маршруты", "Пресеты, Happ, свои правила", SettingsDestination.Routing),
        Triple("Помощь по операторам", "Т2 / DPI / какой протокол нужен", SettingsDestination.OperatorHelp),
        Triple("О приложении", "Версия, FAQ, changelog", SettingsDestination.About),
        Triple("Для разработчиков", "Threat model, OEM, журнал", SettingsDestination.Developer),
    ).filter { (t, s, _) -> match(t, s) }

    LazyColumn(
        state = lazyListState,
        modifier = Modifier
            .fillMaxSize()
            .padding(contentPadding)
            .testTag("settings-list"),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (showCoachMark) {
            item(key = "coach") {
                CoachMarkBanner(screen = CoachMarkScreen.Settings, onDismiss = onDismissCoachMark)
            }
        }
        item(key = "header") {
            QvHubHeader(
                title = "Ещё",
                subtitle = "Настройки QuantumVPN · ${BuildConfig.VERSION_NAME}",
            )
        }
        item(key = "search") {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Поиск") },
                placeholder = { Text("DNS, DPI, тема…") },
            )
        }
        item(key = "hub") {
            QvSection(title = "Разделы") {
                links.forEachIndexed { index, (title, subtitle, dest) ->
                    if (index > 0) QvDivider()
                    QvNavRow(title = title, subtitle = subtitle, onClick = { onOpen(dest) })
                }
            }
        }
        item(key = "quiet") {
            QvSection(title = "Быстро") {
                QvToggleRow(
                    title = "Тихий режим",
                    subtitle = "Без звуков подключения",
                    checked = state.settings.quietMode,
                    onCheckedChange = viewModel::setQuietMode,
                    testTag = "hub-quiet",
                )
            }
        }
    }
}

@Composable
internal fun ConnectionSettingsPage(
    contentPadding: PaddingValues,
    state: ProfilesUiState,
    viewModel: ProfilesViewModel,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val locationPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) viewModel.setAutoConnectTrustedWifi(true)
        else viewModel.showTip("Нужно разрешение геолокации, чтобы читать SSID Wi‑Fi.")
    }
    SettingsSubpage(contentPadding, "Подключение", onBack) {
        QvSection(title = "Защита сессии") {
            QvToggleRow(
                title = "Блокировать трафик вне VPN",
                subtitle = "Kill switch: без VPN интернет не ходит",
                checked = state.settings.blockNonVpnTraffic,
                onCheckedChange = viewModel::setBlockNonVpnTraffic,
                testTag = "hub-kill-switch",
            )
            QvDivider()
            QvToggleRow(
                title = "Автоfailover",
                subtitle = "При ошибке пробовать следующий сервер",
                checked = state.settings.autoFailoverEnabled,
                onCheckedChange = viewModel::setAutoFailoverEnabled,
                testTag = "hub-failover",
            )
            QvDivider()
            QvToggleRow(
                title = "QoE-монитор",
                subtitle = "Раз в 5 мин: высокий пинг → совет/смена сервера",
                checked = state.settings.qoeMonitorEnabled,
                onCheckedChange = viewModel::setQoeMonitorEnabled,
                testTag = "hub-qoe",
            )
            QvDivider()
            QvToggleRow(
                title = "Тихий ночной reconnect",
                subtitle = "0–6 ч без toast при autofailover",
                checked = state.settings.quietNightReconnect,
                onCheckedChange = viewModel::setQuietNightReconnect,
                testTag = "hub-quiet-night",
            )
            QvDivider()
            QvToggleRow(
                title = "Safe mode",
                subtitle = "Минимальный runtime (Android DNS, без DPI)",
                checked = state.settings.safeModeConnect,
                onCheckedChange = viewModel::setSafeModeConnect,
                testTag = "hub-safe-mode",
            )
        }
        QvSection(title = "Аварийный сброс") {
            OutlinedButton(
                onClick = viewModel::panicResetNetworkOverlays,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Сброс DPI / DNS без удаления профилей")
            }
            Text(
                "Если VPN «подключён», но сайты не открываются — сначала это.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        QvSection(title = "Автоподключение") {
            QvToggleRow(
                title = "Доверенный Wi‑Fi",
                subtitle = "Автоподключение на выбранных SSID",
                checked = state.settings.autoConnectTrustedWifi,
                onCheckedChange = { enabled ->
                    if (enabled) locationPermission.launch(Manifest.permission.ACCESS_FINE_LOCATION)
                    else viewModel.setAutoConnectTrustedWifi(false)
                },
                testTag = "hub-trusted-wifi",
            )
            QvDivider()
            QvToggleRow(
                title = "На мобильной сети",
                subtitle = "Автоподключение на cellular",
                checked = state.settings.autoConnectOnCellular,
                onCheckedChange = viewModel::setAutoConnectOnCellular,
                testTag = "hub-cellular-auto",
            )
            QvDivider()
            QvToggleRow(
                title = "Не в роуминге",
                subtitle = "Пропускать автоподключение в роуминге",
                checked = state.settings.skipAutoConnectWhenRoaming,
                onCheckedChange = viewModel::setSkipAutoConnectWhenRoaming,
                testTag = "hub-roaming",
            )
            val ssid = WifiSsidReader.currentSsid(context)
            if (!ssid.isNullOrBlank()) {
                Text("Сейчас: $ssid", style = MaterialTheme.typography.bodySmall)
            }
            OutlinedButton(
                onClick = { context.startActivity(Intent(AndroidSettings.ACTION_VPN_SETTINGS)) },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Always-on VPN в системе") }
        }
    }
}

@Composable
internal fun NetworkSettingsPage(
    contentPadding: PaddingValues,
    state: ProfilesUiState,
    viewModel: ProfilesViewModel,
    onClearDnsCache: () -> Unit,
    onOpen: (SettingsDestination) -> Unit,
    onBack: () -> Unit,
) {
    SettingsSubpage(contentPadding, "Сеть и обход", onBack) {
        QvSection(title = "Обход") {
            QvNavRow(
                title = "Обход DPI",
                subtitle = if (state.settings.carrierBypassEnabled) "Включён" else "Выключен",
                onClick = { onOpen(SettingsDestination.CarrierBypass) },
            )
            QvDivider()
            QvToggleRow(
                title = "Stealth (анти-DPI)",
                subtitle = "Усиленная маскировка трафика всегда",
                checked = state.settings.stealthMode,
                onCheckedChange = viewModel::setStealthMode,
                testTag = "hub-stealth",
            )
            QvDivider()
            QvNavRow(
                title = "Скрытие VPN",
                subtitle = "Localhost / MTU / имя сессии",
                onClick = { onOpen(SettingsDestination.VpnHiding) },
            )
            QvDivider()
            QvNavRow(
                title = "Помощь по операторам",
                subtitle = "Т2, WireGuard vs Reality",
                onClick = { onOpen(SettingsDestination.OperatorHelp) },
            )
        }
        QvSection(title = "DNS") {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                DnsMode.entries.forEach { mode ->
                    FilterChip(
                        selected = state.settings.dnsMode == mode,
                        onClick = { viewModel.setDnsMode(mode) },
                        label = { Text(mode.name) },
                    )
                }
            }
            QvToggleRow(
                title = "Только IPv4 (anti-leak IPv6)",
                subtitle = "Proxy DNS без IPv6 — меньше утечек на LTE",
                checked = state.settings.proxyIpv4Only,
                onCheckedChange = viewModel::setProxyIpv4Only,
                testTag = "hub-ipv4",
                enabled = state.settings.dnsMode != DnsMode.FromJson,
            )
            OutlinedButton(onClick = onClearDnsCache, modifier = Modifier.fillMaxWidth()) {
                Text("Очистить DNS-кэш")
            }
            QvNavRow(
                title = "Блокировка рекламы",
                subtitle = if (state.settings.adBlockEnabled) {
                    "DNS + маршрут · настройки уровня и AdGuard"
                } else {
                    "Выключена"
                },
                onClick = { onOpen(SettingsDestination.AdBlock) },
            )
            var customDoh by rememberSaveable(state.settings.customDohUrl) {
                mutableStateOf(state.settings.customDohUrl)
            }
            OutlinedTextField(
                value = customDoh,
                onValueChange = { customDoh = it },
                label = { Text("Свой DoH URL (режим Secure)") },
                placeholder = { Text("https://dns.example/dns-query") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(
                    onClick = { viewModel.setCustomDohUrl(customDoh.trim()) },
                    modifier = Modifier.weight(1f),
                ) { Text("Сохранить DoH") }
                if (customDoh.isNotBlank()) {
                    TextButton(onClick = {
                        customDoh = ""
                        viewModel.setCustomDohUrl("")
                    }) { Text("Сброс") }
                }
            }
            Text(
                "Пресеты DNS-override (hostname → IPv4 для HTTPS health):",
                style = MaterialTheme.typography.bodySmall,
            )
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                com.quantumvpn.config.DnsPresetCatalog.presets.forEach { preset ->
                    FilterChip(
                        selected = state.settings.dnsOverride.enabled &&
                            state.settings.dnsOverride.hostname == preset.hostname,
                        onClick = {
                            viewModel.setDnsOverride(preset.hostname, preset.ipv4)
                        },
                        label = { Text(preset.title) },
                    )
                }
            }
        }
    }
}

@Composable
internal fun AppearanceSettingsPage(
    contentPadding: PaddingValues,
    state: ProfilesUiState,
    viewModel: ProfilesViewModel,
    onBack: () -> Unit,
) {
    SettingsSubpage(contentPadding, "Внешний вид", onBack) {
        QvSection(title = "Тема") {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                ThemeMode.entries.forEach { mode ->
                    FilterChip(
                        selected = state.settings.themeMode == mode,
                        onClick = { viewModel.setTheme(mode) },
                        label = { Text(mode.name) },
                    )
                }
            }
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                AccentColor.entries.forEach { color ->
                    FilterChip(
                        selected = state.settings.accentColor == color,
                        onClick = { viewModel.setAccentColor(color) },
                        label = { Text(color.name) },
                    )
                }
            }
            QvToggleRow(
                title = "OLED чёрный",
                subtitle = "Чистый чёрный фон в тёмной теме",
                checked = state.settings.oledBlack,
                onCheckedChange = viewModel::setOledBlack,
                testTag = "hub-oled",
            )
            QvDivider()
            QvToggleRow(
                title = "Динамическая тема (Monet)",
                subtitle = "Цвета под обои (Android 12+)",
                checked = state.settings.useDynamicColor,
                onCheckedChange = viewModel::setUseDynamicColor,
                testTag = "hub-dynamic",
            )
            QvDivider()
            QvToggleRow(
                title = "Крупный текст",
                subtitle = "Увеличить базовый кегль",
                checked = state.settings.largeText,
                onCheckedChange = viewModel::setLargeText,
                testTag = "hub-large-text",
            )
            QvDivider()
            QvToggleRow(
                title = "Меньше анимаций",
                subtitle = "Reduce motion",
                checked = state.settings.reduceMotion,
                onCheckedChange = viewModel::setReduceMotion,
                testTag = "hub-reduce-motion",
            )
            QvDivider()
            QvToggleRow(
                title = "Высокий контраст",
                subtitle = "Чётче контуры и текст",
                checked = state.settings.highContrast,
                onCheckedChange = viewModel::setHighContrast,
                testTag = "hub-contrast",
            )
        }
        QvSection(title = "Главный экран") {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                HomeVisualTheme.entries.forEach { theme ->
                    FilterChip(
                        selected = state.settings.homeVisualTheme == theme,
                        onClick = { viewModel.setHomeVisualTheme(theme) },
                        label = {
                            Text(
                                when (theme) {
                                    HomeVisualTheme.Globe3d -> "3D-глобус"
                                    HomeVisualTheme.Classic -> "Классика"
                                },
                            )
                        },
                    )
                }
            }
            Text(
                "3D-глобус — объёмная сфера и стеклянная кнопка Connect. Классика — плоская карта.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            QvToggleRow(
                title = "Режим новичка",
                subtitle = "Только Connect, сервер и ad-block",
                checked = state.settings.beginnerMode,
                onCheckedChange = viewModel::setBeginnerMode,
                testTag = "hub-beginner",
            )
            QvDivider()
            QvToggleRow(
                title = "Компактный Home",
                subtitle = "Меньше отступов",
                checked = state.settings.compactHome,
                onCheckedChange = viewModel::setCompactHome,
                testTag = "hub-compact-home",
            )
            QvDivider()
            QvToggleRow(
                title = "Скрыть фон карты",
                subtitle = "Без глобуса/карты на Home",
                checked = state.settings.hideMap,
                onCheckedChange = viewModel::setHideMap,
                testTag = "hub-hide-map",
            )
        }
    }
}

@Composable
internal fun PrivacySettingsPage(
    contentPadding: PaddingValues,
    state: ProfilesUiState,
    viewModel: ProfilesViewModel,
    onBack: () -> Unit,
    onOpenPrivacyPromise: () -> Unit = {},
) {
    SettingsSubpage(contentPadding, "Приватность", onBack) {
        QvSection(title = "Защита приложения") {
            QvToggleRow(
                title = "App lock",
                subtitle = "Запрос разблокировки устройства",
                checked = state.settings.appLockEnabled,
                onCheckedChange = viewModel::setAppLockEnabled,
                testTag = "hub-app-lock",
            )
            QvDivider()
            QvToggleRow(
                title = "Biometric",
                subtitle = "Отпечаток / Face Unlock",
                checked = state.settings.biometricLockEnabled,
                onCheckedChange = viewModel::setBiometricLockEnabled,
                testTag = "hub-bio",
            )
            QvDivider()
            QvToggleRow(
                title = "Скрыть Exit IP",
                subtitle = "Не показывать IP на Home",
                checked = state.settings.hideExitIp,
                onCheckedChange = viewModel::setHideExitIp,
                testTag = "hub-hide-ip",
            )
            QvDivider()
            QvToggleRow(
                title = "Инкогнито-сессия",
                subtitle = "Не писать журнал/события до отключения",
                checked = state.settings.incognitoSession,
                onCheckedChange = viewModel::setIncognitoSession,
                testTag = "hub-incognito",
            )
            QvDivider()
            QvToggleRow(
                title = "Блок WebRTC / mDNS",
                subtitle = "STUN и multicast в runtime overlay",
                checked = state.settings.blockWebRtcMdns,
                onCheckedChange = viewModel::setBlockWebRtcMdns,
                testTag = "hub-webrtc",
            )
            QvDivider()
            OutlinedButton(
                onClick = viewModel::startStealthThirtyMinutes,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    if (state.settings.stealthUntilEpochMillis > System.currentTimeMillis()) {
                        "Stealth активен"
                    } else {
                        "Stealth 30 мин"
                    },
                )
            }
            QvDivider()
            QvToggleRow(
                title = "FLAG_SECURE",
                subtitle = "Блокировать скриншоты экрана",
                checked = state.settings.flagSecure,
                onCheckedChange = viewModel::setFlagSecure,
                testTag = "hub-flag-secure",
            )
        }
        QvSection(title = "Обещание") {
            QvNavRow(
                title = "Что мы не собираем",
                subtitle = "Локальная политика приватности",
                onClick = onOpenPrivacyPromise,
            )
        }
    }
}

@Composable
internal fun ScheduleSettingsPage(
    contentPadding: PaddingValues,
    state: ProfilesUiState,
    viewModel: ProfilesViewModel,
    onBack: () -> Unit,
) {
    SettingsSubpage(contentPadding, "Расписание", onBack) {
        QvSection(title = "Автоматика") {
            QvToggleRow(
                title = "Ночное подключение",
                subtitle = "Подключать VPN ночью",
                checked = state.settings.scheduleNightAutoConnect,
                onCheckedChange = viewModel::setScheduleNightAutoConnect,
                testTag = "hub-night",
            )
            QvDivider()
            QvToggleRow(
                title = "Утреннее отключение",
                subtitle = "Отключать VPN утром",
                checked = state.settings.scheduleMorningDisconnect,
                onCheckedChange = viewModel::setScheduleMorningDisconnect,
                testTag = "hub-morning",
            )
            QvDivider()
            QvToggleRow(
                title = "Рабочий день",
                subtitle = "Подключать в рабочие часы",
                checked = state.settings.scheduleWorkConnect,
                onCheckedChange = viewModel::setScheduleWorkConnect,
                testTag = "hub-work",
            )
            QvDivider()
            QvToggleRow(
                title = "Time routing",
                subtitle = "Правила маршрутизации по времени",
                checked = state.settings.timeRoutingEnabled,
                onCheckedChange = viewModel::setTimeRoutingEnabled,
                testTag = "hub-time-routing",
            )
        }
        QvSection(title = "Подписки") {
            Text("Автообновление подписок всегда включено: при запуске, каждые 30 мин в фоне и по расписанию.")
            Text("Интервал alarm сейчас: ${state.settings.subscriptionRefreshHours} ч")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf(1, 6, 12, 24).forEach { hours ->
                    FilterChip(
                        selected = state.settings.subscriptionRefreshHours == hours,
                        onClick = { viewModel.setSubscriptionRefreshHours(hours) },
                        label = { Text("${hours}ч") },
                    )
                }
            }
            Text("Приоритет профилей: CSV id в порядке предпочтения.")
            Text(
                state.settings.subscriptionPriorityIds.ifBlank { "Не задан — порядок списка по умолчанию" },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
internal fun UpdatesSettingsPage(
    contentPadding: PaddingValues,
    state: ProfilesUiState,
    viewModel: ProfilesViewModel,
    updateState: UpdateState,
    onCheckUpdate: (UpdateChannel) -> Unit,
    onDownloadUpdate: () -> Unit,
    onInstallUpdate: () -> Unit,
    onCancelUpdate: () -> Unit,
    onBack: () -> Unit,
) {
    SettingsSubpage(contentPadding, "Обновления", onBack) {
        QvSection(title = "Канал") {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                UpdateChannel.entries.forEach { ch ->
                    FilterChip(
                        selected = state.settings.updateChannel == ch,
                        onClick = { viewModel.setUpdateChannel(ch) },
                        label = { Text(ch.name) },
                    )
                }
            }
            Text(
                "Сначала FTP (manifest-stable / manifest-beta), затем GitHub. " +
                    "Виджеты: 2×2 и широкий 4×2 (трафик + серверы) — на рабочий стол Android.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            UpdateControls(
                state = updateState,
                channel = state.settings.updateChannel,
                onCheck = onCheckUpdate,
                onDownload = onDownloadUpdate,
                onInstall = onInstallUpdate,
                onCancel = onCancelUpdate,
            )
        }
    }
}

@Composable
internal fun OperatorHelpPage(
    contentPadding: PaddingValues,
    state: ProfilesUiState,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val carrier = remember(context) { com.quantumvpn.vpn.CarrierDetector.snapshot(context) }
    SettingsSubpage(contentPadding, "Помощь по операторам", onBack) {
        QvSection(title = "Сейчас") {
            Text(
                buildString {
                    append("Сеть: ")
                    append(carrier.displayLabel ?: if (carrier.isCellular) "мобильная" else "Wi‑Fi/другое")
                    carrier.operatorNumeric?.let { append(" · $it") }
                    if (carrier.isTele2Family) append(" · семья Т2")
                    if (carrier.suggestsStrongBypass) append(" · нужен сильный обход")
                },
            )
            val presetLabel = when (state.settings.bypassPreset) {
                com.quantumvpn.hardening.BypassPreset.Soft -> "Мягкий"
                com.quantumvpn.hardening.BypassPreset.Standard -> "Стандарт"
                com.quantumvpn.hardening.BypassPreset.Tele2 -> "Оператор"
                com.quantumvpn.hardening.BypassPreset.Aggressive -> "Агрессивный"
            }
            Text("Обход DPI: всегда вкл · $presetLabel")
            Text(
                "Усиленный режим: ${if (state.settings.carrierBypassAlwaysAggressive || state.settings.bypassPreset == com.quantumvpn.hardening.BypassPreset.Tele2 || state.settings.bypassPreset == com.quantumvpn.hardening.BypassPreset.Aggressive) "вкл" else "выкл"}",
            )
        }
        QvSection(title = "Чеклист «нет трафика»") {
            Text("1. На Home нажмите «Сброс сети» — вернёт Standard DPI + Secure DNS.")
            Text("2. Обход работает на всех операторах и протоколах: VLESS/Trojan/Hysteria/TUIC.")
            Text("3. Reality не получает ClientHello-fragment (это ломало весь трафик).")
            Text("4. Safe mode выключите; усиленный режим должен быть включён при блокировках.")
            Text("5. Переподключите VPN после смены обхода.")
            Text("6. WireGuard почти не получает DPI-bypass — лучше Hysteria/Reality.")
        }
    }
}

@Composable
internal fun DeveloperSettingsPage(
    contentPadding: PaddingValues,
    onOpen: (SettingsDestination) -> Unit,
    onBack: () -> Unit,
) {
    SettingsSubpage(contentPadding, "Для разработчиков", onBack) {
        QvSection(title = "Документация в приложении") {
            listOf(
                Triple("Модель угроз", "Threat model", SettingsDestination.ThreatModel),
                Triple("Приватность", "Privacy promise", SettingsDestination.PrivacyPromise),
                Triple("Глоссарий ошибок", "VPN codes", SettingsDestination.ErrorGlossary),
                Triple("OEM-советы", "MIUI / Huawei…", SettingsDestination.OemQuirks),
                Triple("Доступность", "A11y", SettingsDestination.A11yStatement),
                Triple("Аудит настроек", "Лог изменений", SettingsDestination.AuditLog),
                Triple("Симулятор маршрута", "Куда уйдёт домен", SettingsDestination.RouteSim),
                Triple("Чеклист безопасности", "Kill switch / DNS / lock", SettingsDestination.Checklist),
                Triple("Журнал", "События", SettingsDestination.Journal),
                Triple("FAQ", "Частые вопросы", SettingsDestination.Faq),
                Triple("Changelog", "Что нового", SettingsDestination.Changelog),
                Triple("Дорожная карта 1000", "Только для разработки", SettingsDestination.Backlog),
            ).forEachIndexed { index, (title, subtitle, dest) ->
                if (index > 0) QvDivider()
                QvNavRow(title, subtitle, onClick = { onOpen(dest) })
            }
        }
    }
}

@Composable
internal fun HealthDashboardPage(
    contentPadding: PaddingValues,
    state: ProfilesUiState,
    vpnState: VpnConnectionState,
    sessionStats: VpnSessionStats,
    diagnostics: DiagnosticState,
    viewModel: ProfilesViewModel,
    onBack: () -> Unit,
) {
    val reliability by viewModel.reliabilitySummary.collectAsState(initial = null)
    SettingsSubpage(contentPadding, "Здоровье VPN", onBack) {
        QvSection(title = "Сессия") {
            Text(
                when (vpnState) {
                    is VpnConnectionState.Connected -> "Подключено · ${vpnState.profileName}"
                    is VpnConnectionState.Starting -> "Подключение…"
                    is VpnConnectionState.Error -> "Ошибка: ${vpnState.message.take(80)}"
                    else -> "Отключено"
                },
            )
            sessionStats.externalIp?.let { Text("Exit IP: $it") }
            sessionStats.pingMillis?.let { Text("Пинг: $it ms") }
            Text("↑ ${sessionStats.uploadTotalBytes} · ↓ ${sessionStats.downloadTotalBytes} байт")
        }
        QvSection(title = "Надёжность") {
            Text(reliability?.summaryRu ?: "Пока нет статистики connect.")
            Text("Fail streak DPI: ${state.settings.connectFailStreak}")
            Text("Последний спидтест: ${state.settings.lastSpeedTestDetail.ifBlank { "—" }}")
        }
        QvSection(title = "Система") {
            Text("Always-on: ${diagnostics.vpnPolicy?.alwaysOn == true}")
            Text("Lockdown: ${diagnostics.vpnPolicy?.lockdown == true}")
            Text("Private DNS: ${diagnostics.network?.privateDnsActive == true}")
            Text("Validated: ${diagnostics.network?.validated != false}")
        }
    }
}

@Composable
internal fun SystemWizardsPage(
    contentPadding: PaddingValues,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    SettingsSubpage(contentPadding, "Always-on и батарея", onBack) {
        QvSection(title = "1. Always-on VPN") {
            Text("Включите Always-on VPN в системных настройках Android для этого приложения.")
            OutlinedButton(
                onClick = {
                    runCatching {
                        context.startActivity(
                            Intent(AndroidSettings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                        )
                    }
                },
            ) { Text("Открыть настройки VPN") }
        }
        QvSection(title = "2. Без оптимизации батареи") {
            Text("На Xiaomi/Huawei/Samsung VPN должен игнорировать оптимизацию батареи.")
            OutlinedButton(
                onClick = {
                    runCatching {
                        val intent = com.quantumvpn.vpn.VpnBatteryExemption.requestIntent(context)
                        if (intent != null) context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                        else context.startActivity(
                            Intent(AndroidSettings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                        )
                    }
                },
            ) { Text("Открыть батарею") }
        }
        QvSection(title = "3. Private DNS") {
            Text(
                "Для блокировки рекламы поставьте Private DNS: «Автоматически» или «Выкл.» " +
                    "(не «Указанный DNS» / Strict).",
            )
            OutlinedButton(
                onClick = {
                    com.quantumvpn.hardening.AdBlockConnectPreflight.openPrivateDnsSettings(context)
                },
            ) { Text("Открыть Private DNS") }
        }
        QvSection(title = "4. Проверка") {
            Text("Вернитесь на Home: баннеры Always-on / батарея пропадут после настройки.")
        }
    }
}

@Composable
internal fun AdBlockSettingsPage(
    contentPadding: PaddingValues,
    state: ProfilesUiState,
    viewModel: ProfilesViewModel,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    var whitelist by rememberSaveable { mutableStateOf(state.settings.adBlockWhitelist) }
    val ruleCount = remember(
        state.settings.adBlockLevel,
        state.settings.adBlockTrackersOnly,
        state.settings.adBlockEnabled,
        state.settings.adBlockWhitelist,
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
            ),
        )
    }
    SettingsSubpage(contentPadding, "Блокировка рекламы", onBack) {
        QvSection(title = "Общее") {
            Text(
                "При включённом VPN блокирует рекламу и трекеры в браузерах, приложениях и видео. " +
                    "Перед каждым подключением приложение само ставит: Максимум + AdGuard DoH, " +
                    "Safe mode выкл.; при Strict Private DNS откроет системные настройки.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            QvToggleRow(
                title = "Блокировка рекламы",
                subtitle = if (state.settings.adBlockEnabled) {
                    "Включена · ~$ruleCount правил DNS/маршрут"
                } else {
                    "Выключена — реклама не фильтруется"
                },
                checked = state.settings.adBlockEnabled,
                onCheckedChange = viewModel::setAdBlockEnabled,
                testTag = "adblock-enabled",
            )
            QvDivider()
            QvToggleRow(
                title = "Онлайн DNS-фильтр (AdGuard DoH)",
                subtitle = "Keyword-домены через AdGuard DNS через VPN; ловит новые ad-сети",
                checked = state.settings.adBlockOnlineDns,
                onCheckedChange = viewModel::setAdBlockOnlineDns,
                testTag = "adblock-online-dns",
                enabled = state.settings.adBlockEnabled,
            )
            Text(
                "Всего заблокировано рекламы/трекеров за всё время: " +
                    state.settings.cumulativeBlocked.toString().reversed()
                        .chunked(3) { it.reversed() }.reversed().joinToString(" "),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary,
            )
        }
        QvSection(title = "Уровень списков") {
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.horizontalScroll(rememberScrollState()),
            ) {
                com.quantumvpn.hardening.AdBlockLevel.entries.forEach { level ->
                    FilterChip(
                        selected = state.settings.adBlockLevel == level,
                        onClick = { viewModel.setAdBlockLevel(level) },
                        enabled = state.settings.adBlockEnabled,
                        label = {
                            Text(
                                when (level) {
                                    com.quantumvpn.hardening.AdBlockLevel.Light -> "Лёгкий"
                                    com.quantumvpn.hardening.AdBlockLevel.Standard -> "Стандарт"
                                    com.quantumvpn.hardening.AdBlockLevel.Hard -> "Жёсткий"
                                    com.quantumvpn.hardening.AdBlockLevel.Maximum -> "Максимум"
                                },
                            )
                        },
                    )
                }
            }
            Text(
                "Лёгкий — крупные сети; Стандарт — + RU/VK/Yandex и mobile SDK; " +
                    "Жёсткий — максимум списков; Максимум — весь DNS идёт через блокирующий " +
                    "AdGuard (ловит и новые/неизвестные ad-домены, не только статику).",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            QvToggleRow(
                title = "Только трекеры",
                subtitle = "Без крупных ad-сетей (мягче для сайтов с ложными срабатываниями)",
                checked = state.settings.adBlockTrackersOnly,
                onCheckedChange = viewModel::setAdBlockTrackersOnly,
                testTag = "adblock-trackers",
                enabled = state.settings.adBlockEnabled,
            )
        }
        QvSection(title = "Категории контента") {
            Text(
                "Блокировка целых категорий доменов поверх списков рекламы/трекеров. " +
                    "Работает независимо от уровня выше.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            com.quantumvpn.hardening.AdBlockCategory.entries.forEachIndexed { index, cat ->
                if (index > 0) QvDivider()
                val active = state.settings.adBlockCategories.contains(cat)
                QvToggleRow(
                    title = when (cat) {
                        com.quantumvpn.hardening.AdBlockCategory.Adult -> "18+ / Adult"
                        com.quantumvpn.hardening.AdBlockCategory.Social -> "Соцсети"
                        com.quantumvpn.hardening.AdBlockCategory.Gambling -> "Азартные игры"
                        com.quantumvpn.hardening.AdBlockCategory.Regional -> "Региональные (RU)"
                    },
                    subtitle = when (cat) {
                        com.quantumvpn.hardening.AdBlockCategory.Adult -> "Порно и adult-сети"
                        com.quantumvpn.hardening.AdBlockCategory.Social -> "Facebook, VK, TikTok, YouTube…"
                        com.quantumvpn.hardening.AdBlockCategory.Gambling -> "Букмекеры и казино"
                        com.quantumvpn.hardening.AdBlockCategory.Regional -> "RU рекламные/трекер-сети"
                    },
                    checked = active,
                    enabled = state.settings.adBlockEnabled,
                    testTag = "adblock-cat-${cat.name.lowercase()}",
                    onCheckedChange = { on ->
                        val next = if (on) {
                            state.settings.adBlockCategories + cat
                        } else {
                            state.settings.adBlockCategories - cat
                        }
                        viewModel.setAdBlockCategories(next)
                    },
                )
            }
        }
        QvSection(title = "Как это работает") {
            Text("• Перехват DNS: порт 53 + DoH/DoT (protocol dns) → sing-box")
            Text("• DNS reject: ad-домены → NXDOMAIN")
            Text("• Маршрут reject: пакеты к ad-хостам не проходят даже при прямом IP")
            Text("• AdGuard DoH: keyword-домены и режим «Максимум» — онлайн-фильтр")
            Text("• Перед Connect: Maximum + AdGuard + Safe mode off автоматически")
            Text("• Действует на весь трафик внутри VPN")
            OutlinedButton(
                onClick = {
                    com.quantumvpn.hardening.AdBlockConnectPreflight.openPrivateDnsSettings(context)
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Открыть Private DNS Android")
            }
            Text(
                "Переподключение VPN выполняется автоматически при изменении настроек.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary,
            )
        }
        QvSection(title = "Whitelist") {
            OutlinedTextField(
                value = whitelist,
                onValueChange = { whitelist = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Домены через запятую") },
                placeholder = { Text("example.com, cdn.mysite.ru") },
                enabled = state.settings.adBlockEnabled,
            )
            OutlinedButton(
                onClick = { viewModel.setAdBlockWhitelist(whitelist) },
                enabled = state.settings.adBlockEnabled,
            ) {
                Text("Сохранить whitelist")
            }
        }
    }
}
