package com.quantumvpn.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.remember
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.core.graphics.drawable.toBitmap
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.material3.AlertDialog
import com.quantumvpn.vpn.NamedAppSet
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.quantumvpn.vpn.AppsUiState
import com.quantumvpn.vpn.AppsViewModel
import com.quantumvpn.vpn.AppScopeMode
import com.quantumvpn.vpn.AppScopePreset
import com.quantumvpn.vpn.InstalledApp
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.FilterChip

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppPickerScreen(
    state: AppsUiState,
    viewModel: AppsViewModel,
    onBack: () -> Unit,
    showCoachMark: Boolean = false,
    onDismissCoachMark: () -> Unit = {},
) {
    var query by rememberSaveable { mutableStateOf("") }
    var showSystem by rememberSaveable { mutableStateOf(false) }
    var saveSetName by rememberSaveable { mutableStateOf("") }
    var showSaveDialog by rememberSaveable { mutableStateOf(false) }
    val namedSets by viewModel.namedSets.collectAsState(initial = emptyList())
    BackHandler(onBack = onBack)

    val matchingApps = state.apps.filter { app ->
        query.isBlank() ||
            app.label.contains(query, ignoreCase = true) ||
            app.packageName.contains(query, ignoreCase = true)
    }
    val suggestedApps = matchingApps.filter { it.suggestion != null }
    val regularApps = matchingApps.filter { app ->
        app.suggestion == null && (
            !app.system || showSystem || app.packageName in state.allowedPackages
        )
    }

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = {
                    Text(
                        when (state.scopeMode) {
                            AppScopeMode.Include -> "Приложения для VPN"
                            AppScopeMode.Exclude -> "Приложения напрямую"
                            AppScopeMode.Block -> "Блокировка приложений"
                            AppScopeMode.All -> "Все приложения (полный VPN)"
                        },
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Назад")
                    }
                },
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(bottom = 24.dp),
        ) {
            if (showCoachMark) {
                item(key = "coach-mark") {
                    CoachMarkBanner(
                        screen = CoachMarkScreen.Apps,
                        onDismiss = onDismissCoachMark,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                    )
                }
            }
            item(key = "controls") {
                Column(
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    OutlinedTextField(
                        value = query,
                        onValueChange = { query = it },
                        label = { Text("Поиск по имени или package") },
                        singleLine = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("app-search"),
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Показывать системные")
                            Text(
                                "Службы Android скрыты по умолчанию",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        Switch(
                            checked = showSystem,
                            onCheckedChange = { showSystem = it },
                            modifier = Modifier
                                .testTag("show-system-apps")
                                .semantics {
                                    contentDescription = "Показывать системные приложения"
                                },
                        )
                    }
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        listOf(
                            AppScopeMode.All to "Все",
                            AppScopeMode.Include to "VPN",
                            AppScopeMode.Exclude to "Мимо VPN",
                            AppScopeMode.Block to "Блок",
                        ).forEach { (mode, label) ->
                            FilterChip(
                                selected = state.scopeMode == mode,
                                onClick = { viewModel.setScopeMode(mode) },
                                label = { Text(label) },
                            )
                        }
                    }
                    Text(
                        when (state.scopeMode) {
                            AppScopeMode.All -> "Весь трафик устройства через VPN."
                            AppScopeMode.Include -> "В VPN: ${state.allowedPackages.size}"
                            AppScopeMode.Exclude -> "Напрямую вне VPN: ${state.allowedPackages.size}"
                            AppScopeMode.Block -> "Заблокировано в TUN: ${state.allowedPackages.size}"
                        },
                        style = MaterialTheme.typography.titleMedium,
                    )
                    if (state.scopeMode == AppScopeMode.Block) {
                        Text(
                            "Отмеченные приложения попадают в TUN, но их сеть отклоняется (reject). " +
                                "Остальные приложения не затрагиваются.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                    if (state.scopeMode == AppScopeMode.Exclude) {
                        Text(
                            "Отмеченные приложения используют обычную сеть Android вне VPN и TUN; " +
                                "все остальные идут через VPN. Глобальный tun0 при этом может оставаться видимым. " +
                                "Пустой список заблокирован.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                    Text(
                        "Список приложений обрабатывается только на устройстве и никуда не отправляется.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text("Быстрые пресеты (режим «только выбранные»)", fontWeight = FontWeight.Medium)
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        AppScopePreset.entries.forEach { preset ->
                            FilterChip(
                                selected = false,
                                onClick = { viewModel.applyPreset(preset) },
                                label = { Text(preset.title) },
                            )
                        }
                        FilterChip(
                            selected = false,
                            onClick = viewModel::clearAllowlist,
                            label = { Text("Очистить") },
                        )
                    }
                    Text(
                        "Пресет включает найденные на устройстве приложения из категории.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text("Игровой режим (низкий пинг)", fontWeight = FontWeight.Medium)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Игры напрямую")
                            Text(
                                "Выбранные игры идут мимо VPN-сервера кратчайшим маршрутом. " +
                                    "При включении VPN перезапустится.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        Switch(
                            checked = state.gameModeEnabled,
                            onCheckedChange = { viewModel.setGameModeEnabled(it) },
                            modifier = Modifier
                                .testTag("game-mode-switch")
                                .semantics {
                                    contentDescription = "Игровой режим"
                                },
                        )
                    }
                    if (state.gameModeEnabled) {
                        if (state.detectedGames.isEmpty()) {
                            Text(
                                "Игры из каталога не найдены на устройстве.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        state.detectedGames.forEach { game ->
                            val allSelected = game.selectedPackages.containsAll(game.installedPackages)
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        viewModel.setGamePackagesEnabled(
                                            game.installedPackages,
                                            !allSelected,
                                        )
                                    },
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(game.profile.title)
                                    Text(
                                        game.profile.detail,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                                Checkbox(
                                    checked = allSelected,
                                    onCheckedChange = { checked ->
                                        viewModel.setGamePackagesEnabled(
                                            game.installedPackages,
                                            checked,
                                        )
                                    },
                                    modifier = Modifier.testTag("game-${game.profile.id}"),
                                )
                            }
                        }
                        OutlinedButton(onClick = viewModel::enableDetectedGames) {
                            Text("Выбрать все найденные игры")
                        }
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        OutlinedButton(
                            onClick = {
                                val visible = (suggestedApps + regularApps).map { it.packageName }
                                viewModel.selectAllVisible(visible)
                            },
                            modifier = Modifier.weight(1f),
                        ) { Text("Все видимые") }
                        OutlinedButton(
                            onClick = {
                                val visible = (suggestedApps + regularApps).map { it.packageName }
                                viewModel.invertSelection(visible)
                            },
                            modifier = Modifier.weight(1f),
                        ) { Text("Инверт") }
                    }
                    OutlinedButton(
                        onClick = { showSaveDialog = true },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = state.allowedPackages.isNotEmpty(),
                    ) { Text("Сохранить набор…") }
                    if (namedSets.isNotEmpty()) {
                        Text("Сохранённые наборы", fontWeight = FontWeight.Medium)
                        namedSets.forEach { set ->
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                FilterChip(
                                    selected = false,
                                    onClick = { viewModel.loadNamedSet(set) },
                                    label = { Text("${set.name} (${set.packages.size})") },
                                )
                                TextButton(onClick = { viewModel.deleteNamedSet(set.name) }) {
                                    Text("✕")
                                }
                            }
                        }
                    }
                }
            }

            if (state.loading) {
                item(key = "loading") {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(24.dp),
                        horizontalArrangement = Arrangement.Center,
                    ) {
                        CircularProgressIndicator()
                    }
                }
            }

            state.error?.let { loadError ->
                item(key = "error") {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text(loadError, color = MaterialTheme.colorScheme.error)
                        OutlinedButton(onClick = viewModel::refresh) { Text("Повторить") }
                    }
                }
            }

            if (state.missingPackages.isNotEmpty()) {
                item(key = "missing-header") {
                    SectionHeader("Недоступные")
                }
                items(state.missingPackages.toList(), key = { "missing-$it" }) { packageName ->
                    MissingAppRow(
                        packageName = packageName,
                        onRemove = { viewModel.setAllowed(packageName, false) },
                    )
                }
            }

            if (suggestedApps.isNotEmpty()) {
                item(key = "suggested-header") {
                    SectionHeader("Популярные")
                }
                items(suggestedApps, key = { "suggested-${it.packageName}" }) { app ->
                    AppRow(app, state.allowedPackages, viewModel)
                }
            }

            if (regularApps.isNotEmpty()) {
                item(key = "apps-header") {
                    SectionHeader(if (showSystem) "Все приложения" else "Установленные")
                }
                items(regularApps, key = InstalledApp::packageName) { app ->
                    AppRow(app, state.allowedPackages, viewModel)
                }
            }

            if (!state.loading && state.error == null &&
                suggestedApps.isEmpty() && regularApps.isEmpty() &&
                state.missingPackages.isEmpty()
            ) {
                item(key = "empty") {
                    Text(
                        if (query.isBlank()) "Приложения не найдены." else "По запросу ничего не найдено.",
                        modifier = Modifier.padding(24.dp),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            if (state.missingPackages.isNotEmpty()) {
                item(key = "remove-missing") {
                    TextButton(
                        onClick = viewModel::removeMissingPackages,
                        modifier = Modifier.padding(horizontal = 8.dp),
                    ) {
                        Text("Удалить все недоступные")
                    }
                }
            }
        }
    }

    if (showSaveDialog) {
        AlertDialog(
            onDismissRequest = { showSaveDialog = false },
            title = { Text("Имя набора") },
            text = {
                OutlinedTextField(
                    value = saveSetName,
                    onValueChange = { saveSetName = it.take(40) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    placeholder = { Text("Например: Работа") },
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        viewModel.saveNamedSet(saveSetName)
                        showSaveDialog = false
                        saveSetName = ""
                    },
                    enabled = saveSetName.isNotBlank() && state.allowedPackages.isNotEmpty(),
                ) {
                    Text("Сохранить")
                }
            },
            dismissButton = {
                TextButton(onClick = { showSaveDialog = false }) { Text("Отмена") }
            },
        )
    }
}

@Composable
private fun SectionHeader(title: String) {
    Text(
        text = title,
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.Bold,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier
            .padding(horizontal = 16.dp, vertical = 10.dp)
            .semantics { heading() },
    )
}

@Composable
private fun AppRow(
    app: InstalledApp,
    selectedPackages: Set<String>,
    viewModel: AppsViewModel,
) {
    val context = LocalContext.current
    val selected = app.packageName in selectedPackages
    val canToggle = app.enabled || selected
    val iconBitmap = remember(app.packageName) {
        runCatching {
            context.packageManager.getApplicationIcon(app.packageName).toBitmap().asImageBitmap()
        }.getOrNull()
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 64.dp)
            .testTag("app-row-${app.packageName}")
            .clickable(enabled = canToggle) {
                viewModel.setAllowed(app.packageName, !selected)
            }
            .padding(horizontal = 16.dp, vertical = 10.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (iconBitmap != null) {
            Image(
                bitmap = iconBitmap,
                contentDescription = null,
                modifier = Modifier.size(40.dp),
            )
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(app.label, fontWeight = FontWeight.Medium)
            Text(
                app.packageName,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            val details = buildList {
                app.suggestion?.let { add("Рекомендуем: $it") }
                if (app.system) add("Системное")
                if (!app.enabled) add("Отключено")
            }.joinToString(" · ")
            if (details.isNotEmpty()) {
                Text(
                    details,
                    style = MaterialTheme.typography.labelSmall,
                    color = if (app.enabled) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.error
                    },
                )
            }
        }
        Checkbox(
            checked = selected,
            onCheckedChange = null,
            enabled = canToggle,
        )
    }
    HorizontalDivider()
}

@Composable
private fun MissingAppRow(
    packageName: String,
    onRemove: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 64.dp)
            .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(packageName, fontWeight = FontWeight.Medium)
            Text(
                "Пакет удалён или недоступен. VPN не запустится.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
        TextButton(onClick = onRemove) { Text("Убрать") }
    }
    HorizontalDivider()
}
