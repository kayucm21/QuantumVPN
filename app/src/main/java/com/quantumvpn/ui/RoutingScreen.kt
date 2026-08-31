package com.quantumvpn.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.quantumvpn.routing.ManagedRoutingRule
import com.quantumvpn.routing.RoutingMatchType
import com.quantumvpn.routing.RoutingPreset
import com.quantumvpn.routing.RoutingRuleAction
import com.quantumvpn.routing.RoutingUiState
import com.quantumvpn.routing.RoutingViewModel
import com.quantumvpn.ui.components.QvHubHeader
import com.quantumvpn.ui.components.QvSection

@Composable
fun RoutingScreen(
    contentPadding: PaddingValues,
    routingState: RoutingUiState,
    routingViewModel: RoutingViewModel,
    timeRoutingEnabled: Boolean = false,
    showCoachMark: Boolean = false,
    onDismissCoachMark: () -> Unit = {},
) {
    var editedRule by remember { mutableStateOf<Pair<Int?, ManagedRoutingRule>?>(null) }
    val inspection = routingState.inspection

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(contentPadding)
            .testTag("routing-list"),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (showCoachMark) {
            item(key = "coach") {
                CoachMarkBanner(
                    screen = CoachMarkScreen.Routing,
                    onDismiss = onDismissCoachMark,
                )
            }
        }
        item(key = "header") {
            QvHubHeader(
                title = "Маршруты",
                subtitle = "Пресеты сверху, свои правила ниже",
            )
        }
        item(key = "traffic") {
            var testDomain by remember { mutableStateOf("") }
            var testResult by remember { mutableStateOf<String?>(null) }
            val inspection = routingState.inspection
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        "Правило трафика",
                        style = MaterialTheme.typography.titleLarge,
                        modifier = Modifier.semantics { heading() },
                    )
                    if (routingState.activeProfileId == null) {
                        Text("Сначала выберите активный профиль.", color = MaterialTheme.colorScheme.error)
                    } else if (inspection == null || routingState.loading) {
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            CircularProgressIndicator()
                            Text("Чтение настоящего JSON…")
                        }
                    } else if (routingState.happRoutingAvailable) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text("Включить маршрутизацию", fontWeight = FontWeight.SemiBold)
                                Text(
                                    "Профили из подписки (Happ)",
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            androidx.compose.material3.Switch(
                                checked = routingState.happCatalog.enabled,
                                onCheckedChange = routingViewModel::setHappRoutingEnabled,
                                enabled = !routingState.loading,
                            )
                        }
                        Text("Профили", style = MaterialTheme.typography.titleMedium)
                        routingState.happCatalog.profiles.forEach { profile ->
                            val selected = routingState.happCatalog.enabled &&
                                routingState.happCatalog.activeName == profile.name
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable(enabled = routingState.happCatalog.enabled) {
                                        routingViewModel.selectHappRoutingProfile(profile.name)
                                    },
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                RadioButton(
                                    selected = selected,
                                    onClick = {
                                        routingViewModel.selectHappRoutingProfile(profile.name)
                                    },
                                    enabled = routingState.happCatalog.enabled,
                                )
                                Text(profile.name, fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal)
                            }
                        }
                        Text("Итог", style = MaterialTheme.typography.titleMedium)
                        Text(
                            inspection.summary,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        routingState.ruleSetVersion?.let { version ->
                            Text(
                                "Списки маршрутизации: v$version",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        OutlinedButton(
                            onClick = routingViewModel::refreshRuleSets,
                            enabled = !routingState.loading,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text("Обновить маршруты / rule-set")
                        }
                        OutlinedButton(
                            onClick = {
                                routingViewModel.refreshRuleSetsFromRemote(
                                    "https://raw.githubusercontent.com/youtubediscord/QuantumVPN-android/main/app/src/main/assets/rule-sets/manifest.json",
                                )
                            },
                            enabled = !routingState.loading,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text("Обновить rule-set с GitHub (HTTPS)")
                        }
                    } else {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .horizontalScroll(rememberScrollState()),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            RoutingPreset.entries.forEach { preset ->
                                FilterChip(
                                    selected = inspection.preset == preset,
                                    onClick = { routingViewModel.applyPreset(preset) },
                                    enabled = !routingState.loading,
                                    label = { Text(preset.title) },
                                )
                            }
                        }
                        Text(
                            inspection.preset.detail,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Text("Итог", style = MaterialTheme.typography.titleMedium)
                        Text(
                            inspection.summary,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        routingState.ruleSetVersion?.let { version ->
                            Text(
                                "Списки маршрутизации: v$version (встроенные, обновляются с APK и по кнопке ниже)",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        OutlinedButton(
                            onClick = routingViewModel::refreshRuleSets,
                            enabled = !routingState.loading,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text("Обновить маршруты / rule-set")
                        }
                        OutlinedButton(
                            onClick = {
                                routingViewModel.refreshRuleSetsFromRemote(
                                    "https://raw.githubusercontent.com/youtubediscord/QuantumVPN-android/main/app/src/main/assets/rule-sets/manifest.json",
                                )
                            },
                            enabled = !routingState.loading,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text("Обновить rule-set с GitHub (HTTPS)")
                        }
                    }
                    if (inspection != null && !routingState.loading) {
                        androidx.compose.material3.HorizontalDivider()
                        OutlinedTextField(
                            value = testDomain,
                            onValueChange = { testDomain = it },
                            label = { Text("Тест домена") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Button(
                            onClick = {
                                val domain = testDomain.trim()
                                testResult = if (domain.isBlank()) {
                                    "Введите домен."
                                } else {
                                    val result = RouteSimulator.simulate(
                                        domainRaw = domain,
                                        presetTitle = inspection.preset.title,
                                        summary = inspection.summary,
                                        timeRoutingEnabled = timeRoutingEnabled,
                                    )
                                    "${result.domain} → ${result.action}: ${result.detail}"
                                }
                            },
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text("Проверить маршрут") }
                        testResult?.let { result ->
                            Text(
                                result,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.primary,
                            )
                        }
                    }
                }
            }
        }

        if (inspection != null) {
            item(key = "rules-title") {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column {
                        Text(
                            "Правила",
                            style = MaterialTheme.typography.titleLarge,
                            modifier = Modifier.semantics { heading() },
                        )
                        Text(
                            "Домены, IP/CIDR и rule-set",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Button(
                        onClick = {
                            editedRule = null to ManagedRoutingRule(
                                RoutingMatchType.Domain,
                                emptyList(),
                                RoutingRuleAction.Proxy,
                            )
                        },
                        enabled = !routingState.loading,
                    ) { Text("Добавить") }
                }
            }

            itemsIndexed(inspection.rules, key = { index, rule -> "$index-${rule.hashCode()}" }) { index, rule ->
                ElevatedCard(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 72.dp)
                        .clickable { editedRule = index to rule }
                        .semantics {
                            contentDescription =
                                "Редактировать правило ${rule.action.title}: ${rule.values.joinToString()}"
                        },
                ) {
                    Column(
                        modifier = Modifier.padding(14.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        Text(rule.action.title, color = actionColor(rule.action), fontWeight = FontWeight.Bold)
                        Text("${rule.matchType.title}: ${rule.values.joinToString()}")
                        val outbound = rule.outboundTag
                        if (outbound != null) {
                            Text("Outbound: $outbound", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }

            if (inspection.rules.isEmpty()) {
                item(key = "rules-empty") {
                    Text(
                        "Пользовательских правил нет.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        routingState.managedDiff?.let { diff ->
            item(key = "diff") {
                ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier.padding(18.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text("Последний diff zapret-*", style = MaterialTheme.typography.titleMedium)
                        Text(diff, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }

    editedRule?.let { (index, rule) ->
        RuleEditorDialog(
            initial = rule,
            onDismiss = { editedRule = null },
            onSave = {
                routingViewModel.saveRule(index, it)
                editedRule = null
            },
            onDelete = index?.let {
                {
                    routingViewModel.deleteRule(it)
                    editedRule = null
                }
            },
        )
    }
}

@Composable
private fun RuleEditorDialog(
    initial: ManagedRoutingRule,
    onDismiss: () -> Unit,
    onSave: (ManagedRoutingRule) -> Unit,
    onDelete: (() -> Unit)?,
) {
    var matchType by remember(initial) { mutableStateOf(initial.matchType) }
    var action by remember(initial) { mutableStateOf(initial.action) }
    var values by remember(initial) { mutableStateOf(initial.values.joinToString("\n")) }
    var outbound by remember(initial) { mutableStateOf(initial.outboundTag.orEmpty()) }
    val parsed = values.split(Regex("[,\\n]")).map(String::trim).filter(String::isNotEmpty)

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (initial.values.isEmpty()) "Новое правило" else "Редактировать правило") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    RoutingMatchType.entries.forEach { type ->
                        FilterChip(
                            selected = matchType == type,
                            onClick = { matchType = type },
                            label = { Text(type.title) },
                        )
                    }
                }
                OutlinedTextField(
                    value = values,
                    onValueChange = { values = it },
                    label = { Text("По одному значению на строку") },
                    minLines = 3,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("routing-rule-values"),
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    RoutingRuleAction.entries.forEach { item ->
                        FilterChip(
                            selected = action == item,
                            onClick = { action = item },
                            label = { Text(item.title) },
                        )
                    }
                }
                if (action == RoutingRuleAction.Proxy) {
                    OutlinedTextField(
                        value = outbound,
                        onValueChange = { outbound = it },
                        label = { Text("Outbound tag (пусто = выбранный VPN)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                if (action == RoutingRuleAction.Block && matchType in setOf(
                        RoutingMatchType.Domain,
                        RoutingMatchType.DomainSuffix,
                        RoutingMatchType.DomainRuleSet,
                    )
                ) {
                    Text(
                        "Будут созданы DNS reject и route reject. Встроенный DoH приложения может скрыть domain-only совпадение.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.tertiary,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    onSave(
                        ManagedRoutingRule(
                            matchType = matchType,
                            values = parsed,
                            action = action,
                            outboundTag = outbound.trim().takeIf(String::isNotEmpty),
                        ),
                    )
                },
                enabled = parsed.isNotEmpty(),
            ) { Text("Сохранить") }
        },
        dismissButton = {
            Row {
                onDelete?.let { TextButton(onClick = it) { Text("Удалить") } }
                TextButton(onClick = onDismiss) { Text("Отмена") }
            }
        },
    )
}

@Composable
private fun actionColor(action: RoutingRuleAction) = when (action) {
    RoutingRuleAction.Proxy -> MaterialTheme.colorScheme.primary
    RoutingRuleAction.Direct -> MaterialTheme.colorScheme.tertiary
    RoutingRuleAction.Block -> MaterialTheme.colorScheme.error
}
