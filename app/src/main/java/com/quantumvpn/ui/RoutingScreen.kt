package com.quantumvpn.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.quantumvpn.routing.RoutingUiState
import com.quantumvpn.routing.RoutingViewModel
import com.quantumvpn.ui.components.QvHubHeader
import com.quantumvpn.ui.components.QvSection

@Composable
fun RoutingScreen(
    contentPadding: PaddingValues,
    routingState: RoutingUiState,
    routingViewModel: RoutingViewModel,
    @Suppress("UNUSED_PARAMETER") timeRoutingEnabled: Boolean = false,
    showCoachMark: Boolean = false,
    onDismissCoachMark: () -> Unit = {},
) {
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
                subtitle = "Подписанные правила из Quantum Control",
            )
        }
        item(key = "traffic") {
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
                    Text(
                        "Управление из Quantum Control",
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Маршрутизация", fontWeight = FontWeight.SemiBold)
                            Text(
                                "Подписанные правила из панели",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        androidx.compose.material3.Switch(
                            checked = routingState.panelRoutingEnabled,
                            onCheckedChange = routingViewModel::setPanelRoutingEnabled,
                            enabled = !routingState.loading,
                        )
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Блокировка рекламы", fontWeight = FontWeight.SemiBold)
                            Text(
                                "Только пока VPN подключён",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        androidx.compose.material3.Switch(
                            checked = routingState.adBlockEnabled,
                            onCheckedChange = routingViewModel::setPanelAdBlockEnabled,
                            enabled = !routingState.loading,
                        )
                    }
                    routingState.panelPolicyRevision?.let { revision ->
                        Text(
                            "Панель: r$revision · ${routingState.panelPolicyChannel ?: "production"}" +
                                if (routingState.panelPolicyFromCache) " · сохранённая проверенная копия" else "",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary,
                        )
                    }
                    routingState.panelPolicyMessage?.let { message ->
                        Text(
                            message,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    OutlinedButton(
                        onClick = routingViewModel::refreshPanelPolicy,
                        enabled = !routingState.loading,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Проверить правила панели") }
                    androidx.compose.material3.HorizontalDivider()
                    Text(
                        if (routingState.panelRoutingEnabled) {
                            if (routingState.panelPolicyRevision != null) {
                                "Списки доменов, CIDR и DNS управляются из панели. " +
                                    "При потере сети используется последняя проверенная ревизия."
                            } else {
                                "Ожидаем первую подписанную ревизию панели. Локальные правила не изменяются."
                            }
                        } else {
                            "Панельная маршрутизация выключена на этом устройстве. " +
                                "Текущий профиль работает без управляемых списков."
                        },
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}
