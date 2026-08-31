package com.quantumvpn.ui.screens.settings

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.quantumvpn.recovery.AutoReconnect
import com.quantumvpn.state.LastConnectionState
import com.quantumvpn.protection.OperatorBypassProtection

/**
 * UI для автовосстановления и разных функций
 */

@Composable
fun RecoverySettingsScreen(
    autoReconnect: AutoReconnect,
    lastConnectionState: LastConnectionState,
    bypassProtection: OperatorBypassProtection,
) {
    val autoReconnectDelay by autoReconnect.getAutoReconnectDelay().collectAsState(initial = 5)
    val maxAttempts by autoReconnect.getMaxReconnectAttempts().collectAsState(initial = 5)
    val autoStartEnabled by lastConnectionState.isAutoStartEnabled().collectAsState(initial = false)
    val dohServer by bypassProtection.getDohServer().collectAsState(initial = "https://dns.google/dns-query")
    val antiBlockMode by bypassProtection.getAntiBlockMode().collectAsState(initial = "BALANCED")

    var delayValue by remember { mutableStateOf(autoReconnectDelay.toFloat()) }
    var attemptsValue by remember { mutableStateOf(maxAttempts.toFloat()) }
    var selectedMode by remember { mutableStateOf(antiBlockMode) }
    var showModeMenu by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp)
    ) {
        // Параметры переподключения
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text("Параметры автопереподключения")

                Spacer(modifier = Modifier.height(16.dp))

                Text("Задержка переподключения: ${delayValue.toInt()} сек")
                Slider(
                    value = delayValue,
                    onValueChange = { delayValue = it },
                    valueRange = 1f..60f,
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(16.dp))

                Text("Максимум попыток: ${attemptsValue.toInt()}")
                Slider(
                    value = attemptsValue,
                    onValueChange = { attemptsValue = it },
                    valueRange = 1f..20f,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Восстановление подключения
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text("Восстановление при старте")
                Text("Автоматически подключится к последнему серверу", 
                    style = androidx.compose.material3.MaterialTheme.typography.bodySmall)
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Выбор режима защиты
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text("Режим защиты от блокировок")
                
                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = androidx.compose.foundation.layout.Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = { showModeMenu = true },
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(selectedMode)
                    }

                    DropdownMenu(
                        expanded = showModeMenu,
                        onDismissRequest = { showModeMenu = false }
                    ) {
                        listOf("AGGRESSIVE", "BALANCED", "MINIMAL").forEach { mode ->
                            DropdownMenuItem(
                                text = { Text(mode) },
                                onClick = {
                                    selectedMode = mode
                                    showModeMenu = false
                                }
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                when (selectedMode) {
                    "AGGRESSIVE" -> Text(
                        "Максимальная скрытность, может снизить скорость",
                        style = androidx.compose.material3.MaterialTheme.typography.bodySmall
                    )
                    "BALANCED" -> Text(
                        "Баланс между скрытностью и скоростью (рекомендуется)",
                        style = androidx.compose.material3.MaterialTheme.typography.bodySmall
                    )
                    "MINIMAL" -> Text(
                        "Минимальный оверхед, максимальная скорость",
                        style = androidx.compose.material3.MaterialTheme.typography.bodySmall
                    )
                }
            }
        }
    }
}
