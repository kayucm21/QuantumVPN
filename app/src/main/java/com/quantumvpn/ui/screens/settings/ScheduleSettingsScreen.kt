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
import androidx.compose.material3.Checkbox
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.quantumvpn.scheduling.VpnSchedule
import com.quantumvpn.scheduling.VpnScheduler

/**
 * UI для расписания включения/отключения VPN
 */

@Composable
fun ScheduleSettingsScreen(
    vpnScheduler: VpnScheduler,
    onScheduleUpdate: (VpnSchedule) -> Unit,
) {
    val schedule by vpnScheduler.getSchedule().collectAsState(initial = VpnSchedule())
    val isEnabled by vpnScheduler.isScheduleEnabled().collectAsState(initial = false)

    var startHour by remember { mutableIntStateOf(schedule.startHour) }
    var startMinute by remember { mutableIntStateOf(schedule.startMinute) }
    var endHour by remember { mutableIntStateOf(schedule.endHour) }
    var endMinute by remember { mutableIntStateOf(schedule.endMinute) }
    var selectedDays by remember { mutableIntStateOf(127) } // Все дни по умолчанию

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp)
    ) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Расписание VPN")
                    Spacer(modifier = Modifier.width(8.dp))
                    Switch(
                        checked = isEnabled,
                        onCheckedChange = {},
                        modifier = Modifier.align(Alignment.CenterVertically)
                    )
                }

                // Время включения
                Text("Время включения VPN")
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 8.dp),
                    horizontalArrangement = androidx.compose.foundation.layout.Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedTextField(
                        value = startHour.toString().padStart(2, '0'),
                        onValueChange = { if (it.length <= 2) startHour = it.toIntOrNull() ?: 0 },
                        label = { Text("Часы") },
                        modifier = Modifier.weight(1f)
                    )
                    OutlinedTextField(
                        value = startMinute.toString().padStart(2, '0'),
                        onValueChange = { if (it.length <= 2) startMinute = it.toIntOrNull() ?: 0 },
                        label = { Text("Минуты") },
                        modifier = Modifier.weight(1f)
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Время отключения
                Text("Время отключения VPN")
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 8.dp),
                    horizontalArrangement = androidx.compose.foundation.layout.Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedTextField(
                        value = endHour.toString().padStart(2, '0'),
                        onValueChange = { if (it.length <= 2) endHour = it.toIntOrNull() ?: 0 },
                        label = { Text("Часы") },
                        modifier = Modifier.weight(1f)
                    )
                    OutlinedTextField(
                        value = endMinute.toString().padStart(2, '0'),
                        onValueChange = { if (it.length <= 2) endMinute = it.toIntOrNull() ?: 0 },
                        label = { Text("Минуты") },
                        modifier = Modifier.weight(1f)
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Дни недели
                Text("Дни недели")
                val daysOfWeek = listOf("Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс")
                Column {
                    daysOfWeek.forEachIndexed { index, day ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Checkbox(
                                checked = (selectedDays and (1 shl index)) != 0,
                                onCheckedChange = { checked ->
                                    selectedDays = if (checked) {
                                        selectedDays or (1 shl index)
                                    } else {
                                        selectedDays and (1 shl index).inv()
                                    }
                                }
                            )
                            Text(day, modifier = Modifier.padding(start = 8.dp))
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Кнопка сохранения
                Button(
                    onClick = {
                        onScheduleUpdate(
                            VpnSchedule(
                                isEnabled = isEnabled,
                                startHour = startHour,
                                startMinute = startMinute,
                                endHour = endHour,
                                endMinute = endMinute,
                                daysOfWeek = (0..6).filter { (selectedDays and (1 shl it)) != 0 }.toSet(),
                                profileId = schedule.profileId
                            )
                        )
                    },
                    modifier = Modifier.align(Alignment.End)
                ) {
                    Text("Сохранить расписание")
                }
            }
        }
    }
}
