package com.quantumvpn.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

private val tips = listOf(
    "Свайп вправо на Connect — подключить, влево — отключить.",
    "Долгий тап Connect открывает меню: тест 10 с, hard reconnect.",
    "Share из браузера добавляет домен в маршрутизацию.",
    "Закрепите до 3 серверов — они всегда наверху списка.",
    "Safe mode отключает failover и снижает риск циклов.",
    "Отчёт надёжности в Настройках показывает uptime за неделю.",
)

@Composable
fun TipsCarousel(
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var index by rememberSaveable { mutableIntStateOf(0) }
    val tip = tips[index % tips.size]
    Surface(
        modifier = modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.tertiaryContainer,
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text("Совет", style = MaterialTheme.typography.labelMedium)
            Text(tip, style = MaterialTheme.typography.bodySmall)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                TextButton(onClick = { index = (index + 1) % tips.size }) {
                    Text("Ещё")
                }
                TextButton(onClick = onDismiss) { Text("Скрыть") }
            }
        }
    }
}
