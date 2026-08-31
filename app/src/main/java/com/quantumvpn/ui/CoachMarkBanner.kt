package com.quantumvpn.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

enum class CoachMarkScreen(val title: String, val message: String) {
    Home(
        "Главная",
        "Кнопка Connect: тап, свайп вправо — подключить, влево — отключить. Долгий тап — меню.",
    ),
    Servers(
        "Серверы",
        "Закрепите до 3 серверов, фильтруйте по стране, делитесь карточкой без секретов.",
    ),
    Routing(
        "Маршрутизация",
        "Проверьте домен в тесте маршрута. Share из браузера добавит правило.",
    ),
    Settings(
        "Настройки",
        "Beta-канал, safe mode, блокировка PIN и отчёт надёжности — в Инструментах.",
    ),
    Apps(
        "Приложения",
        "Выберите per-app VPN: иконки приложений и пресеты в один тап.",
    ),
}

@Composable
fun CoachMarkBanner(
    screen: CoachMarkScreen,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.primaryContainer,
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                "${screen.title}: ${screen.message}",
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = onDismiss) { Text("OK") }
        }
    }
}
