package com.quantumvpn.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

@Composable
internal fun OnboardingScreen(
    contentPadding: PaddingValues,
    onFinished: () -> Unit,
    onImport: () -> Unit,
) {
    var step by remember { mutableIntStateOf(0) }
    val pages = listOf(
        Triple(
            "Разрешите VPN",
            "Android спросит разрешение VpnService. Без него защита не запустится.",
            "Дальше",
        ),
        Triple(
            "Добавьте подписку",
            "Вкладка «Подписки»: файл, URL или QR. JSON редактировать не нужно.",
            "Импорт",
        ),
        Triple(
            "Подключитесь",
            "Выберите сервер и нажмите большую кнопку на Главной. На Т2 лучше Reality.",
            "Начать",
        ),
    )
    val page = pages[step]
    val haptics = Haptics.rememberPerformer()
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(contentPadding)
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        LinearProgressIndicator(
            progress = { (step + 1f) / pages.size },
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(modifier = Modifier.height(20.dp))
        Text(
            page.first,
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center,
        )
        Spacer(modifier = Modifier.height(12.dp))
        Text(
            page.second,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        Spacer(modifier = Modifier.height(28.dp))
        Button(
            onClick = {
                haptics(Haptics.Click)
                when {
                    step == 1 -> {
                        onImport()
                        step++
                    }
                    step < pages.lastIndex -> step++
                    else -> onFinished()
                }
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(page.third)
        }
        if (step == 1) {
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedButton(
                onClick = {
                    haptics(Haptics.Confirm)
                    onImport()
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Открыть подписки")
            }
        }
        Spacer(modifier = Modifier.height(8.dp))
        TextButton(onClick = onFinished) {
            Text("Пропустить")
        }
    }
}
