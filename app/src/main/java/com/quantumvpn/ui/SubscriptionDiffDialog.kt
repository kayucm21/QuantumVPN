package com.quantumvpn.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.quantumvpn.profiles.SubscriptionDiffResult

@Composable
fun SubscriptionDiffDialog(
    diff: SubscriptionDiffResult,
    onDismiss: () -> Unit,
    onUndo: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Изменения подписки") },
        text = {
            Column(
                modifier = Modifier
                    .heightIn(max = 320.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(diff.summaryRu)
                if (diff.added.isNotEmpty()) {
                    Text("Добавлены:")
                    diff.added.take(20).forEach { Text("• $it") }
                    if (diff.added.size > 20) Text("…и ещё ${diff.added.size - 20}")
                }
                if (diff.removed.isNotEmpty()) {
                    Text("Удалены:")
                    diff.removed.take(20).forEach { Text("• $it") }
                    if (diff.removed.size > 20) Text("…и ещё ${diff.removed.size - 20}")
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("OK") }
        },
        dismissButton = {
            TextButton(onClick = onUndo) { Text("Отменить") }
        },
    )
}
