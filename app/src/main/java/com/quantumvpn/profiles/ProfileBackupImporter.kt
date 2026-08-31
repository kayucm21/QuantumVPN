package com.quantumvpn.profiles

import android.content.Context
import android.net.Uri
import com.quantumvpn.importer.SubscriptionSourceStore
import com.quantumvpn.security.SecureVault
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class BackupRestoreResult(
    val importedProfiles: Int,
    val skipped: Int,
)

/**
 * Restores profiles from a QVB1 backup created by [ProfileBackupExporter].
 * Same-device Keystore seal — backups from another device cannot be opened.
 */
class ProfileBackupImporter(
    private val context: Context,
    private val profileStore: ProfileStore,
    private val subscriptionSourceStore: SubscriptionSourceStore,
    private val vault: SecureVault = SecureVault(),
) {
    suspend fun restore(uri: Uri): BackupRestoreResult = withContext(Dispatchers.IO) {
        val sealed = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: error("Не удалось прочитать файл бэкапа.")
        val plain = runCatching { vault.open(sealed) }
            .getOrElse { error("Не удалось расшифровать бэкап. Файл с другого устройства или повреждён.") }
        val text = plain.toString(Charsets.UTF_8)
        require(text.startsWith("QVB1")) { "Неизвестный формат бэкапа." }

        var imported = 0
        var skipped = 0
        val blocks = text.split("\n---\n").drop(1)
        for (block in blocks) {
            val lines = block.lines()
            val fields = mutableMapOf<String, String>()
            var jsonStarted = false
            val json = StringBuilder()
            for (line in lines) {
                when {
                    jsonStarted -> {
                        if (json.isNotEmpty()) json.append('\n')
                        json.append(line)
                    }
                    line.startsWith("json=") -> {
                        jsonStarted = true
                        val rest = line.removePrefix("json=")
                        if (rest.isNotEmpty()) json.append(rest)
                    }
                    '=' in line -> {
                        val key = line.substringBefore('=')
                        val value = line.substringAfter('=')
                        fields[key] = value
                    }
                }
            }
            val name = fields["name"]?.trim().orEmpty().ifBlank { "Restored" }
            val source = runCatching {
                ProfileSource.valueOf(fields["source"].orEmpty())
            }.getOrDefault(ProfileSource.RawJson)
            val body = json.toString().trim()
            if (body.isBlank()) {
                skipped++
                continue
            }
            runCatching {
                val meta = profileStore.create(name, body, source)
                val url = fields["url"].orEmpty()
                if (url.isNotBlank() && source == ProfileSource.Subscription) {
                    subscriptionSourceStore.put(meta.id, url)
                }
                imported++
            }.onFailure { skipped++ }
        }
        BackupRestoreResult(importedProfiles = imported, skipped = skipped)
    }
}
