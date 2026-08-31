package com.quantumvpn.profiles

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import com.quantumvpn.importer.SubscriptionSourceStore
import com.quantumvpn.security.SecureVault
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Creates an encrypted on-device backup of profile bodies + subscription URLs.
 * Does not upload anywhere; user shares via the system sheet.
 */
class ProfileBackupExporter(
    private val context: Context,
    private val profileStore: ProfileStore,
    private val subscriptionSourceStore: SubscriptionSourceStore,
    private val vault: SecureVault = SecureVault(),
) {
    suspend fun createShareIntent(): Intent = withContext(Dispatchers.IO) {
        val dir = File(context.cacheDir, "backups").apply { mkdirs() }
        dir.listFiles()?.forEach { it.delete() }
        val zipFile = File(dir, "quantumvpn-backup-${System.currentTimeMillis()}.qvb")
        val payload = buildPayload()
        val sealed = vault.seal(payload)
        zipFile.writeBytes(sealed)
        val uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            zipFile,
        )
        Intent(Intent.ACTION_SEND).apply {
            type = "application/octet-stream"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, "QuantumVPN backup")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
    }

    private suspend fun buildPayload(): ByteArray {
        val profiles = profileStore.profiles.value
        val sb = StringBuilder()
        sb.appendLine("QVB1")
        for (meta in profiles) {
            val body = runCatching { profileStore.read(meta.id).json }.getOrNull() ?: continue
            val url = subscriptionSourceStore.get(meta.id).orEmpty()
            sb.appendLine("---")
            sb.appendLine("id=${meta.id}")
            sb.appendLine("name=${meta.name}")
            sb.appendLine("source=${meta.source.name}")
            sb.appendLine("url=$url")
            sb.appendLine("json=")
            sb.appendLine(body)
        }
        return sb.toString().toByteArray(Charsets.UTF_8)
    }
}
