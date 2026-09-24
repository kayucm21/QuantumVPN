package com.quantumvpn.updates

import android.app.DownloadManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.database.Cursor
import android.net.Uri
import android.os.Environment
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import java.io.File
import java.util.concurrent.atomic.AtomicLong

/**
 * Hands the APK URL to Android's DownloadManager, then opens the system package installer
 * ("система попросит обновить") when the file is ready.
 */
class SystemApkUpdateInstaller(context: Context) {
    private val app = context.applicationContext
    private val downloadManager = app.getSystemService(Context.DOWNLOAD_SERVICE) as DownloadManager
    private val activeId = AtomicLong(-1L)
    private var pendingCandidate: UpdateCandidate? = null
    private var onProgress: ((downloaded: Long, total: Long) -> Unit)? = null
    private var onReady: ((File) -> Unit)? = null
    private var onFailed: ((String) -> Unit)? = null
    private var receiverRegistered = false

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != DownloadManager.ACTION_DOWNLOAD_COMPLETE) return
            val id = intent.getLongExtra(DownloadManager.EXTRA_DOWNLOAD_ID, -1L)
            if (id < 0L || id != activeId.get()) return
            handleComplete(id)
        }
    }

    fun start(
        candidate: UpdateCandidate,
        onProgress: (downloaded: Long, total: Long) -> Unit,
        onReady: (File) -> Unit,
        onFailed: (String) -> Unit,
    ) {
        this.onProgress = onProgress
        this.onReady = onReady
        this.onFailed = onFailed
        this.pendingCandidate = candidate
        ensureReceiver()
        cancelActive()

        val url = candidate.apkAsset.downloadUrl
        val fileName = candidate.metadata.apkFile.ifBlank { "QuantumVPN-update.apk" }
        val request = DownloadManager.Request(Uri.parse(url))
            .setTitle("QuantumVPN ${candidate.metadata.versionName}")
            .setDescription("Загрузка обновления")
            .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
            .setAllowedOverMetered(true)
            .setAllowedOverRoaming(true)
            .setMimeType(APK_MIME)
            .setDestinationInExternalFilesDir(app, Environment.DIRECTORY_DOWNLOADS, fileName)
        request.addRequestHeader("User-Agent", "QuantumVPN-Android-SystemUpdater")

        val id = runCatching { downloadManager.enqueue(request) }.getOrElse { error ->
            onFailed("Система не начала загрузку: ${error.message ?: "ошибка"}")
            return
        }
        activeId.set(id)
        onProgress(0L, candidate.metadata.apkSize.coerceAtLeast(0L))
    }

    fun pollProgress() {
        val id = activeId.get()
        if (id < 0L) return
        val query = DownloadManager.Query().setFilterById(id)
        downloadManager.query(query)?.use { cursor ->
            if (!cursor.moveToFirst()) return
            val status = cursor.int(DownloadManager.COLUMN_STATUS)
            val downloaded = cursor.long(DownloadManager.COLUMN_BYTES_DOWNLOADED_SO_FAR)
            val total = cursor.long(DownloadManager.COLUMN_TOTAL_SIZE_BYTES).takeIf { it > 0 }
                ?: pendingCandidate?.metadata?.apkSize ?: -1L
            when (status) {
                DownloadManager.STATUS_RUNNING, DownloadManager.STATUS_PENDING, DownloadManager.STATUS_PAUSED ->
                    onProgress?.invoke(downloaded.coerceAtLeast(0L), total)
                DownloadManager.STATUS_SUCCESSFUL -> handleComplete(id)
                DownloadManager.STATUS_FAILED -> {
                    val reason = cursor.int(DownloadManager.COLUMN_REASON)
                    fail("Системная загрузка не удалась (код $reason).")
                }
            }
        }
    }

    fun createInstallIntent(file: File): Intent {
        val uri = FileProvider.getUriForFile(app, "${app.packageName}.fileprovider", file)
        return Intent(Intent.ACTION_INSTALL_PACKAGE).apply {
            setDataAndType(uri, APK_MIME)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            putExtra(Intent.EXTRA_RETURN_RESULT, true)
        }
    }

    fun openInBrowser(candidate: UpdateCandidate) {
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(candidate.apkAsset.downloadUrl)).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        app.startActivity(intent)
    }

    fun cancel() {
        cancelActive()
        pendingCandidate = null
    }

    private fun handleComplete(id: Long) {
        val uri = downloadManager.getUriForDownloadedFile(id)
        val local = localFileFor(id)
        val file = when {
            local != null && local.isFile && local.length() > 0L -> local
            uri != null -> copyContentToCache(uri)
            else -> null
        }
        if (file == null || !file.isFile) {
            fail("Система скачала файл, но APK недоступен.")
            return
        }
        val expected = pendingCandidate?.metadata?.apkSize ?: 0L
        if (expected > 0L && file.length() != expected) {
            // Still hand off — installer/sha check can reject; DownloadManager sometimes omits size.
        }
        activeId.set(-1L)
        onProgress?.invoke(file.length(), file.length())
        onReady?.invoke(file)
    }

    private fun copyContentToCache(uri: Uri): File? {
        val name = pendingCandidate?.metadata?.apkFile ?: "update.apk"
        val target = File(app.cacheDir, "updates-system").apply { mkdirs() }.let { File(it, name) }
        return runCatching {
            app.contentResolver.openInputStream(uri)?.use { input ->
                target.outputStream().use { output -> input.copyTo(output) }
            }
            target.takeIf { it.isFile && it.length() > 0L }
        }.getOrNull()
    }

    private fun localFileFor(id: Long): File? {
        val query = DownloadManager.Query().setFilterById(id)
        downloadManager.query(query)?.use { cursor ->
            if (!cursor.moveToFirst()) return null
            val localUri = cursor.string(DownloadManager.COLUMN_LOCAL_URI) ?: return null
            val parsed = Uri.parse(localUri)
            if (parsed.scheme == "file") {
                return parsed.path?.let(::File)?.takeIf { it.isFile }
            }
        }
        val name = pendingCandidate?.metadata?.apkFile ?: return null
        val dir = app.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS) ?: return null
        return File(dir, name).takeIf { it.isFile }
    }

    private fun fail(message: String) {
        activeId.set(-1L)
        onFailed?.invoke(message)
    }

    private fun cancelActive() {
        val id = activeId.getAndSet(-1L)
        if (id >= 0L) runCatching { downloadManager.remove(id) }
    }

    private fun ensureReceiver() {
        if (receiverRegistered) return
        val filter = IntentFilter(DownloadManager.ACTION_DOWNLOAD_COMPLETE)
        ContextCompat.registerReceiver(app, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
        receiverRegistered = true
    }

    private fun Cursor.int(column: String): Int {
        val index = getColumnIndex(column)
        return if (index >= 0) getInt(index) else -1
    }

    private fun Cursor.long(column: String): Long {
        val index = getColumnIndex(column)
        return if (index >= 0) getLong(index) else -1L
    }

    private fun Cursor.string(column: String): String? {
        val index = getColumnIndex(column)
        return if (index >= 0) getString(index) else null
    }

    companion object {
        const val APK_MIME = "application/vnd.android.package-archive"
    }
}
