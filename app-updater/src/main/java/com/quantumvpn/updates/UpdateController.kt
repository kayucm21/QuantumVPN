package com.quantumvpn.updates

import android.content.Context
import android.content.Intent
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlin.coroutines.coroutineContext

class UpdateController(
    context: Context,
    repository: String,
    private val currentVersionName: String,
    private val currentVersionCode: Long,
    private val source: UpdateReleaseSource = GitHubUpdateSource(repository, context.packageName),
    private val http: UpdateHttpClient = GitHubHttpsClient(),
    private val verifier: ApkUpdateVerifier = AndroidApkUpdateVerifier(context),
    private val vpnFallback: UpdateVpnFallback? = null,
    private val installIntentFactory: UpdateInstallIntentFactory = UpdateInstallIntentFactory {
        throw UpdateException("Фабрика системной установки не настроена.")
    },
) {
    private val appContext = context.applicationContext
    private val root = File(appContext.cacheDir, "updates")
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutableState = MutableStateFlow<UpdateState>(UpdateState.Idle)
    val state: StateFlow<UpdateState> = mutableState.asStateFlow()
    private var operation: Job? = null
    private var readyFile: File? = null
    private val automaticCheckStarted = AtomicBoolean(false)

    init {
        cleanupFinishedArtifacts()
    }

    /** Runs at most once per app process; startup may opt into verified automatic download. */
    fun checkOnce(channel: UpdateChannel, autoDownload: Boolean = false) {
        if (automaticCheckStarted.compareAndSet(false, true)) {
            check(channel, autoDownload = autoDownload)
        }
    }

    fun check(channel: UpdateChannel, autoDownload: Boolean = false) {
        when (val current = mutableState.value) {
            is UpdateState.Downloading,
            is UpdateState.Ready,
            is UpdateState.RetryingViaVpn -> return
            is UpdateState.Checking -> return
            is UpdateState.Available -> {
                if (autoDownload) download()
                return
            }
            else -> Unit
        }
        replaceOperation {
            // Do not wipe an in-flight APK if another check sneaks through.
            if (mutableState.value is UpdateState.Downloading ||
                mutableState.value is UpdateState.Ready
            ) {
                return@replaceOperation
            }
            mutableState.value = UpdateState.Checking(channel.name)
            try {
                val candidate = withVpnRetry(UpdateOperation.Check) {
                    source.latest(channel)
                }
                coroutineContext.ensureActive()
                if (candidate.metadata.versionCode > currentVersionCode) {
                    if (autoDownload) {
                        // Startup path: download immediately, then prompt install when Ready.
                        downloadInternal(candidate)
                    } else {
                        mutableState.value = UpdateState.Available(candidate)
                    }
                } else {
                    mutableState.value = UpdateState.UpToDate(candidate.release.tag, currentVersionName)
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: UpdateException) {
                mutableState.value = UpdateState.Failure(error.message ?: "Не удалось проверить обновления.")
            } catch (_: Throwable) {
                mutableState.value = UpdateState.Failure("Не удалось проверить обновления.")
            }
        }
    }

    fun download() {
        when (mutableState.value) {
            is UpdateState.Downloading,
            is UpdateState.Ready,
            is UpdateState.RetryingViaVpn,
            is UpdateState.Checking -> return
            else -> Unit
        }
        val candidate = when (val current = mutableState.value) {
            is UpdateState.Available -> current.candidate
            is UpdateState.Failure -> current.candidate
            else -> null
        } ?: return
        replaceOperation { downloadInternal(candidate) }
    }

    /** UI hook for Android DownloadManager / browser handoff. */
    fun beginSystemDownload(candidate: UpdateCandidate) {
        operation?.cancel()
        operation = null
        mutableState.value = UpdateState.Downloading(candidate, 0L, candidate.metadata.apkSize)
    }

    fun reportSystemProgress(candidate: UpdateCandidate, downloaded: Long, total: Long) {
        if (mutableState.value !is UpdateState.Downloading &&
            mutableState.value !is UpdateState.Available &&
            mutableState.value !is UpdateState.Failure
        ) {
            return
        }
        mutableState.value = UpdateState.Downloading(
            candidate,
            downloaded.coerceAtLeast(0L),
            total.takeIf { it > 0L } ?: candidate.metadata.apkSize,
        )
    }

    fun markReadyFromSystemFile(candidate: UpdateCandidate, file: File) {
        if (!file.isFile) {
            mutableState.value = UpdateState.Failure("Системный APK не найден.", candidate)
            return
        }
        readyFile = file
        mutableState.value = UpdateState.Ready(candidate)
    }

    fun failSystemDownload(message: String, candidate: UpdateCandidate?) {
        mutableState.value = UpdateState.Failure(message, candidate)
    }

    private suspend fun downloadInternal(candidate: UpdateCandidate) {
        root.mkdirs()
        val partial = File(root, "${candidate.metadata.apkFile}.part")
        val complete = File(root, candidate.metadata.apkFile)
        // Drop unrelated leftovers but keep matching .part for resume.
        root.listFiles()?.forEach { file ->
            if (file.isFile && file.name != partial.name && file.name != complete.name) {
                file.delete()
            }
        }
        complete.delete()
        if (partial.isFile && (partial.length() <= 0L || partial.length() > candidate.metadata.apkSize)) {
            partial.delete()
        }
        var lastPublishedAt = 0L
        val already = partial.takeIf { it.isFile }?.length() ?: 0L
        try {
            val downloadJob = coroutineContext[Job]
            // Prefer Wi‑Fi/LTE under the VPN so panel:8443 is not killed mid-APK.
            // Never wipe .part: HTTP client resumes; VPN fallback is last resort only.
            mutableState.value = UpdateState.Downloading(candidate, already, candidate.metadata.apkSize)
            // Never flip the VPN for APK download — updaterRouting resets progress and
            // shows "защищённый канал", then the splash exits with a panel error.
            // Only bind sockets to Wi‑Fi/LTE under an existing tunnel.
            val runDownload = {
                http.download(
                    candidate.apkAsset.downloadUrl,
                    partial,
                    candidate.metadata.apkSize,
                ) { downloaded ->
                    downloadJob?.ensureActive()
                    val now = System.nanoTime()
                    if (downloaded == candidate.metadata.apkSize || now - lastPublishedAt >= 250_000_000L) {
                        lastPublishedAt = now
                        mutableState.value = UpdateState.Downloading(
                            candidate,
                            downloaded,
                            candidate.metadata.apkSize,
                        )
                    }
                }
            }
            var lastError: UpdateException? = null
            repeat(3) { attempt ->
                try {
                    if (vpnFallback != null) {
                        vpnFallback.withUnderlyingNetwork(runDownload)
                    } else {
                        runDownload()
                    }
                    lastError = null
                    return@repeat
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (error: UpdateException) {
                    lastError = error
                    if (attempt < 2) {
                        mutableState.value = UpdateState.Downloading(
                            candidate,
                            partial.takeIf { it.isFile }?.length() ?: 0L,
                            candidate.metadata.apkSize,
                        )
                        kotlinx.coroutines.delay(1_000L * (attempt + 1))
                    }
                }
            }
            lastError?.let { throw it }
            coroutineContext.ensureActive()
            if (sha256(partial) != candidate.metadata.apkSha256) {
                partial.delete()
                throw UpdateException("SHA-256 загруженного APK не совпадает с опубликованным.")
            }
            coroutineContext.ensureActive()
            if (!partial.renameTo(complete)) throw UpdateException("Не удалось завершить временный APK.")
            verifier.verify(complete, candidate.metadata)
            coroutineContext.ensureActive()
            readyFile = complete
            mutableState.value = UpdateState.Ready(candidate)
        } catch (cancelled: CancellationException) {
            // Keep .part so the next attempt can resume.
            throw cancelled
        } catch (error: UpdateException) {
            mutableState.value = UpdateState.Failure(
                error.message ?: "Не удалось загрузить обновление.",
                candidate,
            )
        } catch (_: Throwable) {
            mutableState.value = UpdateState.Failure("Не удалось загрузить обновление.", candidate)
        }
    }

    fun cancelAndDelete() {
        val previous = operation
        operation = scope.launch {
            previous?.cancelAndJoin()
            cleanupFiles()
            mutableState.value = UpdateState.Idle
        }
    }

    fun createInstallIntent(): Intent {
        val file = readyFile?.takeIf(File::isFile)
            ?: throw UpdateException("Проверенный APK больше недоступен.")
        return installIntentFactory.create(file)
    }

    fun onInstallerFinished(installed: Boolean) {
        val candidate = (mutableState.value as? UpdateState.Ready)?.candidate
        cleanupFiles()
        mutableState.value = if (installed) {
            UpdateState.Idle
        } else {
            UpdateState.Failure("Установка отменена или не завершена.", candidate)
        }
    }

    fun failInstallation(message: String) {
        val candidate = (mutableState.value as? UpdateState.Ready)?.candidate
        cleanupFiles()
        mutableState.value = UpdateState.Failure(message, candidate)
    }

    fun cleanupStaleFiles() {
        cleanupFinishedArtifacts()
    }

    private fun replaceOperation(block: suspend () -> Unit) {
        operation?.cancel()
        operation = scope.launch { block() }
    }

    private suspend fun <T> withVpnRetry(
        operation: UpdateOperation,
        candidate: UpdateCandidate? = null,
        block: () -> T,
    ): T {
        val directFailure = try {
            return block()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: UpdateException) {
            if (!error.retryViaVpn || vpnFallback == null) throw error
            error
        }
        // 1) Prefer Wi‑Fi/LTE under an active VPN — never start updaterRouting for checks
        //    (that UI path shows "защищённый канал" and resets splash download progress).
        val afterUnderlying = try {
            vpnFallback.withUnderlyingNetwork {
                try {
                    Result.success(block())
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (error: UpdateException) {
                    Result.failure(error)
                }
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Throwable) {
            Result.failure(directFailure)
        }
        afterUnderlying.getOrNull()?.let { return it }
        afterUnderlying.exceptionOrNull()?.let { err ->
            if (err is UpdateException) throw err
        }
        throw directFailure
    }

    private fun vpnUnavailable(directFailure: UpdateException, detail: String?): UpdateException {
        val fallback = detail?.takeIf(String::isNotBlank)
            ?: "временный VPN-маршрут недоступен"
        return UpdateException(
            "${directFailure.message.orEmpty()} VPN-повтор не выполнен: $fallback",
            directFailure,
        )
    }

    private fun cleanupFiles() {
        readyFile = null
        root.listFiles()?.forEach { file ->
            if (file.isFile) file.delete()
        }
        root.delete()
    }

    /** Drop finished leftovers but keep resumable `.part` across process restarts. */
    private fun cleanupFinishedArtifacts() {
        readyFile = null
        if (!root.isDirectory) return
        root.listFiles()?.forEach { file ->
            if (!file.isFile) return@forEach
            val name = file.name
            if (name.endsWith(".part") || name.endsWith(".part.full")) return@forEach
            file.delete()
        }
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        FileInputStream(file).buffered().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}
