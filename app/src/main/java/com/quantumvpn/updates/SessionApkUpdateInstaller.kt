package com.quantumvpn.updates

import android.Manifest
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.core.content.IntentCompat
import com.quantumvpn.QuantumVpnApplication
import java.io.File
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

sealed interface SessionInstallState {
    data object Idle : SessionInstallState
    data object Preparing : SessionInstallState
    data class Committed(val versionName: String, val versionCode: Long, val automaticRequested: Boolean) : SessionInstallState
    data class RequiresConfirmation(val versionName: String, val versionCode: Long) : SessionInstallState
    data class Installed(val versionName: String, val versionCode: Long) : SessionInstallState
    data object Cancelled : SessionInstallState
    data class Failure(val message: String) : SessionInstallState
}

/**
 * Uses the documented self-update API, not root, accessibility or device-owner privileges.
 * Android may require confirmation even when our reviewed eligibility check succeeds.
 */
class SessionApkUpdateInstaller(context: Context, private val cleanupPrivateApks: () -> Unit) {
    private val app = context.applicationContext
    private val installer = app.packageManager.packageInstaller
    private val preferences = app.getSharedPreferences("verified_update_session", Context.MODE_PRIVATE)
    private val mutex = Mutex()
    private val mutableState = MutableStateFlow<SessionInstallState>(SessionInstallState.Idle)
    val state = mutableState.asStateFlow()
    private val cancellationGeneration = AtomicLong()
    private var confirmationIntent: Intent? = null
    private var confirmationUiInThisProcess = false

    init { reconcilePreviousSession() }

    suspend fun install(candidate: UpdateCandidate, file: File) {
        val generation = cancellationGeneration.get()
        withContext(Dispatchers.IO) {
        mutex.withLock {
            if (preferences.getInt("session_id", -1) >= 0) return@withLock
            mutableState.value = SessionInstallState.Preparing
            var sessionId = -1
            try {
                requireCurrentGeneration(generation)
                val verifier = AndroidApkUpdateVerifier(app)
                verifier.verify(file, candidate.metadata)
                val archive = verifier.inspectArchive(file)
                UpdateStoragePolicy.requireInstallerSpace(candidate.metadata.apkSize, app.cacheDir.usableSpace)
                val automatic = SelfUpdateUserActionPolicy.mayRequestWithoutUserAction(
                    deviceSdk = Build.VERSION.SDK_INT,
                    archiveTargetSdk = archive.targetSdk,
                    installedPackage = app.packageName,
                    archivePackage = archive.packageName,
                    canRequestPackageInstalls = app.packageManager.canRequestPackageInstalls(),
                    declaresUpdatePermission = app.checkSelfPermission(Manifest.permission.UPDATE_PACKAGES_WITHOUT_USER_ACTION) == PackageManager.PERMISSION_GRANTED,
                )
                val parameters = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
                    setAppPackageName(app.packageName)
                    setSize(candidate.metadata.apkSize)
                    setInstallReason(PackageManager.INSTALL_REASON_USER)
                    if (Build.VERSION.SDK_INT >= 31) {
                        setRequireUserAction(if (automatic) PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED
                            else PackageInstaller.SessionParams.USER_ACTION_REQUIRED)
                    }
                }
                requireCurrentGeneration(generation)
                sessionId = installer.createSession(parameters)
                val token = UUID.randomUUID().toString()
                synchronized(this@SessionApkUpdateInstaller) {
                    requireCurrentGeneration(generation)
                    require(preferences.edit().putInt("session_id", sessionId).putString("token", token)
                        .putLong("version_code", candidate.metadata.versionCode).putString("version_name", candidate.metadata.versionName)
                        .putString("phase", "preparing").commit())
                }
                installer.openSession(sessionId).use { session ->
                    val digest = MessageDigest.getInstance("SHA-256")
                    var copied = 0L
                    file.inputStream().buffered().use { input ->
                        session.openWrite("base.apk", 0L, candidate.metadata.apkSize).use { output ->
                            val buffer = ByteArray(64 * 1024)
                            while (true) {
                                kotlin.coroutines.coroutineContext.ensureActive()
                                requireCurrentGeneration(generation)
                                val count = input.read(buffer)
                                if (count < 0) break
                                copied += count
                                if (copied > candidate.metadata.apkSize) throw UpdateException("Размер APK изменился до установки.")
                                digest.update(buffer, 0, count)
                                output.write(buffer, 0, count)
                            }
                            session.fsync(output)
                        }
                    }
                    val actualHash = digest.digest().joinToString("") { "%02x".format(it) }
                    if (copied != candidate.metadata.apkSize || !actualHash.equals(candidate.metadata.apkSha256, true)) {
                        throw UpdateException("Проверенный APK изменился до системной установки.")
                    }
                    val callback = Intent(app, UpdateInstallResultReceiver::class.java).apply {
                        action = RESULT_ACTION
                        data = Uri.parse("quantumvpn-update://session/$sessionId/$token")
                        putExtra(TRANSACTION_TOKEN, token)
                        putExtra(TRANSACTION_SESSION, sessionId)
                    }
                    // PackageInstaller fills in status extras; immutable PendingIntent is invalid
                    // for commit on modern Android. The target is explicit and non-exported.
                    val flags = PendingIntent.FLAG_UPDATE_CURRENT or
                        if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0
                    val pending = PendingIntent.getBroadcast(app, sessionId, callback, flags)
                    synchronized(this@SessionApkUpdateInstaller) {
                        requireCurrentGeneration(generation)
                        require(preferences.edit().putString("phase", "committed").commit())
                        // Announce durable handoff only after Android accepts the commit.
                        session.commit(pending.intentSender)
                        // Cleanup is process-owned, not tied to a visible Activity collector.
                        runCatching(cleanupPrivateApks)
                        mutableState.value = SessionInstallState.Committed(candidate.metadata.versionName, candidate.metadata.versionCode, automatic)
                    }
                }
            } catch (error: Exception) {
                if (sessionId >= 0) runCatching { installer.abandonSession(sessionId) }
                clearTransaction()
                mutableState.value = if (error is CancellationException || cancellationGeneration.get() != generation) {
                    SessionInstallState.Cancelled
                } else SessionInstallState.Failure(
                        (error as? UpdateException)?.message ?: "Android не принял пакет обновления. Повторите загрузку.",
                    )
            }
        }
        }
    }

    @Synchronized
    fun handleResult(intent: Intent) {
        val expectedSession = preferences.getInt("session_id", -1)
        val expectedToken = preferences.getString("token", null) ?: return
        if (!UpdateSessionPolicy.acceptsCallback(expectedSession, expectedToken,
                intent.getIntExtra(TRANSACTION_SESSION, -2),
                intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -2),
                intent.getStringExtra(TRANSACTION_TOKEN), intent.action == RESULT_ACTION)) return
        val versionName = preferences.getString("version_name", "").orEmpty()
        val versionCode = preferences.getLong("version_code", -1L)
        when (intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                val pending = IntentCompat.getParcelableExtra(intent, Intent.EXTRA_INTENT, Intent::class.java)
                val resolved = pending?.resolveActivityInfo(app.packageManager, 0)
                val systemFlags = android.content.pm.ApplicationInfo.FLAG_SYSTEM or android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP
                if (pending == null || resolved == null || resolved.applicationInfo.flags and systemFlags == 0) {
                    failAndAbandon("Android не предоставил доверенное окно подтверждения установки.")
                    return
                }
                confirmationIntent = Intent(pending)
                preferences.edit().putString("phase", "confirmation").commit()
                mutableState.value = SessionInstallState.RequiresConfirmation(versionName, versionCode)
            }
            PackageInstaller.STATUS_SUCCESS -> {
                // Callback success alone is not installation evidence: inspect our actual package.
                if (!recordInstalledPackage(versionCode)) {
                    failAndAbandon("Android сообщил об успехе, но новая версия пока не подтверждена.")
                }
            }
            PackageInstaller.STATUS_FAILURE_ABORTED -> {
                clearTransaction()
                mutableState.value = SessionInstallState.Cancelled
            }
            else -> failAndAbandon("Android отклонил обновление (код ${intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)}).")
        }
    }

    @Synchronized
    fun takeConfirmationIntent(): Intent? = confirmationIntent?.also {
        confirmationIntent = null
        confirmationUiInThisProcess = true
        preferences.edit().putString("phase", "confirmation_launched").commit()
    }

    @Synchronized
    fun cancel() {
        cancellationGeneration.incrementAndGet()
        val id = preferences.getInt("session_id", -1)
        if (id >= 0) runCatching { installer.abandonSession(id) }
        clearTransaction()
        mutableState.value = SessionInstallState.Cancelled
    }

    @Synchronized
    fun failInstallation(message: String) {
        cancellationGeneration.incrementAndGet()
        failAndAbandon(message)
    }

    /** Terminal results are consumed once, so Activity recreation cannot overwrite a new download. */
    @Synchronized
    fun acknowledgeTerminalState() {
        when (mutableState.value) {
            is SessionInstallState.Installed, SessionInstallState.Cancelled,
            is SessionInstallState.Failure -> mutableState.value = SessionInstallState.Idle
            else -> Unit
        }
    }

    /** Called after confirmation UI returns; Activity.RESULT_OK never proves an install. */
    fun refreshInstalledVersion() {
        val expected = preferences.getLong("version_code", -1L)
        recordInstalledPackage(expected)
    }

    private fun reconcilePreviousSession() {
        val id = preferences.getInt("session_id", -1)
        if (id < 0) return
        val expected = preferences.getLong("version_code", -1L)
        val name = preferences.getString("version_name", "").orEmpty()
        if (!recordInstalledPackage(expected)) {
            // The broadcast can be what recreated this process. Do not abandon the
            // session here before handleResult gets its authenticated callback.
            mutableState.value = SessionInstallState.Committed(name, expected, false)
        }
    }

    /** Explicit foreground recovery, separate from initialization by a status broadcast. */
    @Synchronized
    fun recoverForegroundSession() {
        val id = preferences.getInt("session_id", -1)
        if (id < 0) return
        refreshInstalledVersion()
        if (preferences.getInt("session_id", -1) < 0) return
        val phase = preferences.getString("phase", "")
        val info = runCatching { installer.getSessionInfo(id) }.getOrNull()
        if (UpdateSessionPolicy.shouldAbandonOnForeground(info != null, phase.orEmpty(),
                mutableState.value is SessionInstallState.Preparing, confirmationIntent != null,
                confirmationUiInThisProcess)) {
            // A process-lost confirmation Intent is never reconstructed from untrusted data.
            // Abandon only our recorded session and offer a new verified download.
            cancel()
        }
    }

    private fun failAndAbandon(message: String) {
        val id = preferences.getInt("session_id", -1)
        if (id >= 0) runCatching { installer.abandonSession(id) }
        clearTransaction()
        mutableState.value = SessionInstallState.Failure(message)
    }

    private fun clearTransaction() {
        confirmationIntent = null
        confirmationUiInThisProcess = false
        preferences.edit().clear().commit()
        runCatching(cleanupPrivateApks)
    }

    @Synchronized
    private fun recordInstalledPackage(expected: Long): Boolean {
        val identity = runCatching { AndroidApkUpdateVerifier(app).inspectInstalled() }.getOrNull() ?: return false
        if (!UpdateSessionPolicy.installedVersionProvesSuccess(expected, identity.versionCode)) return false
        clearTransaction()
        mutableState.value = SessionInstallState.Installed(identity.versionName, identity.versionCode)
        return true
    }

    private fun requireCurrentGeneration(generation: Long) {
        if (cancellationGeneration.get() != generation) throw CancellationException("Update installation cancelled")
    }

    companion object {
        const val RESULT_ACTION = "com.quantumvpn.UPDATE_INSTALL_RESULT"
        const val TRANSACTION_TOKEN = "verified_transaction_token"
        const val TRANSACTION_SESSION = "verified_transaction_session"
    }
}

/** Explicit PendingIntent target; no app or browser can inject install status broadcasts. */
class UpdateInstallResultReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val app = context.applicationContext as? QuantumVpnApplication ?: return
        app.container.sessionApkInstaller.handleResult(intent)
    }
}
