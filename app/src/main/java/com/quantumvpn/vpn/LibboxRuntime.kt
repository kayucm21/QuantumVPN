package com.quantumvpn.vpn

import android.content.Context
import com.quantumvpn.BuildConfig
import com.quantumvpn.diagnostics.SecretRedactor
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.SetupOptions
import java.io.File
import java.util.Locale

class LibboxRuntime(private val context: Context) {
    @Volatile
    private var initialized = false

    @Volatile
    private var initializationError: String? = null

    @Synchronized
    fun initialize(): Result<Unit> {
        if (initialized) return Result.success(Unit)
        initializationError?.let { return Result.failure(IllegalStateException(it)) }
        return try {
            val working = File(context.filesDir, "core").apply { mkdirs() }
            val temporary = File(context.cacheDir, "core").apply { mkdirs() }
            Libbox.touch()
            Libbox.setup(
                SetupOptions().apply {
                    basePath = context.filesDir.absolutePath
                    workingPath = working.absolutePath
                    tempPath = temporary.absolutePath
                    fixAndroidStack = true
                    commandServerListenPort = 0
                    commandServerSecret = ""
                    logMaxLines = 256
                    debug = BuildConfig.DEBUG
                },
            )
            Libbox.setLocale(Locale.getDefault().toLanguageTag())
            Libbox.setMemoryLimit(false)
            initialized = true
            Result.success(Unit)
        } catch (error: Throwable) {
            val safe = error.message
                ?.lineSequence()
                ?.firstOrNull()
                ?.let(SecretRedactor::redactInline)
                ?.take(240)
                ?: "Не удалось инициализировать libbox."
            initializationError = safe
            Result.failure(IllegalStateException(safe, error))
        }
    }
}
