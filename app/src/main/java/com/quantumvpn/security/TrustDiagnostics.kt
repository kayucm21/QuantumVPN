package com.quantumvpn.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.security.MessageDigest

object TrustDiagnostics {
    data class Report(
        val apkSha256: String?,
        val installSource: String,
        val signatureSha256: String?,
        val rooted: Boolean,
        val tampered: Boolean,
    )

    fun report(context: Context): Report {
        val pm = context.packageManager
        val pkg = context.packageName
        val apkSha = runCatching {
            val info = pm.getApplicationInfo(pkg, 0)
            val file = File(info.sourceDir)
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buf = ByteArray(8192)
                var read: Int
                while (input.read(buf).also { read = it } > 0) {
                    digest.update(buf, 0, read)
                }
            }
            digest.digest().joinToString("") { "%02x".format(it) }
        }.getOrNull()
        val installSource = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(pkg).installingPackageName ?: "unknown"
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(pkg) ?: "unknown"
            }
        }.getOrDefault("unknown")
        val sigSha = runCatching {
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
                    .signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES).signatures
            }
            val first = signatures?.firstOrNull() ?: return@runCatching null
            val digest = MessageDigest.getInstance("SHA-256").digest(first.toByteArray())
            digest.joinToString("") { "%02x".format(it) }
        }.getOrNull()
        val rooted = detectRoot()
        val tampered = sigSha == null
        return Report(apkSha, installSource, sigSha, rooted, tampered)
    }

    private fun detectRoot(): Boolean {
        val tags = Build.TAGS?.contains("test-keys") == true
        val paths = listOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
        )
        return tags || paths.any { File(it).exists() }
    }
}
