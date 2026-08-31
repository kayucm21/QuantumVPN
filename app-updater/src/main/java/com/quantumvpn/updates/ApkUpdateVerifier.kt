package com.quantumvpn.updates

import android.content.Context
import android.annotation.TargetApi
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.SigningInfo
import android.os.Build
import java.io.File
import java.security.MessageDigest

data class SigningIdentity(
    val current: Set<String>,
    val history: Set<String>,
    val multipleSigners: Boolean,
)

data class ApkIdentity(
    val packageName: String,
    val versionName: String,
    val versionCode: Long,
    val minSdk: Int,
    val signing: SigningIdentity,
)

object UpdateInstallPolicy {
    fun requireCompatible(
        installed: ApkIdentity,
        archive: ApkIdentity,
        metadata: ReleaseMetadata,
        deviceSdk: Int = Build.VERSION.SDK_INT,
    ) {
        if (archive.packageName != installed.packageName || archive.packageName != metadata.applicationId) {
            throw UpdateException("APK имеет другой Android package.")
        }
        if (archive.versionCode != metadata.versionCode || archive.versionName != metadata.versionName) {
            throw UpdateException("Версия внутри APK не совпадает с release metadata.")
        }
        if (archive.versionCode <= installed.versionCode) {
            throw UpdateException("Downgrade или повторная установка через updater запрещены.")
        }
        if (archive.minSdk > deviceSdk) {
            throw UpdateException("APK требует более новую версию Android.")
        }
        if (!signingCompatible(installed.signing, archive.signing)) {
            throw UpdateException("Подпись APK не совместима с установленным приложением.")
        }
    }

    fun signingCompatible(installed: SigningIdentity, archive: SigningIdentity): Boolean {
        if (installed.current.isEmpty() || archive.current.isEmpty()) return false
        if (installed.multipleSigners || archive.multipleSigners) {
            return installed.multipleSigners && archive.multipleSigners &&
                installed.current == archive.current
        }
        val installedCurrent = installed.current.singleOrNull() ?: return false
        return installedCurrent in archive.history
    }
}

fun interface ApkUpdateVerifier {
    fun verify(file: File, metadata: ReleaseMetadata)
}

class AndroidApkUpdateVerifier(private val context: Context) : ApkUpdateVerifier {
    @Suppress("DEPRECATION")
    fun inspectInstalled(): ApkIdentity {
        val flags = if (Build.VERSION.SDK_INT >= 28) {
            PackageManager.GET_SIGNING_CERTIFICATES or PackageManager.GET_SIGNATURES
        } else {
            PackageManager.GET_SIGNATURES
        }
        val info = context.packageManager.getPackageInfo(context.packageName, flags)
        return identity(info)
    }

    @Suppress("DEPRECATION")
    fun inspectArchive(file: File): ApkIdentity {
        val flags = if (Build.VERSION.SDK_INT >= 28) {
            PackageManager.GET_SIGNING_CERTIFICATES or PackageManager.GET_SIGNATURES
        } else {
            PackageManager.GET_SIGNATURES
        }
        val info = context.packageManager.getPackageArchiveInfo(file.absolutePath, flags)
            ?: throw UpdateException("Android не распознал загруженный APK.")
        if (!info.splitNames.isNullOrEmpty()) throw UpdateException("Split APK updater не поддерживает.")
        return identity(info)
    }

    override fun verify(file: File, metadata: ReleaseMetadata) {
        UpdateInstallPolicy.requireCompatible(inspectInstalled(), inspectArchive(file), metadata)
    }

    @Suppress("DEPRECATION")
    private fun identity(info: PackageInfo): ApkIdentity {
        val versionCode = if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong()
        val signingInfo = if (Build.VERSION.SDK_INT >= 28) info.signingInfo else null
        val signing = if (Build.VERSION.SDK_INT >= 28 && signingInfo != null) {
            signingIdentity(signingInfo)
        } else {
            val signatures = info.signatures.orEmpty().map(::certificateSha256).toSet()
            if (signatures.isEmpty()) throw UpdateException("Android не прочитал подпись APK.")
            SigningIdentity(signatures, signatures, signatures.size > 1)
        }
        return ApkIdentity(
            packageName = info.packageName,
            versionName = info.versionName.orEmpty(),
            versionCode = versionCode,
            minSdk = info.applicationInfo?.minSdkVersion ?: 1,
            signing = signing,
        )
    }

    @TargetApi(28)
    private fun signingIdentity(value: SigningInfo): SigningIdentity {
        val current = value.apkContentsSigners.orEmpty().map(::certificateSha256).toSet()
        val multipleSigners = value.hasMultipleSigners()
        val history = if (multipleSigners) {
            current
        } else {
            value.signingCertificateHistory.orEmpty().map(::certificateSha256).toSet()
        }
        return SigningIdentity(current, history, multipleSigners)
    }

    private fun certificateSha256(signature: android.content.pm.Signature): String =
        MessageDigest.getInstance("SHA-256")
            .digest(signature.toByteArray())
            .joinToString("") { "%02x".format(it) }
}
