package com.quantumvpn.updates

import android.os.Build
import java.security.MessageDigest
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

/**
 * RosPanel-backed update source. The panel is the operator's single source of truth for
 * the Android app release (auto-update). When no release is published (empty version/url)
 * latest() throws UpdateException so the caller treats the app as up-to-date.
 *
 * The produced UpdateCandidate reuses the GitHub-shaped models so the rest of the update
 * pipeline (download, SHA-256 verify, install-policy check) works unchanged. versionCode
 * comes straight from the panel (it must equal the published APK's integer version code).
 */
class PanelUpdateSource(
    private val baseUrl: String,
    private val applicationId: String,
    private val http: UpdateHttpClient = PanelHttpsClient(),
    private val supportedAbis: List<String> = Build.SUPPORTED_ABIS.toList(),
    private val currentVersionName: String = "",
    private val currentVersionCode: Long = 1,
    deviceId: String = "",
) : UpdateReleaseSource {
    private val rolloutBucket: Int? = deviceId.takeIf(String::isNotBlank)?.let(::stableRolloutBucket)

    override fun latest(channel: UpdateChannel): UpdateCandidate {
        val abi = supportedAbis.firstOrNull { it in setOf("arm64-v8a", "armeabi-v7a", "x86_64") }
            ?: throw UpdateException("Архитектура устройства не поддерживается.")
        val endpoint = buildString {
            append(baseUrl.trimEnd('/')).append("/api/app/version?abi=").append(abi)
            append("&current_version=").append(urlEncode(currentVersionName))
            append("&current_version_code=").append(currentVersionCode.coerceAtLeast(1))
            rolloutBucket?.let { append("&bucket=").append(it) }
        }
        val version = try {
            PanelVersionJson.parse(http.readText(endpoint, MAX_VERSION_BYTES))
        } catch (error: UpdateException) {
            throw error
        } catch (error: Exception) {
            throw UpdateException("Не удалось прочитать версию с панели.", cause = error, retryViaVpn = true)
        }
        if (version.version.isBlank() || version.url.isBlank()) {
            throw UpdateException("Панель не опубликовала релиз.")
        }
        val fileName = version.url.substringAfterLast('/').takeIf { it.endsWith(".apk") } ?: "update.apk"
        val size = try {
            version.size.takeIf { it > 0 } ?: (http as? PanelHttpsClient)?.headSize(version.url) ?: 0L
        } catch (_: Throwable) {
            0L
        }
        if (size <= 0 || size > UpdateJson.MAX_APK_BYTES) throw UpdateException("Панель вернула некорректный размер APK.")

        val release = GitHubRelease(
            tag = "v${version.version}",
            title = version.version,
            body = version.note,
            pageUrl = version.url,
            draft = false,
            prerelease = channel == UpdateChannel.Beta,
            assets = emptyList(),
            publishedAt = null,
        )
        val metadata = ReleaseMetadata(
            versionName = version.version,
            versionCode = version.versionCode.coerceAtLeast(1),
            applicationId = applicationId,
            coreTag = "",
            coreCommit = "",
            abi = listOf(supportedAbis.firstOrNull() ?: "arm64-v8a"),
            apkFile = fileName,
            apkSha256 = UpdateJson.normalizedSha256(version.sha256),
            apkSize = size,
        )
        val apkAsset = GitHubAsset(name = fileName, downloadUrl = version.url, size = size, digest = null)
        val checksumAsset = GitHubAsset(name = "$fileName.sha256", downloadUrl = version.url, size = size, digest = null)
        return UpdateCandidate(release, metadata, apkAsset, checksumAsset)
    }

    private companion object {
        const val MAX_VERSION_BYTES = 16 * 1024

        fun stableRolloutBucket(deviceId: String): Int {
            val digest = MessageDigest.getInstance("SHA-256")
                .digest(deviceId.toByteArray(StandardCharsets.UTF_8))
            val value = ((digest[0].toInt() and 0xff) shl 8) or (digest[1].toInt() and 0xff)
            return value % 100
        }

        fun urlEncode(value: String): String =
            URLEncoder.encode(value, StandardCharsets.UTF_8.name())
    }
}
