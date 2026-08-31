package com.quantumvpn.updates

import android.os.Build

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
) : UpdateReleaseSource {

    override fun latest(channel: UpdateChannel): UpdateCandidate {
        val endpoint = "${baseUrl.trimEnd('/')}/api/app/version"
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
            (http as? PanelHttpsClient)?.headSize(version.url) ?: 0L
        } catch (_: Throwable) {
            0L
        }
        if (size <= 0) throw UpdateException("Панель не вернула размер APK.")

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
    }
}
