package com.quantumvpn.updates

import android.os.Build
import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.longOrNull

/**
 * Reads `/<remoteDir>/manifest.json` from FTP and maps it into [UpdateCandidate].
 *
 * Manifest schema:
 * {
 *   "schema": 1,
 *   "version_name": "4.5.0",
 *   "version_code": 55,
 *   "application_id": "com.quantumvpn",
 *   "kind": "minor" | "global" | "patch",
 *   "notes": "...",
 *   "artifacts": [
 *     { "abi": "arm64-v8a", "apk_file": "...", "apk_sha256": "...", "apk_size": 123 }
 *   ]
 * }
 */
class FtpUpdateSource(
    private val host: String,
    private val username: String,
    private val password: String,
    private val remoteDir: String,
    private val applicationId: String,
    private val supportedAbis: List<String> = Build.SUPPORTED_ABIS.toList(),
) : UpdateReleaseSource {
    private fun client(
        connectTimeoutMs: Int = SimpleFtpClient.DEFAULT_CONNECT_MS,
        readTimeoutMs: Int = SimpleFtpClient.DEFAULT_READ_MS,
    ) = SimpleFtpClient(
        host = host,
        username = username,
        password = password,
        connectTimeoutMs = connectTimeoutMs,
        readTimeoutMs = readTimeoutMs,
    )

    override fun latest(channel: UpdateChannel): UpdateCandidate {
        val names = when (channel) {
            UpdateChannel.Beta -> listOf("manifest-beta.json", MANIFEST)
            UpdateChannel.Stable -> listOf("manifest-stable.json", MANIFEST)
        }
        var lastError: UpdateException? = null
        val probe = client(
            connectTimeoutMs = SimpleFtpClient.MANIFEST_CONNECT_MS,
            readTimeoutMs = SimpleFtpClient.MANIFEST_READ_MS,
        )
        for (name in names) {
            try {
                val path = join(remoteDir, name)
                val raw = probe.readText(path, MAX_MANIFEST_BYTES)
                return parseManifest(raw)
            } catch (error: UpdateException) {
                lastError = error
            }
        }
        throw lastError ?: UpdateException("FTP manifest не найден.")
    }

    fun downloadApk(
        remoteFileName: String,
        target: File,
        expectedBytes: Long,
        onProgress: (Long) -> Unit,
    ) {
        val path = join(remoteDir, remoteFileName)
        client(
            connectTimeoutMs = SimpleFtpClient.DEFAULT_CONNECT_MS,
            readTimeoutMs = 60_000,
        ).downloadFile(path, target, expectedBytes, onProgress)
    }

    private fun parseManifest(raw: String): UpdateCandidate {
        val root = try {
            Json.parseToJsonElement(raw) as? JsonObject
                ?: throw UpdateException("FTP manifest должен быть JSON-объектом.")
        } catch (error: UpdateException) {
            throw error
        } catch (error: Exception) {
            throw UpdateException("FTP manifest повреждён.", cause = error)
        }
        val schema = (root["schema"] as? JsonPrimitive)?.contentOrNull?.toIntOrNull() ?: 1
        if (schema != 1) throw UpdateException("Версия FTP manifest не поддерживается.")
        val versionName = requiredString(root, "version_name")
        val versionCode = requiredLong(root, "version_code")
        if (versionCode <= 0) throw UpdateException("Некорректный version_code в FTP manifest.")
        val packageId = requiredString(root, "application_id")
        if (packageId != applicationId) {
            throw UpdateException("FTP обновление предназначено для другого package.")
        }
        val kind = root.string("kind")?.lowercase().orEmpty().ifBlank { "minor" }
        val notes = root.string("notes").orEmpty().take(8_000)
        val artifacts = (root["artifacts"] as? JsonArray)
            ?.mapNotNull { it as? JsonObject }
            ?: throw UpdateException("В FTP manifest нет artifacts.")
        val chosen = supportedAbis.firstNotNullOfOrNull { abi ->
            artifacts.firstOrNull { it.string("abi") == abi }
        } ?: throw UpdateException("Для архитектуры этого устройства APK на FTP нет.")
        val apkFile = requiredString(chosen, "apk_file")
        if (!APK_FILE.matches(apkFile)) throw UpdateException("Некорректное имя APK в FTP manifest.")
        val apkSha256 = UpdateJson.normalizedSha256(requiredString(chosen, "apk_sha256"))
        val apkSize = requiredLong(chosen, "apk_size")
        if (apkSize <= 0 || apkSize > UpdateJson.MAX_APK_BYTES) {
            throw UpdateException("Некорректный размер APK в FTP manifest.")
        }
        val abi = requiredString(chosen, "abi")
        val metadata = ReleaseMetadata(
            versionName = versionName,
            versionCode = versionCode,
            applicationId = packageId,
            coreTag = root.string("core_tag") ?: "ftp",
            coreCommit = root.string("core_commit")
                ?.takeIf { COMMIT.matches(it) }
                ?: PLACEHOLDER_COMMIT,
            abi = listOf(abi),
            apkFile = apkFile,
            apkSha256 = apkSha256,
            apkSize = apkSize,
        )
        val titleKind = when (kind) {
            "global", "major" -> "Глобальное обновление"
            "patch", "hotfix" -> "Исправление"
            else -> "Обновление"
        }
        val apkAsset = GitHubAsset(
            name = apkFile,
            downloadUrl = FTP_SCHEME + apkFile,
            size = apkSize,
            digest = "sha256:$apkSha256",
        )
        val checksumAsset = GitHubAsset(
            name = "$apkFile.sha256",
            downloadUrl = FTP_SCHEME + "$apkFile.sha256",
            size = 128,
            digest = null,
        )
        val release = GitHubRelease(
            tag = "v$versionName",
            title = "$titleKind $versionName",
            body = notes.ifBlank { "$titleKind QuantumVPN $versionName" },
            pageUrl = "ftp://$host/${join(remoteDir, apkFile).trimStart('/')}",
            draft = false,
            prerelease = kind == "beta",
            assets = listOf(apkAsset, checksumAsset),
            publishedAt = root.string("published_at"),
        )
        return UpdateCandidate(release, metadata, apkAsset, checksumAsset)
    }

    private fun join(dir: String, name: String): String {
        val left = dir.trim().trim('/')
        val right = name.trim().trimStart('/')
        return if (left.isEmpty()) "/$right" else "/$left/$right"
    }

    private fun JsonObject.string(name: String): String? =
        (get(name) as? JsonPrimitive)?.contentOrNull

    private fun requiredString(root: JsonObject, name: String): String =
        root.string(name)?.takeIf(String::isNotBlank)
            ?: throw UpdateException("Поле $name отсутствует в FTP manifest.")

    private fun requiredLong(root: JsonObject, name: String): Long =
        (root[name] as? JsonPrimitive)?.longOrNull
            ?: root.string(name)?.toLongOrNull()
            ?: throw UpdateException("Поле $name отсутствует в FTP manifest.")

    companion object {
        const val MANIFEST = "manifest.json"
        const val FTP_SCHEME = "ftp-quantumvpn://"
        private const val MAX_MANIFEST_BYTES = 64 * 1024
        private val APK_FILE = Regex("[A-Za-z0-9._-]+\\.apk")
        private val COMMIT = Regex("[0-9a-f]{40}")
        private const val PLACEHOLDER_COMMIT = "0000000000000000000000000000000000000000"
    }
}

/** Prefer FTP when configured; fall back to GitHub quickly if FTP is slow/unreachable. */
class PreferFtpThenGitHubSource(
    private val ftp: FtpUpdateSource?,
    private val github: UpdateReleaseSource,
) : UpdateReleaseSource {
    override fun latest(channel: UpdateChannel): UpdateCandidate {
        if (ftp == null) return github.latest(channel)
        val ftpError = try {
            return ftp.latest(channel)
        } catch (error: UpdateException) {
            error
        }
        return try {
            github.latest(channel)
        } catch (_: UpdateException) {
            throw ftpError
        }
    }
}

/** Routes FTP-scheme downloads through [FtpUpdateSource]; everything else via HTTPS. */
class FtpAwareHttpClient(
    private val ftp: FtpUpdateSource?,
    private val https: UpdateHttpClient = GitHubHttpsClient(),
) : UpdateHttpClient {
    override fun readText(url: String, maxBytes: Int): String {
        if (url.startsWith(FtpUpdateSource.FTP_SCHEME)) {
            throw UpdateException("FTP checksum встроен в manifest.")
        }
        return https.readText(url, maxBytes)
    }

    override fun download(
        url: String,
        target: File,
        expectedBytes: Long,
        onProgress: (Long) -> Unit,
    ) {
        if (url.startsWith(FtpUpdateSource.FTP_SCHEME)) {
            val source = ftp ?: throw UpdateException("FTP источник не настроен.")
            val name = url.removePrefix(FtpUpdateSource.FTP_SCHEME)
            source.downloadApk(name, target, expectedBytes, onProgress)
            return
        }
        https.download(url, target, expectedBytes, onProgress)
    }
}
