package com.quantumvpn.utils

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import com.google.gson.Gson
import java.io.File
import java.util.concurrent.TimeUnit

object UpdateChecker {
    private const val TAG = "UpdateChecker"
    private const val GITHUB_API_URL = "https://api.github.com/repos"
    private const val OWNER = "kayucm21"
    private const val REPO = "QuantumVPN"

    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    data class GitHubRelease(
        val tag_name: String,
        val name: String,
        val body: String,
        val assets: List<GitHubAsset>
    )

    data class GitHubAsset(
        val name: String,
        val browser_download_url: String,
        val size: Long
    )

    suspend fun checkForUpdate(currentVersion: String): GitHubRelease? {
        return withContext(Dispatchers.IO) {
            try {
                val url = "$GITHUB_API_URL/$OWNER/$REPO/releases/latest"
                val request = Request.Builder()
                    .url(url)
                    .header("Accept", "application/vnd.github.v3+json")
                    .build()

                val response = client.newCall(request).execute()
                if (response.isSuccessful) {
                    val json = response.body?.string()
                    val release = Gson().fromJson(json, GitHubRelease::class.java)

                    val latestVersion = release.tag_name.removePrefix("v")
                    if (isNewerVersion(latestVersion, currentVersion)) {
                        release
                    } else {
                        null
                    }
                } else {
                    null
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to check for updates", e)
                null
            }
        }
    }

    suspend fun downloadAndInstall(context: Context, asset: GitHubAsset) {
        withContext(Dispatchers.IO) {
            try {
                val downloadsDir = File(context.getExternalFilesDir(null), "downloads")
                if (!downloadsDir.exists()) downloadsDir.mkdirs()

                val apkFile = File(downloadsDir, "update.apk")

                val request = Request.Builder()
                    .url(asset.browser_download_url)
                    .build()

                val response = client.newCall(request).execute()
                if (response.isSuccessful) {
                    response.body?.byteStream()?.use { input ->
                        apkFile.outputStream().use { output ->
                            input.copyTo(output)
                        }
                    }

                    installApk(context, apkFile)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to download update", e)
            }
        }
    }

    private fun installApk(context: Context, apkFile: File) {
        try {
            val intent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(
                    Uri.fromFile(apkFile),
                    "application/vnd.android.package-archive"
                )
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            context.startActivity(intent)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to install APK", e)
        }
    }

    private fun isNewerVersion(newVersion: String, currentVersion: String): Boolean {
        val newParts = newVersion.split(".").map { it.toIntOrNull() ?: 0 }
        val currentParts = currentVersion.split(".").map { it.toIntOrNull() ?: 0 }

        for (i in 0 until maxOf(newParts.size, currentParts.size)) {
            val newPart = newParts.getOrElse(i) { 0 }
            val currentPart = currentParts.getOrElse(i) { 0 }
            if (newPart > currentPart) return true
            if (newPart < currentPart) return false
        }
        return false
    }
}
