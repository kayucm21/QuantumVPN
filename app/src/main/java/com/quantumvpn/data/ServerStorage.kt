package com.quantumvpn.data

import android.content.Context
import android.util.Log
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File

data class SubscriptionMeta(
    val id: String,
    val name: String,
    val url: String,
    val lastUpdate: Long = 0L
)

object ServerStorage {
    private const val TAG = "ServerStorage"
    private val mutex = Mutex()
    private val gson: Gson = GsonBuilder().create()

    suspend fun loadServers(context: Context): List<VPNServer> = withContext(Dispatchers.IO) {
        mutex.withLock {
            readList(context, "servers.json", object : TypeToken<List<VPNServer>>() {})
        }
    }

    suspend fun loadSubscriptions(context: Context): List<Subscription> = withContext(Dispatchers.IO) {
        mutex.withLock {
            loadSubscriptionsLocked(context)
        }
    }

    suspend fun saveAll(context: Context, servers: List<VPNServer>, subscriptions: List<Subscription>) =
        withContext(Dispatchers.IO) {
            mutex.withLock {
                writeList(context, "servers.json", servers)
                val metas = subscriptions.map {
                    SubscriptionMeta(it.id, it.name, it.url, it.lastUpdate)
                }
                writeList(context, "subscriptions.json", metas)
            }
        }

    private fun loadSubscriptionsLocked(context: Context): List<Subscription> {
        val file = File(context.filesDir, "subscriptions.json")
        if (!file.exists() || file.length() == 0L) return emptyList()
        val text = readTextSafe(file) ?: return emptyList()

        try {
            val metas = gson.fromJson<List<SubscriptionMeta>>(
                text,
                object : TypeToken<List<SubscriptionMeta>>() {}.type
            )
            if (!metas.isNullOrEmpty()) {
                return metas.map { Subscription(it.id, it.name, it.url, emptyList(), it.lastUpdate) }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Meta subscription parse failed, trying legacy", e)
        }

        return try {
            val legacy = gson.fromJson<List<Subscription>>(
                text,
                object : TypeToken<List<Subscription>>() {}.type
            ) ?: emptyList()
            legacy.map { it.copy(servers = emptyList()) }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load subscriptions", e)
            emptyList()
        }
    }

    private fun <T> readList(context: Context, name: String, typeToken: TypeToken<List<T>>): List<T> {
        val file = File(context.filesDir, name)
        if (!file.exists() || file.length() == 0L) return emptyList()

        return try {
            val text = readTextSafe(file) ?: return emptyList()
            gson.fromJson<List<T>>(text, typeToken.type) ?: emptyList()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to read $name, trying backup", e)
            val backup = File(context.filesDir, "$name.bak")
            if (backup.exists() && backup.length() > 0) {
                try {
                    val backupText = readTextSafe(backup) ?: return emptyList()
                    gson.fromJson<List<T>>(backupText, typeToken.type) ?: emptyList()
                } catch (e2: Exception) {
                    Log.e(TAG, "Backup $name also failed", e2)
                    emptyList()
                }
            } else {
                emptyList()
            }
        }
    }

    private fun readTextSafe(file: File): String? = try {
        file.readText()
    } catch (e: Exception) {
        Log.e(TAG, "Failed to read file ${file.name}", e)
        null
    }

    private fun <T> writeList(context: Context, name: String, data: List<T>) {
        val file = File(context.filesDir, name)
        val tmp = File(context.filesDir, "$name.tmp")
        val backup = File(context.filesDir, "$name.bak")
        try {
            val json = gson.toJson(data)
            tmp.writeText(json)
            if (file.exists() && file.length() > 0) {
                file.copyTo(backup, overwrite = true)
            }
            if (file.exists()) file.delete()
            if (!tmp.renameTo(file)) {
                tmp.copyTo(file, overwrite = true)
                tmp.delete()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to write $name", e)
            tmp.delete()
        }
    }
}
