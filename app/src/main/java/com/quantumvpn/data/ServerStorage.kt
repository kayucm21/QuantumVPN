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
            readList(context, "subscriptions.json", object : TypeToken<List<Subscription>>() {})
        }
    }

    suspend fun saveAll(context: Context, servers: List<VPNServer>, subscriptions: List<Subscription>) =
        withContext(Dispatchers.IO) {
            mutex.withLock {
                writeList(context, "servers.json", servers)
                writeList(context, "subscriptions.json", subscriptions)
            }
        }

    private fun <T> readList(context: Context, name: String, typeToken: TypeToken<List<T>>): List<T> {
        val file = File(context.filesDir, name)
        if (!file.exists() || file.length() == 0L) return emptyList()

        return try {
            gson.fromJson<List<T>>(file.readText(), typeToken.type) ?: emptyList()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to read $name, trying backup", e)
            val backup = File(context.filesDir, "$name.bak")
            if (backup.exists() && backup.length() > 0) {
                try {
                    gson.fromJson<List<T>>(backup.readText(), typeToken.type) ?: emptyList()
                } catch (e2: Exception) {
                    Log.e(TAG, "Backup $name also failed", e2)
                    emptyList()
                }
            } else {
                emptyList()
            }
        }
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
