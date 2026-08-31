package com.quantumvpn.vpn

import android.annotation.SuppressLint
import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Handler
import android.os.Looper
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/** Resolves the VPN network used by app-level health and identity probes. */
class VpnNetworkProvider(context: Context) {
    private val connectivity = context.applicationContext
        .getSystemService(ConnectivityManager::class.java)

    @SuppressLint("MissingPermission")
    suspend fun awaitActive(): Network {
        connectivity.activeNetwork?.takeIf(::isVpn)?.let { return it }
        return suspendCancellableCoroutine { continuation ->
            val unregistered = AtomicBoolean(false)
            lateinit var callback: ConnectivityManager.NetworkCallback
            fun unregister() {
                if (unregistered.compareAndSet(false, true)) {
                    runCatching { connectivity.unregisterNetworkCallback(callback) }
                }
            }
            callback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    if (isVpn(network) && continuation.isActive) {
                        unregister()
                        continuation.resume(network)
                    }
                }
            }
            connectivity.registerDefaultNetworkCallback(callback, Handler(Looper.getMainLooper()))
            continuation.invokeOnCancellation { unregister() }
        }
    }

    fun requireActive(network: Network) {
        check(connectivity.activeNetwork == network) {
            "VPN не является активной сетью приложения."
        }
    }

    private fun isVpn(network: Network): Boolean = connectivity.getNetworkCapabilities(network)
        ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
}
