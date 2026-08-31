package com.quantumvpn.vpn

import android.content.Context
import com.quantumvpn.networkbootstrap.UnderlyingNetworkMonitor

typealias PrivateDnsMode = com.quantumvpn.networkbootstrap.PrivateDnsMode
typealias UnderlyingNetworkState = com.quantumvpn.networkbootstrap.UnderlyingNetworkState

internal object PrivateDnsClassifier {
    fun classify(apiLevel: Int, active: Boolean, serverName: String?): PrivateDnsMode =
        com.quantumvpn.networkbootstrap.PrivateDnsClassifier.classify(
            apiLevel = apiLevel,
            active = active,
            serverName = serverName,
        )
}

/** App lifecycle adapter; network selection and snapshot consistency live in network-bootstrap. */
class DefaultNetworkMonitor(context: Context) : AutoCloseable {
    private val delegate = UnderlyingNetworkMonitor(context)
    private val started = java.util.concurrent.atomic.AtomicBoolean(false)
    private val closed = java.util.concurrent.atomic.AtomicBoolean(false)

    val current: UnderlyingNetworkState
        get() = delegate.current

    fun start() {
        if (!started.compareAndSet(false, true)) return
        try {
            delegate.start()
            VpnRuntimeMetrics.callbackOpened()
        } catch (error: Throwable) {
            started.set(false)
            throw error
        }
    }

    fun observe(observer: (UnderlyingNetworkState) -> Unit): AutoCloseable = delegate.observe(observer)

    suspend fun awaitUnderlying(timeoutMillis: Long = 8_000): UnderlyingNetworkState =
        delegate.awaitUnderlying(timeoutMillis)

    suspend fun awaitStableUnderlying(timeoutMillis: Long = 8_000): UnderlyingNetworkState =
        delegate.awaitStableUnderlying(timeoutMillis)

    suspend fun <T> runOnStableNetwork(
        operation: suspend (UnderlyingNetworkState) -> T,
    ): com.quantumvpn.networkbootstrap.StableNetworkResult<T> =
        delegate.runOnStableNetwork(operation = operation)

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        delegate.close()
        if (started.compareAndSet(true, false)) VpnRuntimeMetrics.callbackClosed()
    }
}
