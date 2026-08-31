package com.quantumvpn.tile

import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.annotation.RequiresApi
import com.quantumvpn.QuantumVpnApplication
import com.quantumvpn.vpn.VpnConnectionState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

@RequiresApi(Build.VERSION_CODES.N)
class VpnToggleTileService : TileService() {
    private val scope = CoroutineScope(Dispatchers.Main.immediate)
    private var job: Job? = null

    override fun onStartListening() {
        super.onStartListening()
        val controller = (application as? QuantumVpnApplication)?.container?.vpnController ?: return
        job?.cancel()
        job = scope.launch {
            controller.state.collectLatest { state ->
                updateTile(state)
            }
        }
    }

    override fun onStopListening() {
        job?.cancel()
        job = null
        super.onStopListening()
    }

    @Suppress("DEPRECATION")
    override fun onClick() {
        val app = application as? QuantumVpnApplication ?: return
        val controller = app.container.vpnController
        when (controller.state.value) {
            is VpnConnectionState.Connected,
            is VpnConnectionState.Starting,
            -> controller.stop()
            is VpnConnectionState.Stopping -> Unit
            else -> {
                // Open app on Home with connect intent; long-press of QS tile uses TILE_PREFERENCES → servers.
                val launch = packageManager.getLaunchIntentForPackage(packageName)?.apply {
                    addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                    putExtra(com.quantumvpn.MainActivity.SHORTCUT_EXTRA, "connect")
                }
                if (launch != null) {
                    startActivityAndCollapse(launch)
                }
            }
        }
    }

    private fun updateTile(state: VpnConnectionState) {
        val tile = qsTile ?: return
        when (state) {
            is VpnConnectionState.Connected -> {
                tile.state = Tile.STATE_ACTIVE
                tile.label = "QuantumVPN"
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    val ping = com.quantumvpn.vpn.SessionPingCache.snapshot()
                        .values
                        .mapNotNull { it }
                        .minOrNull()
                    tile.subtitle = buildString {
                        append(state.profileName.take(18))
                        if (ping != null) append(" · ").append(ping).append(" ms")
                    }
                }
            }
            is VpnConnectionState.Starting, is VpnConnectionState.Stopping -> {
                tile.state = Tile.STATE_UNAVAILABLE
                tile.label = "QuantumVPN"
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = "…"
                }
            }
            else -> {
                tile.state = Tile.STATE_INACTIVE
                tile.label = "QuantumVPN"
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = "Выкл"
                }
            }
        }
        tile.updateTile()
    }
}
