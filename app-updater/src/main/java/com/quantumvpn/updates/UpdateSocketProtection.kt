package com.quantumvpn.updates

import java.net.Socket

/**
 * Optional binder so FTP/HTTPS update sockets can leave an active VpnService tunnel
 * (Network.bindSocket / protect) without starting a second VPN session.
 */
fun interface UpdateSocketBinder {
    /** Return true if the socket was bound/protected successfully. */
    fun bind(socket: Socket): Boolean
}

object UpdateSocketProtection {
    @Volatile
    var binder: UpdateSocketBinder? = null

    fun bind(socket: Socket): Boolean = runCatching { binder?.bind(socket) == true }.getOrDefault(false)
}
