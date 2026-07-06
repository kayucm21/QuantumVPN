package com.quantumvpn.data

object CurrentServer {
    private var server: VPNServer? = null
    fun set(s: VPNServer) { server = s }
    fun get(): VPNServer? = server
}
