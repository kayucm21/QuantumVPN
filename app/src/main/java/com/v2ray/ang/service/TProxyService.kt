package com.v2ray.ang.service

/**
 * JNI bridge for libhev-socks5-tunnel.so (PKGNAME=com/v2ray/ang/service in prebuilt libs).
 */
object TProxyService {
    init {
        System.loadLibrary("hev-socks5-tunnel")
    }

    @JvmStatic
    external fun TProxyStartService(configPath: String, fd: Int)

    @JvmStatic
    external fun TProxyStopService()

    @JvmStatic
    external fun TProxyGetStats(): LongArray?
}
