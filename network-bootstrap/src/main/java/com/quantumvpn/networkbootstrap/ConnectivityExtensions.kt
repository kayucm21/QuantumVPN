package com.quantumvpn.networkbootstrap

import android.net.ConnectivityManager
import android.net.Network
import android.os.Build

/**
 * Returns all currently known networks, using the modern [ConnectivityManager.getNetworks]
 * on API 36+ and the deprecated [ConnectivityManager.allNetworks] on older platforms.
 * Keeps call sites free of deprecation warnings while remaining compatible with minSdk 26.
 */
val ConnectivityManager.networksCompat: Array<Network>
    get() = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
        getAllNetworks()
    } else {
        @Suppress("DEPRECATION")
        allNetworks
    }
