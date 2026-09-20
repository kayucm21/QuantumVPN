package com.quantumvpn.updates

import java.io.File
import org.junit.Assert.*
import org.junit.Test

class PanelUpdateSourceTest {
    @Test fun selectsEachSupportedArchitecture() {
        for (abi in listOf("arm64-v8a", "armeabi-v7a")) {
            var requested = ""
            val http = object : UpdateHttpClient {
                override fun readText(url: String, maxBytes: Int): String {
                    requested = url
                    return """{"version":"5.6.12","version_code":93,"url":"https://example.org:8443/$abi.apk","sha256":"${"a".repeat(64)}","size":1234,"note":"Changes"}"""
                }
                override fun download(url: String, target: File, expectedBytes: Long, onProgress: (Long) -> Unit) = error("unused")
            }
            val result = PanelUpdateSource("https://example.org:8443", "com.quantumvpn.debug", http, listOf(abi)).latest(UpdateChannel.Stable)
            assertEquals("https://example.org:8443/api/app/version?abi=$abi", requested)
            assertEquals(listOf(abi), result.metadata.abi)
            assertEquals(1234L, result.metadata.apkSize)
            assertEquals("5.6.12", result.metadata.versionName)
        }
    }
}
