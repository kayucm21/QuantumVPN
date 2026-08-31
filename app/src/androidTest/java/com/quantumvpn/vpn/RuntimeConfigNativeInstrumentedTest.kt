package com.quantumvpn.vpn

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.quantumvpn.config.RuntimeConfigBuilder
import com.quantumvpn.config.DnsMode
import com.quantumvpn.config.RuntimeConfigOptions
import com.quantumvpn.config.RuntimeConfigResult
import io.nekohasekai.libbox.Libbox
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RuntimeConfigNativeInstrumentedTest {
    @Test
    fun transformedRuntimeConfigPassesPinnedLibbox() {
        val raw = """
            {
              "inbounds":[{"type":"tun","tag":"tun-in","address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],"auto_route":true}],
              "outbounds":[
                {"type":"direct","tag":"server-a"},
                {"type":"selector","tag":"zapret-proxy","outbounds":["server-a"],"default":"server-a"},
                {"type":"direct","tag":"direct"}
              ],
              "route":{"auto_detect_interface":true,"final":"zapret-proxy"}
            }
        """.trimIndent()
        DnsMode.entries.forEach { mode ->
            listOf(null, "com.quantumvpn").forEach { updaterPackage ->
                val runtime = RuntimeConfigBuilder.build(
                    raw,
                    options = RuntimeConfigOptions(
                        dnsMode = mode,
                        healthCheckPackageName = "com.quantumvpn",
                        updaterPackageName = updaterPackage,
                    ),
                ) as RuntimeConfigResult.Ready
                Libbox.checkConfig(runtime.json)
            }
        }
    }
}
