package com.quantumvpn.config

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConfigAnalyzerTest {
    @Test
    fun `profile DNS requires a usable tagged server selection`() {
        assertTrue(
            ConfigAnalyzer.hasProfileDns(
                """{"dns":{"servers":[{"type":"udp","tag":"profile-dns","server":"192.0.2.53"}],"final":"profile-dns"}}""",
            ),
        )
        assertTrue(
            ConfigAnalyzer.hasProfileDns(
                """{"dns":{"servers":[{"type":"local","tag":"profile-dns"}]}}""",
            ),
        )
        assertFalse(
            ConfigAnalyzer.hasProfileDns(
                """{"dns":{"servers":[{"type":"local","tag":"profile-dns"}],"final":"missing"}}""",
            ),
        )
        assertFalse(ConfigAnalyzer.hasProfileDns("""{"route":{}}"""))
        assertFalse(ConfigAnalyzer.hasProfileDns("not-json"))
    }

    @Test
    fun `unused DNS server is reported without inventing fallback`() {
        val warnings = ConfigAnalyzer.dnsWarnings(
            """
                {
                  "dns":{
                    "servers":[
                      {"type":"local","tag":"bootstrap"},
                      {"type":"udp","tag":"primary","server":"1.1.1.1"},
                      {"type":"udp","tag":"unused","server":"8.8.8.8"}
                    ],
                    "final":"primary"
                  },
                  "route":{"default_domain_resolver":"bootstrap"}
                }
            """.trimIndent(),
        )

        assertTrue(warnings.single().contains("1 сервер"))
        assertTrue(warnings.single().contains("резервными автоматически"))
    }

    @Test
    fun `fallback children count as used DNS servers`() {
        val warnings = ConfigAnalyzer.dnsWarnings(
            """
                {
                  "dns":{
                    "servers":[
                      {"type":"udp","tag":"one","server":"1.1.1.1"},
                      {"type":"udp","tag":"two","server":"8.8.8.8"},
                      {"type":"fallback","tag":"secure","servers":["one","two"],"strategy":"parallel"}
                    ],
                    "final":"secure"
                  }
                }
            """.trimIndent(),
        )

        assertTrue(warnings.isEmpty())
    }
}
