package com.quantumvpn.config

import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Test

class JsonTreeEditorTest {
    @Test
    fun `gui edit keeps unknown extended fields`() {
        val original = JsonConfig.parse(CONFIG)
        val edited = JsonTreeEditor.replace(
            original,
            listOf(
                JsonPathSegment.Key("outbounds"),
                JsonPathSegment.Index(0),
                JsonPathSegment.Key("server_port"),
            ),
            JsonPrimitive(8443),
        )

        val restoredPort = JsonTreeEditor.replace(
            edited,
            listOf(
                JsonPathSegment.Key("outbounds"),
                JsonPathSegment.Index(0),
                JsonPathSegment.Key("server_port"),
            ),
            JsonPrimitive(443),
        )
        assertEquals(original, restoredPort)
    }

    @Test
    fun `selector default edit changes no other field`() {
        val selected = ConfigAnalyzer.selectServer(CONFIG, "group", "server-b")
        val restored = ConfigAnalyzer.selectServer(selected, "group", "server-a")

        assertEquals(JsonConfig.parse(CONFIG), JsonConfig.parse(restored))
    }

    private companion object {
        val CONFIG = """
            {
              "extended_top": {"future": [1, 2, 3]},
              "dns": {"future_dns": true},
              "outbounds": [
                {
                  "type": "vless",
                  "tag": "server-a",
                  "server": "vpn.example",
                  "server_port": 443,
                  "uuid": "11111111-1111-4111-8111-111111111111",
                  "future_protocol_option": {"enabled": true}
                },
                {"type": "direct", "tag": "server-b", "future_direct": 7},
                {
                  "type": "selector",
                  "tag": "group",
                  "outbounds": ["server-a", "server-b"],
                  "default": "server-a",
                  "future_selector": "kept"
                }
              ],
              "route": {"final": "group", "future_route": {"x": "y"}}
            }
        """.trimIndent()
    }
}
