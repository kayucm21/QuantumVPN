package com.quantumvpn.vpn

import com.quantumvpn.config.OutboundDescription
import com.quantumvpn.config.SelectorGroup
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ServerPingTargetResolverTest {
    private val descriptions = mapOf(
        "proxy-a" to OutboundDescription("proxy-a", "vless", "a.example", "a.example:443"),
        "proxy-b" to OutboundDescription("proxy-b", "vless", "b.example", "b.example:443"),
        "direct" to OutboundDescription("direct", "direct", null, null),
    )

    @Test
    fun `selected target follows runtime selector to server hostname`() {
        val resolver = ServerPingTargetResolver(
            descriptions,
            listOf(SelectorGroup("zapret-proxy", listOf("proxy-a", "proxy-b"), "proxy-a")),
        )

        val target = resolver.selected(
            listOf(group("zapret-proxy", selected = "proxy-b", "proxy-a", "proxy-b")),
        )

        assertEquals(ServerPingTarget("proxy-b", "b.example"), target)
    }

    @Test
    fun `group omits non-server outbounds instead of inventing route latency`() {
        val resolver = ServerPingTargetResolver(
            descriptions,
            listOf(SelectorGroup("zapret-proxy", listOf("proxy-a", "direct"), "proxy-a")),
        )
        val runtime = listOf(group("zapret-proxy", selected = "direct", "proxy-a", "direct"))

        assertEquals(listOf(ServerPingTarget("proxy-a", "a.example")), resolver.group("zapret-proxy", runtime))
        assertNull(resolver.selected(runtime))
    }

    @Test
    fun `group expands nested urltest members to leaf hosts`() {
        val descriptions = mapOf(
            "proxy-a" to OutboundDescription("proxy-a", "vless", "a.example", "a.example:443"),
            "proxy-b" to OutboundDescription("proxy-b", "vless", "b.example", "b.example:443"),
            "auto" to OutboundDescription("auto", "urltest", null, null),
        )
        val resolver = ServerPingTargetResolver(
            descriptions,
            listOf(
                SelectorGroup("zapret-proxy", listOf("auto"), "auto"),
                SelectorGroup("auto", listOf("proxy-a", "proxy-b"), "proxy-a"),
            ),
        )
        val runtime = listOf(group("zapret-proxy", selected = "auto", "auto"))

        assertEquals(
            listOf(
                ServerPingTarget("proxy-a", "a.example"),
                ServerPingTarget("proxy-b", "b.example"),
            ),
            resolver.group("zapret-proxy", runtime),
        )
    }

    @Test
    fun `direct selection never falls back to the only configured server`() {
        val oneServer = descriptions.filterKeys { it != "proxy-b" }
        val resolver = ServerPingTargetResolver(
            oneServer,
            listOf(SelectorGroup("zapret-proxy", listOf("proxy-a", "direct"), "proxy-a")),
        )

        assertNull(
            resolver.selected(
                listOf(group("zapret-proxy", selected = "direct", "proxy-a", "direct")),
            ),
        )
    }

    private fun group(tag: String, selected: String, vararg items: String) = RuntimeSelectorGroup(
        tag = tag,
        type = "selector",
        selected = selected,
        selectable = true,
        items = items.map { item ->
            RuntimeOutboundItem(item, "vless", null, null, null)
        },
    )
}
