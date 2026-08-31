package com.quantumvpn.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ServerFailoverTest {
    @Test
    fun picksLowestPingExcludingCurrent() {
        val groups = listOf(
            RuntimeSelectorGroup(
                tag = "proxy",
                type = "selector",
                selected = "a",
                selectable = true,
                items = listOf(
                    RuntimeOutboundItem("a", "vless", null, 10, null),
                    RuntimeOutboundItem("b", "vless", null, 20, null),
                    RuntimeOutboundItem("c", "vless", null, 5, null),
                ),
            ),
        )
        val next = ServerFailover.nextBest(
            groups = groups,
            pingByTag = mapOf("a" to 10, "b" to 20, "c" to 5),
            excludeTag = "a",
        )
        assertEquals("c", next?.outboundTag)
        assertEquals(5, next?.pingMillis)
    }

    @Test
    fun respectsExcludeTags() {
        val groups = listOf(
            RuntimeSelectorGroup(
                tag = "proxy",
                type = "selector",
                selected = "a",
                selectable = true,
                items = listOf(
                    RuntimeOutboundItem("a", "vless", null, 10, null),
                    RuntimeOutboundItem("b", "vless", null, 20, null),
                    RuntimeOutboundItem("c", "vless", null, 5, null),
                ),
            ),
        )
        val next = ServerFailover.nextBest(
            groups = groups,
            pingByTag = mapOf("a" to 10, "b" to 20, "c" to 5),
            excludeTags = setOf("a", "c"),
        )
        assertEquals("b", next?.outboundTag)
    }

    @Test
    fun returnsNullWithoutPings() {
        val groups = listOf(
            RuntimeSelectorGroup(
                tag = "proxy",
                type = "selector",
                selected = "a",
                selectable = true,
                items = listOf(RuntimeOutboundItem("a", "vless", null, null, null)),
            ),
        )
        assertNull(ServerFailover.nextBest(groups, emptyMap(), "a"))
    }
}
