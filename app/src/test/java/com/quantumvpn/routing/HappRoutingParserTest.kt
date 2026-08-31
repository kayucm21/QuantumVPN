package com.quantumvpn.routing

import com.quantumvpn.importer.ImportCandidate
import com.quantumvpn.importer.ImportParser
import com.quantumvpn.profiles.ProfileSource
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HappRoutingParserTest {
    @Test
    fun `extracts happ routing links and leaves server uris`() {
        val profileJson = """{"Name":"RosPanel-RU-Direct","GlobalProxy":"true","DirectSites":["geosite:category-ru"],"DirectIp":["geoip:ru"]}"""
        val encoded = Base64.getEncoder().encodeToString(profileJson.toByteArray())
        val body = """
            happ://routing/onadd/$encoded
            vless://11111111-1111-4111-8111-111111111111@one.example:443?security=tls#One
        """.trimIndent()

        val extracted = HappRoutingParser.extractFromBody(body)
        assertTrue(extracted.import is HappRoutingImport.Profiles)
        val updates = (extracted.import as HappRoutingImport.Profiles).updates
        assertEquals("RosPanel-RU-Direct", updates.single().profile.name)
        assertTrue(updates.single().activate)

        val parsed = ImportParser.parse(body, ProfileSource.Url, "Sub")
        assertTrue(parsed.candidate is ImportCandidate.Managed)
        assertEquals(1, (parsed.candidate as ImportCandidate.Managed).servers.size)
        assertTrue(parsed.routing is HappRoutingImport.Profiles)
    }

    @Test
    fun `header routing merges with body`() {
        val profileJson = """{"Name":"RosPanel-Lite","GlobalProxy":"true"}"""
        val encoded = Base64.getEncoder().encodeToString(profileJson.toByteArray())
        val header = HappRoutingParser.parseHeader("happ://routing/add/$encoded")
        assertTrue(header is HappRoutingImport.Profiles)
        assertEquals("RosPanel-Lite", (header as HappRoutingImport.Profiles).updates.single().profile.name)
    }
}
