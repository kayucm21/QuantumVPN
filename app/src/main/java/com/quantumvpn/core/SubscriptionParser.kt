package com.quantumvpn.core

import android.util.Base64
import com.quantumvpn.data.Protocol
import com.quantumvpn.data.VPNServer
import java.net.URI
import java.net.URLDecoder

object SubscriptionParser {

    fun parse(content: String): List<VPNServer> {
        val servers = mutableListOf<VPNServer>()

        val decoded = try {
            String(Base64.decode(content.trim(), Base64.DEFAULT))
        } catch (e: Exception) {
            content
        }

        decoded.lines().forEach { line ->
            val trimmed = line.trim()
            when {
                trimmed.startsWith("vless://", true) -> parseVless(trimmed)?.let { servers.add(it) }
                trimmed.startsWith("vmess://", true) -> parseVmess(trimmed)?.let { servers.add(it) }
                trimmed.startsWith("trojan://", true) -> parseTrojan(trimmed)?.let { servers.add(it) }
                trimmed.startsWith("ss://", true) -> parseShadowsocks(trimmed)?.let { servers.add(it) }
                trimmed.startsWith("hysteria2://", true) || trimmed.startsWith("hy2://", true) ->
                    parseHysteria2(trimmed)?.let { servers.add(it) }
                trimmed.startsWith("tuic://", true) -> parseTUIC(trimmed)?.let { servers.add(it) }
                trimmed.startsWith("wg://", true) -> parseWireGuard(trimmed)?.let { servers.add(it) }
            }
        }

        return servers
    }

    private fun parseVless(uri: String): VPNServer? {
        return try {
            val cleanUri = uri.removePrefix("vless://")
            val atIndex = cleanUri.indexOf('@')
            if (atIndex == -1) return null

            val uuid = cleanUri.substring(0, atIndex)
            val rest = cleanUri.substring(atIndex + 1)
            val questionIndex = rest.indexOf('?')
            val hostPort = if (questionIndex != -1) rest.substring(0, questionIndex) else rest
            val params = if (questionIndex != -1) parseParams(rest.substring(questionIndex + 1)) else emptyMap()
            val hashIndex = hostPort.indexOf('#')
            val hostPortClean = if (hashIndex != -1) hostPort.substring(0, hashIndex) else hostPort
            val name = if (hashIndex != -1) URLDecoder.decode(hostPort.substring(hashIndex + 1), "UTF-8") else "VLESS Server"

            val colonIndex = hostPortClean.lastIndexOf(':')
            val host = hostPortClean.substring(0, colonIndex)
            val port = hostPortClean.substring(colonIndex + 1).toInt()

            val security = params["security"] ?: "none"
            val sni = params["sni"] ?: params["peer"] ?: ""
            val fingerprint = params["fp"] ?: ""
            val flow = params["flow"] ?: ""
            val path = params["path"] ?: ""
            val host_param = params["host"] ?: ""
            val tls = security == "tls"

            val settings = mutableMapOf<String, Any>(
                "server" to host,
                "server_port" to port.toString(),
                "uuid" to uuid,
                "tls" to tls.toString()
            )
            if (sni.isNotEmpty()) settings["sni"] = sni
            if (fingerprint.isNotEmpty()) settings["fingerprint"] = fingerprint
            if (flow.isNotEmpty()) settings["flow"] = flow
            if (security == "reality") {
                settings["reality"] = "true"
                params["pbk"]?.let { settings["public_key"] = it }
                params["sid"]?.let { settings["short_id"] = it }
            }
            if (security == "ws" || params["type"] == "ws") {
                settings["transport"] = "ws"
                if (path.isNotEmpty()) settings["path"] = path
                if (host_param.isNotEmpty()) settings["host"] = host_param
            }
            if (security == "grpc" || params["type"] == "grpc") {
                settings["transport"] = "grpc"
                params["serviceName"]?.let { settings["service_name"] = it }
            }

            VPNServer(
                name = name,
                country = extractCountry(name),
                countryCode = extractCountryCode(name),
                flag = extractFlag(name),
                host = host,
                port = port,
                protocol = Protocol.VLESS,
                settings = settings
            )
        } catch (e: Exception) {
            null
        }
    }

    private fun parseVmess(uri: String): VPNServer? {
        return try {
            val base64Content = uri.removePrefix("vmess://")
            val json = String(Base64.decode(base64Content, Base64.DEFAULT))
            val obj = com.alibaba.fastjson.JSONObject.parseObject(json)

            val host = obj.getString("add") ?: return null
            val port = obj.getIntValue("port")
            val name = obj.getString("ps") ?: "VMess Server"

            val settings = mutableMapOf<String, Any>(
                "server" to host,
                "server_port" to port.toString(),
                "uuid" to (obj.getString("id") ?: ""),
                "alter_id" to (obj.getString("aid") ?: "0"),
                "security" to (obj.getString("scy") ?: "auto")
            )

            val net = obj.getString("net")
            val tls = obj.getString("tls")
            if (tls == "tls") settings["tls"] = "true"
            if (net == "ws") {
                settings["transport"] = "ws"
                obj.getString("path")?.let { settings["path"] = it }
                obj.getString("host")?.let { settings["host"] = it }
            }
            if (net == "grpc") {
                settings["transport"] = "grpc"
                obj.getString("path")?.let { settings["service_name"] = it }
            }

            VPNServer(
                name = name,
                country = extractCountry(name),
                countryCode = extractCountryCode(name),
                flag = extractFlag(name),
                host = host,
                port = port,
                protocol = Protocol.VMESS,
                settings = settings
            )
        } catch (e: Exception) {
            null
        }
    }

    private fun parseTrojan(uri: String): VPNServer? {
        return try {
            val cleanUri = uri.removePrefix("trojan://")
            val atIndex = cleanUri.indexOf('@')
            if (atIndex == -1) return null

            val password = cleanUri.substring(0, atIndex)
            val rest = cleanUri.substring(atIndex + 1)
            val questionIndex = rest.indexOf('?')
            val hostPort = if (questionIndex != -1) rest.substring(0, questionIndex) else rest
            val params = if (questionIndex != -1) parseParams(rest.substring(questionIndex + 1)) else emptyMap()
            val hashIndex = hostPort.indexOf('#')
            val hostPortClean = if (hashIndex != -1) hostPort.substring(0, hashIndex) else hostPort
            val name = if (hashIndex != -1) URLDecoder.decode(hostPort.substring(hashIndex + 1), "UTF-8") else "Trojan Server"

            val colonIndex = hostPortClean.lastIndexOf(':')
            val host = hostPortClean.substring(0, colonIndex)
            val port = hostPortClean.substring(colonIndex + 1).toInt()

            val settings = mutableMapOf<String, Any>(
                "server" to host,
                "server_port" to port.toString(),
                "password" to password,
                "sni" to (params["sni"] ?: host)
            )

            VPNServer(
                name = name,
                country = extractCountry(name),
                countryCode = extractCountryCode(name),
                flag = extractFlag(name),
                host = host,
                port = port,
                protocol = Protocol.TROJAN,
                settings = settings
            )
        } catch (e: Exception) {
            null
        }
    }

    private fun parseShadowsocks(uri: String): VPNServer? {
        return try {
            val cleanUri = uri.removePrefix("ss://")
            val atIndex = cleanUri.indexOf('@')
            if (atIndex == -1) {
                val decoded = String(Base64.decode(cleanUri.substringBefore('#'), Base64.DEFAULT))
                val (method, rest) = decoded.split(":", limit = 2)
                val (password, hostPort) = rest.split("@", limit = 2)
                val (host, port) = hostPort.split(":", limit = 2)
                val name = cleanUri.substringAfter('#').let { if (it.isNotEmpty()) URLDecoder.decode(it, "UTF-8") else "SS Server" }

                val settings = mutableMapOf<String, Any>(
                    "server" to host,
                    "server_port" to port,
                    "method" to method,
                    "password" to password
                )

                VPNServer(
                    name = name,
                    country = extractCountry(name),
                    countryCode = extractCountryCode(name),
                    flag = extractFlag(name),
                    host = host,
                    port = port.toInt(),
                    protocol = Protocol.SHADOWSOCKS,
                    settings = settings
                )
            } else {
                val userInfo = cleanUri.substring(0, atIndex)
                val decoded = String(Base64.decode(userInfo, Base64.DEFAULT))
                val (method, password) = decoded.split(":", limit = 2)
                val rest = cleanUri.substring(atIndex + 1)
                val questionIndex = rest.indexOf('?')
                val hostPort = if (questionIndex != -1) rest.substring(0, questionIndex) else rest
                val hashIndex = hostPort.indexOf('#')
                val hostPortClean = if (hashIndex != -1) hostPort.substring(0, hashIndex) else hostPort
                val name = if (hashIndex != -1) URLDecoder.decode(hostPort.substring(hashIndex + 1), "UTF-8") else "SS Server"

                val colonIndex = hostPortClean.lastIndexOf(':')
                val host = hostPortClean.substring(0, colonIndex)
                val port = hostPortClean.substring(colonIndex + 1).toInt()

                val settings = mutableMapOf<String, Any>(
                    "server" to host,
                    "server_port" to port.toString(),
                    "method" to method,
                    "password" to password
                )

                VPNServer(
                    name = name,
                    country = extractCountry(name),
                    countryCode = extractCountryCode(name),
                    flag = extractFlag(name),
                    host = host,
                    port = port,
                    protocol = Protocol.SHADOWSOCKS,
                    settings = settings
                )
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun parseHysteria2(uri: String): VPNServer? {
        return try {
            val cleanUri = uri.removePrefix("hysteria2://").removePrefix("hy2://")
            val atIndex = cleanUri.indexOf('@')
            if (atIndex == -1) return null

            val password = cleanUri.substring(0, atIndex)
            val rest = cleanUri.substring(atIndex + 1)
            val questionIndex = rest.indexOf('?')
            val hostPort = if (questionIndex != -1) rest.substring(0, questionIndex) else rest
            val params = if (questionIndex != -1) parseParams(rest.substring(questionIndex + 1)) else emptyMap()
            val hashIndex = hostPort.indexOf('#')
            val hostPortClean = if (hashIndex != -1) hostPort.substring(0, hashIndex) else hostPort
            val name = if (hashIndex != -1) URLDecoder.decode(hostPort.substring(hashIndex + 1), "UTF-8") else "Hysteria2 Server"

            val colonIndex = hostPortClean.lastIndexOf(':')
            val host = hostPortClean.substring(0, colonIndex)
            val port = hostPortClean.substring(colonIndex + 1).toInt()

            val settings = mutableMapOf<String, Any>(
                "server" to host,
                "server_port" to port.toString(),
                "password" to password,
                "sni" to (params["sni"] ?: host)
            )

            VPNServer(
                name = name,
                country = extractCountry(name),
                countryCode = extractCountryCode(name),
                flag = extractFlag(name),
                host = host,
                port = port,
                protocol = Protocol.Hysteria2,
                settings = settings
            )
        } catch (e: Exception) {
            null
        }
    }

    private fun parseTUIC(uri: String): VPNServer? {
        return try {
            val cleanUri = uri.removePrefix("tuic://")
            val atIndex = cleanUri.indexOf('@')
            if (atIndex == -1) return null

            val uuid = cleanUri.substring(0, atIndex)
            val rest = cleanUri.substring(atIndex + 1)
            val questionIndex = rest.indexOf('?')
            val hostPort = if (questionIndex != -1) rest.substring(0, questionIndex) else rest
            val params = if (questionIndex != -1) parseParams(rest.substring(questionIndex + 1)) else emptyMap()
            val hashIndex = hostPort.indexOf('#')
            val hostPortClean = if (hashIndex != -1) hostPort.substring(0, hashIndex) else hostPort
            val name = if (hashIndex != -1) URLDecoder.decode(hostPort.substring(hashIndex + 1), "UTF-8") else "TUIC Server"

            val colonIndex = hostPortClean.lastIndexOf(':')
            val host = hostPortClean.substring(0, colonIndex)
            val port = hostPortClean.substring(colonIndex + 1).toInt()

            val settings = mutableMapOf<String, Any>(
                "server" to host,
                "server_port" to port.toString(),
                "uuid" to uuid,
                "password" to (params["password"] ?: ""),
                "sni" to (params["sni"] ?: host)
            )

            VPNServer(
                name = name,
                country = extractCountry(name),
                countryCode = extractCountryCode(name),
                flag = extractFlag(name),
                host = host,
                port = port,
                protocol = Protocol.TUIC,
                settings = settings
            )
        } catch (e: Exception) {
            null
        }
    }

    private fun parseWireGuard(uri: String): VPNServer? {
        return try {
            val cleanUri = uri.removePrefix("wg://")
            val atIndex = cleanUri.indexOf('@')
            if (atIndex == -1) return null

            val privateKey = cleanUri.substring(0, atIndex)
            val rest = cleanUri.substring(atIndex + 1)
            val questionIndex = rest.indexOf('?')
            val hostPort = if (questionIndex != -1) rest.substring(0, questionIndex) else rest
            val params = if (questionIndex != -1) parseParams(rest.substring(questionIndex + 1)) else emptyMap()
            val hashIndex = hostPort.indexOf('#')
            val hostPortClean = if (hashIndex != -1) hostPort.substring(0, hashIndex) else hostPort
            val name = if (hashIndex != -1) URLDecoder.decode(hostPort.substring(hashIndex + 1), "UTF-8") else "WireGuard Server"

            val colonIndex = hostPortClean.lastIndexOf(':')
            val host = hostPortClean.substring(0, colonIndex)
            val port = hostPortClean.substring(colonIndex + 1).toInt()

            val settings = mutableMapOf<String, Any>(
                "server" to host,
                "server_port" to port.toString(),
                "private_key" to privateKey,
                "peer_public_key" to (params["publickey"] ?: params["public_key"] ?: ""),
                "local_address" to (params["address"] ?: "10.0.0.2/32")
            )

            VPNServer(
                name = name,
                country = extractCountry(name),
                countryCode = extractCountryCode(name),
                flag = extractFlag(name),
                host = host,
                port = port,
                protocol = Protocol.WIREGUARD,
                settings = settings
            )
        } catch (e: Exception) {
            null
        }
    }

    private fun parseParams(query: String): Map<String, String> {
        val params = mutableMapOf<String, String>()
        query.split("&").forEach { param ->
            val kv = param.split("=", limit = 2)
            if (kv.size == 2) {
                params[kv[0].lowercase()] = URLDecoder.decode(kv[1], "UTF-8")
            }
        }
        return params
    }

    private fun extractCountry(name: String): String {
        val lowerName = name.lowercase()
        val countries = mapOf(
            "usa" to "United States", "us" to "United States", "america" to "United States",
            "uk" to "United Kingdom", "gb" to "United Kingdom", "london" to "United Kingdom",
            "germany" to "Germany", "de" to "Germany", "frankfurt" to "Germany",
            "france" to "France", "fr" to "France", "paris" to "France",
            "netherlands" to "Netherlands", "nl" to "Netherlands", "amsterdam" to "Netherlands",
            "japan" to "Japan", "jp" to "Japan", "tokyo" to "Japan",
            "singapore" to "Singapore", "sg" to "Singapore",
            "korea" to "South Korea", "kr" to "South Korea", "seoul" to "South Korea",
            "russia" to "Russia", "ru" to "Russia", "moscow" to "Russia",
            "canada" to "Canada", "ca" to "Canada", "toronto" to "Canada",
            "australia" to "Australia", "au" to "Australia", "sydney" to "Australia",
            "turkey" to "Turkey", "tr" to "Turkey", "istanbul" to "Turkey",
            "india" to "India", "in" to "India", "mumbai" to "India",
            "hong kong" to "Hong Kong", "hk" to "Hong Kong",
            "taiwan" to "Taiwan", "tw" to "Taiwan",
            "ukraine" to "Ukraine", "ua" to "Ukraine", "kiev" to "Ukraine",
            "finland" to "Finland", "fi" to "Finland", "helsinki" to "Finland",
            "sweden" to "Sweden", "se" to "Sweden", "stockholm" to "Sweden",
            "switzerland" to "Switzerland", "ch" to "Switzerland", "zurich" to "Switzerland",
            "israel" to "Israel", "il" to "Israel", "tel aviv" to "Israel",
            "uae" to "UAE", "ae" to "UAE", "dubai" to "UAE",
            "brazil" to "Brazil", "br" to "Brazil", "sao paulo" to "Brazil",
            "indonesia" to "Indonesia", "id" to "Indonesia",
            "thailand" to "Thailand", "th" to "Thailand", "bangkok" to "Thailand",
            "vietnam" to "Vietnam", "vn" to "Vietnam"
        )

        for ((key, country) in countries) {
            if (lowerName.contains(key)) return country
        }
        return "Unknown"
    }

    private fun extractCountryCode(name: String): String {
        val lowerName = name.lowercase()
        val codes = mapOf(
            "usa" to "US", "us" to "US", "america" to "US",
            "uk" to "GB", "gb" to "GB", "london" to "GB",
            "germany" to "DE", "de" to "DE", "frankfurt" to "DE",
            "france" to "FR", "fr" to "FR", "paris" to "FR",
            "netherlands" to "NL", "nl" to "NL", "amsterdam" to "NL",
            "japan" to "JP", "jp" to "JP", "tokyo" to "JP",
            "singapore" to "SG", "sg" to "SG",
            "korea" to "KR", "kr" to "KR", "seoul" to "KR",
            "russia" to "RU", "ru" to "RU", "moscow" to "RU",
            "canada" to "CA", "ca" to "CA", "toronto" to "CA",
            "australia" to "AU", "au" to "AU", "sydney" to "AU",
            "turkey" to "TR", "tr" to "TR", "istanbul" to "TR",
            "india" to "IN", "in" to "IN", "mumbai" to "IN",
            "hong kong" to "HK", "hk" to "HK",
            "taiwan" to "TW", "tw" to "TW",
            "ukraine" to "UA", "ua" to "UA", "kiev" to "UA",
            "finland" to "FI", "fi" to "FI", "helsinki" to "FI",
            "sweden" to "SE", "se" to "SE", "stockholm" to "SE",
            "switzerland" to "CH", "ch" to "CH", "zurich" to "CH",
            "israel" to "IL", "il" to "IL", "tel aviv" to "IL",
            "uae" to "AE", "ae" to "AE", "dubai" to "AE",
            "brazil" to "BR", "br" to "BR", "sao paulo" to "BR",
            "indonesia" to "ID", "id" to "ID",
            "thailand" to "TH", "th" to "TH", "bangkok" to "TH",
            "vietnam" to "VN", "vn" to "VN"
        )

        for ((key, code) in codes) {
            if (lowerName.contains(key)) return code
        }
        return "??"
    }

    private fun extractFlag(name: String): String {
        val code = extractCountryCode(name)
        return if (code != "??") {
            val offset = 0x1F1E6 - 'A'.code
            val first = Character.toChars(code[0].code + offset)
            val second = Character.toChars(code[1].code + offset)
            String(first) + String(second)
        } else {
            "🌐"
        }
    }
}
