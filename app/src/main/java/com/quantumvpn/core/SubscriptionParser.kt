package com.quantumvpn.core

import android.util.Base64
import com.quantumvpn.data.Protocol
import com.quantumvpn.data.VPNServer
import java.net.URLDecoder

object SubscriptionParser {

    fun parse(content: String): List<VPNServer> {
        val servers = mutableListOf<VPNServer>()

        // Try base64 decode first
        val decoded = try {
            val cleaned = content.trim()
                .replace("\r", "")
                .replace("\n", "")
                .replace(" ", "")
            val bytes = Base64.decode(cleaned, Base64.DEFAULT)
            String(bytes, Charsets.UTF_8)
        } catch (e: Exception) {
            content
        }

        decoded.lines().forEach { line ->
            val trimmed = line.trim()
            if (trimmed.isEmpty()) return@forEach

            when {
                trimmed.startsWith("vless://", true) -> parseVless(trimmed)?.let { servers.add(it) }
                trimmed.startsWith("vmess://", true) -> parseVmess(trimmed)?.let { servers.add(it) }
                trimmed.startsWith("trojan://", true) -> parseTrojan(trimmed)?.let { servers.add(it) }
                trimmed.startsWith("ss://", true) -> parseShadowsocks(trimmed)?.let { servers.add(it) }
                trimmed.startsWith("hysteria2://", true) || trimmed.startsWith("hy2://", true) ->
                    parseHysteria2(trimmed)?.let { servers.add(it) }
                trimmed.startsWith("tuic://", true) -> parseTUIC(trimmed)?.let { servers.add(it) }
            }
        }

        return servers
    }

    private fun parseVless(uri: String): VPNServer? {
        return try {
            val cleanUri = uri.removePrefix("vless://").removePrefix("VLESS://")
            val atIndex = cleanUri.indexOf('@')
            if (atIndex == -1) return null

            val uuid = cleanUri.substring(0, atIndex)
            val rest = cleanUri.substring(atIndex + 1)

            // Find question mark for params
            val questionIndex = rest.indexOf('?')
            val hashIndex = rest.indexOf('#')

            val hostPortEnd = when {
                questionIndex != -1 -> questionIndex
                hashIndex != -1 -> hashIndex
                else -> rest.length
            }
            val hostPort = rest.substring(0, hostPortEnd)

            // Parse params
            val params = mutableMapOf<String, String>()
            if (questionIndex != -1) {
                val paramsEnd = if (hashIndex != -1) hashIndex else rest.length
                val paramsStr = rest.substring(questionIndex + 1, paramsEnd)
                paramsStr.split("&").forEach { param ->
                    val kv = param.split("=", limit = 2)
                    if (kv.size == 2) {
                        params[kv[0].lowercase()] = URLDecoder.decode(kv[1], "UTF-8")
                    }
                }
            }

            // Parse name from hash
            val name = if (hashIndex != -1) {
                try {
                    URLDecoder.decode(rest.substring(hashIndex + 1), "UTF-8")
                } catch (e: Exception) {
                    "VLESS сервер"
                }
            } else {
                "VLESS сервер"
            }

            // Parse host:port
            val colonIndex = hostPort.lastIndexOf(':')
            if (colonIndex == -1) return null
            val host = hostPort.substring(0, colonIndex)
            val port = hostPort.substring(colonIndex + 1).toIntOrNull() ?: 443

            val security = params["security"] ?: "none"
            val sni = params["sni"] ?: params["peer"] ?: host
            val fingerprint = params["fp"] ?: "chrome"
            val flow = params["flow"] ?: ""
            val path = params["path"] ?: ""
            val hostParam = params["host"] ?: ""
            val serviceName = params["servicename"] ?: params["serviceName"] ?: ""

            val settings = mutableMapOf<String, String>(
                "uuid" to uuid,
                "server" to host,
                "server_port" to port.toString(),
                "tls" to (security == "tls" || security == "reality").toString(),
                "security" to security,
                "sni" to sni,
                "fingerprint" to fingerprint
            )

            if (flow.isNotEmpty()) settings["flow"] = flow
            if (security == "reality") {
                params["pbk"]?.let { settings["public_key"] = it }
                params["sid"]?.let { settings["short_id"] = it }
            }
            val networkType = params["type"]?.lowercase() ?: "tcp"
            when (networkType) {
                "ws" -> {
                    settings["transport"] = "ws"
                    if (path.isNotEmpty()) settings["path"] = path
                    if (hostParam.isNotEmpty()) settings["host"] = hostParam
                }
                "grpc" -> {
                    settings["transport"] = "grpc"
                    if (serviceName.isNotEmpty()) settings["service_name"] = serviceName
                }
                "http", "h2" -> {
                    settings["transport"] = "http"
                    if (path.isNotEmpty()) settings["path"] = path
                    if (hostParam.isNotEmpty()) settings["host"] = hostParam
                }
            }
            if (networkType != "grpc" && serviceName.isNotEmpty()) {
                settings["transport"] = "grpc"
                settings["service_name"] = serviceName
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
            val base64Content = uri.removePrefix("vmess://").removePrefix("VMESS://")
            val json = String(Base64.decode(base64Content, Base64.DEFAULT), Charsets.UTF_8)
            val obj = com.google.gson.JsonParser.parseString(json).asJsonObject

            val host = obj.get("add")?.asString ?: return null
            val port = obj.get("port")?.asInt ?: 443
            val name = obj.get("ps")?.asString ?: "VMess сервер"
            val uuid = obj.get("id")?.asString ?: ""
            val alterId = obj.get("aid")?.asString ?: "0"
            val security = obj.get("scy")?.asString ?: "auto"

            val settings = mutableMapOf<String, String>(
                "uuid" to uuid,
                "server" to host,
                "server_port" to port.toString(),
                "alter_id" to alterId,
                "security" to security
            )

            val net = obj.get("net")?.asString
            val tls = obj.get("tls")?.asString
            val sni = obj.get("sni")?.asString
            val path = obj.get("path")?.asString
            val hostParam = obj.get("host")?.asString
            val serviceName = obj.get("path")?.asString

            if (tls == "tls") {
                settings["tls"] = "true"
                if (sni != null) settings["sni"] = sni
            }
            if (net == "ws") {
                settings["transport"] = "ws"
                if (path != null) settings["path"] = path
                if (hostParam != null) settings["host"] = hostParam
            }
            if (net == "grpc") {
                settings["transport"] = "grpc"
                if (serviceName != null) settings["service_name"] = serviceName
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
            val cleanUri = uri.removePrefix("trojan://").removePrefix("TROJAN://")
            val atIndex = cleanUri.indexOf('@')
            if (atIndex == -1) return null

            val password = cleanUri.substring(0, atIndex)
            val rest = cleanUri.substring(atIndex + 1)
            val questionIndex = rest.indexOf('?')
            val hashIndex = rest.indexOf('#')

            val hostPortEnd = when {
                questionIndex != -1 -> questionIndex
                hashIndex != -1 -> hashIndex
                else -> rest.length
            }
            val hostPort = rest.substring(0, hostPortEnd)
            val name = if (hashIndex != -1) {
                try { URLDecoder.decode(rest.substring(hashIndex + 1), "UTF-8") } catch (e: Exception) { "Trojan сервер" }
            } else "Trojan сервер"

            val colonIndex = hostPort.lastIndexOf(':')
            if (colonIndex == -1) return null
            val host = hostPort.substring(0, colonIndex)
            val port = hostPort.substring(colonIndex + 1).toIntOrNull() ?: 443

            val params = mutableMapOf<String, String>()
            if (questionIndex != -1) {
                val paramsEnd = if (hashIndex != -1) hashIndex else rest.length
                val paramsStr = rest.substring(questionIndex + 1, paramsEnd)
                paramsStr.split("&").forEach { param ->
                    val kv = param.split("=", limit = 2)
                    if (kv.size == 2) params[kv[0].lowercase()] = URLDecoder.decode(kv[1], "UTF-8")
                }
            }

            val settings = mutableMapOf<String, String>(
                "password" to password,
                "server" to host,
                "server_port" to port.toString(),
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
        } catch (e: Exception) { null }
    }

    private fun parseShadowsocks(uri: String): VPNServer? {
        return try {
            val cleanUri = uri.removePrefix("ss://").removePrefix("SS://")
            val atIndex = cleanUri.indexOf('@')

            if (atIndex != -1) {
                val userInfo = cleanUri.substring(0, atIndex)
                val decoded = try {
                    String(Base64.decode(userInfo, Base64.DEFAULT), Charsets.UTF_8)
                } catch (e: Exception) { userInfo }

                val colonIdx = decoded.indexOf(':')
                if (colonIdx == -1) return null
                val method = decoded.substring(0, colonIdx)
                val password = decoded.substring(colonIdx + 1)

                val rest = cleanUri.substring(atIndex + 1)
                val hashIndex = rest.indexOf('#')
                val hostPort = if (hashIndex != -1) rest.substring(0, hashIndex) else rest
                val name = if (hashIndex != -1) {
                    try { URLDecoder.decode(rest.substring(hashIndex + 1), "UTF-8") } catch (e: Exception) { "SS сервер" }
                } else "SS сервер"

                val colonIndex = hostPort.lastIndexOf(':')
                if (colonIndex == -1) return null
                val host = hostPort.substring(0, colonIndex)
                val port = hostPort.substring(colonIndex + 1).toIntOrNull() ?: 443

                val settings = mutableMapOf<String, String>(
                    "method" to method,
                    "password" to password,
                    "server" to host,
                    "server_port" to port.toString()
                )

                VPNServer(name = name, country = extractCountry(name), countryCode = extractCountryCode(name),
                    flag = extractFlag(name), host = host, port = port, protocol = Protocol.SHADOWSOCKS, settings = settings)
            } else null
        } catch (e: Exception) { null }
    }

    private fun parseHysteria2(uri: String): VPNServer? {
        return try {
            val cleanUri = uri.removePrefix("hysteria2://").removePrefix("hy2://").removePrefix("HYSTERIA2://")
            val atIndex = cleanUri.indexOf('@')
            if (atIndex == -1) return null

            val password = cleanUri.substring(0, atIndex)
            val rest = cleanUri.substring(atIndex + 1)
            val questionIndex = rest.indexOf('?')
            val hashIndex = rest.indexOf('#')
            val hostPortEnd = when {
                questionIndex != -1 -> questionIndex
                hashIndex != -1 -> hashIndex
                else -> rest.length
            }
            val hostPort = rest.substring(0, hostPortEnd)
            val name = if (hashIndex != -1) {
                try { URLDecoder.decode(rest.substring(hashIndex + 1), "UTF-8") } catch (e: Exception) { "Hysteria2 сервер" }
            } else "Hysteria2 сервер"

            val colonIndex = hostPort.lastIndexOf(':')
            if (colonIndex == -1) return null
            val host = hostPort.substring(0, colonIndex)
            val port = hostPort.substring(colonIndex + 1).toIntOrNull() ?: 443

            val settings = mutableMapOf<String, String>(
                "password" to password,
                "server" to host,
                "server_port" to port.toString(),
                "sni" to host
            )

            VPNServer(name = name, country = extractCountry(name), countryCode = extractCountryCode(name),
                flag = extractFlag(name), host = host, port = port, protocol = Protocol.Hysteria2, settings = settings)
        } catch (e: Exception) { null }
    }

    private fun parseTUIC(uri: String): VPNServer? {
        return try {
            val cleanUri = uri.removePrefix("tuic://").removePrefix("TUIC://")
            val atIndex = cleanUri.indexOf('@')
            if (atIndex == -1) return null

            val uuid = cleanUri.substring(0, atIndex)
            val rest = cleanUri.substring(atIndex + 1)
            val questionIndex = rest.indexOf('?')
            val hashIndex = rest.indexOf('#')
            val hostPortEnd = when {
                questionIndex != -1 -> questionIndex
                hashIndex != -1 -> hashIndex
                else -> rest.length
            }
            val hostPort = rest.substring(0, hostPortEnd)
            val name = if (hashIndex != -1) {
                try { URLDecoder.decode(rest.substring(hashIndex + 1), "UTF-8") } catch (e: Exception) { "TUIC сервер" }
            } else "TUIC сервер"

            val colonIndex = hostPort.lastIndexOf(':')
            if (colonIndex == -1) return null
            val host = hostPort.substring(0, colonIndex)
            val port = hostPort.substring(colonIndex + 1).toIntOrNull() ?: 443

            val params = mutableMapOf<String, String>()
            if (questionIndex != -1) {
                val paramsEnd = if (hashIndex != -1) hashIndex else rest.length
                val paramsStr = rest.substring(questionIndex + 1, paramsEnd)
                paramsStr.split("&").forEach { param ->
                    val kv = param.split("=", limit = 2)
                    if (kv.size == 2) params[kv[0].lowercase()] = URLDecoder.decode(kv[1], "UTF-8")
                }
            }

            val settings = mutableMapOf<String, String>(
                "uuid" to uuid,
                "password" to (params["password"] ?: ""),
                "server" to host,
                "server_port" to port.toString(),
                "sni" to (params["sni"] ?: host)
            )

            VPNServer(name = name, country = extractCountry(name), countryCode = extractCountryCode(name),
                flag = extractFlag(name), host = host, port = port, protocol = Protocol.TUIC, settings = settings)
        } catch (e: Exception) { null }
    }

    private fun extractCountry(name: String): String {
        val lower = name.lowercase()
        val countries = mapOf(
            "иркутск" to "Россия", "москва" to "Россия", "петербург" to "Россия", "россия" to "Россия",
            "netherlands" to "Нидерланды", "amsterdam" to "Нидерланды", "нидерланды" to "Нидерланды",
            "germany" to "Германия", "frankfurt" to "Германия", "германия" to "Германия",
            "usa" to "США", "america" to "США", "сша" to "США",
            "france" to "Франция", "paris" to "Франция", "франция" to "Франция",
            "uk" to "Великобритания", "london" to "Великобритания", "великобритания" to "Великобритания",
            "japan" to "Япония", "tokyo" to "Япония", "япония" to "Япония",
            "singapore" to "Сингапур", "сингапур" to "Сингапур",
            "korea" to "Корея", "seoul" to "Корея", "корея" to "Корея",
            "canada" to "Канада", "toronto" to "Канада", "канада" to "Канада",
            "turkey" to "Турция", "istanbul" to "Турция", "турция" to "Турция",
            "india" to "Индия", "mumbai" to "Индия", "индия" to "Индия",
            "hong kong" to "Гонконг", "taiwan" to "Тайвань", "ukraine" to "Украина",
            "finland" to "Финляндия", "helsinki" to "Финляндия", "sweden" to "Швеция",
            "switzerland" to "Швейцария", "israel" to "Израиль", "dubai" to "ОАЭ",
            "brazil" to "Бразилия", "indonesia" to "Индонезия", "thailand" to "Таиланд",
            "vietnam" to "Вьетнам", "australia" to "Австралия"
        )
        for ((key, country) in countries) {
            if (lower.contains(key)) return country
        }
        return "Неизвестно"
    }

    private fun extractCountryCode(name: String): String {
        val lower = name.lowercase()
        val codes = mapOf (
            "иркутск" to "RU", "москва" to "RU", "петербург" to "RU", "россия" to "RU",
            "amsterdam" to "NL", "нидерланды" to "NL",
            "frankfurt" to "DE", "германия" to "DE",
            "usa" to "US", "сша" to "US",
            "paris" to "FR", "франция" to "FR",
            "london" to "GB", "великобритания" to "GB",
            "tokyo" to "JP", "япония" to "JP",
            "singapore" to "SG", "сингапур" to "SG",
            "seoul" to "KR", "корея" to "KR",
            "toronto" to "CA", "канада" to "CA",
            "istanbul" to "TR", "турция" to "TR"
        )
        for ((key, code) in codes) {
            if (lower.contains(key)) return code
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
        } else "\uD83C\uDF10"
    }
}
