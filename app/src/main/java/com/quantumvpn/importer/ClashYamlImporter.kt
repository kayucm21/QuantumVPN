package com.quantumvpn.importer

import com.quantumvpn.profiles.ManagedServer
import com.quantumvpn.profiles.ProtocolOutboundBuilders
import com.quantumvpn.profiles.TlsSettings
import com.quantumvpn.profiles.TransportSettings

/**
 * Imports only the top-level Clash `proxies:` list into sing-box outbounds.
 * DNS, rules and proxy-groups from Clash are intentionally ignored.
 */
object ClashYamlImporter {
    fun parse(text: String): List<ManagedServer> {
        val proxies = parseProxiesSection(text)
        if (proxies.isEmpty()) {
            throw ImportException(
                "Clash YAML не содержит proxies или список пуст. " +
                    "Экспортируйте sing-box JSON, если нужны DNS и rules.",
            )
        }
        return proxies.mapIndexedNotNull { index, map ->
            runCatching { toManagedServer(map, index) }.getOrNull()
        }.also { servers ->
            if (servers.isEmpty()) {
                throw ImportException("Не удалось преобразовать ни одного Clash proxy в sing-box outbound.")
            }
        }
    }

    private fun toManagedServer(map: Map<String, String>, index: Int): ManagedServer {
        val name = map["name"]?.trim().orEmpty().ifBlank { "Clash ${index + 1}" }
        return when (map["type"]?.lowercase()) {
            "ss", "shadowsocks" -> {
                val server = required(map, "server")
                val port = intRequired(map, "port")
                ProtocolOutboundBuilders.shadowsocks(
                    displayName = name,
                    server = server,
                    serverPort = port,
                    method = required(map, "cipher"),
                    password = required(map, "password"),
                )
            }
            "vmess" -> {
                val server = required(map, "server")
                val port = intRequired(map, "port")
                val uuid = required(map, "uuid")
                val network = map["network"].orEmpty().lowercase()
                val transport = when (network) {
                    "", "tcp" -> null
                    "ws" -> TransportSettings(
                        type = "ws",
                        path = map["ws-path"] ?: map["path"],
                        host = map["ws-headers"]?.substringAfter("Host:")?.trim()
                            ?: map["host"],
                    )
                    "grpc" -> TransportSettings(type = "grpc", serviceName = map["grpc-service-name"])
                    else -> throw ImportException("Clash VMess network '$network' не поддерживается.")
                }
                val tlsEnabled = map["tls"]?.equals("true", true) == true ||
                    map["skip-cert-verify"]?.equals("true", true) == true
                ProtocolOutboundBuilders.vmess(
                    displayName = name,
                    server = server,
                    serverPort = port,
                    uuid = uuid,
                    security = map["cipher"] ?: "auto",
                    alterId = map["alterId"]?.toIntOrNull() ?: 0,
                    tls = TlsSettings(
                        enabled = tlsEnabled,
                        serverName = map["servername"] ?: map["sni"] ?: server,
                        insecure = map["skip-cert-verify"]?.equals("true", true) == true,
                    ),
                    transport = transport,
                )
            }
            "trojan" -> ProtocolOutboundBuilders.trojan(
                displayName = name,
                server = required(map, "server"),
                serverPort = intRequired(map, "port"),
                password = required(map, "password"),
                tls = TlsSettings(
                    enabled = true,
                    serverName = map["sni"] ?: required(map, "server"),
                    insecure = map["skip-cert-verify"]?.equals("true", true) == true,
                ),
                transport = map["network"]?.lowercase()?.takeIf { it == "ws" }?.let {
                    TransportSettings(type = "ws", path = map["ws-path"], host = map["host"])
                },
            )
            "vless" -> ProtocolOutboundBuilders.vless(
                displayName = name,
                server = required(map, "server"),
                serverPort = intRequired(map, "port"),
                uuid = required(map, "uuid"),
                flow = map["flow"],
                tls = TlsSettings(
                    enabled = map["tls"]?.equals("true", true) == true ||
                        map["security"]?.equals("tls", true) == true,
                    serverName = map["sni"] ?: map["servername"] ?: required(map, "server"),
                    insecure = map["skip-cert-verify"]?.equals("true", true) == true,
                    realityPublicKey = map["reality-public-key"] ?: map["public-key"],
                    realityShortId = map["reality-short-id"] ?: map["short-id"],
                ),
                transport = map["network"]?.lowercase()?.takeIf { it.isNotBlank() }?.let { net ->
                    when (net) {
                        "tcp" -> null
                        "ws" -> TransportSettings(type = "ws", path = map["ws-path"], host = map["host"])
                        "grpc" -> TransportSettings(type = "grpc", serviceName = map["grpc-service-name"])
                        else -> throw ImportException("Clash VLESS network '$net' не поддерживается.")
                    }
                },
            )
            "hysteria" -> ProtocolOutboundBuilders.hysteria(
                displayName = name,
                server = required(map, "server"),
                serverPort = intRequired(map, "port"),
                authStr = map["auth_str"] ?: map["auth-str"] ?: required(map, "auth"),
                obfs = map["obfs"],
                upMbps = map["up"]?.toIntOrNull() ?: map["upmbps"]?.toIntOrNull(),
                downMbps = map["down"]?.toIntOrNull() ?: map["downmbps"]?.toIntOrNull(),
                tls = TlsSettings(
                    enabled = true,
                    serverName = map["sni"] ?: required(map, "server"),
                    insecure = map["skip-cert-verify"]?.equals("true", true) == true,
                ),
            )
            "hysteria2", "hy2" -> ProtocolOutboundBuilders.hysteria2(
                displayName = name,
                server = required(map, "server"),
                serverPort = intRequired(map, "port"),
                password = map["password"] ?: required(map, "auth"),
                tls = TlsSettings(
                    enabled = true,
                    serverName = map["sni"] ?: required(map, "server"),
                    insecure = map["skip-cert-verify"]?.equals("true", true) == true,
                ),
                obfsPassword = map["obfs-password"],
            )
            "tuic" -> ProtocolOutboundBuilders.tuic(
                displayName = name,
                server = required(map, "server"),
                serverPort = intRequired(map, "port"),
                uuid = required(map, "uuid"),
                password = required(map, "password"),
                congestionControl = map["congestion-controller"],
                udpRelayMode = map["udp-relay-mode"],
                tls = TlsSettings(
                    enabled = true,
                    serverName = map["sni"] ?: required(map, "server"),
                    insecure = map["skip-cert-verify"]?.equals("true", true) == true,
                ),
            )
            else -> throw ImportException(
                "Clash proxy '${map["type"]}' (${name}) не поддерживается. " +
                    "Поддерживаются: ss, vmess, trojan, vless, hysteria, hysteria2, tuic.",
            )
        }
    }

    private fun required(map: Map<String, String>, key: String): String =
        map[key]?.trim()?.takeIf(String::isNotEmpty)
            ?: throw ImportException("Clash proxy '${map["name"] ?: "?"}' не содержит '$key'.")

    private fun intRequired(map: Map<String, String>, key: String): Int =
        required(map, key).toIntOrNull()?.takeIf { it in 1..65535 }
            ?: throw ImportException("Clash proxy '${map["name"] ?: "?"}': некорректный '$key'.")

    /** Minimal YAML list-of-maps parser for Clash `proxies:` only. */
    internal fun parseProxiesSection(text: String): List<Map<String, String>> {
        val lines = text.lineSequence().map { it.trimEnd() }.toList()
        val proxiesStart = lines.indexOfFirst { it.startsWith("proxies:") }
        if (proxiesStart < 0) return emptyList()
        val result = mutableListOf<Map<String, String>>()
        var index = proxiesStart + 1
        while (index < lines.size) {
            val line = lines[index].trim()
            if (line.isEmpty() || line.startsWith('#')) {
                index++
                continue
            }
            if (!line.startsWith("-")) {
                if (line.endsWith(':') && !line.contains(' ')) break
                index++
                continue
            }
            val item = mutableMapOf<String, String>()
            var key = scalarKey(line.removePrefix("-").trim())
            var value = scalarValue(line.removePrefix("-").trim())
            if (key != null) {
                if (value != null) item[key] = value
                index++
                while (index < lines.size) {
                    val nested = lines[index]
                    val trimmed = nested.trim()
                    if (trimmed.isEmpty() || trimmed.startsWith('#')) {
                        index++
                        continue
                    }
                    if (trimmed.startsWith("-")) break
                    if (trimmed.endsWith(':') && !trimmed.contains(' ') && nested.takeWhile { it.isWhitespace() }.length <= 4) {
                        break
                    }
                    val indent = nested.takeWhile { it.isWhitespace() }.length
                    if (indent < 2) break
                    val nk = scalarKey(trimmed) ?: break
                    val nv = scalarValue(trimmed) ?: ""
                    item[nk] = nv
                    index++
                }
                if (item.isNotEmpty()) result += item
                continue
            }
            index++
        }
        return result
    }

    private fun scalarKey(line: String): String? {
        val colon = line.indexOf(':')
        if (colon <= 0) return null
        return line.substring(0, colon).trim().lowercase().replace('-', '-')
    }

    private fun scalarValue(line: String): String? {
        val colon = line.indexOf(':')
        if (colon < 0) return null
        return unquote(line.substring(colon + 1).trim())
    }

    private fun unquote(value: String): String = when {
        value.startsWith('"') && value.endsWith('"') -> value.substring(1, value.length - 1)
        value.startsWith('\'') && value.endsWith('\'') -> value.substring(1, value.length - 1)
        else -> value
    }
}
