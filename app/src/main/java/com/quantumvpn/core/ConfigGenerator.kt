package com.quantumvpn.core

import android.content.Context
import android.util.Log
import com.quantumvpn.data.Protocol
import com.quantumvpn.data.VPNServer
import java.io.File

object ConfigGenerator {
    private const val TAG = "ConfigGenerator"

    private fun jsonEscape(value: String): String =
        value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "")

    fun generate(context: Context, server: VPNServer): String? {
        return try {
            val config = generateSingBoxConfig(context, server)
            val configFile = File(context.filesDir, "sing-box-config.json")
            configFile.writeText(config)
            Log.d(TAG, "Config: ${configFile.absolutePath}")
            Log.d(TAG, "Config content: $config")
            configFile.absolutePath
        } catch (e: Exception) {
            Log.e(TAG, "Failed to generate config", e)
            null
        }
    }

    private fun generateSingBoxConfig(context: Context, server: VPNServer): String {
        val outbound = generateOutbound(server)
        val logPath = jsonEscape(File(context.filesDir, "sing-box.log").absolutePath)
        return """{
  "log": {
    "level": "info",
    "timestamp": true,
    "output": "$logPath"
  },
  "dns": {
    "servers": [
      {
        "tag": "dns-direct",
        "type": "udp",
        "server": "223.5.5.5"
      },
      {
        "tag": "dns-remote",
        "type": "tls",
        "server": "8.8.8.8",
        "detour": "proxy"
      }
    ],
    "strategy": "prefer_ipv4"
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "address": ["172.19.0.1/30"],
      "mtu": 1500,
      "auto_route": false,
      "strict_route": false,
      "stack": "system",
      "sniff": true,
      "sniff_override_destination": true
    }
  ],
  "outbounds": [
    $outbound,
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ],
  "route": {
    "rules": [
      {
        "action": "sniff"
      },
      {
        "protocol": "dns",
        "action": "hijack-dns"
      },
      {
        "ip_is_private": true,
        "outbound": "direct"
      }
    ],
    "final": "proxy"
  }
}"""
    }

    private fun generateOutbound(server: VPNServer): String {
        return when (server.protocol) {
            Protocol.VLESS -> generateVlessOutbound(server)
            Protocol.VMESS -> generateVmessOutbound(server)
            Protocol.TROJAN -> generateTrojanOutbound(server)
            Protocol.SHADOWSOCKS -> generateShadowsocksOutbound(server)
            Protocol.Hysteria2 -> generateHysteria2Outbound(server)
            Protocol.TUIC -> generateTUICOutbound(server)
            Protocol.WIREGUARD -> generateVlessOutbound(server)
        }
    }

    private fun setting(server: VPNServer, key: String, default: String = ""): String =
        server.settings[key] ?: default

    private fun generateVlessOutbound(server: VPNServer): String {
        val s = server.settings
        val sb = StringBuilder()
        sb.append("{\n")
        sb.append("      \"type\": \"vless\",\n")
        sb.append("      \"tag\": \"proxy\",\n")
        sb.append("      \"server\": \"${jsonEscape(server.host)}\",\n")
        sb.append("      \"server_port\": ${server.port},\n")
        sb.append("      \"uuid\": \"${jsonEscape(setting(server, "uuid"))}\"")

        val flow = setting(server, "flow")
        if (flow.isNotEmpty()) {
            sb.append(",\n      \"flow\": \"${jsonEscape(flow)}\"")
        }

        val security = setting(server, "security", "none")
        if (security == "tls" || security == "reality") {
            val sni = setting(server, "sni", server.host)
            val fp = setting(server, "fingerprint", "chrome")
            sb.append(",\n      \"tls\": {\n")
            sb.append("        \"enabled\": true,\n")
            sb.append("        \"server_name\": \"${jsonEscape(sni)}\",\n")
            sb.append("        \"utls\": {\n")
            sb.append("          \"enabled\": true,\n")
            sb.append("          \"fingerprint\": \"${jsonEscape(fp)}\"\n")
            sb.append("        }")
            if (security == "reality") {
                sb.append(",\n        \"reality\": {\n")
                sb.append("          \"enabled\": true,\n")
                sb.append("          \"public_key\": \"${jsonEscape(setting(server, "public_key"))}\",\n")
                sb.append("          \"short_id\": \"${jsonEscape(setting(server, "short_id"))}\"\n")
                sb.append("        }")
            }
            sb.append("\n      }")
        }

        appendTransport(sb, s, server.host)
        sb.append("\n    }")
        return sb.toString()
    }

    private fun generateVmessOutbound(server: VPNServer): String {
        val s = server.settings
        val sb = StringBuilder()
        sb.append("{\n")
        sb.append("      \"type\": \"vmess\",\n")
        sb.append("      \"tag\": \"proxy\",\n")
        sb.append("      \"server\": \"${jsonEscape(server.host)}\",\n")
        sb.append("      \"server_port\": ${server.port},\n")
        sb.append("      \"uuid\": \"${jsonEscape(setting(server, "uuid"))}\",\n")
        sb.append("      \"alter_id\": ${setting(server, "alter_id", "0")},\n")
        sb.append("      \"security\": \"${jsonEscape(setting(server, "security", "auto"))}\"")

        if (setting(server, "tls") == "true") {
            val sni = setting(server, "sni", server.host)
            sb.append(",\n      \"tls\": {\n")
            sb.append("        \"enabled\": true,\n")
            sb.append("        \"server_name\": \"${jsonEscape(sni)}\"\n")
            sb.append("      }")
        }

        appendTransport(sb, s, server.host)
        sb.append("\n    }")
        return sb.toString()
    }

    private fun appendTransport(sb: StringBuilder, s: Map<String, String>, defaultHost: String) {
        val transport = s["transport"] ?: ""
        val serviceName = s["service_name"] ?: ""
        val wsPath = s["path"] ?: ""
        val wsHost = s["host"] ?: ""

        if (transport == "ws" || (wsPath.isNotEmpty() && serviceName.isEmpty())) {
            sb.append(",\n      \"transport\": {\n")
            sb.append("        \"type\": \"ws\",\n")
            sb.append("        \"path\": \"${jsonEscape(wsPath)}\"")
            if (wsHost.isNotEmpty()) {
                sb.append(",\n        \"headers\": {\n")
                sb.append("          \"Host\": \"${jsonEscape(wsHost)}\"\n")
                sb.append("        }")
            }
            sb.append("\n      }")
        } else if (transport == "grpc" || serviceName.isNotEmpty()) {
            sb.append(",\n      \"transport\": {\n")
            sb.append("        \"type\": \"grpc\",\n")
            sb.append("        \"service_name\": \"${jsonEscape(serviceName)}\"\n")
            sb.append("      }")
        } else if (transport == "http") {
            sb.append(",\n      \"transport\": {\n")
            sb.append("        \"type\": \"http\",\n")
            sb.append("        \"path\": \"${jsonEscape(wsPath)}\",\n")
            sb.append("        \"host\": \"${jsonEscape(wsHost.ifEmpty { defaultHost })}\"\n")
            sb.append("      }")
        }
    }

    private fun generateTrojanOutbound(server: VPNServer): String {
        return """{
      "type": "trojan",
      "tag": "proxy",
      "server": "${jsonEscape(server.host)}",
      "server_port": ${server.port},
      "password": "${jsonEscape(setting(server, "password"))}",
      "tls": {
        "enabled": true,
        "server_name": "${jsonEscape(setting(server, "sni", server.host))}"
      }
    }"""
    }

    private fun generateShadowsocksOutbound(server: VPNServer): String {
        return """{
      "type": "shadowsocks",
      "tag": "proxy",
      "server": "${jsonEscape(server.host)}",
      "server_port": ${server.port},
      "method": "${jsonEscape(setting(server, "method", "aes-256-gcm"))}",
      "password": "${jsonEscape(setting(server, "password"))}"
    }"""
    }

    private fun generateHysteria2Outbound(server: VPNServer): String {
        return """{
      "type": "hysteria2",
      "tag": "proxy",
      "server": "${jsonEscape(server.host)}",
      "server_port": ${server.port},
      "password": "${jsonEscape(setting(server, "password"))}",
      "tls": {
        "enabled": true,
        "server_name": "${jsonEscape(setting(server, "sni", server.host))}"
      }
    }"""
    }

    private fun generateTUICOutbound(server: VPNServer): String {
        return """{
      "type": "tuic",
      "tag": "proxy",
      "server": "${jsonEscape(server.host)}",
      "server_port": ${server.port},
      "uuid": "${jsonEscape(setting(server, "uuid"))}",
      "password": "${jsonEscape(setting(server, "password"))}",
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "server_name": "${jsonEscape(setting(server, "sni", server.host))}"
      }
    }"""
    }
}
