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
        val logPath = File(context.filesDir, "sing-box.log").absolutePath
        return """{
  "log": {
    "level": "info",
    "timestamp": true,
    "output": "$logPath"
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "inet4_address": "172.19.0.1/30",
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
    },
    {
      "type": "dns",
      "tag": "dns-out"
    }
  ],
  "route": {
    "rules": [
      {
        "protocol": "dns",
        "outbound": "dns-out"
      },
      {
        "ip_is_private": true,
        "outbound": "direct"
      }
    ],
    "final": "proxy"
  },
  "dns": {
    "servers": [
      {
        "tag": "dns-remote",
        "address": "tls://8.8.8.8",
        "detour": "proxy"
      },
      {
        "tag": "dns-direct",
        "address": "223.5.5.5",
        "detour": "direct"
      }
    ],
    "rules": [],
    "final": "dns-remote",
    "strategy": "prefer_ipv4"
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

    private fun generateVlessOutbound(server: VPNServer): String {
        val s = server.settings
        val sb = StringBuilder()
        sb.append("{\n")
        sb.append("      \"type\": \"vless\",\n")
        sb.append("      \"tag\": \"proxy\",\n")
        sb.append("      \"server\": \"${server.host}\",\n")
        sb.append("      \"server_port\": ${server.port},\n")
        sb.append("      \"uuid\": \"${jsonEscape(s["uuid"]?.toString() ?: "")}\"")

        val flow = s["flow"]?.toString() ?: ""
        if (flow.isNotEmpty()) {
            sb.append(",\n      \"flow\": \"$flow\"")
        }

        val security = s["security"]?.toString() ?: "none"
        if (security == "tls" || security == "reality") {
            val sni = s["sni"]?.toString() ?: server.host
            val fp = s["fingerprint"]?.toString() ?: "chrome"
            sb.append(",\n      \"tls\": {\n")
            sb.append("        \"enabled\": true,\n")
            sb.append("        \"server_name\": \"$sni\",\n")
            sb.append("        \"utls\": {\n")
            sb.append("          \"enabled\": true,\n")
            sb.append("          \"fingerprint\": \"$fp\"\n")
            sb.append("        }")
            if (security == "reality") {
                sb.append(",\n        \"reality\": {\n")
                sb.append("          \"enabled\": true,\n")
                sb.append("          \"public_key\": \"${s["public_key"] ?: ""}\",\n")
                sb.append("          \"short_id\": \"${s["short_id"] ?: ""}\"\n")
                sb.append("        }")
            }
            sb.append("\n      }")
        }

        val transport = s["transport"]?.toString() ?: ""
        val serviceName = s["service_name"]?.toString() ?: ""
        val wsPath = s["path"]?.toString() ?: ""
        val wsHost = s["host"]?.toString() ?: ""

        if (transport == "ws" || (wsPath.isNotEmpty() && serviceName.isEmpty())) {
            sb.append(",\n      \"transport\": {\n")
            sb.append("        \"type\": \"ws\",\n")
            sb.append("        \"path\": \"$wsPath\"")
            if (wsHost.isNotEmpty()) {
                sb.append(",\n        \"headers\": {\n")
                sb.append("          \"Host\": \"$wsHost\"\n")
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
            sb.append("        \"host\": \"${jsonEscape(wsHost.ifEmpty { server.host })}\"\n")
            sb.append("      }")
        }

        sb.append("\n    }")
        return sb.toString()
    }

    private fun generateVmessOutbound(server: VPNServer): String {
        val s = server.settings
        val sb = StringBuilder()
        sb.append("{\n")
        sb.append("      \"type\": \"vmess\",\n")
        sb.append("      \"tag\": \"proxy\",\n")
        sb.append("      \"server\": \"${server.host}\",\n")
        sb.append("      \"server_port\": ${server.port},\n")
        sb.append("      \"uuid\": \"${s["uuid"] ?: ""}\",\n")
        sb.append("      \"alter_id\": ${s["alter_id"] ?: "0"},\n")
        sb.append("      \"security\": \"${s["security"] ?: "auto"}\"")

        if (s["tls"]?.toString() == "true") {
            val sni = s["sni"]?.toString() ?: server.host
            sb.append(",\n      \"tls\": {\n")
            sb.append("        \"enabled\": true,\n")
            sb.append("        \"server_name\": \"$sni\"\n")
            sb.append("      }")
        }

        val transport = s["transport"]?.toString() ?: ""
        val serviceName = s["service_name"]?.toString() ?: ""
        val wsPath = s["path"]?.toString() ?: ""
        val wsHost = s["host"]?.toString() ?: ""

        if (transport == "ws" || (wsPath.isNotEmpty() && serviceName.isEmpty())) {
            sb.append(",\n      \"transport\": {\n")
            sb.append("        \"type\": \"ws\",\n")
            sb.append("        \"path\": \"$wsPath\"")
            if (wsHost.isNotEmpty()) {
                sb.append(",\n        \"headers\": {\n")
                sb.append("          \"Host\": \"$wsHost\"\n")
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
            sb.append("        \"host\": \"${jsonEscape(wsHost.ifEmpty { server.host })}\"\n")
            sb.append("      }")
        }

        sb.append("\n    }")
        return sb.toString()
    }

    private fun generateTrojanOutbound(server: VPNServer): String {
        val s = server.settings
        return """{
      "type": "trojan",
      "tag": "proxy",
      "server": "${server.host}",
      "server_port": ${server.port},
      "password": "${s["password"] ?: ""}",
      "tls": {
        "enabled": true,
        "server_name": "${s["sni"] ?: server.host}"
      }
    }"""
    }

    private fun generateShadowsocksOutbound(server: VPNServer): String {
        val s = server.settings
        return """{
      "type": "shadowsocks",
      "tag": "proxy",
      "server": "${server.host}",
      "server_port": ${server.port},
      "method": "${s["method"] ?: "aes-256-gcm"}",
      "password": "${s["password"] ?: ""}"
    }"""
    }

    private fun generateHysteria2Outbound(server: VPNServer): String {
        val s = server.settings
        return """{
      "type": "hysteria2",
      "tag": "proxy",
      "server": "${server.host}",
      "server_port": ${server.port},
      "password": "${s["password"] ?: ""}",
      "tls": {
        "enabled": true,
        "server_name": "${s["sni"] ?: server.host}"
      }
    }"""
    }

    private fun generateTUICOutbound(server: VPNServer): String {
        val s = server.settings
        return """{
      "type": "tuic",
      "tag": "proxy",
      "server": "${server.host}",
      "server_port": ${server.port},
      "uuid": "${s["uuid"] ?: ""}",
      "password": "${s["password"] ?: ""}",
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "server_name": "${s["sni"] ?: server.host}"
      }
    }"""
    }
}
