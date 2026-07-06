package com.quantumvpn.core

import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.*
import java.nio.ByteBuffer
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

object VPNCore {
    private const val TAG = "VPNCore"
    private var tunFd: ParcelFileDescriptor? = null
    @Volatile var isRunning = false; private set
    private var forwardingJob: Job? = null
    private var vpnService: VpnService? = null
    var totalDownload = 0L; private set
    var totalUpload = 0L; private set

    fun setVpnService(s: VpnService) { vpnService = s }
    fun resetTraffic() { totalDownload = 0; totalUpload = 0 }

    fun establishVPN(builder: VpnService.Builder): ParcelFileDescriptor? {
        try {
            builder.setSession("QuantumVPN")
                .setMtu(9000)
                .addAddress("10.0.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")
                .addDnsServer("1.1.1.1")
                .addDnsServer("223.5.5.5")
            val fd = builder.establish()
            tunFd = fd
            isRunning = true
            resetTraffic()
            Log.d(TAG, "TUN established")
            return fd
        } catch (e: Exception) {
            Log.e(TAG, "establishVPN failed", e)
            return null
        }
    }

    fun startForwarding(fd: ParcelFileDescriptor, server: com.quantumvpn.data.VPNServer) {
        forwardingJob = CoroutineScope(Dispatchers.IO).launch {
            try {
                val input = FileInputStream(fd.fileDescriptor)
                val output = FileOutputStream(fd.fileDescriptor)
                val buf = ByteArray(32767)

                while (isActive && isRunning) {
                    val len = input.read(buf)
                    if (len > 0) {
                        handlePacket(buf.copyOf(len), len, output, server)
                    }
                }
            } catch (e: Exception) {
                if (isRunning) Log.e(TAG, "Forwarding error", e)
            }
        }
    }

    private fun handlePacket(raw: ByteArray, len: Int, output: FileOutputStream, server: com.quantumvpn.data.VPNServer) {
        if (len < 20) return
        val ver = (raw[0].toInt() shr 4) and 0xF
        if (ver != 4) return

        val proto = raw[9].toInt() and 0xFF
        val ihl = (raw[0].toInt() and 0xF) * 4
        val srcIp = InetAddress.getByAddress(raw.copyOfRange(12, 16))
        val dstIp = InetAddress.getByAddress(raw.copyOfRange(16, 20))

        when (proto) {
            6 -> handleTCP(raw, len, ihl, srcIp, dstIp, output, server)
            17 -> handleUDP(raw, len, ihl, srcIp, dstIp, output, server)
        }
    }

    private fun handleTCP(raw: ByteArray, len: Int, ihl: Int, src: InetAddress, dst: InetAddress, output: FileOutputStream, server: com.quantumvpn.data.VPNServer) {
        CoroutineScope(Dispatchers.IO).launch {
            var socket: Socket? = null
            try {
                val dstPort = ((raw[ihl + 2].toInt() and 0xFF) shl 8) or (raw[ihl + 3].toInt() and 0xFF)
                val srcPort = ((raw[ihl].toInt() and 0xFF) shl 8) or (raw[ihl + 1].toInt() and 0xFF)

                socket = Socket()
                vpnService?.protect(socket)

                when (server.protocol) {
                    com.quantumvpn.data.Protocol.VLESS -> connectVLESS(socket, server, dst.hostAddress ?: "0.0.0.0", dstPort)
                    com.quantumvpn.data.Protocol.VMESS -> connectVMess(socket, server, dst.hostAddress ?: "0.0.0.0", dstPort)
                    com.quantumvpn.data.Protocol.TROJAN -> connectTrojan(socket, server, dst.hostAddress ?: "0.0.0.0", dstPort)
                    com.quantumvpn.data.Protocol.SHADOWSOCKS -> connectShadowsocks(socket, server, dst.hostAddress ?: "0.0.0.0", dstPort)
                    else -> socket.connect(InetSocketAddress(dst, dstPort), 5000)
                }

                val payload = raw.copyOfRange(ihl + 4, len)
                socket.getOutputStream().write(payload)
                socket.getOutputStream().flush()
                totalUpload += payload.size

                val resp = ByteArray(32767)
                socket.soTimeout = 3000
                val read = try { socket.getInputStream().read(resp) } catch (e: SocketTimeoutException) { 0 }

                if (read > 0) {
                    totalDownload += read
                    val pkt = buildTCP(src, dst, srcPort, dstPort, resp.copyOf(read))
                    synchronized(output) {
                        output.write(pkt)
                        output.flush()
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "TCP: ${e.message}")
            } finally {
                try { socket?.close() } catch (_: Exception) {}
            }
        }
    }

    private fun handleUDP(raw: ByteArray, len: Int, ihl: Int, src: InetAddress, dst: InetAddress, output: FileOutputStream, server: com.quantumvpn.data.VPNServer) {
        CoroutineScope(Dispatchers.IO).launch {
            var socket: DatagramSocket? = null
            try {
                val dstPort = ((raw[ihl + 2].toInt() and 0xFF) shl 8) or (raw[ihl + 3].toInt() and 0xFF)
                val srcPort = ((raw[ihl].toInt() and 0xFF) shl 8) or (raw[ihl + 1].toInt() and 0xFF)

                socket = DatagramSocket()
                vpnService?.protect(socket)
                socket.soTimeout = 3000

                val data = raw.copyOfRange(ihl + 8, len)
                socket.send(DatagramPacket(data, data.size, dst, dstPort))
                totalUpload += data.size

                val resp = ByteArray(32767)
                val dp = DatagramPacket(resp, resp.size)
                try {
                    socket.receive(dp)
                    totalDownload += dp.length
                    val pkt = buildUDP(src, dst, srcPort, dstPort, resp.copyOf(dp.length))
                    synchronized(output) {
                        output.write(pkt)
                        output.flush()
                    }
                } catch (_: SocketTimeoutException) {}
            } catch (e: Exception) {
                Log.w(TAG, "UDP: ${e.message}")
            } finally {
                try { socket?.close() } catch (_: Exception) {}
            }
        }
    }

    // VLESS connection
    private fun connectVLESS(socket: Socket, server: com.quantumvpn.data.VPNServer, targetHost: String, targetPort: Int) {
        val uuid = server.settings["uuid"]?.toString() ?: throw Exception("No UUID")
        val security = server.settings["security"]?.toString() ?: "none"
        val sni = server.settings["sni"]?.toString() ?: targetHost
        val fp = server.settings["fingerprint"]?.toString() ?: "chrome"
        val transport = server.settings["transport"]?.toString() ?: "tcp"
        val serviceName = server.settings["service_name"]?.toString() ?: ""
        val path = server.settings["path"]?.toString() ?: ""
        val flow = server.settings["flow"]?.toString() ?: ""

        if (security == "tls" || security == "reality") {
            val sslContext = javax.net.ssl.SSLContext.getInstance("TLS").apply {
                init(null, arrayOf(object : javax.net.ssl.X509TrustManager {
                    override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
                    override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
                    override fun getAcceptedIssuers() = arrayOf<java.security.cert.X509Certificate>()
                }), java.security.SecureRandom())
            }
            socket.connect(InetSocketAddress(server.host, server.port), 5000)
            val factory = sslContext.socketFactory
            val methods = factory.javaClass.methods
            val createSocketMethod = methods.find { it.name == "createSocket" && it.parameterCount == 3 }
            val sslSocket = if (createSocketMethod != null) {
                createSocketMethod.invoke(factory, socket, server.host, server.port) as SSLSocket
            } else {
                factory.createSocket() as SSLSocket
            }
            sslSocket.soTimeout = 10000
            sendVLESSHandshake(sslSocket.getOutputStream(), uuid, targetHost, targetPort, flow)
            return
        }

        socket.connect(InetSocketAddress(server.host, server.port), 5000)
        sendVLESSHandshake(socket.getOutputStream(), uuid, targetHost, targetPort, flow)
    }

    private fun sendVLESSHandshake(out: java.io.OutputStream, uuid: String, host: String, port: Int, flow: String) {
        val version: Byte = 0
        val uuidBytes = java.util.UUID.fromString(uuid).let {
            val bb = java.nio.ByteBuffer.allocate(16)
            bb.putLong(it.mostSignificantBits)
            bb.putLong(it.leastSignificantBits)
            bb.array()
        }
        val addrlen: Byte = 1
        val addrType: Byte = 1 // IPv4
        val inetAddr = InetAddress.getByName(host)
        val addrBytes = inetAddr.address

        val body = mutableListOf<Byte>()
        body.addAll(uuidBytes.toList())
        body.add(addrlen)
        body.add(0) // version
        body.add(addrType)
        body.addAll(addrBytes.toList())
        body.addAll(listOf(((port shr 8) and 0xFF).toByte(), (port and 0xFF).toByte()))

        if (flow.isNotEmpty()) {
            body.add(flow.length.toByte())
            body.addAll(flow.toByteArray().toList())
        } else {
            body.add(0)
        }

        val header = byteArrayOf(version) + body.toByteArray()
        out.write(header)
        out.flush()
    }

    private fun connectVMess(socket: Socket, server: com.quantumvpn.data.VPNServer, targetHost: String, targetPort: Int) {
        val uuid = server.settings["uuid"]?.toString() ?: throw Exception("No UUID")
        val alterId = (server.settings["alter_id"]?.toString() ?: "0").toIntOrNull() ?: 0
        val security = server.settings["security"]?.toString() ?: "auto"

        socket.connect(InetSocketAddress(server.host, server.port), 5000)

        val uuidBytes = java.util.UUID.fromString(uuid).let {
            val bb = java.nio.ByteBuffer.allocate(16)
            bb.putLong(it.mostSignificantBits)
            bb.putLong(it.leastSignificantBits)
            bb.array()
        }

        val header = mutableListOf<Byte>()
        header.add(0x01) // version
        header.addAll(uuidBytes.toList())
        header.add(alterId.toByte())
        header.add(0x01) // command: TCP
        header.add(0x00) // reserved
        header.add(0x01) // addr type: IPv4
        val inetAddr = InetAddress.getByName(targetHost)
        header.addAll(inetAddr.address.toList())
        header.addAll(listOf(((targetPort shr 8) and 0xFF).toByte(), (targetPort and 0xFF).toByte()))

        // VMess header is usually 16-byte aligned
        while (header.size % 16 != 0) header.add(0x00)

        socket.getOutputStream().write(header.toByteArray())
        socket.getOutputStream().flush()
    }

    private fun connectTrojan(socket: Socket, server: com.quantumvpn.data.VPNServer, targetHost: String, targetPort: Int) {
        val password = server.settings["password"]?.toString() ?: throw Exception("No password")
        val sni = server.settings["sni"]?.toString() ?: targetHost

        val sslContext = javax.net.ssl.SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(object : javax.net.ssl.X509TrustManager {
                override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
                override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
                override fun getAcceptedIssuers() = arrayOf<java.security.cert.X509Certificate>()
            }), java.security.SecureRandom())
        }

        socket.connect(InetSocketAddress(server.host, server.port), 5000)
        val factory = sslContext.socketFactory
        val methods = factory.javaClass.methods
        val createSocketMethod = methods.find { it.name == "createSocket" && it.parameterCount == 3 }
        val sslSocket = if (createSocketMethod != null) {
            createSocketMethod.invoke(factory, socket, server.host, server.port) as SSLSocket
        } else {
            factory.createSocket() as SSLSocket
        }

        val passHash = java.security.MessageDigest.getInstance("SHA-224")
            .digest(password.toByteArray())
            .joinToString("") { "%02x".format(it) }

        val cmd: Byte = 0x01 // CONNECT
        val atype: Byte = 0x01 // IPv4
        val inetAddr = InetAddress.getByName(targetHost)

        val buf = mutableListOf<Byte>()
        buf.addAll(passHash.toByteArray().toList())
        buf.add(cmd)
        buf.add(0x00) // reserved
        buf.add(atype)
        buf.addAll(inetAddr.address.toList())
        buf.addAll(listOf(((targetPort shr 8) and 0xFF).toByte(), (targetPort and 0xFF).toByte()))

        sslSocket.getOutputStream().write(buf.toByteArray())
        sslSocket.getOutputStream().flush()
    }

    private fun connectShadowsocks(socket: Socket, server: com.quantumvpn.data.VPNServer, targetHost: String, targetPort: Int) {
        val method = server.settings["method"]?.toString() ?: "aes-256-gcm"
        val password = server.settings["password"]?.toString() ?: throw Exception("No password")

        socket.connect(InetSocketAddress(server.host, server.port), 5000)

        val inetAddr = InetAddress.getByName(targetHost)
        val payload = mutableListOf<Byte>()
        payload.add(0x01) // ATYP IPv4
        payload.addAll(inetAddr.address.toList())
        payload.addAll(listOf(((targetPort shr 8) and 0xFF).toByte(), (targetPort and 0xFF).toByte()))

        // Simple SS: just send the header (real implementation needs encryption)
        socket.getOutputStream().write(payload.toByteArray())
        socket.getOutputStream().flush()
    }

    private fun buildTCP(srcIp: InetAddress, dstIp: InetAddress, srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
        val totalLen = 20 + payload.size
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x45; pkt[1] = 0x00
        pkt[2] = (totalLen shr 8).toByte(); pkt[3] = totalLen.toByte()
        pkt[6] = 0x40.toByte(); pkt[8] = 0x40.toByte(); pkt[9] = 0x06 // TCP
        System.arraycopy(srcIp.address, 0, pkt, 12, 4)
        System.arraycopy(dstIp.address, 0, pkt, 16, 4)
        pkt[20] = (srcPort shr 8).toByte(); pkt[21] = srcPort.toByte()
        pkt[22] = (dstPort shr 8).toByte(); pkt[23] = dstPort.toByte()
        pkt[26] = 0x50.toByte() // data offset
        pkt[47] = 0x02.toByte() // SYN-ACK flags
        val csum = checksum(pkt)
        pkt[10] = (csum shr 8).toByte(); pkt[11] = csum.toByte()
        System.arraycopy(payload, 0, pkt, 20, payload.size)
        return pkt
    }

    private fun buildUDP(srcIp: InetAddress, dstIp: InetAddress, srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
        val totalLen = 20 + 8 + payload.size
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x45; pkt[1] = 0x00
        pkt[2] = (totalLen shr 8).toByte(); pkt[3] = totalLen.toByte()
        pkt[6] = 0x40.toByte(); pkt[8] = 0x40.toByte(); pkt[9] = 0x11 // UDP
        System.arraycopy(srcIp.address, 0, pkt, 12, 4)
        System.arraycopy(dstIp.address, 0, pkt, 16, 4)
        pkt[20] = (srcPort shr 8).toByte(); pkt[21] = srcPort.toByte()
        pkt[22] = (dstPort shr 8).toByte(); pkt[23] = dstPort.toByte()
        val udpLen = 8 + payload.size
        pkt[24] = (udpLen shr 8).toByte(); pkt[25] = udpLen.toByte()
        val csum = checksum(pkt)
        pkt[10] = (csum shr 8).toByte(); pkt[11] = csum.toByte()
        System.arraycopy(payload, 0, pkt, 28, payload.size)
        return pkt
    }

    private fun checksum(data: ByteArray): Int {
        var sum = 0L
        var i = 0
        while (i < data.size - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (data.size % 2 == 1) sum += (data[data.size - 1].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.toInt().inv()) and 0xFFFF
    }

    fun stop() {
        isRunning = false
        forwardingJob?.cancel()
        forwardingJob = null
        try { tunFd?.close(); tunFd = null } catch (_: Exception) {}
        Log.d(TAG, "Stopped")
    }

    suspend fun testPing(host: String, port: Int, timeout: Int = 5000): Long = withContext(Dispatchers.IO) {
        try {
            val t = System.currentTimeMillis()
            Socket().use { it.connect(InetSocketAddress(host, port), timeout) }
            System.currentTimeMillis() - t
        } catch (e: Exception) { -1L }
    }
}
