package com.quantumvpn.core

import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.*
import java.util.concurrent.ConcurrentHashMap

object VPNCore {
    private const val TAG = "VPNCore"
    private var tunFd: ParcelFileDescriptor? = null
    @Volatile var isRunning = false; private set
    private var forwardingJob: Job? = null
    private var vpnService: VpnService? = null
    var totalDownload = 0L; private set
    var totalUpload = 0L; private set
    private val dnsCache = ConcurrentHashMap<String, InetAddress>()
    private val connections = ConcurrentHashMap<Int, Socket>()

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
                if (isRunning) Log.e(TAG, "Forwarding error: ${e.message}")
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
            17 -> handleUDP(raw, len, ihl, srcIp, dstIp, output, server)
            6 -> handleTCP(raw, len, ihl, srcIp, dstIp, output, server)
        }
    }

    private fun handleUDP(raw: ByteArray, len: Int, ihl: Int, src: InetAddress, dst: InetAddress, output: FileOutputStream, server: com.quantumvpn.data.VPNServer) {
        CoroutineScope(Dispatchers.IO).launch {
            var socket: DatagramSocket? = null
            try {
                val dstPort = ((raw[ihl + 2].toInt() and 0xFF) shl 8) or (raw[ihl + 3].toInt() and 0xFF)
                val srcPort = ((raw[ihl].toInt() and 0xFF) shl 8) or (raw[ihl + 1].toInt() and 0xFF)
                val data = raw.copyOfRange(ihl + 8, len)

                if (dstPort == 53) {
                    handleDNS(data, src, dst, srcPort, output)
                    return@launch
                }

                socket = DatagramSocket()
                vpnService?.protect(socket)
                socket.soTimeout = 3000

                val proxySocket = createProxyConnection(server, dst.hostAddress ?: "0.0.0.0", dstPort)
                if (proxySocket != null) {
                    val proxyOut = proxySocket.getOutputStream()
                    proxyOut.write(data)
                    proxyOut.flush()
                    totalUpload += data.size

                    val resp = ByteArray(32767)
                    val dp = DatagramPacket(resp, resp.size)
                    try {
                        proxySocket.getInputStream().let { inp ->
                            val read = inp.read(resp)
                            if (read > 0) {
                                totalDownload += read
                                val pkt = buildUDP(src, dst, srcPort, dstPort, resp.copyOf(read))
                                synchronized(output) { output.write(pkt); output.flush() }
                            }
                        }
                    } catch (_: Exception) {}
                    proxySocket.close()
                } else {
                    socket.send(DatagramPacket(data, data.size, dst, dstPort))
                    totalUpload += data.size

                    val resp = ByteArray(32767)
                    val dp = DatagramPacket(resp, resp.size)
                    try {
                        socket.receive(dp)
                        totalDownload += dp.length
                        val pkt = buildUDP(src, dst, srcPort, dstPort, resp.copyOf(dp.length))
                        synchronized(output) { output.write(pkt); output.flush() }
                    } catch (_: SocketTimeoutException) {}
                }
            } catch (e: Exception) {
                Log.w(TAG, "UDP: ${e.message}")
            } finally {
                try { socket?.close() } catch (_: Exception) {}
            }
        }
    }

    private fun handleDNS(data: ByteArray, src: InetAddress, dst: InetAddress, srcPort: Int, output: FileOutputStream) {
        try {
            if (data.size < 12) return
            val txId = data.copyOfRange(0, 2)
            val questions = ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)
            if (questions == 0) return

            var offset = 12
            val qname = StringBuilder()
            while (offset < data.size && data[offset] != 0.toByte()) {
                val labelLen = data[offset].toInt() and 0xFF
                offset++
                if (offset + labelLen <= data.size) {
                    if (qname.isNotEmpty()) qname.append(".")
                    qname.append(String(data, offset, labelLen))
                }
                offset += labelLen
            }
            offset++

            if (offset + 4 > data.size) return
            val qtype = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
            offset += 2
            val qclass = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

            val domain = qname.toString()
            Log.d(TAG, "DNS query: $domain (type=$qtype)")

            val resolved = try {
                InetAddress.getByName(domain)
            } catch (e: Exception) {
                try {
                    val dnsSocket = Socket()
                    vpnService?.protect(dnsSocket)
                    dnsSocket.connect(InetSocketAddress("8.8.8.8", 53), 3000)
                    val dnsOut = dnsSocket.getOutputStream()
                    dnsOut.write(data)
                    dnsOut.flush()

                    val dnsResp = ByteArray(512)
                    val dnsIn = dnsSocket.getInputStream()
                    val read = dnsIn.read(dnsResp)
                    dnsSocket.close()

                    if (read > 0) {
                        totalDownload += read
                        val pkt = buildUDP(src, dst, srcPort, 53, dnsResp.copyOf(read))
                        synchronized(output) { output.write(pkt); output.flush() }
                        return
                    }
                    null
                } catch (e2: Exception) { null }
            }

            if (resolved != null) {
                val resp = buildDNSResponse(txId, data, resolved)
                totalDownload += resp.size
                val pkt = buildUDP(src, dst, srcPort, 53, resp)
                synchronized(output) { output.write(pkt); output.flush() }
            }
        } catch (e: Exception) {
            Log.w(TAG, "DNS: ${e.message}")
        }
    }

    private fun buildDNSResponse(txId: ByteArray, query: ByteArray, answer: InetAddress): ByteArray {
        val resp = mutableListOf<Byte>()
        resp.addAll(txId.toList())
        resp.add(0x81.toByte())
        resp.add(0x80.toByte())
        resp.addAll(query.copyOfRange(4, 6).toList())
        resp.add(0x00.toByte())
        resp.add(0x01.toByte())
        resp.addAll(query.copyOfRange(6, 8).toList())
        resp.addAll(query.copyOfRange(8, 10).toList())
        resp.addAll(query.copyOfRange(10, 12).toList())

        var offset = 12
        while (offset < query.size && query[offset] != 0.toByte()) {
            val labelLen = query[offset].toInt() and 0xFF
            resp.add(query[offset])
            offset++
            if (offset + labelLen <= query.size) {
                for (i in 0 until labelLen) resp.add(query[offset + i])
            }
            offset += labelLen
        }
        resp.add(0x00)
        resp.addAll(query.copyOfRange(query.size - 4, query.size).toList())

        resp.add(0xC0.toByte())
        resp.add(0x0C.toByte())
        resp.add(0x00.toByte())
        resp.add(0x01.toByte())
        resp.add(0x00.toByte())
        resp.add(0x01.toByte())
        resp.add(0x00.toByte())
        resp.add(0x00.toByte())
        resp.add(0x01.toByte())
        resp.add(0x2C.toByte())
        resp.add(0x00.toByte())
        resp.add(0x04.toByte())
        resp.addAll(answer.address.toList())

        return resp.toByteArray()
    }

    private fun createProxyConnection(server: com.quantumvpn.data.VPNServer, targetHost: String, targetPort: Int): Socket? {
        return try {
            val socket = Socket()
            vpnService?.protect(socket)
            socket.connect(InetSocketAddress(server.host, server.port), 5000)

            when (server.protocol) {
                com.quantumvpn.data.Protocol.VLESS -> {
                    val uuid = server.settings["uuid"]?.toString() ?: return null
                    val security = server.settings["security"]?.toString() ?: "none"
                    val flow = server.settings["flow"]?.toString() ?: ""

                    if (security == "tls" || security == "reality") {
                        val sslContext = javax.net.ssl.SSLContext.getInstance("TLS")
                        sslContext.init(null, arrayOf(TrustAllManager()), java.security.SecureRandom())
                        val sslSocket = sslContext.socketFactory.createSocket() as javax.net.ssl.SSLSocket
                        sslSocket.connect(java.net.InetSocketAddress(server.host, server.port), 5000)
                        sendVLESSHeader(sslSocket.getOutputStream(), uuid, targetHost, targetPort, flow)
                        sslSocket
                    } else {
                        sendVLESSHeader(socket.getOutputStream(), uuid, targetHost, targetPort, flow)
                        socket
                    }
                }
                com.quantumvpn.data.Protocol.VMESS -> {
                    val uuid = server.settings["uuid"]?.toString() ?: return null
                    val alterId = (server.settings["alter_id"]?.toString() ?: "0").toIntOrNull() ?: 0
                    sendVMessHeader(socket.getOutputStream(), uuid, targetHost, targetPort, alterId)
                    socket
                }
                com.quantumvpn.data.Protocol.TROJAN -> {
                    val password = server.settings["password"]?.toString() ?: return null
                    val sslContext = javax.net.ssl.SSLContext.getInstance("TLS")
                    sslContext.init(null, arrayOf(TrustAllManager()), java.security.SecureRandom())
                    val sslSocket = sslContext.socketFactory.createSocket() as javax.net.ssl.SSLSocket
                    sslSocket.connect(java.net.InetSocketAddress(server.host, server.port), 5000)
                    sendTrojanHeader(sslSocket.getOutputStream(), password, targetHost, targetPort)
                    sslSocket
                }
                else -> null
            }
        } catch (e: Exception) {
            Log.w(TAG, "Proxy connection failed: ${e.message}")
            null
        }
    }

    private fun sendVLESSHeader(out: java.io.OutputStream, uuid: String, host: String, port: Int, flow: String) {
        val uuidBytes = java.util.UUID.fromString(uuid).let {
            val bb = java.nio.ByteBuffer.allocate(16)
            bb.putLong(it.mostSignificantBits)
            bb.putLong(it.leastSignificantBits)
            bb.array()
        }

        val buf = mutableListOf<Byte>()
        buf.add(0) // version
        buf.addAll(uuidBytes.toList())
        buf.add(1) // addon length
        buf.add(0) // addon type
        buf.add(0) // addon data
        buf.add(1) // command: TCP
        buf.add(0) // reserved

        val hostBytes = host.toByteArray()
        buf.add(2) // addr type: domain
        buf.add(hostBytes.size.toByte())
        buf.addAll(hostBytes.toList())
        buf.addAll(listOf(((port shr 8) and 0xFF).toByte(), (port and 0xFF).toByte()))

        if (flow.isNotEmpty()) {
            buf.add(flow.length.toByte())
            buf.addAll(flow.toByteArray().toList())
        } else {
            buf.add(0)
        }

        out.write(buf.toByteArray())
        out.flush()
    }

    private fun sendVMessHeader(out: java.io.OutputStream, uuid: String, host: String, port: Int, alterId: Int) {
        val uuidBytes = java.util.UUID.fromString(uuid).let {
            val bb = java.nio.ByteBuffer.allocate(16)
            bb.putLong(it.mostSignificantBits)
            bb.putLong(it.leastSignificantBits)
            bb.array()
        }

        val buf = mutableListOf<Byte>()
        buf.add(1) // version
        buf.addAll(uuidBytes.toList())
        buf.add(alterId.toByte())
        buf.add(1) // command: TCP
        buf.add(0) // reserved
        buf.add(2) // addr type: domain
        val hostBytes = host.toByteArray()
        buf.add(hostBytes.size.toByte())
        buf.addAll(hostBytes.toList())
        buf.addAll(listOf(((port shr 8) and 0xFF).toByte(), (port and 0xFF).toByte()))

        while (buf.size % 16 != 0) buf.add(0)

        out.write(buf.toByteArray())
        out.flush()
    }

    private fun sendTrojanHeader(out: java.io.OutputStream, password: String, host: String, port: Int) {
        val passHash = java.security.MessageDigest.getInstance("SHA-224")
            .digest(password.toByteArray())
            .joinToString("") { "%02x".format(it) }

        val buf = mutableListOf<Byte>()
        buf.addAll(passHash.toByteArray().toList())
        buf.add(1) // command: CONNECT
        buf.add(0) // reserved
        buf.add(2) // addr type: domain
        val hostBytes = host.toByteArray()
        buf.add(hostBytes.size.toByte())
        buf.addAll(hostBytes.toList())
        buf.addAll(listOf(((port shr 8) and 0xFF).toByte(), (port and 0xFF).toByte()))

        out.write(buf.toByteArray())
        out.flush()
    }

    private fun handleTCP(raw: ByteArray, len: Int, ihl: Int, src: InetAddress, dst: InetAddress, output: FileOutputStream, server: com.quantumvpn.data.VPNServer) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val dstPort = ((raw[ihl + 2].toInt() and 0xFF) shl 8) or (raw[ihl + 3].toInt() and 0xFF)
                val srcPort = ((raw[ihl].toInt() and 0xFF) shl 8) or (raw[ihl + 1].toInt() and 0xFF)
                val flags = raw[ihl + 13].toInt() and 0xFF
                val payload = raw.copyOfRange(ihl + 4, len)

                val isSyn = (flags and 0x02) != 0
                val isAck = (flags and 0x10) != 0
                val isFin = (flags and 0x01) != 0
                val isRst = (flags and 0x04) != 0

                if (isSyn && !isAck) {
                    val sock = createProxyConnection(server, dst.hostAddress ?: "0.0.0.0", dstPort)
                    if (sock != null) {
                        connections[srcPort] = sock
                        val synAck = buildTCP(dst, src, dstPort, srcPort, ByteArray(0), 0x12)
                        synchronized(output) { output.write(synAck); output.flush() }
                        val ack = buildTCP(src, dst, srcPort, dstPort, ByteArray(0), 0x10)
                        synchronized(output) { output.write(ack); output.flush() }
                        CoroutineScope(Dispatchers.IO).launch { readFromProxy(sock, src, dst, srcPort, dstPort, output) }
                    }
                } else if (isFin || isRst) {
                    connections.remove(srcPort)?.close()
                    val finAck = buildTCP(dst, src, dstPort, srcPort, ByteArray(0), 0x12)
                    synchronized(output) { output.write(finAck); output.flush() }
                } else if (payload.isNotEmpty()) {
                    val sock = connections[srcPort]
                    if (sock != null && sock.isConnected) {
                        sock.getOutputStream().write(payload)
                        sock.getOutputStream().flush()
                        totalUpload += payload.size
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "TCP: ${e.message}")
            }
        }
    }

    private fun readFromProxy(sock: Socket, src: InetAddress, dst: InetAddress, srcPort: Int, dstPort: Int, output: FileOutputStream) {
        try {
            val buf = ByteArray(32767)
            sock.soTimeout = 5000
            while (isRunning && sock.isConnected) {
                val read = try { sock.getInputStream().read(buf) } catch (_: SocketTimeoutException) { continue }
                if (read == -1) break
                if (read > 0) {
                    totalDownload += read
                    val pkt = buildTCP(dst, src, dstPort, srcPort, buf.copyOf(read), 0x18)
                    synchronized(output) { output.write(pkt); output.flush() }
                }
            }
        } catch (_: Exception) {} finally {
            try { sock.close() } catch (_: Exception) {}
            connections.remove(srcPort)
        }
    }

    private fun buildTCP(srcIp: InetAddress, dstIp: InetAddress, srcPort: Int, dstPort: Int, payload: ByteArray, flags: Int): ByteArray {
        val totalLen = 20 + payload.size
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x45; pkt[1] = 0x00
        pkt[2] = (totalLen shr 8).toByte(); pkt[3] = totalLen.toByte()
        pkt[4] = 0x00; pkt[5] = 0x00
        pkt[6] = 0x40.toByte(); pkt[7] = 0x00
        pkt[8] = 0x40.toByte(); pkt[9] = 0x06
        pkt[10] = 0x00; pkt[11] = 0x00
        System.arraycopy(srcIp.address, 0, pkt, 12, 4)
        System.arraycopy(dstIp.address, 0, pkt, 16, 4)
        pkt[20] = (srcPort shr 8).toByte(); pkt[21] = srcPort.toByte()
        pkt[22] = (dstPort shr 8).toByte(); pkt[23] = dstPort.toByte()
        pkt[24] = 0x00; pkt[25] = 0x00
        pkt[26] = 0x00; pkt[27] = 0x00
        pkt[28] = 0x50.toByte()
        pkt[29] = flags.toByte()
        pkt[30] = (65535 shr 8).toByte(); pkt[31] = 65535.toByte()
        pkt[32] = 0x00; pkt[33] = 0x00
        pkt[34] = 0x00; pkt[35] = 0x00
        if (payload.isNotEmpty()) System.arraycopy(payload, 0, pkt, 20, payload.size)
        val csum = ipChecksum(pkt)
        pkt[10] = (csum shr 8).toByte(); pkt[11] = csum.toByte()
        return pkt
    }

    private fun buildUDP(srcIp: InetAddress, dstIp: InetAddress, srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
        val totalLen = 20 + 8 + payload.size
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x45; pkt[1] = 0x00
        pkt[2] = (totalLen shr 8).toByte(); pkt[3] = totalLen.toByte()
        pkt[6] = 0x40.toByte(); pkt[8] = 0x40.toByte(); pkt[9] = 0x11
        System.arraycopy(srcIp.address, 0, pkt, 12, 4)
        System.arraycopy(dstIp.address, 0, pkt, 16, 4)
        pkt[20] = (srcPort shr 8).toByte(); pkt[21] = srcPort.toByte()
        pkt[22] = (dstPort shr 8).toByte(); pkt[23] = dstPort.toByte()
        val udpLen = 8 + payload.size
        pkt[24] = (udpLen shr 8).toByte(); pkt[25] = udpLen.toByte()
        pkt[26] = 0x00; pkt[27] = 0x00
        if (payload.isNotEmpty()) System.arraycopy(payload, 0, pkt, 28, payload.size)
        val csum = ipChecksum(pkt)
        pkt[10] = (csum shr 8).toByte(); pkt[11] = csum.toByte()
        return pkt
    }

    private fun ipChecksum(data: ByteArray): Int {
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
        connections.values.forEach { try { it.close() } catch (_: Exception) {} }
        connections.clear()
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

    private class TrustAllManager : javax.net.ssl.X509TrustManager {
        override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers() = arrayOf<java.security.cert.X509Certificate>()
    }
}
