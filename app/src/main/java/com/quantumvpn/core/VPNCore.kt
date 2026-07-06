package com.quantumvpn.core

import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

object VPNCore {
    private const val TAG = "VPNCore"
    private var tunInterface: ParcelFileDescriptor? = null
    private var isRunning = false
    private var forwardingJob: Job? = null
    private var vpnService: VpnService? = null

    fun isRunning(): Boolean = isRunning

    fun setVpnService(service: VpnService) {
        vpnService = service
    }

    fun establishVPN(builder: VpnService.Builder): ParcelFileDescriptor? {
        try {
            builder.setSession("QuantumVPN")
                .setMtu(1500)
                .addAddress("10.0.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")
                .addDnsServer("8.8.4.4")
                .addDnsServer("1.1.1.1")

            val fd = builder.establish()
            tunInterface = fd
            isRunning = true
            Log.d(TAG, "VPN TUN interface established")
            return fd
        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish VPN", e)
            return null
        }
    }

    fun startPacketForwarding(tunFd: ParcelFileDescriptor) {
        forwardingJob = CoroutineScope(Dispatchers.IO).launch {
            try {
                val inputStream = FileInputStream(tunFd.fileDescriptor)
                val outputStream = FileOutputStream(tunFd.fileDescriptor)
                val buffer = ByteArray(32767)

                while (isActive && isRunning) {
                    val length = inputStream.read(buffer)
                    if (length > 0) {
                        processPacket(buffer.copyOf(length), length, outputStream)
                    }
                }
            } catch (e: Exception) {
                if (isRunning) {
                    Log.e(TAG, "Packet forwarding error", e)
                }
            }
        }
    }

    private fun processPacket(packet: ByteArray, length: Int, output: FileOutputStream) {
        try {
            if (length < 20) return

            val version = (packet[0].toInt() shr 4) and 0x0F
            if (version != 4) return

            val protocol = packet[9].toInt() and 0xFF
            val srcIpBytes = packet.copyOfRange(12, 16)
            val dstIpBytes = packet.copyOfRange(16, 20)
            val srcIp = InetAddress.getByAddress(srcIpBytes)
            val dstIp = InetAddress.getByAddress(dstIpBytes)

            when (protocol) {
                6 -> handleTCP(packet, length, srcIp, dstIp, output)
                17 -> handleUDP(packet, length, srcIp, dstIp, output)
                1 -> handleICMP(packet, length, srcIp, dstIp, output)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to process packet: ${e.message}")
        }
    }

    private fun handleTCP(packet: ByteArray, length: Int, src: InetAddress, dst: InetAddress, output: FileOutputStream) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val headerLength = ((packet[0].toInt() and 0x0F) * 4)
                val dstPort = ((packet[headerLength + 2].toInt() and 0xFF) shl 8) or
                        (packet[headerLength + 3].toInt() and 0xFF)
                val srcPort = ((packet[headerLength].toInt() and 0xFF) shl 8) or
                        (packet[headerLength + 1].toInt() and 0xFF)

                val socket = Socket()
                vpnService?.protect(socket)
                socket.connect(InetSocketAddress(dst, dstPort), 5000)

                val data = packet.copyOfRange(headerLength + 4, length)
                socket.getOutputStream().write(data)

                val responseBuffer = ByteArray(32767)
                val responseLength = socket.getInputStream().read(responseBuffer)

                if (responseLength > 0) {
                    val responsePacket = buildIPPacket(
                        srcIp = dst,
                        dstIp = src,
                        srcPort = dstPort,
                        dstPort = srcPort,
                        payload = responseBuffer.copyOf(responseLength),
                        protocol = 6
                    )
                    output.write(responsePacket)
                    output.flush()
                }

                socket.close()
            } catch (e: Exception) {
                Log.w(TAG, "TCP forwarding failed: ${e.message}")
            }
        }
    }

    private fun handleUDP(packet: ByteArray, length: Int, src: InetAddress, dst: InetAddress, output: FileOutputStream) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val headerLength = ((packet[0].toInt() and 0x0F) * 4)
                val dstPort = ((packet[headerLength + 2].toInt() and 0xFF) shl 8) or
                        (packet[headerLength + 3].toInt() and 0xFF)
                val srcPort = ((packet[headerLength].toInt() and 0xFF) shl 8) or
                        (packet[headerLength + 1].toInt() and 0xFF)

                val socket = DatagramSocket()
                vpnService?.protect(socket)

                val data = packet.copyOfRange(headerLength + 8, length)
                val dp = DatagramPacket(data, data.size, dst, dstPort)
                socket.send(dp)

                val responseBuffer = ByteArray(32767)
                val responseDp = DatagramPacket(responseBuffer, responseBuffer.size)
                socket.soTimeout = 3000
                socket.receive(responseDp)

                val responsePacket = buildIPPacket(
                    srcIp = dst,
                    dstIp = src,
                    srcPort = dstPort,
                    dstPort = srcPort,
                    payload = responseBuffer.copyOf(responseDp.length),
                    protocol = 17
                )
                output.write(responsePacket)
                output.flush()

                socket.close()
            } catch (e: Exception) {
                Log.w(TAG, "UDP forwarding failed: ${e.message}")
            }
        }
    }

    private fun handleICMP(packet: ByteArray, length: Int, src: InetAddress, dst: InetAddress, output: FileOutputStream) {
        try {
            val headerLength = ((packet[0].toInt() and 0x0F) * 4)
            val icmpData = packet.copyOfRange(headerLength, length)

            if (icmpData.size < 8) return
            val icmpType = icmpData[0].toInt() and 0xFF

            if (icmpType == 8) {
                val responsePayload = icmpData.copyOfRange(8, icmpData.size)
                val responseIcmp = ByteArray(8 + responsePayload.size)
                responseIcmp[0] = 0x00.toByte()
                responseIcmp[1] = 0x00.toByte()
                System.arraycopy(responsePayload, 0, responseIcmp, 8, responsePayload.size)

                val icmpChecksum = calculateChecksum(responseIcmp)
                responseIcmp[2] = (icmpChecksum shr 8).toByte()
                responseIcmp[3] = icmpChecksum.toByte()

                val responsePacket = buildIPPacket(
                    srcIp = dst,
                    dstIp = src,
                    payload = responseIcmp,
                    protocol = 1
                )
                output.write(responsePacket)
                output.flush()
            }
        } catch (e: Exception) {
            Log.w(TAG, "ICMP handling failed: ${e.message}")
        }
    }

    private fun buildIPPacket(
        srcIp: InetAddress,
        dstIp: InetAddress,
        payload: ByteArray,
        protocol: Int,
        srcPort: Int = 0,
        dstPort: Int = 0
    ): ByteArray {
        val totalLength = 20 + payload.size
        val packet = ByteArray(totalLength)

        packet[0] = 0x45.toByte()
        packet[1] = 0x00.toByte()
        packet[2] = (totalLength shr 8).toByte()
        packet[3] = totalLength.toByte()
        packet[4] = 0x00.toByte()
        packet[5] = 0x00.toByte()
        packet[6] = 0x40.toByte()
        packet[7] = 0x00.toByte()
        packet[8] = 0x40.toByte()
        packet[9] = protocol.toByte()
        packet[10] = 0x00.toByte()
        packet[11] = 0x00.toByte()
        System.arraycopy(srcIp.address, 0, packet, 12, 4)
        System.arraycopy(dstIp.address, 0, packet, 16, 4)

        if (protocol == 6 || protocol == 17) {
            packet[12 + 2] = (srcPort shr 8).toByte()
            packet[12 + 3] = srcPort.toByte()
            packet[16 + 2] = (dstPort shr 8).toByte()
            packet[16 + 3] = dstPort.toByte()
        }

        val checksum = calculateChecksum(packet)
        packet[10] = (checksum shr 8).toByte()
        packet[11] = checksum.toByte()

        System.arraycopy(payload, 0, packet, 20, payload.size)
        return packet
    }

    private fun calculateChecksum(data: ByteArray): Int {
        var sum = 0L
        var i = 0
        while (i < data.size - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (data.size % 2 == 1) {
            sum += (data[data.size - 1].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return (sum.toInt().inv()) and 0xFFFF
    }

    fun stop() {
        isRunning = false
        forwardingJob?.cancel()
        forwardingJob = null
        try {
            tunInterface?.close()
            tunInterface = null
        } catch (e: Exception) {
            Log.e(TAG, "Error closing TUN", e)
        }
        Log.d(TAG, "VPN Core stopped")
    }

    suspend fun testPing(host: String, port: Int, timeout: Int = 5000): Long {
        return withContext(Dispatchers.IO) {
            try {
                val startTime = System.currentTimeMillis()
                val socket = Socket()
                socket.connect(InetSocketAddress(host, port), timeout)
                val latency = System.currentTimeMillis() - startTime
                socket.close()
                latency
            } catch (e: Exception) {
                -1L
            }
        }
    }
}
