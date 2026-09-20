package com.quantumvpn.diagnostics

import android.app.ActivityManager
import android.content.Context
import android.os.Debug
import java.util.Locale

/**
 * Snapshot of the app process and device memory state used by the
 * "Memory usage" diagnostics screen. Pure read-only; never mutates state.
 */
data class MemoryUsageSnapshot(
    val heapUsedBytes: Long,
    val heapMaxBytes: Long,
    val nativeHeapUsedBytes: Long,
    val nativeHeapMaxBytes: Long,
    val totalPssBytes: Long,
    val deviceTotalBytes: Long,
    val deviceAvailBytes: Long,
    val deviceThresholdBytes: Long,
    val lowMemory: Boolean,
) {
    val heapUsedMb: Double get() = heapUsedBytes / 1048576.0
    val heapMaxMb: Double get() = heapMaxBytes / 1048576.0
    val nativeHeapUsedMb: Double get() = nativeHeapUsedBytes / 1048576.0
    val nativeHeapMaxMb: Double get() = nativeHeapMaxBytes / 1048576.0
    val totalPssMb: Double get() = totalPssBytes / 1048576.0
    val deviceTotalMb: Double get() = deviceTotalBytes / 1048576.0
    val deviceAvailMb: Double get() = deviceAvailBytes / 1048576.0
    val deviceThresholdMb: Double get() = deviceThresholdBytes / 1048576.0

    val heapUsagePercent: Int
        get() = if (heapMaxBytes > 0) {
            ((heapUsedBytes * 100) / heapMaxBytes).toInt().coerceIn(0, 100)
        } else {
            0
        }

    val deviceUsagePercent: Int
        get() = if (deviceTotalBytes > 0) {
            (((deviceTotalBytes - deviceAvailBytes) * 100) / deviceTotalBytes)
                .toInt().coerceIn(0, 100)
        } else {
            0
        }

    fun formatMb(value: Double): String = String.format(Locale.US, "%.1f МБ", value)
}

object MemoryUsageProbe {
    fun snapshot(context: Context): MemoryUsageSnapshot {
        val runtime = Runtime.getRuntime()
        val heapUsed = runtime.totalMemory() - runtime.freeMemory()
        val heapMax = runtime.maxMemory()
        val nativeHeap = Debug.getNativeHeapAllocatedSize()
        val nativeMax = Debug.getNativeHeapSize()

        val am = context.getSystemService(ActivityManager::class.java)
        val memInfo = ActivityManager.MemoryInfo()
        am.getMemoryInfo(memInfo)

        var totalPss = 0L
        runCatching {
            val pid = android.os.Process.myPid()
            val pids = intArrayOf(pid)
            val mem = am.getProcessMemoryInfo(pids).firstOrNull()
            totalPss = mem?.totalPss?.toLong()?.times(1024) ?: 0L
        }

        return MemoryUsageSnapshot(
            heapUsedBytes = heapUsed,
            heapMaxBytes = heapMax,
            nativeHeapUsedBytes = nativeHeap,
            nativeHeapMaxBytes = nativeMax,
            totalPssBytes = totalPss,
            deviceTotalBytes = memInfo.totalMem,
            deviceAvailBytes = memInfo.availMem,
            deviceThresholdBytes = memInfo.threshold,
            lowMemory = memInfo.lowMemory,
        )
    }
}
