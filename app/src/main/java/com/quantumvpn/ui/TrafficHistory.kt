package com.quantumvpn.ui

import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import com.quantumvpn.vpn.TrafficSample
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlin.math.max

/**
 * Хранит историю трафика для отображения графика в реальном времени.
 * Максимум 60 сэмплов (за последние 60 секунд).
 */
class TrafficHistory(
    private val maxSamples: Int = 60
) {
    private val _samples = MutableStateFlow<List<TrafficSample>>(emptyList())
    val samples: Flow<List<TrafficSample>> = _samples.asStateFlow()

    private var lastUpdateTime = 0L
    private val handler = Handler(Looper.getMainLooper())
    private var updateRunnable: Runnable? = null

    /**
     * Добавляет новый сэмпл трафика.
     * Если сэмплов больше maxSamples, удаляет самые старые.
     */
    fun addSample(sample: TrafficSample) {
        val currentTime = System.currentTimeMillis()
        // Обновляем не чаще чем раз в секунду
        if (currentTime - lastUpdateTime < 1000) {
            // Обновляем последний сэмпл (накапливаем данные)
            _samples.update { list ->
                if (list.isNotEmpty()) {
                    val last = list.last()
                    val updated = last.copy(
                        downloadBytesPerSecond = max(last.downloadBytesPerSecond, sample.downloadBytesPerSecond),
                        uploadBytesPerSecond = max(last.uploadBytesPerSecond, sample.uploadBytesPerSecond)
                    )
                    list.dropLast(1) + updated
                } else {
                    list + sample
                }
            }
            return
        }

        lastUpdateTime = currentTime
        _samples.update { list ->
            val newList = list + sample
            if (newList.size > maxSamples) {
                newList.drop(newList.size - maxSamples)
            } else {
                newList
            }
        }
    }

    /**
     * Очищает историю.
     */
    fun clear() {
        _samples.update { emptyList() }
        lastUpdateTime = 0L
    }

    /**
     * Запускает автоматическое обновление истории.
     * Каждую секунду добавляет нулевой сэмпл, чтобы график не стоял на месте.
     */
    fun startAutoUpdate() {
        stopAutoUpdate()
        updateRunnable = object : Runnable {
            override fun run() {
                // Добавляем нулевой сэмпл, если нет активного трафика
                _samples.update { list ->
                    if (list.isEmpty() || list.last().downloadBytesPerSecond > 0 || list.last().uploadBytesPerSecond > 0) {
                        list + TrafficSample(
                            downloadBytesPerSecond = 0,
                            uploadBytesPerSecond = 0,
                        )
                    } else {
                        list
                    }
                }
                handler.postDelayed(this, 1000)
            }
        }
        handler.post(updateRunnable!!)
    }

    /**
     * Останавливает автоматическое обновление.
     */
    fun stopAutoUpdate() {
        updateRunnable?.let { handler.removeCallbacks(it) }
        updateRunnable = null
    }

    /**
     * Возвращает текущую скорость загрузки (download) в байтах/сек.
     */
    fun currentDownloadSpeed(): Long =
        _samples.value.lastOrNull()?.downloadBytesPerSecond ?: 0L

    /**
     * Возвращает текущую скорость отдачи (upload) в байтах/сек.
     */
    fun currentUploadSpeed(): Long =
        _samples.value.lastOrNull()?.uploadBytesPerSecond ?: 0L
}

/**
 * Composable-обёртка для использования TrafficHistory в UI.
 */
@Composable
fun rememberTrafficHistory(
    maxSamples: Int = 60,
    autoUpdate: Boolean = true
): TrafficHistory {
    val history = remember { TrafficHistory(maxSamples) }

    LaunchedEffect(autoUpdate) {
        if (autoUpdate) {
            history.startAutoUpdate()
        }
    }

    return history
}
