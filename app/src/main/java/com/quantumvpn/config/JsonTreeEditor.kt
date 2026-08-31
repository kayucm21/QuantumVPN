package com.quantumvpn.config

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

sealed interface JsonPathSegment {
    data class Key(val value: String) : JsonPathSegment
    data class Index(val value: Int) : JsonPathSegment
}

object JsonTreeEditor {
    fun replace(
        root: JsonElement,
        path: List<JsonPathSegment>,
        replacement: JsonElement,
    ): JsonElement {
        if (path.isEmpty()) return replacement
        return when (val segment = path.first()) {
            is JsonPathSegment.Key -> {
                val source = root as? JsonObject
                    ?: throw IllegalArgumentException("Ожидался JSON-объект у '${segment.value}'.")
                val tail = path.drop(1)
                val child = source[segment.value]
                if (tail.isNotEmpty() && child == null) {
                    throw IllegalArgumentException("Поле '${segment.value}' не найдено.")
                }
                JsonObject(
                    source.toMutableMap().apply {
                        put(
                            segment.value,
                            if (tail.isEmpty()) replacement else replace(requireNotNull(child), tail, replacement),
                        )
                    },
                )
            }

            is JsonPathSegment.Index -> {
                val source = root as? JsonArray
                    ?: throw IllegalArgumentException("Ожидался JSON-массив у ${segment.value}.")
                require(segment.value in source.indices) { "Индекс ${segment.value} вне массива." }
                val updated = source.toMutableList()
                updated[segment.value] = replace(updated[segment.value], path.drop(1), replacement)
                JsonArray(updated)
            }
        }
    }

    fun remove(root: JsonElement, path: List<JsonPathSegment>): JsonElement {
        require(path.isNotEmpty()) { "Нельзя удалить корень JSON." }
        return when (val segment = path.first()) {
            is JsonPathSegment.Key -> {
                val source = root as? JsonObject
                    ?: throw IllegalArgumentException("Ожидался JSON-объект у '${segment.value}'.")
                require(source.containsKey(segment.value)) { "Поле '${segment.value}' не найдено." }
                val updated = source.toMutableMap()
                if (path.size == 1) {
                    updated.remove(segment.value)
                } else {
                    updated[segment.value] = remove(requireNotNull(source[segment.value]), path.drop(1))
                }
                JsonObject(updated)
            }

            is JsonPathSegment.Index -> {
                val source = root as? JsonArray
                    ?: throw IllegalArgumentException("Ожидался JSON-массив у ${segment.value}.")
                require(segment.value in source.indices) { "Индекс ${segment.value} вне массива." }
                val updated = source.toMutableList()
                if (path.size == 1) {
                    updated.removeAt(segment.value)
                } else {
                    updated[segment.value] = remove(updated[segment.value], path.drop(1))
                }
                JsonArray(updated)
            }
        }
    }
}
