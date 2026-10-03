package com.quantumvpn.ui

import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import com.quantumvpn.R
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

// Two bundled wallpapers, each decoded at 512x768 on IO, shared across thumbnails/pages.
private val wallpaperCache = ConcurrentHashMap<Int, ImageBitmap>()

@Composable
internal fun Quantum2Wallpaper(modifier: Modifier = Modifier, earth: Boolean = false) {
    val resources = LocalContext.current.resources
    val id = if (earth) R.drawable.quantum2_earth else R.drawable.quantum2_aurora
    val bitmap by produceState(wallpaperCache[id], id) {
        value = withContext(Dispatchers.IO) {
            wallpaperCache[id] ?: BitmapFactory.decodeResource(resources, id, BitmapFactory.Options().apply {
                inScaled = false
                inSampleSize = 2
            })?.asImageBitmap()?.also { wallpaperCache[id] = it }
        }
    }
    Box(modifier.background(Color(0xFF040B16))) {
        bitmap?.let {
            Image(it, null, Modifier.fillMaxSize().testTag("quantum2-wallpaper"), contentScale = ContentScale.Crop)
        }
    }
}
