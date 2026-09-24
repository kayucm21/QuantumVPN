package com.quantumvpn.orbit

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.security.SecureRandom
import java.security.MessageDigest
import java.util.Base64

private val OrbitBackground = Color(0xFF050B12)
private val OrbitSurface = Color(0xFF0B1722)
private val OrbitSurface2 = Color(0xFF102435)
private val OrbitCyan = Color(0xFF24D7FF)
private val OrbitBlue = Color(0xFF2D80FF)
private val OrbitText = Color(0xFFE8F5FF)
private val OrbitMuted = Color(0xFF8CA7B9)

class MainActivity : ComponentActivity() {
    private var authMessage = mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        authMessage.value = callbackMessage(intent)
        setContent {
            OrbitTheme {
                OrbitApp(
                    authMessage = authMessage.value,
                    onLogin = ::startVkLogin,
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        authMessage.value = callbackMessage(intent)
    }

    private fun callbackMessage(intent: Intent?): String? {
        val data = intent?.data ?: return null
        if (data.scheme != "orbit-social") return null
        return data.getQueryParameter("error_description")
            ?: data.getQueryParameter("error")
            ?: if (!data.getQueryParameter("code").isNullOrBlank()) {
                "Код VK ID получен. Обмен будет выполнен через защищённый proxy панели."
            } else {
                "VK ID не вернул код авторизации."
            }
    }

    private fun startVkLogin() {
        val clientId = BuildConfig.VK_CLIENT_ID.trim()
        if (clientId.isEmpty()) {
            authMessage.value = "VK ID ещё не настроен: добавьте Client ID в панели и пересоберите приложение."
            return
        }
        val verifier = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val state = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val verifierText = Base64.getUrlEncoder().withoutPadding().encodeToString(verifier)
        val challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(verifierText.toByteArray()))
        val stateText = Base64.getUrlEncoder().withoutPadding().encodeToString(state)
        val uri = Uri.parse("https://id.vk.com/auth").buildUpon()
            .appendQueryParameter("app_id", clientId)
            .appendQueryParameter("response_type", "code")
            .appendQueryParameter("redirect_uri", BuildConfig.VK_REDIRECT_URI)
            .appendQueryParameter("state", stateText)
            .appendQueryParameter("code_challenge", challenge)
            .appendQueryParameter("code_challenge_method", "S256")
            .build()
        startActivity(Intent(Intent.ACTION_VIEW, uri))
    }
}

@Composable
private fun OrbitTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = androidx.compose.material3.darkColorScheme(
            primary = OrbitCyan,
            secondary = OrbitBlue,
            background = OrbitBackground,
            surface = OrbitSurface,
            onBackground = OrbitText,
            onSurface = OrbitText,
        ),
        content = content,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun OrbitApp(authMessage: String?, onLogin: () -> Unit) {
    var selected by remember { mutableIntStateOf(0) }
    Scaffold(
        containerColor = OrbitBackground,
        topBar = {
            TopAppBar(
                title = { Text("Orbit Social", fontWeight = FontWeight.Bold) },
                actions = { IconButton(onClick = {}) { Icon(Icons.Outlined.Search, "Поиск") } },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = OrbitBackground),
            )
        },
        bottomBar = {
            NavigationBar(containerColor = OrbitSurface) {
                listOf("Лента", "Музыка", "Сохранённое", "Профиль").forEachIndexed { index, item ->
                    NavigationBarItem(
                        selected = selected == index,
                        onClick = { selected = index },
                        icon = { Text(listOf("⌂", "♫", "▢", "◉")[index], color = OrbitCyan) },
                        label = { Text(item, fontSize = 10.sp) },
                    )
                }
            }
        },
    ) { padding ->
        when (selected) {
            0 -> FeedScreen(padding, authMessage, onLogin)
            1 -> MusicScreen(padding)
            2 -> SavedScreen(padding)
            else -> ProfileScreen(padding, authMessage, onLogin)
        }
    }
}

@Composable
private fun FeedScreen(padding: PaddingValues, authMessage: String?, onLogin: () -> Unit) {
    LazyColumn(contentPadding = padding, modifier = Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item { WelcomeCard(authMessage, onLogin) }
        items(listOf("Город по-другому прекрасен, когда смотришь чуть выше.", "Небольшие маршруты — большие открытия.")) { text -> PostCard(text) }
    }
}

@Composable
private fun WelcomeCard(authMessage: String?, onLogin: () -> Unit) {
    Card(
        modifier = Modifier.padding(14.dp).fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = OrbitSurface),
    ) {
        Column(modifier = Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Ближе к людям.", color = OrbitCyan, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            Text("Лента, профиль и музыка в одном спокойном пространстве.", color = OrbitMuted)
            Button(onClick = onLogin, colors = ButtonDefaults.buttonColors(containerColor = OrbitCyan, contentColor = Color(0xFF041019))) {
                Text("Войти через официальный VK ID", fontWeight = FontWeight.Bold)
            }
            Text(authMessage ?: "Без пароля внутри приложения. Авторизация открывается на официальной странице VK ID.", color = OrbitMuted, fontSize = 12.sp)
        }
    }
}

@Composable
private fun PostCard(text: String) {
    Card(modifier = Modifier.padding(horizontal = 14.dp).fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = OrbitSurface)) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(36.dp).clip(RoundedCornerShape(50)).background(Brush.linearGradient(listOf(OrbitCyan, OrbitBlue))))
                Spacer(Modifier.width(10.dp)); Column { Text("Orbit demo", fontWeight = FontWeight.Bold); Text("сегодня", color = OrbitMuted, fontSize = 12.sp) }
            }
            Text(text, color = OrbitText, fontSize = 16.sp)
            Box(Modifier.fillMaxWidth().height(130.dp).clip(RoundedCornerShape(14.dp)).background(Brush.linearGradient(listOf(Color(0xFF153B58), Color(0xFF07111B)))))
            Text("♡  237     ◯ 12      ↗ 5", color = OrbitMuted)
        }
    }
}

@Composable
private fun MusicScreen(padding: PaddingValues) = SimpleListScreen(padding, "Музыка", listOf("Офлайн-кэш", "Север", "Рассвет", "Планеты"))

@Composable
private fun SavedScreen(padding: PaddingValues) = SimpleListScreen(padding, "Сохранённое", listOf("Сохранённые посты", "Избранные треки", "Офлайн-кэш"))

@Composable
private fun SimpleListScreen(padding: PaddingValues, title: String, rows: List<String>) {
    LazyColumn(contentPadding = padding, modifier = Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        item { Text(title, modifier = Modifier.padding(18.dp), style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold) }
        items(rows) { row -> Card(modifier = Modifier.padding(horizontal = 14.dp).fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = OrbitSurface2)) { Text(row, modifier = Modifier.padding(18.dp), color = OrbitText) } }
    }
}

@Composable
private fun ProfileScreen(padding: PaddingValues, authMessage: String?, onLogin: () -> Unit) {
    Column(modifier = Modifier.fillMaxSize().padding(padding).padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Профиль", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        Text("Аккаунт подключается через VK ID OAuth.", color = OrbitMuted)
        OutlinedButton(onClick = onLogin) { Text("Подключить VK ID") }
        if (!authMessage.isNullOrBlank()) Text(authMessage, color = OrbitCyan, fontSize = 12.sp)
    }
}
