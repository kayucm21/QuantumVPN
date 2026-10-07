package com.quantumvpn.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** A local nickname, not an account, password or network setting. */
internal fun normalizeAuroraDisplayName(input: String): String? {
    if (input.any { it.isISOControl() || Character.getType(it) == Character.FORMAT.toInt() }) return null
    val name = input.trim().replace(Regex("[\\p{Zs} ]+"), " ")
    return name.takeIf { it.length in 2..24 && it.any(Char::isLetterOrDigit) }
}

@Composable
internal fun AuroraNamedOnboarding2026(onFinished: (String) -> Unit) {
    var nameStep by rememberSaveable { mutableStateOf(false) }
    var name by rememberSaveable { mutableStateOf("") }
    BackHandler(nameStep) { nameStep = false }
    val normalized = normalizeAuroraDisplayName(name)
    val focus = LocalFocusManager.current
    BoxWithConstraints(Modifier.fillMaxSize().background(Color(0xFF040B16))) {
        Quantum2Wallpaper(Modifier.fillMaxSize())
        Box(Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Color(0x30040B16), Color(0x60040B16), Color(0xF9040B16)))))
        val compact = maxHeight < 740.dp
        Column(Modifier.fillMaxSize().navigationBarsPadding().imePadding()
            .verticalScroll(rememberScrollState()).padding(horizontal = 24.dp, vertical = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally) {
            if (nameStep) {
                TextButton(onClick = { nameStep = false }, modifier = Modifier.align(Alignment.Start)) { Text("← Назад", color = Color(0xFF55ECD5)) }
            } else Spacer(Modifier.height(if (compact) 8.dp else 52.dp))
            AuroraQMark2026(Modifier.size(if (compact) 76.dp else 118.dp))
            Text(LocalAppResources.current?.text("brand_name", "QuantumVPN") ?: "QuantumVPN", color = Color.White,
                fontSize = 29.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 12.dp))
            Text("Больше свободы. Ближе к вам.", color = Color(0xFFABC0D4), fontSize = 13.sp)
            Spacer(Modifier.height(if (compact) 24.dp else 66.dp))
            Text(if (nameStep) "Как вас зовут?" else "Добро пожаловать", color = Color.White,
                fontSize = if (compact) 24.sp else 27.sp, fontWeight = FontWeight.Bold, textAlign = TextAlign.Center)
            Text(if (nameStep) "Так мы будем приветствовать вас в приложении." else "Защищённое соединение и игры с друзьями — в одном месте.",
                color = Color(0xFFABC0D4), textAlign = TextAlign.Center, fontSize = 13.sp, modifier = Modifier.padding(top = 12.dp))
            Spacer(Modifier.height(if (compact) 20.dp else 24.dp))
            if (nameStep) {
                AuroraNameField2026(name, { name = it }, onDone = { normalized?.let { focus.clearFocus(); onFinished(it) } })
                Spacer(Modifier.height(16.dp))
            } else {
                Surface(color = Color(0xD0091D31), border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFF25445F)),
                    shape = RoundedCornerShape(20.dp), modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(if (compact) 14.dp else 18.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("◎  Ваш VPN под контролем", color = Color.White)
                        Text("♠  Дурак с друзьями — отдельной кнопкой", color = Color.White)
                        Text("✦  Свой фон и комфортные настройки", color = Color.White)
                    }
                }
                Spacer(Modifier.height(if (compact) 14.dp else 22.dp))
            }
            Button(onClick = { if (nameStep) normalized?.let { focus.clearFocus(); onFinished(it) } else nameStep = true },
                enabled = !nameStep || normalized != null,
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF55ECD5), contentColor = Color(0xFF042124)),
                shape = RoundedCornerShape(18.dp), modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp).testTag("onboarding-continue")) {
                Text(if (nameStep) "Продолжить" else "Начать", fontSize = 16.sp, fontWeight = FontWeight.Bold)
            }
            Text(if (nameStep) "Имя хранится на устройстве. Его можно изменить в настройках. Для игры имя передаётся только при входе в комнату."
                else "Регистрация по телефону и почте не нужна. VPN подключается только по вашему нажатию.",
                color = Color(0xFFABC0D4), fontSize = 12.sp, textAlign = TextAlign.Center, modifier = Modifier.padding(top = 18.dp))
        }
    }
}

@Composable
private fun AuroraNameField2026(name: String, onChange: (String) -> Unit, onDone: () -> Unit) {
    OutlinedTextField(value = name, onValueChange = { onChange(it.take(48)) }, singleLine = true,
        label = { Text("Ваше имя") }, supportingText = { Text("От 2 до 24 символов") },
        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Words, imeAction = ImeAction.Done),
        keyboardActions = KeyboardActions(onDone = { onDone() }),
        colors = OutlinedTextFieldDefaults.colors(focusedTextColor = Color.White, unfocusedTextColor = Color.White,
            focusedBorderColor = Color(0xFF55ECD5), unfocusedBorderColor = Color(0xFF345575),
            focusedLabelColor = Color(0xFF55ECD5), unfocusedLabelColor = Color(0xFFABC0D4),
            focusedContainerColor = Color(0xD0091D31), unfocusedContainerColor = Color(0xD0091D31)),
        shape = RoundedCornerShape(18.dp), modifier = Modifier.fillMaxWidth().testTag("onboarding-name"))
}

@Composable
internal fun AuroraNameDialog2026(initialName: String, onSave: (String) -> Unit, onDismiss: () -> Unit) {
    var name by rememberSaveable { mutableStateOf(initialName) }
    val normalized = normalizeAuroraDisplayName(name)
    AlertDialog(onDismissRequest = onDismiss, title = { Text("Ваше имя") },
        text = { AuroraNameField2026(name, { name = it }, { normalized?.let(onSave) }) },
        confirmButton = { TextButton(enabled = normalized != null, onClick = { normalized?.let(onSave) }) { Text("Сохранить") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } })
}
