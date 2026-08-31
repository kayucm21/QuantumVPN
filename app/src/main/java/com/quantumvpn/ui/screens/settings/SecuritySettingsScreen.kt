package com.quantumvpn.ui.screens.settings

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.quantumvpn.security.KillSwitch
import com.quantumvpn.security.BiometricAuth
import com.quantumvpn.recovery.AutoReconnect
import com.quantumvpn.protection.OperatorBypassProtection

/**
 * UI для новых функций безопасности v5.0.0
 */

@Composable
fun SecuritySettingsScreen(
    killSwitch: KillSwitch,
    biometricAuth: BiometricAuth,
    autoReconnect: AutoReconnect,
    bypassProtection: OperatorBypassProtection,
    onBiometricEnabledChange: (Boolean) -> Unit,
    onAutoReconnectChange: (Boolean) -> Unit,
    onKillSwitchChange: (Boolean) -> Unit,
) {
    val killSwitchEnabled by killSwitch.isKillSwitchEnabled().collectAsState(initial = false)
    val biometricEnabled by biometricAuth.isBiometricEnabled().collectAsState(initial = false)
    val autoReconnectEnabled by autoReconnect.isAutoReconnectEnabled().collectAsState(initial = true)
    val dohEnabled by bypassProtection.isDohEnabled().collectAsState(initial = true)
    val antiBlockMode by bypassProtection.getAntiBlockMode().collectAsState(initial = "BALANCED")
    val sniObfuscationEnabled by bypassProtection.isSniObfuscationEnabled().collectAsState(initial = true)
    val echEnabled by bypassProtection.isEchEnabled().collectAsState(initial = true)

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp)
    ) {
        // Kill Switch
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text("Kill Switch")
                Text("Блокирует интернет при падении VPN", style = androidx.compose.material3.MaterialTheme.typography.bodySmall)
                Spacer(modifier = Modifier.height(8.dp))
                Switch(
                    checked = killSwitchEnabled,
                    onCheckedChange = { onKillSwitchChange(it) },
                    modifier = Modifier.align(Alignment.End)
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Биометрия
        if (biometricAuth.isBiometricAvailable()) {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("Биометрическая аутентификация")
                    Text("Защита отпечатком или лицом", style = androidx.compose.material3.MaterialTheme.typography.bodySmall)
                    Spacer(modifier = Modifier.height(8.dp))
                    Switch(
                        checked = biometricEnabled,
                        onCheckedChange = { onBiometricEnabledChange(it) },
                        modifier = Modifier.align(Alignment.End)
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))
        }

        // Автопереподключение
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text("Автоматическое переподключение")
                Text("Восстанавливает VPN при разрыве", style = androidx.compose.material3.MaterialTheme.typography.bodySmall)
                Spacer(modifier = Modifier.height(8.dp))
                Switch(
                    checked = autoReconnectEnabled,
                    onCheckedChange = { onAutoReconnectChange(it) },
                    modifier = Modifier.align(Alignment.End)
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Защита от блокировок
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text("Защита от блокировок операторов")
                Text("DoH, SNI обфускация, ECH", style = androidx.compose.material3.MaterialTheme.typography.bodySmall)
                
                Spacer(modifier = Modifier.height(12.dp))

                Text("Режим: $antiBlockMode", style = androidx.compose.material3.MaterialTheme.typography.bodySmall)
                
                Spacer(modifier = Modifier.height(8.dp))

                Column(modifier = Modifier.padding(start = 8.dp)) {
                    Text("DNS-over-HTTPS", modifier = Modifier.padding(vertical = 4.dp))
                    Switch(
                        checked = dohEnabled,
                        onCheckedChange = {},
                        modifier = Modifier.align(Alignment.End)
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    Text("SNI обфускация", modifier = Modifier.padding(vertical = 4.dp))
                    Switch(
                        checked = sniObfuscationEnabled,
                        onCheckedChange = {},
                        modifier = Modifier.align(Alignment.End)
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    Text("ECH (Encrypted Client Hello)", modifier = Modifier.padding(vertical = 4.dp))
                    Switch(
                        checked = echEnabled,
                        onCheckedChange = {},
                        modifier = Modifier.align(Alignment.End)
                    )
                }
            }
        }
    }
}
