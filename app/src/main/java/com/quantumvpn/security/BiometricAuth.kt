package com.quantumvpn.security

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

/**
 * Биометрическая аутентификация (отпечаток пальца / распознавание лица)
 */
class BiometricAuth(
    private val context: Context,
    private val dataStore: DataStore<Preferences>
) {
    companion object {
        private val BIOMETRIC_AUTH_ENABLED_KEY = booleanPreferencesKey("biometric_auth_enabled")
        private val BIOMETRIC_LOCK_KEY = booleanPreferencesKey("biometric_lock_app")
    }

    private val biometricManager = BiometricManager.from(context)

    /**
     * Проверяет, поддерживается ли биометрия на устройстве
     */
    fun isBiometricAvailable(): Boolean {
        return when (biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.BIOMETRIC_WEAK
        )) {
            BiometricManager.BIOMETRIC_SUCCESS -> true
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> false
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> false
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> false
            else -> false
        }
    }

    fun isBiometricEnabled(): Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[BIOMETRIC_AUTH_ENABLED_KEY] ?: false
    }

    suspend fun setBiometricEnabled(enabled: Boolean) {
        dataStore.edit { prefs ->
            prefs[BIOMETRIC_AUTH_ENABLED_KEY] = enabled
        }
    }

    fun isAppLocked(): Flow<Boolean> = dataStore.data.map { prefs ->
        prefs[BIOMETRIC_LOCK_KEY] ?: false
    }

    suspend fun setAppLocked(locked: Boolean) {
        dataStore.edit { prefs ->
            prefs[BIOMETRIC_LOCK_KEY] = locked
        }
    }

    /**
     * Показывает диалог биометрической аутентификации
     */
    fun authenticate(
        activity: FragmentActivity,
        onSuccess: () -> Unit,
        onFailure: (error: String) -> Unit,
        onCancel: () -> Unit
    ) {
        val executor = context.mainExecutor
        val biometricPrompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    onSuccess()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    onFailure(errString.toString())
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    onCancel()
                }
            }
        )

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Аутентификация QuantumVPN")
            .setSubtitle("Используйте биометрию для доступа")
            .setNegativeButtonText("Отмена")
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                        BiometricManager.Authenticators.DEVICE_CREDENTIAL
            )
            .build()

        biometricPrompt.authenticate(promptInfo)
    }
}
