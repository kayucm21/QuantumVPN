package com.quantumvpn.ui

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

object DeviceUnlock {
    fun authenticate(
        activity: FragmentActivity,
        preferBiometric: Boolean,
        title: String,
        subtitle: String,
        onSuccess: () -> Unit,
        onFailure: () -> Unit,
    ) {
        if (!preferBiometric) {
            onFailure()
            return
        }
        val manager = BiometricManager.from(activity)
        val can = manager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.BIOMETRIC_WEAK,
        )
        if (can != BiometricManager.BIOMETRIC_SUCCESS) {
            onFailure()
            return
        }
        val executor = ContextCompat.getMainExecutor(activity)
        val prompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onSuccess()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onFailure()
                }

                override fun onAuthenticationFailed() = Unit
            },
        )
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle(subtitle)
                .setNegativeButtonText("PIN")
                .build(),
        )
    }
}
