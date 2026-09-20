package com.quantumvpn.profiles

/**
 * Public, versioned endpoint for the subscription bundled with QuantumVPN.
 *
 * This endpoint is intentionally an API proxy. The provider URL and its access
 * token remain on the VDS, never in the APK or in the profile metadata.
 */
object ManagedSubscriptionEndpoint {
    const val url = "https://tepacom.o190.com:8443/api/v1/subscription"
    const val profileName = "QuantumVPN"
    const val sourceDescription = "Защищённая подписка QuantumVPN"
}
