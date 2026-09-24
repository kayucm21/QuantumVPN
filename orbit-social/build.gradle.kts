plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

val orbitVersionCode = providers.gradleProperty("orbitVersionCode").orElse("1").get().toInt()
val orbitVersionName = providers.gradleProperty("orbitVersionName").orElse("1.0.0").get()
val orbitClientId = providers.gradleProperty("orbitVkClientId").orElse("").get()
val orbitRedirectUri = providers.gradleProperty("orbitVkRedirectUri").orElse("orbit-social://oauth/callback").get()
val orbitPanelVersionUrl = providers.gradleProperty("orbitPanelVersionUrl")
    .orElse("https://tepacom.o190.com:8443/api/vk/version")
    .get()

android {
    namespace = "com.quantumvpn.orbit"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.quantumvpn.orbit"
        minSdk = 26
        targetSdk = 37
        versionCode = orbitVersionCode
        versionName = orbitVersionName
        buildConfigField("String", "VK_CLIENT_ID", "\"${orbitClientId.replace("\"", "\\\"")}\"")
        buildConfigField("String", "VK_REDIRECT_URI", "\"${orbitRedirectUri.replace("\"", "\\\"")}\"")
        buildConfigField("String", "PANEL_VERSION_URL", "\"${orbitPanelVersionUrl.replace("\"", "\\\"")}\"")
    }

    buildTypes {
        debug { isMinifyEnabled = false }
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        buildConfig = true
        compose = true
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2026.08.00")
    implementation("androidx.core:core-ktx:1.19.0")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation(composeBom)
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material:material-icons-core")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
}
