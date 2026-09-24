import java.security.MessageDigest
import java.util.Properties
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

val coreProperties = Properties().apply {
    rootProject.file("core.properties").inputStream().use { load(it) }
}
// Local build secrets (FTP/panel/operator). Read from local-secrets.properties (git-ignored)
// or env vars; never hardcode credentials in the source tree.
val localSecrets = Properties().apply {
    val file = rootProject.file("local-secrets.properties")
    if (file.isFile) file.inputStream().use { load(it) }
}
fun secretProp(envName: String, propName: String): String =
    providers.environmentVariable(envName).orNull
        ?: localSecrets.getProperty(propName)?.takeIf(String::isNotBlank)
        ?: ""
val coreTag = coreProperties.getProperty("CORE_TAG")
val coreCommit = coreProperties.getProperty("CORE_COMMIT")
val corePatchFile = coreProperties.getProperty("CORE_PATCH_FILE")
val corePatchSha256 = coreProperties.getProperty("CORE_PATCH_SHA256")
val libboxAar = layout.projectDirectory.file("libs/libbox.aar").asFile
val olcrtcAar = layout.projectDirectory.file("libs/olcrtc.aar").asFile
val libboxMetadata = layout.projectDirectory.file("libs/libbox.properties").asFile
val appVersionCode = providers.gradleProperty("zapretVersionCode")
    .orElse(providers.environmentVariable("ZAPRET_VERSION_CODE"))
    .orElse("119")
    .get()
    .toInt()
val appVersionName = providers.gradleProperty("zapretVersionName")
    .orElse(providers.environmentVariable("ZAPRET_VERSION_NAME"))
    .orElse("5.9.4")
    .get()
val ftpUpdateHost = providers.gradleProperty("zapretFtpHost")
    .orElse(secretProp("ZAPRET_FTP_HOST", "zapretFtpHost"))
    .get()
val ftpUpdateUser = providers.gradleProperty("zapretFtpUser")
    .orElse(secretProp("ZAPRET_FTP_USER", "zapretFtpUser"))
    .get()
val ftpUpdatePassword = providers.gradleProperty("zapretFtpPassword")
    .orElse(secretProp("ZAPRET_FTP_PASSWORD", "zapretFtpPassword"))
    .get()
val ftpUpdateDir = providers.gradleProperty("zapretFtpDir")
    .orElse(secretProp("ZAPRET_FTP_DIR", "zapretFtpDir"))
    .get()
val ftpUpdateEnabled = providers.gradleProperty("zapretFtpUpdates")
    .orElse(providers.environmentVariable("ZAPRET_FTP_UPDATES"))
    .orElse("false")
    .get()
    .toBoolean()
val operatorIngestUrl = providers.gradleProperty("zapretOperatorIngestUrl")
    .orElse(providers.environmentVariable("ZAPRET_OPERATOR_INGEST_URL"))
    .orElse("")
    .get()
val operatorIngestToken = providers.gradleProperty("zapretOperatorIngestToken")
    .orElse(providers.environmentVariable("ZAPRET_OPERATOR_INGEST_TOKEN"))
    .orElse("")
    .get()
val panelUpdateBaseUrl = providers.gradleProperty("zapretPanelUpdateBaseUrl")
    .orElse(secretProp("ZAPRET_PANEL_UPDATE_BASE_URL", "zapretPanelUpdateBaseUrl"))
    .get()
val defaultUpdateChannel = if (
    Regex("""^\d+\.\d+\.\d+-beta\.\d+$""").matches(appVersionName)
) {
    "Beta"
} else {
    "Stable"
}
val debugVersionNameSuffix = providers.gradleProperty("zapretDebugVersionNameSuffix")
    .orElse("-debug")
    .get()
val updateRepository = providers.gradleProperty("zapretUpdateRepository")
    .orElse(providers.environmentVariable("ZAPRET_UPDATE_REPOSITORY"))
    .orElse("youtubediscord/QuantumVPN-android")
    .get()
    .also { require(Regex("[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+").matches(it)) }
val supportedApkAbis = setOf("arm64-v8a", "armeabi-v7a", "x86_64")
val requestedApkAbi = providers.gradleProperty("zapretAbi")
    .orElse(providers.gradleProperty("zapretReleaseAbi"))
    .orNull
    ?.also { require(it in supportedApkAbis) { "Unsupported APK ABI: $it" } }

val localSigningProperties = Properties().apply {
    val file = rootProject.file("keystore.properties")
    if (file.isFile) file.inputStream().use(::load)
}
fun signingProp(envName: String, propName: String): String? =
    providers.environmentVariable(envName).orNull
        ?: localSigningProperties.getProperty(propName)?.takeIf(String::isNotBlank)

val signingStorePath = signingProp("ZAPRET_SIGNING_STORE_FILE", "storeFile")
val signingStorePassword = signingProp("ZAPRET_SIGNING_STORE_PASSWORD", "storePassword")
val signingKeyAlias = signingProp("ZAPRET_SIGNING_KEY_ALIAS", "keyAlias")
val signingKeyPassword = signingProp("ZAPRET_SIGNING_KEY_PASSWORD", "keyPassword")
val releaseSigningConfigured = listOf(
    signingStorePath,
    signingStorePassword,
    signingKeyAlias,
    signingKeyPassword,
).all { !it.isNullOrBlank() }
val releaseSigningValueCount = listOf(
    signingStorePath,
    signingStorePassword,
    signingKeyAlias,
    signingKeyPassword,
).count { !it.isNullOrBlank() }
require(releaseSigningValueCount == 0 || releaseSigningValueCount == 4) {
    "Release signing requires all four ZAPRET_SIGNING_* env vars or keystore.properties entries."
}

android {
    namespace = "com.quantumvpn"
    compileSdk = 37
    // Native core ships inside app/libs/libbox.aar; pin NDK only when present locally.
    val pinnedNdk = coreProperties.getProperty("ANDROID_NDK_VERSION")
    val sdkDir = System.getenv("ANDROID_HOME")
        ?: providers.gradleProperty("sdk.dir").orNull
        ?: rootProject.file("local.properties").takeIf { it.isFile }?.let { propsFile ->
            Properties().apply { propsFile.inputStream().use { load(it) } }.getProperty("sdk.dir")
        }
    if (sdkDir != null && file("$sdkDir/ndk/$pinnedNdk").isDirectory) {
        ndkVersion = pinnedNdk
    }

    defaultConfig {
        applicationId = "com.quantumvpn"
        minSdk = 26
        targetSdk = 37
        versionCode = appVersionCode
        versionName = appVersionName

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        requestedApkAbi?.let { abi ->
            ndk {
                abiFilters += abi
            }
        }

        buildConfigField("String", "CORE_TAG", "\"$coreTag\"")
        buildConfigField("String", "UPDATE_REPOSITORY", "\"$updateRepository\"")
        buildConfigField("String", "DEFAULT_UPDATE_CHANNEL", "\"$defaultUpdateChannel\"")
        buildConfigField(
            "String",
            "CORE_COMMIT",
            "\"$coreCommit\"",
        )
        buildConfigField("String", "CORE_PATCH_SHA256", "\"$corePatchSha256\"")
        buildConfigField("boolean", "FTP_UPDATES_ENABLED", "$ftpUpdateEnabled")
        buildConfigField("String", "FTP_UPDATE_HOST", "\"${ftpUpdateHost.replace("\"", "")}\"")
        buildConfigField("String", "FTP_UPDATE_USER", "\"${ftpUpdateUser.replace("\"", "")}\"")
        buildConfigField("String", "FTP_UPDATE_PASSWORD", "\"${ftpUpdatePassword.replace("\"", "\\\"")}\"")
        buildConfigField("String", "FTP_UPDATE_DIR", "\"${ftpUpdateDir.replace("\"", "")}\"")
        buildConfigField(
            "String",
            "OPERATOR_INGEST_URL",
            "\"${operatorIngestUrl.replace("\\", "\\\\").replace("\"", "\\\"")}\"",
        )
        buildConfigField(
            "String",
            "OPERATOR_INGEST_TOKEN",
            "\"${operatorIngestToken.replace("\\", "\\\\").replace("\"", "\\\"")}\"",
        )
        buildConfigField(
            "String",
            "PANEL_UPDATE_BASE_URL",
            "\"${panelUpdateBaseUrl.replace("\\", "\\\\").replace("\"", "\\\"")}\"",
        )
    }

    signingConfigs {
        if (releaseSigningConfigured) {
            create("release") {
                val configured = file(requireNotNull(signingStorePath))
                storeFile = when {
                    configured.isFile -> configured
                    else -> rootProject.file(requireNotNull(signingStorePath))
                }
                storePassword = signingStorePassword
                keyAlias = signingKeyAlias
                keyPassword = signingKeyPassword
                enableV1Signing = true
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            if (debugVersionNameSuffix.isNotEmpty()) {
                versionNameSuffix = debugVersionNameSuffix
            }
            if (requestedApkAbi == null) {
                ndk {
                    // CI and the default local Android test target use an x86_64 AVD.
                    // Device tests can select another single ABI with -PzapretAbi.
                    abiFilters += "x86_64"
                }
            }
        }
        release {
            // Local builds without ZAPRET_SIGNING_* fall back to the debug keystore
            // so the APK is installable; CI/production should set the four env vars.
            signingConfig = signingConfigs.findByName("release")
                ?: signingConfigs.getByName("debug")
            isMinifyEnabled = true
            isShrinkResources = true
            if (requestedApkAbi == null) {
                ndk {
                    // A direct assembleRelease remains small and predictable. The release
                    // workflow passes zapretAbi once per supported architecture.
                    abiFilters += "arm64-v8a"
                }
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
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

    packaging {
        resources {
            // Drop duplicate license/legal metadata from AARs; keep the bundled
            // raw legal resources referenced by the app's legal screen.
            excludes += setOf(
                "/META-INF/{AL2.0,LGPL2.1}",
                "/META-INF/DEPENDENCIES",
                "/META-INF/LICENSE*",
                "/META-INF/NOTICE*",
                "/META-INF/*.version",
            )
        }
    }

}

val olcrtcStrippedAar = layout.buildDirectory.file("olcrtc-stripped/olcrtc.aar")

val stripOlcrtcAar by tasks.registering {
    group = "build"
    description = "Repacks app/libs/olcrtc.aar without the duplicate gomobile go.* runtime (libbox.aar already supplies it)."
    inputs.file(olcrtcAar)
    outputs.file(olcrtcStrippedAar)
    doLast {
        val output = olcrtcStrippedAar.get().asFile
        output.parentFile.mkdirs()
        val tmp = File(output.parentFile, "olcrtc-repack")
        if (tmp.exists()) tmp.deleteRecursively()
        tmp.mkdirs()
        val classesBytes = ZipInputStream(olcrtcAar.inputStream()).use { input ->
            var entry = input.nextEntry
            var bytes: ByteArray? = null
            while (entry != null) {
                if (entry.name == "classes.jar") {
                    bytes = input.readBytes()
                    break
                }
                entry = input.nextEntry
            }
            check(bytes != null) { "olcrtc.aar does not contain classes.jar." }
            bytes
        }
        val strippedClasses = File(tmp, "classes.jar")
        ZipOutputStream(strippedClasses.outputStream()).use { out ->
            ZipInputStream(classesBytes.inputStream()).use { input ->
                var entry = input.nextEntry
                while (entry != null) {
                    val name = entry.name
                    val keep = !entry.isDirectory && !name.startsWith("go/") && !name.startsWith("META-INF/")
                    if (keep) {
                        out.putNextEntry(ZipEntry(name))
                        input.copyTo(out)
                        out.closeEntry()
                    }
                    entry = input.nextEntry
                }
            }
        }
        ZipOutputStream(output.outputStream()).use { out ->
            ZipInputStream(olcrtcAar.inputStream()).use { input ->
                var entry = input.nextEntry
                while (entry != null) {
                    if (!entry.isDirectory && entry.name != "classes.jar" && !entry.name.startsWith("META-INF/")) {
                        out.putNextEntry(ZipEntry(entry.name))
                        input.copyTo(out)
                        out.closeEntry()
                    }
                    entry = input.nextEntry
                }
            }
            out.putNextEntry(ZipEntry("classes.jar"))
            strippedClasses.inputStream().use { it.copyTo(out) }
            out.closeEntry()
        }
        check(output.isFile && output.length() > 0L) { "Failed to repack olcrtc AAR." }
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2026.08.00")

    implementation("androidx.core:core-ktx:1.19.0")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.datastore:datastore-preferences:1.2.1")
    implementation(composeBom)
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material:material-icons-core")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation(files(libboxAar))
    implementation(project.files(olcrtcStrippedAar) { builtBy("stripOlcrtcAar") })
    implementation(project(":app-updater"))
    implementation(project(":network-bootstrap"))
    implementation(project(":wireguard-import"))
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.fragment:fragment-ktx:1.9.0")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")

    testImplementation("junit:junit:4.13.2")

    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation(composeBom)
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
}

val verifyPinnedLibbox by tasks.registering {
    group = "verification"
    description = "Fails when the pinned libbox AAR has not been built."
    inputs.files(libboxAar, libboxMetadata)
    inputs.property("expectedCoreTag", coreTag)
    inputs.property("expectedCoreCommit", coreCommit)
    inputs.property("expectedCorePatchFile", corePatchFile)
    inputs.property("expectedCorePatchSha256", corePatchSha256)
    doLast {
        val aar = inputs.files.single { it.name == "libbox.aar" }
        val metadataFile = inputs.files.single { it.name == "libbox.properties" }
        check(aar.isFile && aar.length() > 0L) {
            "Missing app/libs/libbox.aar. Run scripts/build-core.sh first."
        }
        check(metadataFile.isFile) {
            "Missing app/libs/libbox.properties. Run scripts/build-core.sh first."
        }

        val metadata = Properties().apply {
            metadataFile.inputStream().use { load(it) }
        }
        check(metadata.getProperty("CORE_TAG") == inputs.properties["expectedCoreTag"]) {
            "libbox tag does not match core.properties. Rebuild the core."
        }
        check(metadata.getProperty("CORE_COMMIT") == inputs.properties["expectedCoreCommit"]) {
            "libbox commit does not match core.properties. Rebuild the core."
        }
        check(metadata.getProperty("CORE_PATCH_FILE") == inputs.properties["expectedCorePatchFile"]) {
            "libbox patch file does not match core.properties. Rebuild the core."
        }
        check(metadata.getProperty("CORE_PATCH_SHA256") == inputs.properties["expectedCorePatchSha256"]) {
            "libbox patch hash does not match core.properties. Rebuild the core."
        }

        val digest = MessageDigest.getInstance("SHA-256")
        aar.inputStream().buffered().use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        val actualSha256 = digest.digest().joinToString("") { "%02x".format(it) }
        check(metadata.getProperty("LIBBOX_SHA256") == actualSha256) {
            "libbox SHA-256 does not match its build metadata. Rebuild the core."
        }
    }
}

tasks.named("preBuild").configure {
    dependsOn(verifyPinnedLibbox)
}
