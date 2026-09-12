import java.security.KeyStore
import java.security.MessageDigest
import java.util.Base64
import java.util.Locale
import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.variant.BuildConfigField

val defaultManagerPackageName = rootProject.extra["defaultManagerPackageName"] as String
val apiCode = rootProject.extra["apiCode"] as Int
val verCode = rootProject.extra["verCode"] as Int
val verName = rootProject.extra["verName"] as String
val coreVerCode = rootProject.extra["coreVerCode"] as Int
val coreVerName = rootProject.extra["coreVerName"] as String

fun decodeSha256Hex(value: String): ByteArray {
    require(value.length == 64) { "Manager signature digest must be 64 hex chars: $value" }
    return ByteArray(value.length / 2) { index ->
        value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }
}

fun encodeAllowlistEntry(value: String): String {
    val key = 0x5A
    val obfuscated = decodeSha256Hex(value).map { byte -> (byte.toInt() xor key).toByte() }.toByteArray()
    return Base64.getEncoder().encodeToString(obfuscated)
}

plugins {
    alias(libs.plugins.agp.app)
    alias(npatch.plugins.kotlin.serialization)
    alias(npatch.plugins.compose.compiler)
    alias(npatch.plugins.google.devtools.ksp)
    alias(npatch.plugins.rikka.tools.refine)
    alias(npatch.plugins.kotlin.parcelize)
}

android {
    defaultConfig {
        applicationId = defaultManagerPackageName
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    packaging {
        jniLibs {
            excludes += "lib/*/libandroidx.graphics.path.so"
            excludes += "lib/*/libdatastore_shared_counter.so"
        }
        resources {
            excludes += "kotlin/**"
            excludes += "META-INF/androidx*"
            excludes += "META-INF/androidx/**"
            excludes += "DebugProbesKt.bin"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true      // 启用 R8/ProGuard 进行代码压缩、优化和混淆。
            isShrinkResources = true    // 启用资源缩减，移除未被引用的资源文件。
            isDebuggable = false        // 发布版本禁止调试。
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        all {
            sourceSets[name].assets.directories.add(rootProject.projectDir.resolve("out/assets/$name").absolutePath)
        }
    }

    buildFeatures {
        aidl = true
        compose = true
        buildConfig = true
    }

    // In-app language selection must work offline without Play language-split downloads.
    bundle.language.enableSplit = false

    namespace = "top.nkbe.npatch"

}

androidComponents {
    onVariants { variant ->
        val variantLowered = variant.name.lowercase()
        val variantCapped = variant.name.replaceFirstChar { it.uppercase() }

        val configuredSignature = providers.environmentVariable("NPATCH_MANAGER_SIGNATURE_SHA256")
            .orElse(providers.gradleProperty("npatchManagerSignatureSha256"))
        val signingConfig = android.buildTypes.getByName(requireNotNull(variant.buildType)).signingConfig
        val signatureAllowlist = configuredSignature.orElse(providers.provider {
            val config = requireNotNull(signingConfig) { "Missing manager signing config for ${variant.name}" }
            val storeFile = requireNotNull(config.storeFile) { "Missing manager signing keystore for ${variant.name}" }
            val store = KeyStore.getInstance(config.storeType ?: KeyStore.getDefaultType())
            storeFile.inputStream().use { store.load(it, config.storePassword?.toCharArray()) }
            val certificate = requireNotNull(store.getCertificate(config.keyAlias)) {
                "Missing manager signing certificate for ${variant.name}"
            }
            MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
                .joinToString("") { "%02X".format(Locale.ROOT, it) }
        })
        requireNotNull(variant.buildConfigFields).put("MANAGER_SIGNATURE_SHA256_ALLOWLIST", signatureAllowlist.map { fingerprints ->
            val encoded = fingerprints.split(',', ';', ' ', '\n', '\r', '\t')
                .map { it.trim().uppercase(Locale.ROOT) }
                .filter { it.isNotEmpty() }
                .distinct()
                .joinToString(",", transform = ::encodeAllowlistEntry)
            BuildConfigField("String", "\"$encoded\"", "SHA-256 fingerprints for the selected signing certificate")
        })
        // validateSigning also creates the default debug keystore on a fresh checkout.
        tasks.configureEach {
            if (name == "generate${variantCapped}BuildConfig") {
                dependsOn("validateSigning$variantCapped")
            }
        }

        val copyAssetsTaskProvider = tasks.register<Copy>("copy${variantCapped}Assets") {
            dependsOn(":meta-loader:copy$variantCapped")
            dependsOn(":patch-loader:copy$variantCapped")

            val targetDir = layout.buildDirectory.dir("intermediates/assets/$variantLowered/merge${variantCapped}Assets")
            doFirst {
                delete(targetDir.map { it.file("npatch/loader.dex") })
            }
            into(targetDir)

            from("${rootProject.projectDir}/out/assets/${variant.name}")
        }

        tasks.configureEach {
            if (name == "merge${variantCapped}Assets") {
                dependsOn(copyAssetsTaskProvider)
            }
            // Lint inspects the same asset directory. If packaging is requested in the
            // same invocation, wait for its producers; standalone Lint need not build JNI.
            if (name == "generate${variantCapped}LintReportModel" || name == "lintAnalyze${variantCapped}") {
                mustRunAfter(
                    ":meta-loader:copyDex$variantCapped",
                    ":patch-loader:copyDex$variantCapped",
                    ":patch-loader:copySo$variantCapped",
                )
            }
        }

        tasks.register<Copy>("build$variantCapped") {
            dependsOn("assemble$variantCapped")
            from(variant.artifacts.get(SingleArtifact.APK))
            into("${rootProject.projectDir}/out/$variantLowered")
            rename(".*.apk", "NPatch-v$verName-$verCode-$variantLowered.apk")
        }
    }
}

dependencies {
    implementation(projects.patch)
    implementation(projects.share.android)
    implementation(projects.share.java)
    implementation("vector:daemon-service")

    implementation(platform(npatch.androidx.compose.bom))
    implementation(npatch.androidx.activity.compose)
    implementation(npatch.androidx.compose.material.icons.extended)
    implementation(npatch.androidx.compose.material3)
    implementation(npatch.materialkolor)
    // Miuix is confined to navigation and blur; all widgets use Material 3.
    implementation(npatch.miuix.nav)
    implementation(npatch.miuix.blur)
    implementation(npatch.miuix.shader)
    implementation(npatch.androidx.compose.ui)
    implementation(npatch.androidx.compose.ui.tooling.preview)
    implementation(npatch.androidx.core.ktx)
    implementation(npatch.androidx.splashscreen)
    implementation(npatch.androidx.datastore.preferences)
    implementation(npatch.coil.compose)
    implementation(libs.gson)
    implementation(npatch.androidx.lifecycle.viewmodel.compose)
    implementation("androidx.preference:preference-ktx:1.2.1")
    implementation(npatch.androidx.room.ktx)
    implementation(npatch.androidx.room.runtime)
    implementation("com.squareup.okhttp3:okhttp:5.5.0")
    implementation("com.squareup.okhttp3:okhttp-dnsoverhttps:5.5.0")

    implementation(libs.gson)
    implementation(npatch.rikka.shizuku.api)
    implementation(npatch.rikka.shizuku.provider)
    implementation(npatch.rikka.refine)
    //implementation(npatch.raamcosta.compose.destinations)
    implementation("me.zhanghai.android.appiconloader:appiconloader:1.5.0")
    implementation(npatch.hiddenapibypass)

    implementation(npatch.androidx.webkit)


    annotationProcessor(npatch.androidx.room.compiler)
    compileOnly(npatch.rikka.hidden.stub)
    ksp(npatch.androidx.room.compiler)
    //ksp(npatch.raamcosta.compose.destinations.ksp)

    // Keep app/test runtime versions aligned with AndroidX Test 1.7.
    implementation("androidx.concurrent:concurrent-futures:1.3.0")
    androidTestImplementation(platform(npatch.androidx.compose.bom))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    debugImplementation("androidx.compose.ui:ui-test-manifest")

    debugImplementation(npatch.androidx.compose.ui.tooling)
    debugImplementation(npatch.androidx.customview)
    debugImplementation(npatch.androidx.customview.poolingcontainer)
}

kotlin {
    compilerOptions {
        // Match WeKit: all manager compilations, including tests, use these Material APIs.
        optIn.addAll(
            "androidx.compose.material3.ExperimentalMaterial3Api",
            "androidx.compose.material3.ExperimentalMaterial3ExpressiveApi",
        )
    }
}
