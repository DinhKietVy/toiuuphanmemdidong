plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.example.mobitive"
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        applicationId = "com.example.mobitive"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

dependencies {
    // TensorFlow Lite: chạy mô hình GRU
    implementation("org.tensorflow:tensorflow-lite:2.16.1")

    // DEX: parsed by analyzer/DexMethodTable (method_ids), no external library (M5).

    // APK and AndroidManifest parser
    implementation("net.dongliu:apk-parser:2.6.10")
    // JSON parser
    implementation("com.google.code.gson:gson:2.11.0")

    // AndroidX
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation(libs.appcompat)
    implementation(libs.material)
    testImplementation(libs.junit)
    // M8: GPU delegate only in the TEST APK (AccelBenchmark); the shipped app stays CPU-only.
    androidTestImplementation("org.tensorflow:tensorflow-lite-gpu:2.16.1")
    androidTestImplementation("org.tensorflow:tensorflow-lite-gpu-api:2.16.1")
    androidTestImplementation(libs.espresso.core)
    androidTestImplementation(libs.ext.junit)
}