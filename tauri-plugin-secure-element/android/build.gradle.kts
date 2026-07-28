plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jlleitschuh.gradle.ktlint") version "12.1.0"
}

android {
    namespace = "net.kackman.secureelement"
    compileSdk = 36

    buildFeatures {
        buildConfig = true
    }

    defaultConfig {
        // API 30 (Android 11) is the floor. Below API 30, androidx.biometric 1.1.0
        // throws IllegalArgumentException("Crypto-based authentication is not
        // supported for Device Credential prior to API 30") for the
        // BIOMETRIC_STRONG or DEVICE_CREDENTIAL prompt this plugin always builds, so
        // every pinOrBiometric signature failed on API 23-29 in practice. There is no
        // stable androidx.biometric release newer than 1.1.0 to fix that with (1.2-1.4
        // only ever shipped as alphas), so raising the floor was the fix rather than a
        // library bump.
        minSdk = 30
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
    sourceSets {
        getByName("main") {
            java.srcDirs("src/main/java")
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.9.0")
    implementation("androidx.appcompat:appcompat:1.6.0")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.fragment:fragment-ktx:1.6.2")
    implementation("com.google.android.material:material:1.7.0")
    implementation(project(":tauri-android"))

    // Host-JVM unit tests (src/test) use JUnit 4.
    testImplementation("junit:junit:4.13.2")
}

ktlint {
    // Must match the ktlint the CLI runs, which is the one bundled with the pinned
    // @naturalcycles/ktlint in ../package.json (currently ktlint 1.8.0). When the two
    // drift, `pnpm lint:kotlin` and `./gradlew ktlintCheck` disagree about the same
    // files — ktlint 1.1 rejected trailing commas that 1.8 accepts.
    version.set("1.8.0")
    android.set(true)
    ignoreFailures.set(false)
}
