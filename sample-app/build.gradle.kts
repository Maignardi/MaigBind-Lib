plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "io.github.maignardi.maigbind.sample.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.maignardi.maigbind.sample.app"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "0.2.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }

    testOptions {
        unitTests.isIncludeAndroidResources = true
    }

    lint {
        checkDependencies = true
        abortOnError = true
        error += "NewApi"
    }
}

dependencies {
    implementation(project(":maigbind-android"))
    implementation(libs.androidx.fragment.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.okhttp)

    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)

    testImplementation(libs.junit)
    testImplementation(libs.robolectric)
    testImplementation(libs.asm)
    testImplementation(libs.asm.commons)
    testImplementation(libs.asm.tree)
    testImplementation(libs.androidx.test.core)
    testImplementation(libs.androidx.compose.ui.test.junit4)
    testImplementation(libs.kotlinx.coroutines.test)
}
