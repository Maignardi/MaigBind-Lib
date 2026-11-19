plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.dokka)
}

kotlin {
    explicitApi()

    iosArm64()
    iosSimulatorArm64()
    iosX64()

    sourceSets {
        commonMain.dependencies {
            api(project(":maigbind-core"))
        }
    }
}
