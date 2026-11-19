plugins {
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.android.kmp.library) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.dokka) apply false
    alias(libs.plugins.ktlint) apply false
    alias(libs.plugins.detekt) apply false
    alias(libs.plugins.vanniktech.publish) apply false
}

subprojects {
    group = providers.gradleProperty("GROUP").getOrElse("io.github.maignardi")
    version = providers.gradleProperty("VERSION_NAME").getOrElse("0.2.0-SNAPSHOT")

    apply(plugin = "org.jlleitschuh.gradle.ktlint")
    apply(plugin = "dev.detekt")

    extensions.configure<dev.detekt.gradle.extensions.DetektExtension> {
        buildUponDefaultConfig.set(true)
        config.setFrom(rootProject.files("config/detekt/detekt.yml"))
        parallel.set(true)
    }

    tasks.withType<dev.detekt.gradle.Detekt>().configureEach {
        jvmTarget.set("17")
    }
}
