import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    application
}

kotlin {
    explicitApi()
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

application {
    mainClass.set("io.github.maignardi.maigbind.sample.server.SampleServerKt")
}

dependencies {
    implementation(project(":maigbind-core"))
    implementation(project(":maigbind-verifier"))
    implementation(libs.ktor.server.core)
    implementation(libs.ktor.server.netty)
    implementation(libs.ktor.server.content.negotiation)
    implementation(libs.ktor.serialization.kotlinx.json)
    implementation(libs.ktor.server.status.pages)
    implementation(libs.ktor.server.call.logging)
    implementation(libs.logback.classic)

    testImplementation(kotlin("test"))
    testImplementation(libs.junit)
    testImplementation(libs.ktor.server.test.host)
    testImplementation(libs.bouncycastle.bcprov)
    testImplementation(libs.bouncycastle.bcpkix)
}
