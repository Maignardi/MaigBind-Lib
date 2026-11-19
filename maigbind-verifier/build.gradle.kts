import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.dokka)
    alias(libs.plugins.vanniktech.publish)
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

dependencies {
    api(project(":maigbind-core"))
    implementation(libs.bouncycastle.bcprov)
    implementation(libs.bouncycastle.bcpkix)
    implementation(libs.kotlinx.serialization.json)

    testImplementation(kotlin("test"))
    testImplementation(libs.junit)
}

mavenPublishing {
    publishToMavenCentral()
    if (providers.gradleProperty("signingInMemoryKey").isPresent ||
        providers.gradleProperty("signing.keyId").isPresent
    ) {
        signAllPublications()
    }

    pom {
        name.set("MaigBind Verifier")
        description.set(
            "JVM server-side verifier for Android Key Attestation, Google revocation lists, immediate PoP, and ECDSA transaction payloads.",
        )
        url.set(providers.gradleProperty("POM_URL"))
        licenses {
            license {
                name.set(providers.gradleProperty("POM_LICENCE_NAME"))
                url.set(providers.gradleProperty("POM_LICENCE_URL"))
            }
        }
        developers {
            developer {
                id.set(providers.gradleProperty("POM_DEVELOPER_ID"))
                name.set(providers.gradleProperty("POM_DEVELOPER_NAME"))
                url.set(providers.gradleProperty("POM_DEVELOPER_URL"))
            }
        }
        scm {
            url.set(providers.gradleProperty("POM_SCM_URL"))
            connection.set(providers.gradleProperty("POM_SCM_CONNECTION"))
            developerConnection.set(providers.gradleProperty("POM_SCM_DEV_CONNECTION"))
        }
    }
}
