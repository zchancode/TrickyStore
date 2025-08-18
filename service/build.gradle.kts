import android.databinding.tool.ext.capitalizeUS
import org.jetbrains.kotlin.daemon.common.toHexString
import java.security.MessageDigest

plugins {
    alias(libs.plugins.jetbrains.kotlin.android)
    alias(libs.plugins.kotlinx.serialization)
    alias(libs.plugins.agp.app)
}

val moduleId: String by rootProject.extra
val moduleName: String by rootProject.extra
val verCode: Int by rootProject.extra
val verName: String by rootProject.extra
val commitHash: String by rootProject.extra
val author: String by rootProject.extra
val description: String by rootProject.extra

fun calculateChecksum(variantLowered: String): String {
    return MessageDigest.getInstance("SHA-256").run {
        update(moduleId.toByteArray(Charsets.UTF_8))
        update(moduleName.toByteArray(Charsets.UTF_8))
        update("$verName ($verCode-$commitHash-$variantLowered)".toByteArray(Charsets.UTF_8))
        update(verCode.toString().toByteArray(Charsets.UTF_8))
        update(author.toByteArray(Charsets.UTF_8))
        update(description.toByteArray(Charsets.UTF_8))
        digest().toHexString()
    }
}

android {
    namespace = "io.github.a13e300.tricky_store"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.a13e300.tricky_store"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            isShrinkResources = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        forEach {
            val checksum = calculateChecksum(it.name)
            it.buildConfigField("String", "CHECKSUM", "\"$checksum\"")
        }
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildTypes {
        release {
            signingConfig = signingConfigs["debug"]
        }
    }

    packaging {
        resources {
            excludes += "**"
        }
    }

    lint {
        checkReleaseBuilds = false
        abortOnError = true
    }

    buildFeatures {
        buildConfig = true
    }

}

dependencies {
    implementation(files("src/lib/bcpkix-jdk18on-1.79.jar"))
    implementation(files("src/lib/bcprov-jdk18on-1.79.jar"))
    implementation(files("src/lib/bcutil-jdk18on-1.79.jar"))
    compileOnly(project(":stub"))
    compileOnly(libs.annotation)
    compileOnly(libs.dev.rikka.hidden.stub)
    implementation(kotlin("reflect"))
    implementation(libs.ktoml.core)
    implementation(libs.ktoml.file)
    implementation(libs.kotlinx.coroutines.android)
}

afterEvaluate {
    android.applicationVariants.forEach { variant ->
        val variantLowered = variant.name.lowercase()
        val variantCapped = variant.name.capitalizeUS()
        val pushTask = task<Task>("pushService$variantCapped") {
            group = "Service"
            dependsOn("assemble$variantCapped")
            doLast {
                exec {
                    commandLine(
                        "adb",
                        "push",
                        layout.buildDirectory.file("outputs/apk/$variantLowered/service-$variantLowered.apk")
                            .get().asFile.absolutePath,
                        "/data/local/tmp/service.apk"
                    )
                }
                exec {
                    commandLine(
                        "adb",
                        "shell",
                        "su -c 'rm /data/adb/modules/tricky_store/service.apk; mv /data/local/tmp/service.apk /data/adb/modules/tricky_store/'"
                    )
                }
            }
        }

        task<Task>("pushAndRestartService$variantCapped") {
            group = "Service"
            dependsOn(pushTask)
            doLast {
                exec {
                    commandLine("adb", "shell", "su -c \"setprop ctl.restart keystore2\"")
                }
            }
        }
    }
}
