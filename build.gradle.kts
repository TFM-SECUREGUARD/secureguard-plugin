plugins {
    id("java")
    id("org.jetbrains.intellij") version "1.17.0"
}

group = "com.secureguard"
version = "1.0.0-SNAPSHOT"

repositories {
    mavenCentral()
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    implementation("com.microsoft.onnxruntime:onnxruntime:1.16.3")
    implementation("com.google.code.gson:gson:2.10.1")
    implementation("com.github.javaparser:javaparser-core:3.25.8")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.16.1")
    implementation("org.slf4j:slf4j-api:2.0.9")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.mockito:mockito-core:5.8.0")
}

intellij {
    version.set("2023.3")
    type.set("IC")
    plugins.set(listOf("java"))
    updateSinceUntilBuild.set(false)
}

tasks {
    withType<JavaCompile> {
        sourceCompatibility = "17"
        targetCompatibility = "17"
        options.encoding = "UTF-8"
    }

    buildSearchableOptions {
        enabled = false
    }

    patchPluginXml {
        sinceBuild.set("233.0")
        untilBuild.set("241.*")
    }

    runIde {
        jvmArgs("-Xmx2048m")
    }
}