rootProject.name = "callis-java"

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

include("core")
include("cli")
include("gradle-plugin")
include("tools:coveragetool")
