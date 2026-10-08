rootProject.name = "reachability-analyzer"

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

include("core")
include("cli")
include("tools:coveragetool")
