plugins {
    id("com.android.application") version "9.4.0"
}

android {
    namespace = "com.pif.companion"

    compileSdk {
        version = release(37)
    }
    defaultConfig {
        applicationId = "com.pif.companion"
        minSdk = 21
        targetSdk = 37

        val code =
            findProperty("app.versionCode")?.toString()?.toIntOrNull()
                ?: error("Missing or invalid app.versionCode")
        versionCode = code
        versionName = "1.0.$code"
    }
    buildTypes {
        release {
            optimization { enable = true }
            signingConfig = signingConfigs.getByName("debug")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    packaging {
        resources {
            excludes.add("**/kotlin/**")
        }
    }
}
