package com.selinuxassistant.guardx.engine

import android.content.Context
import android.os.Build

class RootDetector(private val context: Context) {

    fun scan(): List<Finding> {
        val findings = mutableListOf<Finding>()
        val pm = context.packageManager

        val rootManagers = LocalIoCs.knownRootPackages.filter { pm.isInstalled(it) }
        if (rootManagers.isNotEmpty()) {
            findings += Finding(
                id = "ROOT_MANAGER_APPS",
                category = Category.ROOT,
                severity = Severity.MEDIUM,
                domain = Domain.INTEGRITY,
                title = "Root yönetim uygulaması bulundu",
                description = "Root yönetim uygulaması cihaz bütünlüğü açısından bir risk göstergesi olabilir; tek başına malware anlamına gelmez.",
                evidence = rootManagers,
                score = 18
            )
        }

        val tags = Build.TAGS.orEmpty()
        if (tags.contains("test-keys")) {
            findings += Finding(
                id = "BUILD_TEST_KEYS",
                category = Category.SYSTEM,
                severity = Severity.LOW,
                domain = Domain.INTEGRITY,
                title = "Build test-keys içeriyor",
                description = "Cihaz üretim dışı veya modifiye bir build kullanıyor olabilir.",
                evidence = listOf(tags),
                score = 8
            )
        }

        val buildType = Build.TYPE.orEmpty()
        if (buildType == "eng" || buildType == "userdebug") {
            findings += Finding(
                id = "BUILD_DEBUG_TYPE",
                category = Category.SYSTEM,
                severity = Severity.MEDIUM,
                domain = Domain.INTEGRITY,
                title = "Debug/engineering build",
                description = "Cihaz system build tipi user yerine eng/userdebug.",
                evidence = listOf(buildType),
                score = 12
            )
        }

        val fingerprint = Build.FINGERPRINT.orEmpty()
        if (fingerprint.contains("generic", true) || fingerprint.contains("test-keys", true)) {
            findings += Finding(
                id = "BUILD_SUSPICIOUS_FINGERPRINT",
                category = Category.SYSTEM,
                severity = Severity.LOW,
                domain = Domain.INTEGRITY,
                title = "Şüpheli fingerprint",
                description = "Fingerprint emülatör veya test build çağrışımı yapıyor olabilir.",
                evidence = listOf(fingerprint),
                score = 6
            )
        }

        return findings
    }
}