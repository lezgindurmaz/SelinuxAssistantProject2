package com.selinuxassistant.guardx.engine

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

class AppScanner(private val context: Context) {

    suspend fun scan(): ScanChunk = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val packages = getInstalledPackagesCompat(pm)
        val findings = mutableListOf<Finding>()

        for (pkg in packages) {
            analyzePackage(pm, pkg)?.let { findings += it }
        }

        ScanChunk(findings, packages.size)
    }

    private fun analyzePackage(pm: PackageManager, pkg: PackageInfo): Finding? {
        val appInfo = pkg.applicationInfo ?: return null
        if (pkg.packageName == context.packageName) return null
        if (!isThirdParty(appInfo)) return null

        val evidence = mutableListOf<String>()
        var score = 0

        val permissions = pkg.requestedPermissions?.toSet().orEmpty()
        val riskyPerms = permissions.intersect(LocalIoCs.highRiskPermissions)
        if (riskyPerms.size >= 4) {
            score += 12
            evidence += "Riskli izinler: ${riskyPerms.take(6).joinToString()}"
        }

        if (Manifest.permission.REQUEST_INSTALL_PACKAGES in permissions) {
            score += 8
            evidence += "REQUEST_INSTALL_PACKAGES"
        }

        if (Manifest.permission.QUERY_ALL_PACKAGES in permissions) {
            score += 6
            evidence += "QUERY_ALL_PACKAGES"
        }

        if (Manifest.permission.SYSTEM_ALERT_WINDOW in permissions) {
            score += 8
            evidence += "SYSTEM_ALERT_WINDOW"
        }

        if ("android.permission.RECEIVE_BOOT_COMPLETED" in permissions) {
            score += 4
            evidence += "RECEIVE_BOOT_COMPLETED"
        }

        val hasAccessibilityService = pkg.services?.any {
            it.permission == Manifest.permission.BIND_ACCESSIBILITY_SERVICE
        } == true
        if (hasAccessibilityService) {
            score += 18
            evidence += "AccessibilityService"
        }

        val hasNotificationListener = pkg.services?.any {
            it.permission == Manifest.permission.BIND_NOTIFICATION_LISTENER_SERVICE
        } == true
        if (hasNotificationListener) {
            score += 10
            evidence += "NotificationListenerService"
        }

        val hasDeviceAdmin = pkg.receivers?.any {
            it.permission == Manifest.permission.BIND_DEVICE_ADMIN
        } == true
        if (hasDeviceAdmin) {
            score += 15
            evidence += "DeviceAdmin receiver"
        }

        if (hasAccessibilityService && Manifest.permission.SYSTEM_ALERT_WINDOW in permissions) {
            score += 12
            evidence += "Accessibility + Overlay kombinasyonu"
        }

        if (hasAccessibilityService && "android.permission.RECEIVE_BOOT_COMPLETED" in permissions) {
            score += 10
            evidence += "Accessibility + BootCompleted kombinasyonu"
        }

        val installer = pm.installerOf(pkg.packageName)
        if (installer == null || installer !in LocalIoCs.trustedInstallers) {
            score += 6
            evidence += "Unknown installer=$installer"
        }

        if ((appInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            score += 10
            evidence += "FLAG_DEBUGGABLE"
        }

        if ((appInfo.flags and ApplicationInfo.FLAG_TEST_ONLY) != 0) {
            score += 10
            evidence += "FLAG_TEST_ONLY"
        }

        if (pkg.packageName in LocalIoCs.knownBadPackages) {
            score += 80
            evidence += "Known bad package IoC"
        }

        val signerHits = signerDigests(pkg).filter { it in LocalIoCs.knownBadSignerDigests }
        if (signerHits.isNotEmpty()) {
            score += 80
            evidence += "Bad signer IoC=${signerHits.joinToString()}"
        }

        score += inspectApk(File(appInfo.sourceDir), evidence)

        score = score.coerceAtMost(100)
        if (score < 25) return null

        return Finding(
            id = "APP_${pkg.packageName}",
            category = Category.APP,
            severity = severityFor(score),
            domain = Domain.MALWARE,
            title = "Riskli uygulama: ${pkg.packageName}",
            description = "İzinler, bileşenler, kurulum kaynağı ve APK içerik heuristics sonucunda uygulama riskli görünüyor.",
            evidence = evidence.take(10),
            score = score
        )
    }

    private fun signerDigests(pkg: PackageInfo): List<String> {
        val signatures = if (Build.VERSION.SDK_INT >= 28) {
            pkg.signingInfo?.apkContentsSigners?.toList().orEmpty()
        } else {
            @Suppress("DEPRECATION")
            pkg.signatures?.toList().orEmpty()
        }

        return signatures.map { sig ->
            val digest = MessageDigest.getInstance("SHA-256").digest(sig.toByteArray())
            digest.joinToString("") { "%02x".format(it) }
        }
    }

    private fun inspectApk(apkFile: File, evidence: MutableList<String>): Int {
        var score = 0
        if (!apkFile.exists() || !apkFile.canRead()) return 0

        sha256(apkFile)?.let {
            if (it in LocalIoCs.knownBadApkHashes) {
                score += 80
                evidence += "APK hash IoC=$it"
            }
        }

        runCatching {
            ZipFile(apkFile).use { zip ->
                val hits = mutableListOf<String>()
                val entries = zip.entries()
                var count = 0

                while (entries.hasMoreElements() && count < 2500) {
                    val name = entries.nextElement().name.lowercase()
                    count++

                    if (LocalIoCs.suspiciousApkEntryKeywords.any { key -> name.contains(key) }) {
                        hits += name
                    }
                }

                if (hits.isNotEmpty()) {
                    score += 18
                    evidence += "Şüpheli APK girdileri: ${hits.take(5).joinToString()}"
                }
            }
        }

        return score
    }
}