package com.selinuxassistant.guardx.engine

import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

data class ScanChunk(
    val findings: List<Finding>,
    val scannedCount: Int = 0
)

internal fun severityFor(score: Int): Severity = when {
    score >= 75 -> Severity.CRITICAL
    score >= 50 -> Severity.HIGH
    score >= 30 -> Severity.MEDIUM
    score >= 10 -> Severity.LOW
    else -> Severity.INFO
}

internal fun sha256(file: File): String? = runCatching {
    val md = MessageDigest.getInstance("SHA-256")
    file.inputStream().buffered().use { input ->
        val buffer = ByteArray(8192)
        while (true) {
            val read = input.read(buffer)
            if (read <= 0) break
            md.update(buffer, 0, read)
        }
    }
    md.digest().joinToString("") { "%02x".format(it) }
}.getOrNull()

internal fun readFirstLine(path: String): String? = runCatching {
    File(path).bufferedReader().use { it.readLine() }
}.getOrNull()

internal fun readBytesLimited(file: File, limit: Int): ByteArray = runCatching {
    file.inputStream().use { input ->
        val buf = ByteArray(limit)
        val read = input.read(buf)
        if (read <= 0) ByteArray(0) else buf.copyOf(read)
    }
}.getOrDefault(ByteArray(0))

internal fun isThirdParty(appInfo: ApplicationInfo): Boolean {
    val system = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
    val updatedSystem = (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
    return !system || updatedSystem
}

internal fun PackageManager.isInstalled(packageName: String): Boolean = try {
    if (Build.VERSION.SDK_INT >= 33) {
        getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
    } else {
        @Suppress("DEPRECATION")
        getPackageInfo(packageName, 0)
    }
    true
} catch (_: Exception) {
    false
}

internal fun PackageManager.installerOf(packageName: String): String? = try {
    if (Build.VERSION.SDK_INT >= 30) {
        getInstallSourceInfo(packageName).installingPackageName
    } else {
        @Suppress("DEPRECATION")
        getInstallerPackageName(packageName)
    }
} catch (_: Exception) {
    null
}

internal fun getInstalledPackagesCompat(pm: PackageManager): List<PackageInfo> {
    val flags = PackageManager.GET_PERMISSIONS or
            PackageManager.GET_SERVICES or
            PackageManager.GET_RECEIVERS or
            PackageManager.GET_SIGNING_CERTIFICATES

    return if (Build.VERSION.SDK_INT >= 33) {
        pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
    } else {
        @Suppress("DEPRECATION")
        pm.getInstalledPackages(flags)
    }
}

internal fun JSONObject.optStringList(key: String): List<String> {
    val arr = optJSONArray(key) ?: return emptyList()
    val out = ArrayList<String>(arr.length())
    for (i in 0 until arr.length()) {
        out += arr.optString(i)
    }
    return out
}