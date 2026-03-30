package com.selinuxassistant.guardx.engine

import org.json.JSONObject

object NativeDetector {

    fun scan(): List<Finding> {
        val findings = mutableListOf<Finding>()
        val jsonStr = runCatching { NativeBridge.runNativeChecks() }.getOrNull() ?: return emptyList()
        val json = JSONObject(jsonStr)

        val suPaths = json.optStringList("suPaths")
        if (suPaths.isNotEmpty()) {
            findings += Finding(
                id = "ROOT_SU_PATHS",
                category = Category.ROOT,
                severity = Severity.HIGH,
                domain = Domain.INTEGRITY,
                title = "su binary izi bulundu",
                description = "Cihazda root erişimiyle ilişkili su binary izleri tespit edildi.",
                evidence = suPaths,
                score = 28
            )
        }

        val rootArtifacts = json.optStringList("rootArtifacts")
        if (rootArtifacts.isNotEmpty()) {
            findings += Finding(
                id = "ROOT_ARTIFACTS",
                category = Category.ROOT,
                severity = Severity.CRITICAL,
                domain = Domain.INTEGRITY,
                title = "Magisk/root artifact bulundu",
                description = "Dosya sistemi üzerinde root framework artifaktları bulundu.",
                evidence = rootArtifacts,
                score = 35
            )
        }

        val mounts = json.optStringList("suspiciousMounts")
        if (mounts.isNotEmpty()) {
            findings += Finding(
                id = "ROOT_SUSPICIOUS_MOUNTS",
                category = Category.ROOT,
                severity = Severity.HIGH,
                domain = Domain.INTEGRITY,
                title = "Şüpheli mount durumu",
                description = "System/vendor/product bölümlerinde overlay veya root ilişkili mount izleri var.",
                evidence = mounts,
                score = 25
            )
        }

        val props = json.optStringList("insecureProps")
        if (props.isNotEmpty()) {
            findings += Finding(
                id = "SYSTEM_INSECURE_PROPS",
                category = Category.SYSTEM,
                severity = Severity.MEDIUM,
                domain = Domain.INTEGRITY,
                title = "Güvensiz sistem özellikleri",
                description = "Build/debug/boot bütünlüğüyle ilişkili şüpheli sistem property değerleri tespit edildi.",
                evidence = props,
                score = 18
            )
        }

        val tracerPid = json.optInt("tracerPid", 0)
        if (tracerPid > 0) {
            findings += Finding(
                id = "DEBUG_TRACERPID",
                category = Category.DEBUG,
                severity = Severity.HIGH,
                domain = Domain.INTEGRITY,
                title = "Debugger/trace izi",
                description = "Süreç bir tracer tarafından izleniyor görünüyor.",
                evidence = listOf("TracerPid=$tracerPid"),
                score = 25
            )
        }

        val maps = json.optStringList("suspiciousMaps")
        if (maps.isNotEmpty()) {
            findings += Finding(
                id = "HOOK_SUSPICIOUS_MAPS",
                category = Category.HOOK,
                severity = Severity.HIGH,
                domain = Domain.INTEGRITY,
                title = "Bellekte hook/enjeksiyon izi",
                description = "Uygulamanın kendi process map alanında hook framework çağrışımlı isimler bulundu.",
                evidence = maps,
                score = 30
            )
        }

        val envIndicators = json.optStringList("envIndicators")
        if (envIndicators.isNotEmpty()) {
            findings += Finding(
                id = "HOOK_ENV_INDICATORS",
                category = Category.HOOK,
                severity = Severity.MEDIUM,
                domain = Domain.INTEGRITY,
                title = "Şüpheli environment değişkeni",
                description = "Runtime enjeksiyonla ilişkili environment değişkenleri bulundu.",
                evidence = envIndicators,
                score = 15
            )
        }

        if (!json.optBoolean("selinuxEnforcing", true)) {
            findings += Finding(
                id = "SELINUX_PERMISSIVE_NATIVE",
                category = Category.SELINUX,
                severity = Severity.CRITICAL,
                domain = Domain.INTEGRITY,
                title = "SELinux permissive",
                description = "SELinux enforcing kapalı görünüyor.",
                evidence = listOf("selinuxEnforcing=false"),
                score = 35
            )
        }

        val context = json.optString("selinuxContext", "")
        if (context.isNotBlank() &&
            !context.contains("untrusted_app") &&
            !context.contains("isolated_app") &&
            !context.contains("sdk_sandbox")
        ) {
            findings += Finding(
                id = "SELINUX_UNEXPECTED_CONTEXT",
                category = Category.SELINUX,
                severity = Severity.MEDIUM,
                domain = Domain.INTEGRITY,
                title = "Beklenmeyen SELinux context",
                description = "Uygulama sürecinin context değeri olağandışı görünüyor.",
                evidence = listOf(context),
                score = 15
            )
        }

        val nativeBridge = json.optString("nativeBridge", "")
        if (nativeBridge.contains("zygisk", ignoreCase = true) ||
            nativeBridge.contains("magisk", ignoreCase = true)
        ) {
            findings += Finding(
                id = "HOOK_ZYGISK_NATIVE_BRIDGE",
                category = Category.HOOK,
                severity = Severity.HIGH,
                domain = Domain.INTEGRITY,
                title = "Şüpheli native bridge",
                description = "Native bridge değeri Zygisk/Magisk ile ilişkili görünüyor.",
                evidence = listOf(nativeBridge),
                score = 30
            )
        }

        val verifiedBootState = json.optString("verifiedBootState", "")
        if (verifiedBootState.isNotBlank() && !verifiedBootState.equals("green", true)) {
            findings += Finding(
                id = "BOOT_VERIFIED_STATE",
                category = Category.SYSTEM,
                severity = Severity.HIGH,
                domain = Domain.INTEGRITY,
                title = "Verified Boot yeşil değil",
                description = "Cihazın verified boot durumu green değil.",
                evidence = listOf(verifiedBootState),
                score = 22
            )
        }

        val seccompMode = json.optInt("seccompMode", -1)
        if (seccompMode == 0) {
            findings += Finding(
                id = "SYSCALL_SECCOMP_OFF",
                category = Category.SYSTEM,
                severity = Severity.LOW,
                domain = Domain.INTEGRITY,
                title = "Seccomp kapalı olabilir",
                description = "Self-process syscall filtrelemesi aktif görünmüyor.",
                evidence = listOf("Seccomp=$seccompMode"),
                score = 8
            )
        }

        return findings
    }
}