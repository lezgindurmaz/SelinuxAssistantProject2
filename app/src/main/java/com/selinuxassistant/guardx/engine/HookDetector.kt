package com.selinuxassistant.guardx.engine

import android.content.Context

class HookDetector(private val context: Context) {

    fun scan(): List<Finding> {
        val findings = mutableListOf<Finding>()
        val pm = context.packageManager

        val hookPackages = LocalIoCs.knownHookPackages.filter { pm.isInstalled(it) }
        if (hookPackages.isNotEmpty()) {
            findings += Finding(
                id = "HOOK_MANAGER_PACKAGES",
                category = Category.HOOK,
                severity = Severity.MEDIUM,
                domain = Domain.INTEGRITY,
                title = "Hook framework yöneticisi bulundu",
                description = "Xposed/LSPosed/Substrate türü framework yöneticileri bulundu.",
                evidence = hookPackages,
                score = 20
            )
        }

        val xposedClassPresent = runCatching {
            Class.forName("de.robv.android.xposed.XposedBridge")
            true
        }.getOrDefault(false)

        if (xposedClassPresent) {
            findings += Finding(
                id = "HOOK_XPOSED_CLASS",
                category = Category.HOOK,
                severity = Severity.HIGH,
                domain = Domain.INTEGRITY,
                title = "Xposed sınıfı erişilebilir",
                description = "ClassLoader üzerinde XposedBridge erişilebilir görünüyor.",
                evidence = listOf("de.robv.android.xposed.XposedBridge"),
                score = 28
            )
        }

        val stackHits = Throwable().stackTrace
            .map { "${it.className}.${it.methodName}" }
            .filter {
                it.contains("xposed", true) ||
                it.contains("lsposed", true) ||
                it.contains("edxposed", true)
            }

        if (stackHits.isNotEmpty()) {
            findings += Finding(
                id = "HOOK_STACKTRACE_HITS",
                category = Category.HOOK,
                severity = Severity.HIGH,
                domain = Domain.INTEGRITY,
                title = "Stack trace hook izi",
                description = "Stack trace üzerinde hook framework izleri görüldü.",
                evidence = stackHits.take(5),
                score = 25
            )
        }

        return findings
    }
}