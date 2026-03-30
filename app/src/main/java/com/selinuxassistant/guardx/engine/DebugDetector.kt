package com.selinuxassistant.guardx.engine

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Debug
import android.provider.Settings

class DebugDetector(private val context: Context) {

    fun scan(): List<Finding> {
        val findings = mutableListOf<Finding>()

        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            findings += Finding(
                id = "DEBUG_CONNECTED",
                category = Category.DEBUG,
                severity = Severity.HIGH,
                domain = Domain.INTEGRITY,
                title = "Debugger bağlı",
                description = "Uygulama süreci bir debugger ile çalışıyor.",
                evidence = listOf(
                    "isDebuggerConnected=${Debug.isDebuggerConnected()}",
                    "waitingForDebugger=${Debug.waitingForDebugger()}"
                ),
                score = 25
            )
        }

        val appDebuggable = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        if (appDebuggable) {
            findings += Finding(
                id = "APP_DEBUGGABLE",
                category = Category.DEBUG,
                severity = Severity.MEDIUM,
                domain = Domain.INTEGRITY,
                title = "Uygulama debuggable build",
                description = "Release güvenliği açısından debuggable build önerilmez.",
                evidence = listOf("FLAG_DEBUGGABLE"),
                score = 12
            )
        }

        val adbEnabled = runCatching {
            Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        }.getOrDefault(false)

        if (adbEnabled) {
            findings += Finding(
                id = "ADB_ENABLED",
                category = Category.DEBUG,
                severity = Severity.LOW,
                domain = Domain.INTEGRITY,
                title = "ADB açık",
                description = "ADB etkin. Bu tek başına kötü niyet göstergesi değildir ama saldırı yüzeyini artırır.",
                evidence = listOf("ADB_ENABLED=1"),
                score = 6
            )
        }

        val devOptions = runCatching {
            Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        }.getOrDefault(false)

        if (devOptions) {
            findings += Finding(
                id = "DEV_OPTIONS_ENABLED",
                category = Category.DEBUG,
                severity = Severity.LOW,
                domain = Domain.INTEGRITY,
                title = "Geliştirici seçenekleri açık",
                description = "Geliştirici seçenekleri aktif.",
                evidence = listOf("DEVELOPMENT_SETTINGS_ENABLED=1"),
                score = 4
            )
        }

        return findings
    }
}