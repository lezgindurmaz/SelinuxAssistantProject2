package com.selinuxassistant.guardx.engine

import java.io.File

class SelinuxAnalyzer {

    fun scan(): List<Finding> {
        val findings = mutableListOf<Finding>()

        val enforce = readFirstLine("/sys/fs/selinux/enforce")?.trim()
        when (enforce) {
            "0" -> findings += Finding(
                id = "SELINUX_PERMISSIVE_KT",
                category = Category.SELINUX,
                severity = Severity.CRITICAL,
                domain = Domain.INTEGRITY,
                title = "SELinux permissive",
                description = "SELinux enforcing kapalı.",
                evidence = listOf("enforce=0"),
                score = 35
            )
            null -> findings += Finding(
                id = "SELINUX_STATE_UNKNOWN",
                category = Category.SELINUX,
                severity = Severity.MEDIUM,
                domain = Domain.INTEGRITY,
                title = "SELinux durumu okunamadı",
                description = "SELinux enforce dosyası okunamadı.",
                evidence = listOf("/sys/fs/selinux/enforce"),
                score = 12
            )
        }

        if (!File("/sys/fs/selinux/policy").exists()) {
            findings += Finding(
                id = "SELINUX_POLICY_MISSING",
                category = Category.SELINUX,
                severity = Severity.MEDIUM,
                domain = Domain.INTEGRITY,
                title = "SELinux policy dosyası bulunamadı",
                description = "Beklenen SELinux policy dosyası yok veya erişilemiyor.",
                evidence = listOf("/sys/fs/selinux/policy"),
                score = 10
            )
        }

        val current = readFirstLine("/proc/self/attr/current")
        if (current.isNullOrBlank()) {
            findings += Finding(
                id = "SELINUX_CONTEXT_UNKNOWN",
                category = Category.SELINUX,
                severity = Severity.LOW,
                domain = Domain.INTEGRITY,
                title = "SELinux context okunamadı",
                description = "Self-process context değeri okunamadı.",
                evidence = listOf("/proc/self/attr/current"),
                score = 6
            )
        }

        return findings
    }
}