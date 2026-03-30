package com.selinuxassistant.guardx.engine

enum class Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL }
enum class Category { ROOT, DEBUG, SELINUX, HOOK, APP, FILESYSTEM, SYSTEM }
enum class Domain { INTEGRITY, MALWARE }
enum class Verdict { CLEAN, LOW_RISK, ELEVATED, HIGH_RISK, COMPROMISED }

data class Finding(
    val id: String,
    val category: Category,
    val severity: Severity,
    val domain: Domain,
    val title: String,
    val description: String,
    val evidence: List<String> = emptyList(),
    val score: Int = 0
)

data class ScanReport(
    val integrityScore: Int,
    val malwareScore: Int,
    val overallScore: Int,
    val verdict: Verdict,
    val findings: List<Finding>,
    val scannedPackages: Int,
    val scannedFiles: Int,
    val generatedAt: Long = System.currentTimeMillis()
)