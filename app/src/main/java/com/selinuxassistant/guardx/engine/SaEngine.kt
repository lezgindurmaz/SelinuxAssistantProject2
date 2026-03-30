package com.selinuxassistant.guardx.engine

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import java.io.File

class SaEngine(private val context: Context) {

    suspend fun fullScan(scanRoots: List<File> = defaultScanRoots()): ScanReport = coroutineScope {
        val nativeJob = async(Dispatchers.IO) { NativeDetector.scan() }
        val rootJob = async(Dispatchers.Default) { RootDetector(context).scan() }
        val debugJob = async(Dispatchers.Default) { DebugDetector(context).scan() }
        val selinuxJob = async(Dispatchers.IO) { SelinuxAnalyzer().scan() }
        val hookJob = async(Dispatchers.Default) { HookDetector(context).scan() }
        val appJob = async(Dispatchers.IO) { AppScanner(context).scan() }
        val fileJob = async(Dispatchers.IO) { FileScanner(context).scan(scanRoots) }

        val findings = mutableListOf<Finding>()
        findings += nativeJob.await()
        findings += rootJob.await()
        findings += debugJob.await()
        findings += selinuxJob.await()
        findings += hookJob.await()

        val appChunk = appJob.await()
        findings += appChunk.findings

        val fileChunk = fileJob.await()
        findings += fileChunk.findings

        val integrityScore = findings
            .filter { it.domain == Domain.INTEGRITY }
            .sumOf { it.score }
            .coerceAtMost(100)

        val malwareScore = findings
            .filter { it.domain == Domain.MALWARE }
            .sumOf { it.score }
            .coerceAtMost(100)

        val overallScore = maxOf(
            integrityScore,
            malwareScore,
            ((integrityScore * 0.6) + (malwareScore * 0.9)).toInt().coerceAtMost(100)
        )

        ScanReport(
            integrityScore = integrityScore,
            malwareScore = malwareScore,
            overallScore = overallScore,
            verdict = toVerdict(overallScore),
            findings = findings.sortedByDescending { it.score },
            scannedPackages = appChunk.scannedCount,
            scannedFiles = fileChunk.scannedCount
        )
    }

    private fun defaultScanRoots(): List<File> {
        val roots = mutableListOf<File>()

        listOf(
            File("/sdcard/Download"),
            File("/sdcard/Documents"),
            context.filesDir,
            context.cacheDir
        ).forEach {
            if (it.exists() && it.canRead()) roots += it
        }

        context.getExternalFilesDirs(null)
            .filterNotNull()
            .filter { it.exists() && it.canRead() }
            .forEach { roots += it }

        return roots.distinctBy { it.absolutePath }
    }

    private fun toVerdict(score: Int): Verdict = when {
        score >= 80 -> Verdict.COMPROMISED
        score >= 60 -> Verdict.HIGH_RISK
        score >= 35 -> Verdict.ELEVATED
        score >= 15 -> Verdict.LOW_RISK
        else -> Verdict.CLEAN
    }
}