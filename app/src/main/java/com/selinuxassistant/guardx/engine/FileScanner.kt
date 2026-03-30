package com.selinuxassistant.guardx.engine

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.ArrayDeque

class FileScanner(private val context: Context) {

    suspend fun scan(roots: List<File>): ScanChunk = withContext(Dispatchers.IO) {
        val findings = mutableListOf<Finding>()
        val queue = ArrayDeque<Pair<File, Int>>()

        roots.filter { it.exists() && it.canRead() }
            .distinctBy { it.absolutePath }
            .forEach { queue.add(it to 0) }

        var scanned = 0
        val maxFiles = 5000
        val maxDepth = 5

        while (queue.isNotEmpty() && scanned < maxFiles) {
            val (file, depth) = queue.removeFirst()
            scanned++

            if (file.isDirectory) {
                if (depth >= maxDepth) continue
                file.listFiles()?.take(100)?.forEach { child ->
                    queue.add(child to depth + 1)
                }
                continue
            }

            analyzeFile(file)?.let { findings += it }
        }

        ScanChunk(findings, scanned)
    }

    private fun analyzeFile(file: File): Finding? {
        if (!file.exists() || !file.canRead()) return null
        if (file.length() > 32L * 1024L * 1024L) return null

        val name = file.name.lowercase()
        val evidence = mutableListOf<String>()
        var score = 0
        var domain = Domain.MALWARE

        sha256(file)?.let { hash ->
            if (hash in LocalIoCs.knownBadFileHashes) {
                score += 90
                evidence += "Bad file hash IoC=$hash"
                domain = Domain.MALWARE
            }
        }

        if (name.contains("magisk") ||
            name.contains("zygisk") ||
            name.contains("riru") ||
            name.contains("xposed") ||
            name.contains("lsposed") ||
            name.contains("frida") ||
            name == "su" ||
            name == "busybox"
        ) {
            score += 18
            evidence += "Şüpheli dosya adı=$name"
            domain = Domain.INTEGRITY
        }

        val ext = file.extension.lowercase()
        if (ext in setOf("apk", "dex", "jar", "so", "sh")) {
            evidence += "Uzantı=$ext"
        }

        val bytes = readBytesLimited(file, 128 * 1024)
        if (bytes.isNotEmpty()) {
            val body = String(bytes, Charsets.ISO_8859_1).lowercase()
            val hits = LocalIoCs.suspiciousBinaryStrings.filter { body.contains(it.lowercase()) }
            if (hits.isNotEmpty()) {
                score += 15
                evidence += "İçerik eşleşmeleri=${hits.take(5).joinToString()}"
                if (hits.any {
                        it.contains("magisk", true) ||
                        it.contains("zygisk", true) ||
                        it.contains("xposed", true) ||
                        it.contains("frida", true)
                    }) {
                    domain = Domain.INTEGRITY
                }
            }
        }

        score = score.coerceAtMost(100)
        if (score < 20) return null

        return Finding(
            id = "FILE_${file.absolutePath.hashCode()}",
            category = Category.FILESYSTEM,
            severity = severityFor(score),
            domain = domain,
            title = "Şüpheli dosya: ${file.name}",
            description = "Dosya, isim/içerik/hash bazlı heuristics ile riskli görünüyor. Otomatik silmeden önce doğrulama yapın.",
            evidence = listOf(file.absolutePath) + evidence.take(6),
            score = score
        )
    }
}