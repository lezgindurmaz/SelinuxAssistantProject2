package com.selinuxassistant.guardx

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.lifecycleScope
import com.selinuxassistant.guardx.engine.*
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    SelinuxAssistantApp()
                }
            }
        }
    }

    @Composable
    fun SelinuxAssistantApp() {
        var scanReport by remember { mutableStateOf<ScanReport?>(null) }
        var isScanning by remember { mutableStateOf(false) }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = "Selinux Assistant",
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(bottom = 16.dp)
            )

            if (isScanning) {
                CircularProgressIndicator(modifier = Modifier.padding(16.dp))
                Text(text = "Sistem taranıyor...")
            } else {
                Button(
                    onClick = {
                        isScanning = true
                        lifecycleScope.launch {
                            scanReport = SaEngine(this@MainActivity).fullScan()
                            isScanning = false
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(text = if (scanReport == null) "Taramayı Başlat" else "Yeniden Tara")
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            scanReport?.let { report ->
                ScanResultSummary(report)
                Spacer(modifier = Modifier.height(16.dp))
                FindingsList(report.findings)
            }
        }
    }

    @Composable
    fun ScanResultSummary(report: ScanReport) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = when (report.verdict) {
                    Verdict.CLEAN -> Color(0xFFE8F5E9)
                    Verdict.LOW_RISK -> Color(0xFFFFF3E0)
                    else -> Color(0xFFFFEBEE)
                }
            )
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = if (report.verdict == Verdict.CLEAN) Icons.Default.CheckCircle else Icons.Default.Warning,
                        contentDescription = null,
                        tint = if (report.verdict == Verdict.CLEAN) Color(0xFF2E7D32) else Color(0xFFC62828)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Durum: ${report.verdict}",
                        fontWeight = FontWeight.Bold,
                        fontSize = 18.sp
                    )
                }
                Spacer(modifier = Modifier.height(8.dp))
                Text(text = "Genel Skor: ${report.overallScore}/100")
                Text(text = "Bütünlük Skoru: ${report.integrityScore}")
                Text(text = "Zararlı Yazılım Skoru: ${report.malwareScore}")
                Text(text = "Taranan Uygulama: ${report.scannedPackages}")
                Text(text = "Taranan Dosya: ${report.scannedFiles}")
            }
        }
    }

    @Composable
    fun FindingsList(findings: List<Finding>) {
        Text(
            text = "Bulgular (${findings.size})",
            fontWeight = FontWeight.Bold,
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 8.dp)
        )
        LazyColumn {
            items(findings) { finding ->
                FindingItem(finding)
            }
        }
    }

    @Composable
    fun FindingItem(finding: Finding) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 4.dp),
            elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = finding.title,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.weight(1f)
                    )
                    Text(
                        text = finding.severity.name,
                        color = when (finding.severity) {
                            Severity.CRITICAL -> Color.Red
                            Severity.HIGH -> Color(0xFFE65100)
                            Severity.MEDIUM -> Color(0xFFF57C00)
                            else -> Color.Gray
                        },
                        fontWeight = FontWeight.Bold
                    )
                }
                Text(text = finding.description, fontSize = 14.sp)
                if (finding.evidence.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Kanıt: ${finding.evidence.joinToString(", ")}",
                        fontSize = 12.sp,
                        color = Color.DarkGray
                    )
                }
            }
        }
    }
}
