package com.selinuxassistant.guardx.engine

object LocalIoCs {

    val trustedInstallers = setOf(
        "com.android.vending",
        "com.google.android.packageinstaller",
        "com.samsung.android.packageinstaller",
        "com.miui.packageinstaller",
        "com.android.packageinstaller"
    )

    val knownRootPackages = setOf(
        "com.topjohnwu.magisk",
        "eu.chainfire.supersu",
        "com.kingroot.kinguser",
        "me.weishu.kernelsu",
        "me.bmax.apatch"
    )

    val knownHookPackages = setOf(
        "org.lsposed.manager",
        "de.robv.android.xposed.installer",
        "org.meowcat.edxposed.manager",
        "com.saurik.substrate"
    )

    val knownBadPackages = setOf<String>(
        // doğrulanmış zararlı paket adlarını burada tut
    )

    val knownBadApkHashes = setOf<String>(
        // SHA-256
    )

    val knownBadFileHashes = setOf<String>(
        // SHA-256
    )

    val knownBadSignerDigests = setOf<String>(
        // SHA-256 signer cert digest
    )

    val highRiskPermissions = setOf(
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.CALL_PHONE",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_AUDIO"
    )

    val suspiciousApkEntryKeywords = listOf(
        "xposed",
        "lsposed",
        "edxposed",
        "magisk",
        "zygisk",
        "riru",
        "frida",
        "substrate"
    )

    val suspiciousBinaryStrings = listOf(
        "zygisk",
        "magisk",
        "magiskinit",
        "riru",
        "xposed",
        "lsposed",
        "edxposed",
        "frida",
        "frida-server",
        "setenforce 0",
        "mount -o rw,remount /system"
    )
}