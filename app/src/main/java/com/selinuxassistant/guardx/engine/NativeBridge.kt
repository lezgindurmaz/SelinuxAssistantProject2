package com.selinuxassistant.guardx.engine

object NativeBridge {
    init {
        System.loadLibrary("sa_engine")
    }

    external fun runNativeChecks(): String
}