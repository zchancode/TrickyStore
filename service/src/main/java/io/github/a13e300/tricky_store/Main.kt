package io.github.a13e300.tricky_store

import android.os.Build

fun main(args: Array<String>) {
    try {
        Class.forName("org.bouncycastle.asn1.misc.MiscObjectIdentifiers")
        Class.forName("org.bouncycastle.operator.jcajce.JcaContentSignerBuilder")
    } catch (e: ClassNotFoundException) {
        Logger.i("Bouncy Castle classes not found, please ensure Bouncy Castle is included in the classpath.")
    }

    Logger.i("Welcome to TrickyStore!")
    while (true) {
        if (Build.VERSION.SDK_INT == Build.VERSION_CODES.Q || Build.VERSION.SDK_INT == Build.VERSION_CODES.R) {
            if (!KeystoreInterceptor().tryRunKeystoreInterceptor()) {
                Thread.sleep(1000)
                continue
            }
        }
        Config.initialize()
        while (true) {
            Thread.sleep(1000000)
        }
    }
}
