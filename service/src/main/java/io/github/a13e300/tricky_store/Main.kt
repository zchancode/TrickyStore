package io.github.a13e300.tricky_store

import android.os.Build
import keybox.KeystoreInterceptor
import keybox.Logger
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    val interceptor = KeystoreInterceptor()
    var res = interceptor.inject()
    if (!res) {
        Logger.i("Failed to inject KeystoreInterceptor, exiting...")
        exitProcess(0)
    }
    res = interceptor.readKeyBox()
    if (!res) {
        Logger.i("Failed to read KeyBox, exiting...")
        exitProcess(0)
    }

    Logger.i("KeyBox read successfully, starting app...")



    while (true) {
        Thread.sleep(1000000)
    }
}
