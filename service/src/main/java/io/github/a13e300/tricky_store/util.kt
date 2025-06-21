package io.github.a13e300.tricky_store

import android.content.pm.IPackageManager
import android.content.pm.PackageManager
import android.os.Build
import android.os.ServiceManager
import android.os.SystemProperties
import android.telephony.TelephonyManager
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject
import java.security.MessageDigest
import java.util.concurrent.ThreadLocalRandom


fun getTransactCode(clazz: Class<*>, method: String) =
    clazz.getDeclaredField("TRANSACTION_$method").apply { isAccessible = true }
        .getInt(null) // 2

val bootHash by lazy {
    getBootHashFromProp() ?: randomBytes()
}

// TODO: get verified boot keys
val bootKey by lazy {
    randomBytes()
}

@OptIn(ExperimentalStdlibApi::class)
fun getBootHashFromProp(): ByteArray? {
    val b = SystemProperties.get("ro.boot.vbmeta.digest", null) ?: return null
    if (b.length != 64) return null
    return b.hexToByteArray()
}

fun randomBytes() = ByteArray(32).also { ThreadLocalRandom.current().nextBytes(it) }

val patchLevel
    get() = runCatching {
        Config.devConfig.securityPatch.convertPatchLevel(false)
    }.getOrDefault(Build.VERSION.SECURITY_PATCH.convertPatchLevel(false))

val patchLevelLong
    get() = runCatching {
        Config.devConfig.securityPatch.convertPatchLevel(true)
    }.getOrDefault(Build.VERSION.SECURITY_PATCH.convertPatchLevel(false))

val osVersion
    get() = Config.devConfig.osVersion.run {
        if (this > 0) return@run getOsVersion(this)
        else return@run getOsVersion(Build.VERSION.SDK_INT)
    }

private fun getOsVersion(num: Int) = when (num) {
    Build.VERSION_CODES.VANILLA_ICE_CREAM -> 150000
    Build.VERSION_CODES.UPSIDE_DOWN_CAKE -> 140000
    Build.VERSION_CODES.TIRAMISU -> 130000
    Build.VERSION_CODES.S_V2 -> 120100
    Build.VERSION_CODES.S -> 120000
    // i don't know whether rest of these are correct actually, so PR if anything is wrong.
    Build.VERSION_CODES.Q -> 110000
    else -> 150000
}

fun String.convertPatchLevel(long: Boolean) = kotlin.runCatching {
    val l = split("-")
    if (long) l[0].toInt() * 10000 + l[1].toInt() * 100 + l[2].toInt()
    else l[0].toInt() * 100 + l[1].toInt()
}.onFailure { Logger.e("invalid patch level $this !", it) }.getOrDefault(202404)

fun IPackageManager.getPackageInfoCompat(name: String, flags: Long, userId: Int) =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        getPackageInfo(name, flags, userId)
    } else {
        getPackageInfo(name, flags.toInt(), userId)
    }

val apexInfos by lazy {
    mutableListOf<Pair<String, Long>>().also { list ->
        IPackageManager.Stub.asInterface(ServiceManager.getService("package")).run {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                getInstalledPackages(PackageManager.MATCH_APEX.toLong(), 0)
            } else {
                getInstalledPackages(PackageManager.MATCH_APEX, 0)
            }.list.forEach {
                list.add(Pair(it.packageName, it.longVersionCode))
            }
        }
    }.toList()
}

val moduleHash by lazy {
    mutableListOf<ASN1Encodable>().apply {
        apexInfos.forEach {
            add(DEROctetString(it.first.toByteArray()))
            add(ASN1Integer(it.second))
        }
    }.toTypedArray().run {
        DERSequence(this)
    }.encoded.run {
        MessageDigest.getInstance("SHA-256").also { it.update(this) }.digest()
    }
}

@Suppress("MissingPermission")
val telephonyInfos by lazy {
    mutableListOf<ASN1Encodable>().apply {
        add(DERTaggedObject(true, 714, (DEROctetString(SystemProperties.get("ro.ril.oem.imei", null)?.toByteArray()))))
        add(DERTaggedObject(true, 715, DEROctetString(SystemProperties.get("ro.ril.oem.meid", null)?.toByteArray())))
        add(DERTaggedObject(true, 723, DEROctetString(SystemProperties.get("ro.ril.oem.imei2", null)?.toByteArray())))
        add(DERTaggedObject(true, 713, DEROctetString(SystemProperties.get("ro.serialno", null)?.toByteArray())))
    }.toList()
}

fun String.trimLine() = trim().split("\n").joinToString("\n") { it.trim() }
