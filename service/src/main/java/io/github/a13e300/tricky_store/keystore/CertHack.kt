package io.github.a13e300.tricky_store.keystore

import android.content.pm.PackageManager
import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.Tag
import android.security.keystore.KeyProperties
import android.system.keystore2.KeyDescriptor
import android.util.Pair
import io.github.a13e300.tricky_store.Config.getPm
import io.github.a13e300.tricky_store.Logger
import io.github.a13e300.tricky_store.SecurityLevelInterceptor.Companion.getKeyPairs
import io.github.a13e300.tricky_store.bootHash
import io.github.a13e300.tricky_store.bootKey
import io.github.a13e300.tricky_store.getPackageInfoCompat
import io.github.a13e300.tricky_store.moduleHash
import io.github.a13e300.tricky_store.osVersion
import io.github.a13e300.tricky_store.patchLevel
import io.github.a13e300.tricky_store.patchLevelLong
import io.github.a13e300.tricky_store.strongBox
import io.github.a13e300.tricky_store.telephonyInfos
import io.github.a13e300.tricky_store.trimLine
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.util.io.pem.PemReader
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.StringReader
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Security
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.util.Date
import java.util.LinkedList
import java.util.Locale
import javax.security.auth.x500.X500Principal

object CertHack {
    private val OID = ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")

    private const val ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX = 0
    private const val ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX = 1
    private val keyboxes: MutableMap<String?, KeyBox?> = HashMap<String?, KeyBox?>()
    private val leafAlgorithm: MutableMap<Key?, String?> = HashMap<Key?, String?>()
    private const val ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX = 0

    private val certificateFactory: CertificateFactory

    init {
        try {
            certificateFactory = CertificateFactory.getInstance("X.509")
        } catch (t: Throwable) {
            Logger.e("", t)
            throw RuntimeException(t)
        }
    }

    private const val ATTESTATION_PACKAGE_INFO_VERSION_INDEX = 1

    fun canHack(): Boolean {
        return !keyboxes.isEmpty()
    }

    @Throws(Throwable::class)
    private fun parseKeyPair(key: String): PEMKeyPair? {
        PEMParser(StringReader(key.trimLine())).use { parser ->
            return parser.readObject() as PEMKeyPair?
        }
    }

    @Throws(Throwable::class)
    private fun parseCert(cert: String): Certificate? {
        PemReader(StringReader(cert.trimLine())).use { reader ->
            return certificateFactory.generateCertificate(ByteArrayInputStream(reader.readPemObject().content))
        }
    }

    @Throws(CertificateParsingException::class)
    private fun getByteArrayFromAsn1(asn1Encodable: ASN1Encodable?): ByteArray? {
        if (asn1Encodable !is DEROctetString) {
            throw CertificateParsingException("Expected DEROctetString")
        }
        return asn1Encodable.octets
    }

    fun readFromXml(data: String?) {
        keyboxes.clear()
        if (data == null) {
            Logger.i("clear all keyboxes")
            return
        }
        val xmlParser = XMLParser(data)

        try {
            val numberOfKeyboxes = xmlParser.obtainPath(
                "AndroidAttestation.NumberOfKeyboxes"
            )["text"]!!.toInt()
            for (i in 0..<numberOfKeyboxes) {
                val keyboxAlgorithm = xmlParser.obtainPath(
                    "AndroidAttestation.Keybox.Key[$i]"
                )["algorithm"]
                val privateKey = xmlParser.obtainPath(
                    "AndroidAttestation.Keybox.Key[$i].PrivateKey"
                )["text"]
                val numberOfCertificates = xmlParser.obtainPath(
                    "AndroidAttestation.Keybox.Key[$i].CertificateChain.NumberOfCertificates"
                )["text"]!!.toInt()

                val certificateChain = LinkedList<Certificate>()

                for (j in 0..<numberOfCertificates) {
                    val certData = xmlParser.obtainPath(
                        "AndroidAttestation.Keybox.Key[$i].CertificateChain.Certificate[$j]"
                    )
                    certificateChain.add(parseCert(certData["text"]!!)!!)
                }
                val algo = if (keyboxAlgorithm!!.lowercase(Locale.getDefault()) == "ecdsa") {
                    KeyProperties.KEY_ALGORITHM_EC
                } else {
                    KeyProperties.KEY_ALGORITHM_RSA
                }
                val pemKp = parseKeyPair(privateKey!!)
                val kp = JcaPEMKeyConverter().getKeyPair(pemKp)
                keyboxes.put(algo, KeyBox(pemKp, kp, certificateChain))
            }
            Logger.i("update $numberOfKeyboxes keyboxes")
        } catch (t: Throwable) {
            Logger.e("Error loading xml file (keyboxes cleared): $t")
        }
    }

    fun hackCertificateChain(caList: Array<Certificate?>): Array<Certificate?> {
        try {
            val leaf = certificateFactory.generateCertificate(ByteArrayInputStream(caList[0]!!.encoded)) as X509Certificate
            val bytes = leaf.getExtensionValue(OID.getId())
            if (bytes == null) return caList

            val leafHolder = X509CertificateHolder(leaf.encoded)
            val ext = leafHolder.getExtension(OID)
            val sequence = ASN1Sequence.getInstance(ext.extnValue.octets)
            val encodables = sequence.toArray()
            val teeEnforced = encodables[7] as ASN1Sequence
            val vector = ASN1EncodableVector()
            var rootOfTrust: ASN1Encodable? = null

            for (asn1Encodable in teeEnforced) {
                val taggedObject = asn1Encodable as ASN1TaggedObject
                if (taggedObject.getTagNo() == 704) {
                    rootOfTrust = taggedObject.baseObject.toASN1Primitive()
                    continue
                }
                vector.add(taggedObject)
            }

            val k = keyboxes[leaf.publicKey.algorithm]
            if (k == null) throw UnsupportedOperationException("unsupported algorithm " + leaf.publicKey.algorithm)
            val certificates = LinkedList<Certificate?>(k.certificates)
            val builder = X509v3CertificateBuilder(
                X509CertificateHolder(
                    certificates[0]!!.encoded
                ).subject,
                leafHolder.serialNumber,
                leafHolder.notBefore,
                leafHolder.notAfter,
                leafHolder.subject,
                leafHolder.subjectPublicKeyInfo
            )
            val signer = JcaContentSignerBuilder(leaf.sigAlgName)
                .build(k.keyPair.private)

            val verifiedBootKey = bootKey
            var verifiedBootHash: ByteArray? = null
            try {
                if (rootOfTrust !is ASN1Sequence) {
                    throw CertificateParsingException(
                        "Expected sequence for root of trust, found "
                                + rootOfTrust!!.javaClass.getName()
                    )
                }
                verifiedBootHash = getByteArrayFromAsn1(rootOfTrust.getObjectAt(3))
            } catch (t: Throwable) {
                Logger.e("failed to get verified boot key or hash from original, use randomly generated instead", t)
            }

            if (verifiedBootHash == null) {
                verifiedBootHash = bootHash
            }

            val rootOfTrustEnc = arrayOf<ASN1Encodable?>(
                DEROctetString(verifiedBootKey),
                ASN1Boolean.TRUE,
                ASN1Enumerated(0),
                DEROctetString(verifiedBootHash)
            )

            val hackedRootOfTrust: ASN1Sequence = DERSequence(rootOfTrustEnc)
            val rootOfTrustTagObj: ASN1TaggedObject = DERTaggedObject(704, hackedRootOfTrust)
            vector.add(rootOfTrustTagObj)

            val hackEnforced: ASN1Sequence = DERSequence(vector)
            encodables[7] = hackEnforced
            val hackedSeq: ASN1Sequence = DERSequence(encodables)

            val hackedSeqOctets: ASN1OctetString = DEROctetString(hackedSeq)
            val hackedExt = Extension(OID, false, hackedSeqOctets)
            builder.addExtension(hackedExt)

            for (extensionOID in leafHolder.extensions.extensionOIDs) {
                if (OID.getId() == extensionOID.getId()) continue
                builder.addExtension(leafHolder.getExtension(extensionOID))
            }
            certificates.addFirst(JcaX509CertificateConverter().getCertificate(builder.build(signer)))

            return certificates.toTypedArray<Certificate?>()
        } catch (t: Throwable) {
            Logger.e("", t)
        }
        return caList
    }

    fun hackCertificateChainCA(caList: ByteArray, alias: String?, uid: Int): ByteArray? {
        try {
            val key = Key(alias, uid)
            val algorithm = leafAlgorithm[key]
            leafAlgorithm.remove(key)
            val k = keyboxes[algorithm]
            if (k == null) throw UnsupportedOperationException("unsupported algorithm $algorithm")
            return Utils.toBytes(k.certificates)
        } catch (t: Throwable) {
            Logger.e("", t)
        }
        return caList
    }

    fun hackCertificateChainUSR(certificate: ByteArray, alias: String?, uid: Int): ByteArray? {
        try {
            val leaf = certificateFactory.generateCertificate(ByteArrayInputStream(certificate)) as X509Certificate
            val bytes = leaf.getExtensionValue(OID.getId())
            if (bytes == null) return certificate

            val leafHolder = X509CertificateHolder(leaf.encoded)
            val ext = leafHolder.getExtension(OID)
            val sequence = ASN1Sequence.getInstance(ext.extnValue.octets)
            val encodables = sequence.toArray()
            val teeEnforced = encodables[7] as ASN1Sequence
            val vector = ASN1EncodableVector()
            var rootOfTrust: ASN1Encodable? = null

            for (asn1Encodable in teeEnforced) {
                val taggedObject = asn1Encodable as ASN1TaggedObject
                if (taggedObject.getTagNo() == 704) {
                    rootOfTrust = taggedObject.baseObject.toASN1Primitive()
                    continue
                }
                vector.add(taggedObject)
            }

            val certificates: LinkedList<Certificate?>?
            val signer: ContentSigner?

            leafAlgorithm.put(Key(alias, uid), leaf.publicKey.algorithm)
            val k = keyboxes[leaf.publicKey.algorithm]
            if (k == null) throw UnsupportedOperationException("unsupported algorithm " + leaf.publicKey.algorithm)
            certificates = LinkedList<Certificate?>(k.certificates)
            val builder = X509v3CertificateBuilder(
                X509CertificateHolder(
                    certificates[0]!!.encoded
                ).subject,
                leafHolder.serialNumber,
                leafHolder.notBefore,
                leafHolder.notAfter,
                leafHolder.subject,
                leafHolder.subjectPublicKeyInfo
            )
            signer = JcaContentSignerBuilder(leaf.sigAlgName)
                .build(k.keyPair.private)

            val verifiedBootKey = bootKey
            var verifiedBootHash: ByteArray? = null
            try {
                if (rootOfTrust !is ASN1Sequence) {
                    throw CertificateParsingException(
                        "Expected sequence for root of trust, found "
                                + rootOfTrust!!.javaClass.getName()
                    )
                }
                verifiedBootHash = getByteArrayFromAsn1(rootOfTrust.getObjectAt(3))
            } catch (t: Throwable) {
                Logger.e("failed to get verified boot key or hash from original, use randomly generated instead", t)
            }

            if (verifiedBootHash == null) {
                verifiedBootHash = bootHash
            }

            val rootOfTrustEnc = arrayOf<ASN1Encodable?>(
                DEROctetString(verifiedBootKey),
                ASN1Boolean.TRUE,
                ASN1Enumerated(0),
                DEROctetString(verifiedBootHash)
            )

            val hackedRootOfTrust: ASN1Sequence = DERSequence(rootOfTrustEnc)
            val rootOfTrustTagObj: ASN1TaggedObject = DERTaggedObject(704, hackedRootOfTrust)
            vector.add(rootOfTrustTagObj)

            val hackEnforced: ASN1Sequence = DERSequence(vector)
            encodables[7] = hackEnforced
            val hackedSeq: ASN1Sequence = DERSequence(encodables)

            val hackedSeqOctets: ASN1OctetString = DEROctetString(hackedSeq)
            val hackedExt = Extension(OID, false, hackedSeqOctets)
            builder.addExtension(hackedExt)

            for (extensionOID in leafHolder.extensions.extensionOIDs) {
                if (OID.getId() == extensionOID.getId()) continue
                builder.addExtension(leafHolder.getExtension(extensionOID))
            }
            return JcaX509CertificateConverter().getCertificate(builder.build(signer)).encoded
        } catch (t: Throwable) {
            Logger.e("", t)
        }
        return certificate
    }

    fun generateKeyPair(params: KeyGenParameters): KeyPair? {
        val kp: KeyPair?
        try {
            val algo = params.algorithm
            if (algo == Algorithm.EC) {
                Logger.d("GENERATING EC KEYPAIR OF SIZE " + params.keySize)
                kp = buildECKeyPair(params)
            } else if (algo == Algorithm.RSA) {
                Logger.d("GENERATING RSA KEYPAIR OF SIZE " + params.keySize)
                kp = buildRSAKeyPair(params)
            } else {
                Logger.e("UNSUPPORTED ALGORITHM: $algo")
                return null
            }
            return kp
        } catch (t: Throwable) {
            Logger.e("", t)
        }
        return null
    }

    fun generateChain(uid: Int, params: KeyGenParameters, kp: KeyPair): MutableList<ByteArray?>? {
        val rootKP: KeyPair
        val issuer: X500Name?
        var keyBox: KeyBox? = null
        try {
            val algo = params.algorithm
            if (algo == Algorithm.EC) {
                keyBox = keyboxes[KeyProperties.KEY_ALGORITHM_EC]
            } else if (algo == Algorithm.RSA) {
                keyBox = keyboxes[KeyProperties.KEY_ALGORITHM_RSA]
            }
            if (keyBox == null) {
                Logger.e("UNSUPPORTED ALGORITHM: $algo")
                return null
            }
            rootKP = keyBox.keyPair
            issuer = X509CertificateHolder(
                keyBox.certificates[0].encoded
            ).subject

            val certBuilder: X509v3CertificateBuilder = JcaX509v3CertificateBuilder(
                issuer,
                BigInteger("1"),  //params.certificateSerial,
                params.certificateNotBefore,
                (keyBox.certificates[0] as X509Certificate).notAfter,  //params.certificateNotAfter,
                X500Name("CN=Android KeyStore Key"),  //params.certificateSubject,
                kp.public
            )

            val keyUsage = KeyUsage(KeyUsage.keyCertSign)
            certBuilder.addExtension(Extension.keyUsage, true, keyUsage)
            certBuilder.addExtension(createExtension(params, uid))

            val contentSigner: ContentSigner?
            if (algo == Algorithm.EC) {
                contentSigner = JcaContentSignerBuilder("SHA256withECDSA").build(rootKP.private)
            } else {
                contentSigner = JcaContentSignerBuilder("SHA256withRSA").build(rootKP.private)
            }
            val certHolder = certBuilder.build(contentSigner)
            val leaf = JcaX509CertificateConverter().getCertificate(certHolder)
            val chain: MutableList<Certificate?> = ArrayList(keyBox.certificates)
            chain.add(0, leaf)
            //Logger.d("Successfully generated X500 Cert for alias: " + descriptor.alias);
            return Utils.toListBytes(chain)
        } catch (t: Throwable) {
            Logger.e("", t)
        }
        return null
    }

    fun generateKeyPair(uid: Int, descriptor: KeyDescriptor, attestKeyDescriptor: KeyDescriptor?, params: KeyGenParameters): Pair<KeyPair, MutableList<Certificate>>? {
        Logger.i("Requested KeyPair with alias: " + descriptor.alias)
        val attestPurpose = attestKeyDescriptor != null
        if (attestPurpose) Logger.i("Requested KeyPair with attestKey: " + attestKeyDescriptor.alias)
        var rootKP: KeyPair
        var issuer: X500Name?
        val size = params.keySize
        var kp: KeyPair? = null
        var keyBox: KeyBox? = null
        try {
            val algo = params.algorithm
            if (algo == Algorithm.EC) {
                Logger.d("GENERATING EC KEYPAIR OF SIZE $size")
                kp = buildECKeyPair(params)
                keyBox = keyboxes[KeyProperties.KEY_ALGORITHM_EC]
            } else if (algo == Algorithm.RSA) {
                Logger.d("GENERATING RSA KEYPAIR OF SIZE $size")
                kp = buildRSAKeyPair(params)
                keyBox = keyboxes[KeyProperties.KEY_ALGORITHM_RSA]
            }
            if (keyBox == null) {
                Logger.e("UNSUPPORTED ALGORITHM: $algo")
                return null
            }
            rootKP = keyBox.keyPair
            issuer = X509CertificateHolder(
                keyBox.certificates[0].encoded
            ).subject

            if (attestPurpose) {
                val info = getKeyPairs(uid, attestKeyDescriptor.alias)
                if (info != null) {
                    rootKP = info.first
                    issuer = X509CertificateHolder(
                        info.second[0].encoded
                    ).subject
                }
            }

            Logger.d("certificateSubject: " + params.certificateSubject)
            val certBuilder: X509v3CertificateBuilder = JcaX509v3CertificateBuilder(
                issuer,
                params.certificateSerial,
                params.certificateNotBefore,
                params.certificateNotAfter,
                params.certificateSubject,
                kp!!.public
            )

            val keyUsage = KeyUsage(KeyUsage.keyCertSign)
            certBuilder.addExtension(Extension.keyUsage, true, keyUsage)
            certBuilder.addExtension(createExtension(params, uid))

            val contentSigner = if (algo == Algorithm.EC) {
                JcaContentSignerBuilder("SHA256withECDSA").build(rootKP.private)
            } else {
                JcaContentSignerBuilder("SHA256withRSA").build(rootKP.private)
            }
            val certHolder = certBuilder.build(contentSigner)
            val leaf = JcaX509CertificateConverter().getCertificate(certHolder)
            val chain = if (!attestPurpose) {
                keyBox.certificates
            } else {
                mutableListOf()
            }
            chain.add(0, leaf)
            Logger.d("Successfully generated X500 Cert for alias: " + descriptor.alias)
            return Pair(kp, chain)
        } catch (t: Throwable) {
            Logger.e("", t)
        }
        return null
    }

    @Throws(Exception::class)
    private fun buildECKeyPair(params: KeyGenParameters): KeyPair? {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.addProvider(BouncyCastleProvider())
        val spec = ECGenParameterSpec(params.ecCurveName)
        val kpg = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME)
        kpg.initialize(spec)
        return kpg.generateKeyPair()
    }

    @Throws(Exception::class)
    private fun buildRSAKeyPair(params: KeyGenParameters): KeyPair? {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.addProvider(BouncyCastleProvider())
        val spec = RSAKeyGenParameterSpec(
            params.keySize, params.rsaPublicExponent
        )
        val kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME)
        kpg.initialize(spec)
        return kpg.generateKeyPair()
    }

    private fun fromIntList(list: MutableList<Int>): Array<ASN1Encodable?> {
        val result = arrayOfNulls<ASN1Encodable>(list.size)
        for (i in list.indices) {
            result[i] = ASN1Integer(list[i].toLong())
        }
        return result
    }

    private fun createExtension(params: KeyGenParameters, uid: Int): Extension? = runCatching {
        val key = bootKey
        val hash = bootHash

        val rootOfTrustEncodables = arrayOf<ASN1Encodable?>(
            DEROctetString(key), ASN1Boolean.TRUE,
            ASN1Enumerated(0), DEROctetString(hash)
        )

        val rootOfTrustSeq: ASN1Sequence = DERSequence(rootOfTrustEncodables)

        Logger.dd("params.purpose: " + params.purpose)

        val Apurpose = DERSet(fromIntList(params.purpose))
        val Aalgorithm = ASN1Integer(params.algorithm.toLong())
        val AkeySize = ASN1Integer(params.keySize.toLong())
        val Adigest = DERSet(fromIntList(params.digest))
        val AecCurve = ASN1Integer(params.ecCurve.toLong())
        val AnoAuthRequired = DERNull.INSTANCE

        // To be loaded
        val AosVersion = ASN1Integer(osVersion.toLong())
        val AosPatchLevel = ASN1Integer(patchLevel.toLong())

        val AapplicationID = createApplicationId(uid)
        val AbootPatchlevel = ASN1Integer(patchLevelLong.toLong())
        val AvendorPatchLevel = ASN1Integer(patchLevelLong.toLong())

        val AcreationDateTime = ASN1Integer(System.currentTimeMillis())
        val Aorigin = ASN1Integer(0)

        val purpose = DERTaggedObject(true, 1, Apurpose)
        val algorithm = DERTaggedObject(true, 2, Aalgorithm)
        val keySize = DERTaggedObject(true, 3, AkeySize)
        val digest = DERTaggedObject(true, 5, Adigest)
        val ecCurve = DERTaggedObject(true, 10, AecCurve)
        val noAuthRequired = DERTaggedObject(true, 503, AnoAuthRequired)
        val creationDateTime = DERTaggedObject(true, 701, AcreationDateTime)
        val origin = DERTaggedObject(true, 702, Aorigin)
        val rootOfTrust = DERTaggedObject(true, 704, rootOfTrustSeq)
        val osVersion = DERTaggedObject(true, 705, AosVersion)
        val osPatchLevel = DERTaggedObject(true, 706, AosPatchLevel)
        val applicationID = DERTaggedObject(true, 709, AapplicationID)
        val vendorPatchLevel = DERTaggedObject(true, 718, AvendorPatchLevel)
        val bootPatchLevel = DERTaggedObject(true, 719, AbootPatchlevel)

        val rollbackResistance = DERTaggedObject(true, 303, ASN1Boolean.TRUE)

        val AmoduleHash = DEROctetString(moduleHash)
        val moduleHash = DERTaggedObject(true, 724, AmoduleHash)

        val teeEnforced = mutableListOf<ASN1Encodable>(
            purpose, algorithm, keySize, digest, ecCurve,
            noAuthRequired, origin, rootOfTrust, osVersion, osPatchLevel, vendorPatchLevel,
            bootPatchLevel, moduleHash, rollbackResistance
        )

        // Support device properties attestation
        if (params.brand != null) {
            val Abrand = DEROctetString(params.brand)
            val Adevice = DEROctetString(params.device)
            val Aproduct = DEROctetString(params.product)
            val Amanufacturer = DEROctetString(params.manufacturer)
            val Amodel = DEROctetString(params.model)

            val brand = DERTaggedObject(true, 710, Abrand)
            val device = DERTaggedObject(true, 711, Adevice)
            val product = DERTaggedObject(true, 712, Aproduct)
            val manufacturer = DERTaggedObject(true, 716, Amanufacturer)
            val model = DERTaggedObject(true, 717, Amodel)

            teeEnforced.addAll(listOf(brand, device, product, manufacturer, model))
            teeEnforced.addAll(telephonyInfos)
        }

        val softwareEnforced = arrayOf<ASN1Encodable?>(applicationID, creationDateTime)

        val keyDescriptionOctetStr = getAsn1OctetString(teeEnforced.toTypedArray(), softwareEnforced, params)

        return Extension(ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), false, keyDescriptionOctetStr)
    }.onFailure {
        Logger.e("", it)
    }.getOrNull()

    @Throws(IOException::class)
    private fun getAsn1OctetString(teeEnforcedEncodables: Array<ASN1Encodable?>, softwareEnforcedEncodables: Array<ASN1Encodable?>, params: KeyGenParameters): ASN1OctetString {
        val attestationVersion = ASN1Integer(4)
        val attestationSecurityLevel = ASN1Enumerated(if (strongBox) 2 else 1)
        val keymasterVersion = ASN1Integer(4)
        val keymasterSecurityLevel = ASN1Enumerated(if (strongBox) 2 else 1)
        val attestationChallenge: ASN1OctetString = DEROctetString(params.attestationChallenge)
        val uniqueId: ASN1OctetString = DEROctetString("".toByteArray())
        val softwareEnforced: ASN1Encodable = DERSequence(softwareEnforcedEncodables)
        val teeEnforced: ASN1Sequence = DERSequence(teeEnforcedEncodables)

        val keyDescriptionEncodables = arrayOf<ASN1Encodable?>(
            attestationVersion, attestationSecurityLevel, keymasterVersion,
            keymasterSecurityLevel, attestationChallenge, uniqueId, softwareEnforced, teeEnforced
        )

        val keyDescriptionHackSeq: ASN1Sequence = DERSequence(keyDescriptionEncodables)

        return DEROctetString(keyDescriptionHackSeq)
    }

    @Throws(Throwable::class)
    private fun createApplicationId(uid: Int): DEROctetString {
        val pm = getPm()
        checkNotNull(pm) { "createApplicationId: pm not found!" }
        val packages = pm.getPackagesForUid(uid)
        val size = packages.size
        val packageInfoAA = arrayOfNulls<ASN1Encodable>(size)
        val signatures: MutableSet<Digest> = HashSet<Digest>()
        val dg = MessageDigest.getInstance("SHA-256")
        for (i in 0..<size) {
            val name: String = packages[i]!!
            val info = pm.getPackageInfoCompat(name, PackageManager.GET_SIGNATURES.toLong(), uid / 100000)
            val arr = arrayOfNulls<ASN1Encodable>(2)
            arr[ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX] =
                DEROctetString(packages[i]!!.toByteArray(StandardCharsets.UTF_8))
            arr[ATTESTATION_PACKAGE_INFO_VERSION_INDEX] = ASN1Integer(info.longVersionCode)
            packageInfoAA[i] = DERSequence(arr)
            for (s in info.signatures!!) {
                signatures.add(Digest(dg.digest(s.toByteArray())))
            }
        }

        val signaturesAA = arrayOfNulls<ASN1Encodable>(signatures.size)
        var i = 0
        for (d in signatures) {
            signaturesAA[i] = DEROctetString(d.digest)
            i++
        }

        val applicationIdAA = arrayOfNulls<ASN1Encodable>(2)
        applicationIdAA[ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX] =
            DERSet(packageInfoAA)
        applicationIdAA[ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX] =
            DERSet(signaturesAA)

        return DEROctetString(DERSequence(applicationIdAA).getEncoded())
    }

    @JvmRecord
    data class Key(val alias: String?, val uid: Int)

    @JvmRecord
    internal data class Digest(val digest: ByteArray?) {
        override fun equals(o: Any?): Boolean {
            if (o is Digest) return digest.contentEquals(o.digest)
            return false
        }

        override fun hashCode(): Int {
            return digest.contentHashCode()
        }
    }

    @JvmRecord
    internal data class KeyBox(val pemKeyPair: PEMKeyPair?, val keyPair: KeyPair, val certificates: LinkedList<Certificate>)

    class KeyGenParameters {
        var keySize: Int = 0
        var algorithm: Int = 0
        var certificateSerial: BigInteger? = null
        var certificateNotBefore: Date? = null
        var certificateNotAfter: Date? = null
        var certificateSubject: X500Name? = null

        var rsaPublicExponent: BigInteger? = null
        var ecCurve: Int = 0
        var ecCurveName: String? = null

        var purpose: MutableList<Int> = ArrayList()
        var digest: MutableList<Int> = ArrayList()

        var attestationChallenge: ByteArray? = null
        var brand: ByteArray? = null
        var device: ByteArray? = null
        var product: ByteArray? = null
        var manufacturer: ByteArray? = null
        var model: ByteArray? = null
        var imei1: ByteArray? = null
        var imei2: ByteArray? = null
        var meid: ByteArray? = null

        constructor()
        constructor(params: Array<KeyParameter>) {
            for (kp in params) {
                Logger.d("kp: " + kp.tag)
                val p = kp.value
                when (kp.tag) {
                    Tag.KEY_SIZE -> keySize = p.integer
                    Tag.ALGORITHM -> algorithm = p.algorithm
                    Tag.CERTIFICATE_SERIAL -> certificateSerial = BigInteger(p.blob)
                    Tag.CERTIFICATE_NOT_BEFORE -> certificateNotBefore = Date(p.dateTime)
                    Tag.CERTIFICATE_NOT_AFTER -> certificateNotAfter = Date(p.dateTime)
                    Tag.CERTIFICATE_SUBJECT -> certificateSubject = X500Name(X500Principal(p.blob).name)
                    Tag.RSA_PUBLIC_EXPONENT -> rsaPublicExponent = BigInteger(p.blob)
                    Tag.EC_CURVE -> {
                        ecCurve = p.ecCurve
                        ecCurveName = getEcCurveName(ecCurve)
                    }

                    Tag.PURPOSE -> purpose.add(p.keyPurpose)
                    Tag.DIGEST -> digest.add(p.digest)
                    Tag.ATTESTATION_CHALLENGE -> attestationChallenge = p.blob
                    Tag.ATTESTATION_ID_BRAND -> brand = p.blob
                    Tag.ATTESTATION_ID_DEVICE -> device = p.blob
                    Tag.ATTESTATION_ID_PRODUCT -> product = p.blob
                    Tag.ATTESTATION_ID_MANUFACTURER -> manufacturer = p.blob
                    Tag.ATTESTATION_ID_MODEL -> model = p.blob
                    Tag.ATTESTATION_ID_IMEI -> imei1 = p.blob
                    Tag.ATTESTATION_ID_SECOND_IMEI -> imei2 = p.blob
                    Tag.ATTESTATION_ID_MEID -> meid = p.blob
                }
            }
        }

        fun setEcCurveName(curve: Int) {
            when (curve) {
                224 -> this.ecCurveName = "secp224r1"
                256 -> this.ecCurveName = "secp256r1"
                384 -> this.ecCurveName = "secp384r1"
                521 -> this.ecCurveName = "secp521r1"
            }
        }

        companion object {
            private fun getEcCurveName(curve: Int): String {
                val res: String
                when (curve) {
                    EcCurve.CURVE_25519 -> res = "CURVE_25519"
                    EcCurve.P_224 -> res = "secp224r1"
                    EcCurve.P_256 -> res = "secp256r1"
                    EcCurve.P_384 -> res = "secp384r1"
                    EcCurve.P_521 -> res = "secp521r1"
                    else -> throw IllegalArgumentException("unknown curve")
                }
                return res
            }
        }
    }
}