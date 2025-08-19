package keybox.decoder;

import android.content.pm.IPackageManager;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.ServiceManager;
import android.security.keystore.KeyProperties;


import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import keybox.Logger;
import keybox.TrickyStoreUtils;
import keybox.bean.Digest;
import keybox.bean.KeyBox;
import keybox.bean.KeyGenParameters;
import keybox.bean.keymint.Algorithm;

public class PreDecoder {

    private static final int ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX = 0;
    private static final int ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX = 1;
    private static final int ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX = 0;
    private static final int ATTESTATION_PACKAGE_INFO_VERSION_INDEX = 1;

    public static KeyPair generateKeyPair(KeyGenParameters params) {
        KeyPair kp;
        try {
            int algo = params.algorithm;
            if (algo == Algorithm.EC) {
                Logger.d("GENERATING EC KEYPAIR OF SIZE " + params.keySize);
                kp = buildECKeyPair(params);
            } else if (algo == Algorithm.RSA) {
                Logger.d("GENERATING RSA KEYPAIR OF SIZE " + params.keySize);
                kp = buildRSAKeyPair(params);
            } else {
                Logger.e("UNSUPPORTED ALGORITHM: " + algo);
                return null;
            }
            return kp;
        } catch (Throwable t) {
            Logger.e("", t);
        }
        return null;
    }

    public static List<byte[]> generateChain(Map<String, KeyBox> keyboxes, int uid, KeyGenParameters params, KeyPair kp) {
        KeyPair rootKP;
        X500Name issuer;
        KeyBox keyBox = null;
        try {
            int algo = params.algorithm;
            if (algo == Algorithm.EC) {
                keyBox = keyboxes.get(KeyProperties.KEY_ALGORITHM_EC);
            } else if (algo == Algorithm.RSA) {
                keyBox = keyboxes.get(KeyProperties.KEY_ALGORITHM_RSA);
            }
            if (keyBox == null) {
                Logger.e("UNSUPPORTED ALGORITHM: " + algo);
                return null;
            }
            rootKP = keyBox.keyPair;
            issuer = new X509CertificateHolder(
                    keyBox.certificates.get(0).getEncoded()
            ).getSubject();

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer,
                    new BigInteger("1"),//params.certificateSerial,
                    params.certificateNotBefore,
                    ((X509Certificate) keyBox.certificates.get(0)).getNotAfter(),//params.certificateNotAfter,
                    new X500Name("CN=Android KeyStore Key"),//params.certificateSubject,
                    kp.getPublic()
            );

            KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign);
            certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
            certBuilder.addExtension(createExtension(params, uid));

            ContentSigner contentSigner;
            if (algo == Algorithm.EC) {
                contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(rootKP.getPrivate());
            } else {
                contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(rootKP.getPrivate());
            }
            X509CertificateHolder certHolder = certBuilder.build(contentSigner);
            X509Certificate leaf = new JcaX509CertificateConverter().getCertificate(certHolder);
            List<Certificate> chain = new ArrayList<>(keyBox.certificates);
            chain.add(0, leaf);
            return TrickyStoreUtils.toListBytes(chain);
        } catch (Throwable t) {
            Logger.e("", t);
        }
        return null;
    }

    private static KeyPair buildECKeyPair(KeyGenParameters params) throws Exception {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(new BouncyCastleProvider());
        ECGenParameterSpec spec = new ECGenParameterSpec(params.ecCurveName);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    private static KeyPair buildRSAKeyPair(KeyGenParameters params) throws Exception {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(new BouncyCastleProvider());
        RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(
                params.keySize, params.rsaPublicExponent);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    private static ASN1Encodable[] fromIntList(List<Integer> list) {
        ASN1Encodable[] result = new ASN1Encodable[list.size()];
        for (int i = 0; i < list.size(); i++) {
            result[i] = new ASN1Integer(list.get(i));
        }
        return result;
    }

    private static Extension createExtension(KeyGenParameters params, int uid) {
        try {
            byte[] key = TrickyStoreUtils.getBootKey();
            byte[] hash = TrickyStoreUtils.getBootHash();

            ASN1Encodable[] rootOfTrustEncodables = {new DEROctetString(key), ASN1Boolean.TRUE,
                    new ASN1Enumerated(0), new DEROctetString(hash)};

            ASN1Sequence rootOfTrustSeq = new DERSequence(rootOfTrustEncodables);

            Logger.dd("params.purpose: " + params.purpose);

            DERSet Apurpose = new DERSet(fromIntList(params.purpose));
            ASN1Integer Aalgorithm = new ASN1Integer(params.algorithm);
            ASN1Integer AkeySize = new ASN1Integer(params.keySize);
            DERSet Adigest = new DERSet(fromIntList(params.digest));
            ASN1Integer AecCurve = new ASN1Integer(params.ecCurve);
            DERNull AnoAuthRequired = DERNull.INSTANCE;

            // To be loaded
            ASN1Integer AosVersion = new ASN1Integer(TrickyStoreUtils.getOsVersion());
            ASN1Integer AosPatchLevel = new ASN1Integer(TrickyStoreUtils.getPatchLevel());

            DEROctetString AapplicationID = createApplicationId(uid);
            ASN1Integer AbootPatchlevel = new ASN1Integer(TrickyStoreUtils.getPatchLevelLong());
            ASN1Integer AvendorPatchLevel = new ASN1Integer(TrickyStoreUtils.getPatchLevelLong());

            ASN1Integer AcreationDateTime = new ASN1Integer(System.currentTimeMillis());
            ASN1Integer Aorigin = new ASN1Integer(0);

            DERTaggedObject purpose = new DERTaggedObject(true, 1, Apurpose);
            DERTaggedObject algorithm = new DERTaggedObject(true, 2, Aalgorithm);
            DERTaggedObject keySize = new DERTaggedObject(true, 3, AkeySize);
            DERTaggedObject digest = new DERTaggedObject(true, 5, Adigest);
            DERTaggedObject ecCurve = new DERTaggedObject(true, 10, AecCurve);
            DERTaggedObject noAuthRequired = new DERTaggedObject(true, 503, AnoAuthRequired);
            DERTaggedObject creationDateTime = new DERTaggedObject(true, 701, AcreationDateTime);
            DERTaggedObject origin = new DERTaggedObject(true, 702, Aorigin);
            DERTaggedObject rootOfTrust = new DERTaggedObject(true, 704, rootOfTrustSeq);
            DERTaggedObject osVersion = new DERTaggedObject(true, 705, AosVersion);
            DERTaggedObject osPatchLevel = new DERTaggedObject(true, 706, AosPatchLevel);
            DERTaggedObject applicationID = new DERTaggedObject(true, 709, AapplicationID);
            DERTaggedObject vendorPatchLevel = new DERTaggedObject(true, 718, AvendorPatchLevel);
            DERTaggedObject bootPatchLevel = new DERTaggedObject(true, 719, AbootPatchlevel);

            DEROctetString AmoduleHash = new DEROctetString(TrickyStoreUtils.getModuleHash());
            DERTaggedObject moduleHash = new DERTaggedObject(true, 724, AmoduleHash);

            ArrayList<ASN1Encodable> arrayList = new ArrayList<>(Arrays.asList(purpose, algorithm, keySize, digest, ecCurve,
                    noAuthRequired, origin, rootOfTrust, osVersion, osPatchLevel, vendorPatchLevel,
                    bootPatchLevel, moduleHash));

            if (params.brand != null) {
                arrayList.addAll(TrickyStoreUtils.getTelephonyInfos());
            }

            arrayList.sort(new Comparator<ASN1Encodable>() {
                @Override
                public int compare(ASN1Encodable o1, ASN1Encodable o2) {
                    return Integer.compare(((ASN1TaggedObject) o1).getTagNo(), ((ASN1TaggedObject) o2).getTagNo());
                }
            });

            ASN1Encodable[] softwareEnforced = {applicationID, creationDateTime};

            ASN1OctetString keyDescriptionOctetStr = getAsn1OctetString(arrayList.toArray(new ASN1Encodable[]{}), softwareEnforced, params);

            return new Extension(new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), false, keyDescriptionOctetStr);
        } catch (Throwable t) {
            Logger.e("", t);
        }
        return null;
    }

    private static ASN1OctetString getAsn1OctetString(ASN1Encodable[] teeEnforcedEncodables, ASN1Encodable[] softwareEnforcedEncodables, KeyGenParameters params) throws IOException {
        ASN1Integer attestationVersion = new ASN1Integer(400);
        ASN1Enumerated attestationSecurityLevel = new ASN1Enumerated(1);
        ASN1Integer keymasterVersion = new ASN1Integer(400);
        ASN1Enumerated keymasterSecurityLevel = new ASN1Enumerated(1);
        ASN1OctetString attestationChallenge = new DEROctetString(params.attestationChallenge);
        ASN1OctetString uniqueId = new DEROctetString("".getBytes());
        ASN1Encodable softwareEnforced = new DERSequence(softwareEnforcedEncodables);
        ASN1Sequence teeEnforced = new DERSequence(teeEnforcedEncodables);

        ASN1Encodable[] keyDescriptionEncodables = {attestationVersion, attestationSecurityLevel, keymasterVersion,
                keymasterSecurityLevel, attestationChallenge, uniqueId, softwareEnforced, teeEnforced};

        ASN1Sequence keyDescriptionHackSeq = new DERSequence(keyDescriptionEncodables);

        return new DEROctetString(keyDescriptionHackSeq);
    }


    private static DEROctetString createApplicationId(int uid) throws Throwable {
        IPackageManager pm = IPackageManager.Stub.asInterface(ServiceManager.getService("package"));
        if (pm == null) {
            throw new IllegalStateException("createApplicationId: pm not found!");
        }
        String[] packages = pm.getPackagesForUid(uid);
        int size = packages.length;
        ASN1Encodable[] packageInfoAA = new ASN1Encodable[size];
        Set<Digest> signatures = new HashSet<>();
        MessageDigest dg = MessageDigest.getInstance("SHA-256");
        for (int i = 0; i < size; i++) {
            String name = packages[i];
            android.content.pm.PackageInfo info = TrickyStoreUtils.getPackageInfoCompat(pm, name, PackageManager.GET_SIGNATURES, uid / 100000);
            ASN1Encodable[] arr = new ASN1Encodable[2];
            arr[ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX] =
                    new DEROctetString(packages[i].getBytes(StandardCharsets.UTF_8));
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                arr[ATTESTATION_PACKAGE_INFO_VERSION_INDEX] = new ASN1Integer(info.getLongVersionCode());
            }
            packageInfoAA[i] = new DERSequence(arr);
            for (android.content.pm.Signature s : info.signatures) {
                signatures.add(new Digest(dg.digest(s.toByteArray())));
            }
        }

        ASN1Encodable[] signaturesAA = new ASN1Encodable[signatures.size()];
        int i = 0;
        for (Digest d : signatures) {
            signaturesAA[i] = new DEROctetString(d.digest);
            i++;
        }

        ASN1Encodable[] applicationIdAA = new ASN1Encodable[2];
        applicationIdAA[ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX] =
                new DERSet(packageInfoAA);
        applicationIdAA[ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX] =
                new DERSet(signaturesAA);

        return new DEROctetString(new DERSequence(applicationIdAA).getEncoded());
    }

}
