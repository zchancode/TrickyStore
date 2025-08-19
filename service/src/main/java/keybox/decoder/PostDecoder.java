package keybox.decoder;

import keybox.Logger;
import keybox.TrickyStoreUtils;
import keybox.bean.Key;
import keybox.bean.KeyBox;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.Map;

public class PostDecoder {

    private static byte[] getByteArrayFromAsn1(ASN1Encodable asn1Encodable) throws CertificateParsingException {
        if (!(asn1Encodable instanceof DEROctetString)) {
            throw new CertificateParsingException("Expected DEROctetString");
        }
        DEROctetString derOctectString = (DEROctetString) asn1Encodable;
        return derOctectString.getOctets();
    }
    public static byte[] hackCertificateChainUSR(Map<Key, String> leafAlgorithm, Map<String, KeyBox> keyboxes, byte[] certificate, String alias, int uid) {
        if (certificate == null) throw new UnsupportedOperationException("leaf is null!");
        try {
            ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17");
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate leaf = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificate));
            byte[] bytes = leaf.getExtensionValue(OID.getId());
            if (bytes == null) return certificate;

            X509CertificateHolder leafHolder = new X509CertificateHolder(leaf.getEncoded());
            Extension ext = leafHolder.getExtension(OID);
            ASN1Sequence sequence = ASN1Sequence.getInstance(ext.getExtnValue().getOctets());
            ASN1Encodable[] encodables = sequence.toArray();
            ASN1Sequence teeEnforced = (ASN1Sequence) encodables[7];
            ASN1EncodableVector vector = new ASN1EncodableVector();
            ASN1Encodable rootOfTrust = null;

            for (ASN1Encodable asn1Encodable : teeEnforced) {
                ASN1TaggedObject taggedObject = (ASN1TaggedObject) asn1Encodable;
                if (taggedObject.getTagNo() == 704) {
                    rootOfTrust = taggedObject.getBaseObject().toASN1Primitive();
                    continue;
                }
                vector.add(taggedObject);
            }

            LinkedList<Certificate> certificates;
            X509v3CertificateBuilder builder;
            ContentSigner signer;

            leafAlgorithm.put(new Key(uid, alias), leaf.getPublicKey().getAlgorithm());
            KeyBox k = keyboxes.get(leaf.getPublicKey().getAlgorithm());
            if (k == null)
                throw new UnsupportedOperationException("unsupported algorithm " + leaf.getPublicKey().getAlgorithm());
            certificates = new LinkedList<>(k.certificates);
            builder = new X509v3CertificateBuilder(
                    new X509CertificateHolder(
                            certificates.get(0).getEncoded()
                    ).getSubject(),
                    leafHolder.getSerialNumber(),
                    leafHolder.getNotBefore(),
                    leafHolder.getNotAfter(),
                    leafHolder.getSubject(),
                    leafHolder.getSubjectPublicKeyInfo()
            );
            signer = new JcaContentSignerBuilder(leaf.getSigAlgName())
                    .build(k.keyPair.getPrivate());

            byte[] verifiedBootKey = TrickyStoreUtils.getBootKey();
            byte[] verifiedBootHash = null;
            try {
                if (!(rootOfTrust instanceof ASN1Sequence)) {
                    throw new CertificateParsingException("Expected sequence for root of trust, found "
                            + rootOfTrust.getClass().getName());
                }
                ASN1Sequence r = (ASN1Sequence) rootOfTrust;
                verifiedBootHash = getByteArrayFromAsn1(r.getObjectAt(3));
            } catch (Throwable t) {
                Logger.e("failed to get verified boot key or hash from original, use randomly generated instead", t);
            }

            if (verifiedBootHash == null) {
                verifiedBootHash = TrickyStoreUtils.getBootHash();
            }

            ASN1Encodable[] rootOfTrustEnc = {
                    new DEROctetString(verifiedBootKey),
                    ASN1Boolean.TRUE,
                    new ASN1Enumerated(0),
                    new DEROctetString(verifiedBootHash)
            };

            ASN1Sequence hackedRootOfTrust = new DERSequence(rootOfTrustEnc);
            ASN1TaggedObject rootOfTrustTagObj = new DERTaggedObject(704, hackedRootOfTrust);
            vector.add(rootOfTrustTagObj);

            ASN1Sequence hackEnforced = new DERSequence(vector);
            encodables[7] = hackEnforced;
            ASN1Sequence hackedSeq = new DERSequence(encodables);

            ASN1OctetString hackedSeqOctets = new DEROctetString(hackedSeq);
            Extension hackedExt = new Extension(OID, false, hackedSeqOctets);
            builder.addExtension(hackedExt);

            for (ASN1ObjectIdentifier extensionOID : leafHolder.getExtensions().getExtensionOIDs()) {
                if (OID.getId().equals(extensionOID.getId())) continue;
                builder.addExtension(leafHolder.getExtension(extensionOID));
            }
            return new JcaX509CertificateConverter().getCertificate(builder.build(signer)).getEncoded();

        } catch (Throwable t) {
            Logger.e("", t);
        }
        return certificate;
    }

    public static byte[] hackCertificateChainCA(Map<Key, String> leafAlgorithm, Map<String, KeyBox> keyboxes, byte[] caList, String alias, int uid) {
        if (caList == null) throw new UnsupportedOperationException("caList is null!");
        try {
            Key key = new Key(uid, alias);
            String algorithm = leafAlgorithm.get(key);
            leafAlgorithm.remove(key);
            KeyBox k = keyboxes.get(algorithm);
            if (k == null)
                throw new UnsupportedOperationException("unsupported algorithm " + algorithm);
            return TrickyStoreUtils.toBytes(k.certificates);
        } catch (Throwable t) {
            Logger.e("", t);
        }
        return caList;
    }
}
