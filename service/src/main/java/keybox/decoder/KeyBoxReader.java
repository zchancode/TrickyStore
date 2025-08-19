package keybox.decoder;

import android.security.keystore.KeyProperties;

import keybox.Logger;
import keybox.XMLParser;
import keybox.bean.KeyBox;

import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Objects;

public class KeyBoxReader {

    public static String trimLine(String str) {
        String[] lines = str.trim().split("\n");
        StringBuilder sb = new StringBuilder();
        for (String line : lines) {
            if (sb.length() > 0) {
                sb.append("\n");
            }
            sb.append(line.trim());
        }
        return sb.toString();
    }

    private static PEMKeyPair parseKeyPair(String key) throws Throwable {
        try (PEMParser parser = new PEMParser(new StringReader(trimLine(key)))) {
            return (PEMKeyPair) parser.readObject();
        }
    }

    private static Certificate parseCert(String cert) throws Throwable {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        try (PemReader reader = new PemReader(new StringReader(trimLine(cert)))) {
            return certificateFactory.generateCertificate(new ByteArrayInputStream(reader.readPemObject().getContent()));
        }
    }


    public static Map<String, KeyBox> readFromXml(String data) {
        Map<String, KeyBox> keyboxes = new HashMap<>();
        if (data == null) {
            Logger.i("clear all keyboxes");
            return keyboxes;
        }
        XMLParser xmlParser = new XMLParser(data);

        try {
            int numberOfKeyboxes = Integer.parseInt(Objects.requireNonNull(xmlParser.obtainPath(
                    "AndroidAttestation.NumberOfKeyboxes").get("text")));
            for (int i = 0; i < numberOfKeyboxes; i++) {
                String keyboxAlgorithm = xmlParser.obtainPath(
                        "AndroidAttestation.Keybox.Key[" + i + "]").get("algorithm");
                String privateKey = xmlParser.obtainPath(
                        "AndroidAttestation.Keybox.Key[" + i + "].PrivateKey").get("text");
                int numberOfCertificates = Integer.parseInt(Objects.requireNonNull(xmlParser.obtainPath(
                        "AndroidAttestation.Keybox.Key[" + i + "].CertificateChain.NumberOfCertificates").get("text")));

                LinkedList<Certificate> certificateChain = new LinkedList<>();

                for (int j = 0; j < numberOfCertificates; j++) {
                    Map<String, String> certData = xmlParser.obtainPath(
                            "AndroidAttestation.Keybox.Key[" + i + "].CertificateChain.Certificate[" + j + "]");
                    certificateChain.add(parseCert(certData.get("text")));
                }
                String algo;
                if (keyboxAlgorithm.equalsIgnoreCase("ecdsa")) {
                    algo = KeyProperties.KEY_ALGORITHM_EC;
                } else {
                    algo = KeyProperties.KEY_ALGORITHM_RSA;
                }
                PEMKeyPair pemKp = parseKeyPair(privateKey);
                KeyPair kp = new JcaPEMKeyConverter().getKeyPair(pemKp);
                keyboxes.put(algo, new KeyBox(pemKp, kp, certificateChain));
            }
            Logger.i("update " + numberOfKeyboxes + " keyboxes");
        } catch (Throwable t) {
            Logger.e("Error loading xml file (keyboxes cleared): " + t);
        }
        return keyboxes;
    }



}
