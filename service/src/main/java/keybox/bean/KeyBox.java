package keybox.bean;

import org.bouncycastle.openssl.PEMKeyPair;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.util.List;

public class KeyBox {
        public final PEMKeyPair pemKeyPair;
        public final KeyPair keyPair;
        public final List<Certificate> certificates;

        public KeyBox(PEMKeyPair pemKeyPair, KeyPair keyPair, List<Certificate> certificates) {
            this.pemKeyPair = pemKeyPair;
            this.keyPair = keyPair;
            this.certificates = certificates;
        }
    }