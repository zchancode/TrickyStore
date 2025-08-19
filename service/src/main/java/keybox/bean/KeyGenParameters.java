package keybox.bean;

import org.bouncycastle.asn1.x500.X500Name;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class KeyGenParameters {
        public int keySize;
        public int algorithm;
        public BigInteger certificateSerial;
        public Date certificateNotBefore;
        public Date certificateNotAfter;
        public X500Name certificateSubject;

        public BigInteger rsaPublicExponent;
        public int ecCurve;
        public String ecCurveName;

        public List<Integer> purpose = new ArrayList<>();
        public List<Integer> digest = new ArrayList<>();

        public byte[] attestationChallenge;
        public byte[] brand;
        public byte[] device;
        public byte[] product;
        public byte[] manufacturer;
        public byte[] model;
        public byte[] imei1, imei2;
        public byte[] meid;

        public KeyGenParameters() {
        }

        public void setEcCurveName(int curve) {
            switch (curve) {
                case 224:
                    this.ecCurveName = "secp224r1";
                    break;
                case 256:
                    this.ecCurveName = "secp256r1";
                    break;
                case 384:
                    this.ecCurveName = "secp384r1";
                    break;
                case 521:
                    this.ecCurveName = "secp521r1";
                    break;
            }
        }
    }