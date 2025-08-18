package io.github.a13e300.tricky_store;


import static io.github.a13e300.tricky_store.TrickyStoreUtils.getTransactCode;

import android.annotation.SuppressLint;
import android.os.IBinder;
import android.os.Parcel;
import android.os.ServiceManager;
import android.security.Credentials;
import android.security.KeyStore;
import android.security.keymaster.ExportResult;
import android.security.keymaster.KeyCharacteristics;
import android.security.keymaster.KeymasterArguments;
import android.security.keymaster.KeymasterCertificateChain;
import android.security.keymaster.KeymasterDefs;
import android.security.keystore.IKeystoreCertificateChainCallback;
import android.security.keystore.IKeystoreExportKeyCallback;
import android.security.keystore.IKeystoreKeyCharacteristicsCallback;
import android.security.keystore.IKeystoreService;
import android.security.keystore.KeystoreResponse;
import io.github.a13e300.tricky_store.binder.BinderInterceptor;
import io.github.a13e300.tricky_store.keystore.CertHack;

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@SuppressLint("BlockedPrivateApi")
public class KeystoreInterceptor extends BinderInterceptor {



    private final int getTransaction = getTransactCode(IKeystoreService.Stub.class, "get");
    private final int generateKeyTransaction = getTransactCode(IKeystoreService.Stub.class, "generateKey");
    private final int getKeyCharacteristicsTransaction = getTransactCode(IKeystoreService.Stub.class, "getKeyCharacteristics");
    private final int exportKeyTransaction = getTransactCode(IKeystoreService.Stub.class, "exportKey");
    private final int attestKeyTransaction = getTransactCode(IKeystoreService.Stub.class, "attestKey");

    private IBinder keystore;

    private static final String DESCRIPTOR = "android.security.keystore.IKeystoreService";

    private final Map<Key, CertHack.KeyGenParameters> KeyArguments = new HashMap<>();
    private final Map<Key, KeyPair> KeyPairs = new HashMap<>();

    public static class Key {
        public final int uid;
        public final String alias;

        public Key(int uid, String alias) {
            this.uid = uid;
            this.alias = alias;
        }

        @Override
        public boolean equals(Object obj) {
            if (!(obj instanceof Key)) return false;
            Key k = (Key) obj;
            return uid == k.uid && alias.equals(k.alias);
        }

        @Override
        public int hashCode() {
            return uid * 31 + alias.hashCode();
        }
    }

    @Override
    public Result onPreTransact(IBinder target, int code, int flags, int callingUid, int callingPid, Parcel data) {
        if (!CertHack.canHack()) return Skip.INSTANCE;

        try {
            if (code == getTransaction) {
                if (Config.needGenerate(callingUid)) {
                    Logger.i("不需要拦截 getTransaction uid " + callingUid);
                    return Skip.INSTANCE;
                }
            } else if (Config.needGenerate(callingUid)) {
                if (code == generateKeyTransaction) {
                    try {
                        Logger.i("拦截 generateKeyTransaction uid " + callingUid);
                        data.enforceInterface(DESCRIPTOR);
                        IKeystoreKeyCharacteristicsCallback callback = IKeystoreKeyCharacteristicsCallback.Stub.asInterface(data.readStrongBinder());
                        String alias = data.readString().split("_")[1];
                        Logger.i("generateKeyTransaction uid " + callingUid + " alias " + alias);
                        int check = data.readInt();
                        KeymasterArguments kma = new KeymasterArguments();
                        CertHack.KeyGenParameters kgp = new CertHack.KeyGenParameters();
                        if (check == 1) {
                            kma.readFromParcel(data);
                            kgp.algorithm = kma.getEnum(KeymasterDefs.KM_TAG_ALGORITHM, 0);
                            kgp.keySize = (int) kma.getUnsignedInt(KeymasterDefs.KM_TAG_KEY_SIZE, 0);
                            kgp.setEcCurveName(kgp.keySize);
                            kgp.purpose = kma.getEnums(KeymasterDefs.KM_TAG_PURPOSE);
                            kgp.digest = kma.getEnums(KeymasterDefs.KM_TAG_DIGEST);
                            kgp.certificateNotBefore = kma.getDate(KeymasterDefs.KM_TAG_ACTIVE_DATETIME, new Date());
                            if (kgp.algorithm == KeymasterDefs.KM_ALGORITHM_RSA) {
                                try {
                                    @SuppressLint("SoonBlockedPrivateApi") java.lang.reflect.Method getArgumentByTag = KeymasterArguments.class.getDeclaredMethod("getArgumentByTag", int.class);
                                    getArgumentByTag.setAccessible(true);
                                    Object rsaArgument = getArgumentByTag.invoke(kma, KeymasterDefs.KM_TAG_RSA_PUBLIC_EXPONENT);

                                    java.lang.reflect.Method getLongTagValue = KeymasterArguments.class.getDeclaredMethod("getLongTagValue", Object.class);
                                    getLongTagValue.setAccessible(true);
                                    kgp.rsaPublicExponent = (BigInteger) getLongTagValue.invoke(kma, rsaArgument);
                                } catch (Exception ex) {
                                    Logger.e("Read rsaPublicExponent error", ex);
                                }
                            }
                            KeyArguments.put(new Key(callingUid, alias), kgp);
                        }

                        KeyCharacteristics kc = new KeyCharacteristics();
                        kc.swEnforced = new KeymasterArguments();
                        kc.hwEnforced = kma;

                        Parcel ksrP = Parcel.obtain();
                        ksrP.writeInt(KeyStore.NO_ERROR);
                        ksrP.writeString("");
                        ksrP.setDataPosition(0);
                        KeystoreResponse ksr = KeystoreResponse.CREATOR.createFromParcel(ksrP);
                        ksrP.recycle();

                        callback.onFinished(ksr, kc);

                        Parcel p = Parcel.obtain();
                        p.writeNoException();
                        p.writeInt(KeyStore.NO_ERROR);
                        return new OverrideReply(0, p);

                    } catch (Throwable t) {
                        Logger.e("generateKeyTransaction error", t);
                    }
                } else if (code == getKeyCharacteristicsTransaction) {
                    try {
                        Logger.i("拦截 getKeyCharacteristicsTransaction uid " + callingUid);
                        data.enforceInterface(DESCRIPTOR);
                        IKeystoreKeyCharacteristicsCallback callback = IKeystoreKeyCharacteristicsCallback.Stub.asInterface(data.readStrongBinder());
                        String alias = data.readString().split("_")[1];
                        Logger.i("getKeyCharacteristicsTransaction uid " + callingUid + " alias " + alias);
                        KeyCharacteristics kc = new KeyCharacteristics();
                        KeymasterArguments kma = new KeymasterArguments();
                        CertHack.KeyGenParameters kgp = KeyArguments.get(new Key(callingUid, alias));
                        kma.addEnum(KeymasterDefs.KM_TAG_ALGORITHM, kgp.algorithm);
                        kc.swEnforced = new KeymasterArguments();
                        kc.hwEnforced = kma;

                        Parcel ksrP = Parcel.obtain();
                        ksrP.writeInt(KeyStore.NO_ERROR);
                        ksrP.writeString("");
                        ksrP.setDataPosition(0);
                        KeystoreResponse ksr = KeystoreResponse.CREATOR.createFromParcel(ksrP);
                        ksrP.recycle();

                        callback.onFinished(ksr, kc);

                        Parcel p = Parcel.obtain();
                        p.writeNoException();
                        p.writeInt(KeyStore.NO_ERROR);
                        return new OverrideReply(0, p);

                    } catch (Throwable t) {
                        Logger.e("getKeyCharacteristicsTransaction error", t);
                    }
                } else if (code == exportKeyTransaction) {
                    try {
                        Logger.i("拦截 exportKeyTransaction uid " + callingUid);
                        data.enforceInterface(DESCRIPTOR);
                        IKeystoreExportKeyCallback callback = IKeystoreExportKeyCallback.Stub.asInterface(data.readStrongBinder());
                        String alias = data.readString().split("_")[1];
                        Logger.i("exportKeyTransaction uid " + callingUid + " alias " + alias);
                        KeyPair kp = CertHack.generateKeyPair(KeyArguments.get(new Key(callingUid, alias)));
                        KeyPairs.put(new Key(callingUid, alias), kp);

                        Parcel erP = Parcel.obtain();
                        erP.writeInt(KeyStore.NO_ERROR);
                        erP.writeByteArray(kp.getPublic().getEncoded());
                        erP.setDataPosition(0);
                        ExportResult er = ExportResult.CREATOR.createFromParcel(erP);
                        erP.recycle();

                        callback.onFinished(er);

                        Parcel p = Parcel.obtain();
                        p.writeNoException();
                        p.writeInt(KeyStore.NO_ERROR);
                        return new OverrideReply(0, p);

                    } catch (Throwable t) {
                        Logger.e("exportKeyTransaction error", t);
                    }
                } else if (code == attestKeyTransaction) {
                    try {
                        Logger.i("拦截 attestKeyTransaction uid " + callingUid);
                        data.enforceInterface(DESCRIPTOR);
                        IKeystoreCertificateChainCallback callback = IKeystoreCertificateChainCallback.Stub.asInterface(data.readStrongBinder());
                        String alias = data.readString().split("_")[1];
                        Logger.i("attestKeyTransaction uid " + callingUid + " alias " + alias);
                        int check = data.readInt();
                        KeymasterArguments kma = new KeymasterArguments();
                        if (check == 1) {
                            kma.readFromParcel(data);
                            byte[] attestationChallenge = kma.getBytes(KeymasterDefs.KM_TAG_ATTESTATION_CHALLENGE, new byte[0]);

                            Parcel ksrP = Parcel.obtain();
                            ksrP.writeInt(KeyStore.NO_ERROR);
                            ksrP.writeString("");
                            ksrP.setDataPosition(0);
                            KeystoreResponse ksr = KeystoreResponse.CREATOR.createFromParcel(ksrP);
                            ksrP.recycle();

                            Key key = new Key(callingUid, alias);
                            CertHack.KeyGenParameters ka = KeyArguments.get(key);
                            ka.attestationChallenge = attestationChallenge;
                            KeyPair kp = KeyPairs.get(key);
                            List<byte[]> chain = CertHack.generateChain(callingUid, ka, kp);

                            KeymasterCertificateChain kcc = new KeymasterCertificateChain(chain);
                            callback.onFinished(ksr, kcc);
                        }

                        Parcel p = Parcel.obtain();
                        p.writeNoException();
                        p.writeInt(KeyStore.NO_ERROR);
                        return new OverrideReply(0, p);

                    } catch (Throwable t) {
                        Logger.e("attestKeyTransaction error", t);
                    }
                }
            }
        } catch (Throwable ignored) {}
        return Skip.INSTANCE;
    }

    @Override
    public Result onPostTransact(IBinder target, int code, int flags, int callingUid, int callingPid, Parcel data, Parcel reply, int resultCode) {
        if (target != keystore || code != getTransaction || reply == null) return Skip.INSTANCE;

        try {
            reply.readException();
        } catch (Throwable t) {
            return Skip.INSTANCE;
        }

        Parcel p = Parcel.obtain();
        Logger.d("intercept post " + target + " uid=" + callingUid + " pid=" + callingPid
                + " dataSz=" + data.dataSize() + " replySz=" + reply.dataSize());
        try {
            data.enforceInterface(DESCRIPTOR);
            String alias = data.readString();
            byte[] response = reply.createByteArray();
            if (alias.startsWith(Credentials.USER_CERTIFICATE)) {
                Logger.i("拦截证书链USER_CERTIFICATE uid=" + callingUid + " pid=" + callingPid + " alias=" + alias);
                response = CertHack.hackCertificateChainUSR(response, alias.split("_")[1], callingUid);
                Logger.i("hacked leaf of uid=" + callingUid);
                p.writeNoException();
                p.writeByteArray(response);
                return new OverrideReply(0, p);
            } else if (alias.startsWith(Credentials.CA_CERTIFICATE)) {
                Logger.i("拦截证书链CA_CERTIFICATE uid=" + callingUid + " pid=" + callingPid + " alias=" + alias);
                response = CertHack.hackCertificateChainCA(response, alias.split("_")[1], callingUid);
                Logger.i("hacked caList of uid=" + callingUid);
                p.writeNoException();
                p.writeByteArray(response);
                return new OverrideReply(0, p);
            } else {
                p.recycle();
            }
        } catch (Throwable t) {
            Logger.e("failed to hack certificate chain of uid=" + callingUid + " pid=" + callingPid + "!", t);
            p.recycle();
        }
        return Skip.INSTANCE;
    }

    private int triedCount = 0;
    private boolean injected = false;

    public boolean tryRunKeystoreInterceptor() {
        Logger.i("trying to register keystore interceptor (" + triedCount + ") ...");
        IBinder b = ServiceManager.getService("android.security.keystore");
        if (b == null) return false;
        IBinder bd = getBinderBackdoor(b);
        if (bd == null) {
            if (triedCount >= 3) {
                Logger.e("tried injection but still has no backdoor, exit");
                System.exit(1);
            }
            if (!injected) {
                Logger.i("trying to inject keystore ...");
                try {
                    Process p = Runtime.getRuntime().exec(new String[]{
                            "/system/bin/sh",
                            "-c",
                            "exec ./inject `pidof keystore` libtricky_store.so entry"
                    });
                    if (p.waitFor() != 0) {
                        Logger.e("failed to inject! daemon exit");
                        System.exit(1);
                    }
                    injected = true;
                } catch (Exception e) {
                    Logger.e("failed to inject process", e);
                    System.exit(1);
                }
            }
            triedCount++;
            return false;
        }
        keystore = b;
        Logger.i("register for Keystore " + keystore + "!");
        registerBinderInterceptor(bd, b, this);
        try {
            keystore.linkToDeath(Killer.INSTANCE, 0);
        } catch (Exception ignored) {}
        return true;
    }

    public enum Killer implements IBinder.DeathRecipient {
        INSTANCE;

        @Override
        public void binderDied() {
            Logger.d("keystore exit, daemon restart");
            System.exit(0);
        }
    }
}
