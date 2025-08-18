package io.github.a13e300.tricky_store;

import static io.github.a13e300.tricky_store.TrickyStoreUtils.getTransactCode;

import android.hardware.security.keymint.KeyParameter;
import android.hardware.security.keymint.KeyParameterValue;
import android.hardware.security.keymint.Tag;
import android.os.IBinder;
import android.os.Parcel;
import android.system.keystore2.Authorization;
import android.system.keystore2.IKeystoreSecurityLevel;
import android.system.keystore2.KeyDescriptor;
import android.system.keystore2.KeyEntryResponse;
import android.system.keystore2.KeyMetadata;
import android.util.Pair;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import io.github.a13e300.tricky_store.binder.BinderInterceptor;
import io.github.a13e300.tricky_store.keystore.CertHack;
import io.github.a13e300.tricky_store.keystore.Utils;

public class SecurityLevelInterceptor extends BinderInterceptor {
    private final IKeystoreSecurityLevel original;
    private final int level;
    
    private static int generateKeyTransaction;
    private static int deleteKeyTransaction;
    private static int createOperationTransaction;

    static {
        try {
            generateKeyTransaction = getTransactCode(IKeystoreSecurityLevel.Stub.class, "generateKey");
            deleteKeyTransaction = getTransactCode(IKeystoreSecurityLevel.Stub.class, "deleteKey");
            createOperationTransaction = getTransactCode(IKeystoreSecurityLevel.Stub.class, "createOperation");
        } catch (Exception e) {
            Logger.e("Failed to get transaction codes", e);
        }
    }
    
    public static final Map<Key, Info> keys = new ConcurrentHashMap<>();
    public static final Map<Key, Pair<KeyPair, List<Certificate>>> keyPairs = new ConcurrentHashMap<>();
    
    public static KeyEntryResponse getKeyResponse(int uid, String alias) {
        Info info = keys.get(new Key(uid, alias));
        return info != null ? info.response : null;
    }
    
    public static Pair<KeyPair, List<Certificate>> getKeyPairs(int uid, String alias) {
        return keyPairs.get(new Key(uid, alias));
    }
    
    public SecurityLevelInterceptor(IKeystoreSecurityLevel original, int level) {
        this.original = original;
        this.level = level;
    }
    
    @Override
    public Result onPreTransact(IBinder target, int code, int flags, int callingUid, int callingPid, Parcel data) {
        if (code == generateKeyTransaction && Config.needGenerate(callingUid)) {
            Logger.i("intercept key gen uid=" + callingUid + " pid=" + callingPid);
            try {
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR);
                KeyDescriptor keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR);
                if (keyDescriptor == null) return Skip.INSTANCE;
                
                KeyDescriptor attestationKeyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR);
                KeyParameter[] params = data.createTypedArray(KeyParameter.CREATOR);
                int aFlags = data.readInt();
                byte[] entropy = data.createByteArray();
                
                CertHack.KeyGenParameters kgp = new CertHack.KeyGenParameters(params);
                Pair<KeyPair, List<Certificate>> pair = CertHack.generateKeyPair(
                    callingUid, keyDescriptor, attestationKeyDescriptor, kgp);
                
                if (pair == null) return Skip.INSTANCE;
                
                keyPairs.put(new Key(callingUid, keyDescriptor.alias), pair);
                KeyEntryResponse response = buildResponse(
                    pair.second, kgp, attestationKeyDescriptor != null ? attestationKeyDescriptor : keyDescriptor);
                keys.put(new Key(callingUid, keyDescriptor.alias), new Info(pair.first, response));
                
                Parcel p = Parcel.obtain();
                p.writeNoException();
                p.writeTypedObject(response.metadata, 0);
                return new OverrideReply(0, p);
            } catch (Exception e) {
                Logger.e("parse key gen request", e);
            }
        }
        return Skip.INSTANCE;
    }
    
    private KeyEntryResponse buildResponse(
        List<Certificate> chain,
        CertHack.KeyGenParameters params,
        KeyDescriptor descriptor
    ) {
        KeyEntryResponse response = new KeyEntryResponse();
        KeyMetadata metadata = new KeyMetadata();
        metadata.keySecurityLevel = level;
        try {
            Utils.putCertificateChain(metadata, chain.toArray(new Certificate[0]));
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }

        KeyDescriptor d = new KeyDescriptor();
        d.domain = descriptor.domain;
        d.nspace = descriptor.nspace;
        metadata.key = d;
        
        List<Authorization> authorizations = new ArrayList<>();
        Authorization a;
        
        for (int i : params.purpose) {
            a = new Authorization();
            a.keyParameter = new KeyParameter();
            a.keyParameter.tag = Tag.PURPOSE;
            a.keyParameter.value = KeyParameterValue.keyPurpose(i);
            a.securityLevel = level;
            authorizations.add(a);
        }
        
        for (int i : params.digest) {
            a = new Authorization();
            a.keyParameter = new KeyParameter();
            a.keyParameter.tag = Tag.DIGEST;
            a.keyParameter.value = KeyParameterValue.digest(i);
            a.securityLevel = level;
            authorizations.add(a);
        }
        
        a = new Authorization();
        a.keyParameter = new KeyParameter();
        a.keyParameter.tag = Tag.ALGORITHM;
        a.keyParameter.value = KeyParameterValue.algorithm(params.algorithm);
        a.securityLevel = level;
        authorizations.add(a);
        
        a = new Authorization();
        a.keyParameter = new KeyParameter();
        a.keyParameter.tag = Tag.KEY_SIZE;
        a.keyParameter.value = KeyParameterValue.integer(params.keySize);
        a.securityLevel = level;
        authorizations.add(a);
        
        a = new Authorization();
        a.keyParameter = new KeyParameter();
        a.keyParameter.tag = Tag.EC_CURVE;
        a.keyParameter.value = KeyParameterValue.ecCurve(params.ecCurve);
        a.securityLevel = level;
        authorizations.add(a);
        
        a = new Authorization();
        a.keyParameter = new KeyParameter();
        a.keyParameter.tag = Tag.NO_AUTH_REQUIRED;
        a.keyParameter.value = KeyParameterValue.boolValue(true); // TODO: copy
        a.securityLevel = level;
        authorizations.add(a);
        
        metadata.authorizations = authorizations.toArray(new Authorization[0]);
        response.metadata = metadata;
        response.iSecurityLevel = original;
        return response;
    }

    public static class Key {
        public final int uid;
        public final String alias;

        public Key(int uid, String alias) {
            this.uid = uid;
            this.alias = alias;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Key key = (Key) o;
            return uid == key.uid && alias.equals(key.alias);
        }

        @Override
        public int hashCode() {
            return 31 * uid + alias.hashCode();
        }
    }

    public static class Info {
        public final KeyPair keyPair;
        public final KeyEntryResponse response;

        public Info(KeyPair keyPair, KeyEntryResponse response) {
            this.keyPair = keyPair;
            this.response = response;
        }
    }

}