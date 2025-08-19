package keybox;


import android.content.pm.IPackageManager;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.ServiceManager;
import android.os.SystemProperties;
import android.util.Log;
import android.util.Pair;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

public class TrickyStoreUtils {
    private static byte[] bootHash;
    private static byte[] bootKey;
    private static List<Pair<String, Long>> apexInfos;
    private static byte[] moduleHash;
    private static List<DERTaggedObject> telephonyInfos;

    public static int getTransactCode(Class<?> clazz, String method) {
        try {
            java.lang.reflect.Field field = clazz.getDeclaredField("TRANSACTION_" + method);
            field.setAccessible(true);
            return field.getInt(null);
        } catch (NoSuchFieldException e) {
            throw new RuntimeException("Transaction field not found for method: " + method, e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException("Failed to access transaction field for method: " + method, e);
        }
    }

    public static synchronized byte[] getBootHash() {
        if (bootHash == null) {
            byte[] hash = getBootHashFromProp();
            bootHash = hash != null ? hash : randomBytes();
        }
        return bootHash;
    }

    public static synchronized byte[] getBootKey() {
        if (bootKey == null) {
            bootKey = randomBytes();
        }
        return bootKey;
    }

    public static byte[] toBytes(Collection<Certificate> certificates) {
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            for (Certificate cert : certificates) {
                byteArrayOutputStream.write(cert.getEncoded());
            }
            return byteArrayOutputStream.toByteArray();
        } catch (Exception e) {
            Log.w("Couldn't getBytes certificates in keystore", e);
            return null;
        }
    }
    public static List<byte[]> toListBytes(Collection<Certificate> certificates) {
        try {
            List<byte[]> chain = new ArrayList<>();
            for (Certificate cert : certificates) {
                chain.add(cert.getEncoded());
            }
            return chain;
        } catch (Exception e) {
            Log.w("Couldn't toListBytes certificates in keystore", e);
            return null;
        }
    }

    public static byte[] getBootHashFromProp() {
        String b = SystemProperties.get("ro.boot.vbmeta.digest", null);
        if (b == null || b.length() != 64) {
            return null;
        }
        return hexStringToByteArray(b);
    }

    public static byte[] randomBytes() {
        byte[] bytes = new byte[32];
        ThreadLocalRandom.current().nextBytes(bytes);
        return bytes;
    }

    public static int getPatchLevel() {
        return convertPatchLevel(Build.VERSION.SECURITY_PATCH, false);
    }

    public static int getPatchLevelLong() {
        return convertPatchLevel(Build.VERSION.SECURITY_PATCH, false);
    }

    public static int getOsVersion() {
        return getOsVersion(Build.VERSION.SDK_INT);
    }

    private static int getOsVersion(int num) {
        if (num == Build.VERSION_CODES.VANILLA_ICE_CREAM) return 150000;
        if (num == Build.VERSION_CODES.UPSIDE_DOWN_CAKE) return 140000;
        if (num == Build.VERSION_CODES.TIRAMISU) return 130000;
        if (num == Build.VERSION_CODES.S_V2) return 120100;
        if (num == Build.VERSION_CODES.S) return 120000;
        if (num == Build.VERSION_CODES.Q) return 110000;
        return 150000;
    }

    public static int convertPatchLevel(String patchLevel, boolean longVersion) {
        try {
            String[] l = patchLevel.split("-");
            if (longVersion) {
                return Integer.parseInt(l[0]) * 10000 + Integer.parseInt(l[1]) * 100 + Integer.parseInt(l[2]);
            } else {
                return Integer.parseInt(l[0]) * 100 + Integer.parseInt(l[1]);
            }
        } catch (Exception e) {
            Logger.e("invalid patch level " + patchLevel + " !", e);
            return 202404;
        }
    }

    public static PackageInfo getPackageInfoCompat(IPackageManager pm, String name, long flags, int userId) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                return pm.getPackageInfo(name, flags, userId);
            } else {
                return pm.getPackageInfo(name, (int) flags, userId);
            }
        }catch (Exception e) {
            Logger.e("Failed to get package info for " + name, e);
            return null;
        }
    }

    public static synchronized List<Pair<String, Long>> getApexInfos() {
        if (apexInfos == null) {
            apexInfos = new ArrayList<>();
            IPackageManager pm = IPackageManager.Stub.asInterface(ServiceManager.getService("package"));
            try {
                List<?> packages;
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    packages = pm.getInstalledPackages((long) PackageManager.MATCH_APEX, 0).getList();
                } else {
                    packages = pm.getInstalledPackages(PackageManager.MATCH_APEX, 0).getList();
                }
                
                for (Object pkg : packages) {
                    // Assuming PackageInfo has packageName and longVersionCode fields
                    // You'll need to adjust this based on your actual PackageInfo class
                    String packageName = (String) pkg.getClass().getField("packageName").get(pkg);
                    long versionCode = (Long) pkg.getClass().getField("longVersionCode").get(pkg);
                    apexInfos.add(new Pair<>(packageName, versionCode));
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            
            // Sort lexicographically
            apexInfos.sort((o1, o2) -> o1.first.compareTo(o2.first));
        }
        return apexInfos;
    }

    public static synchronized byte[] getModuleHash() {
        if (moduleHash == null) {
            List<ASN1Encodable> list = new ArrayList<>();
            for (Pair<String, Long> apexInfo : getApexInfos()) {
                list.add(new DEROctetString(apexInfo.first.getBytes()));
                list.add(new ASN1Integer(apexInfo.second));
            }
            
            try {
                DERSequence sequence = new DERSequence(list.toArray(new ASN1Encodable[0]));
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(sequence.getEncoded());
                moduleHash = md.digest();
            } catch (Exception e){
                Logger.e("Failed to compute module hash", e);
            }
        }
        return moduleHash;
    }

    public static synchronized List<DERTaggedObject> getTelephonyInfos() {
        if (telephonyInfos == null) {
            telephonyInfos = new ArrayList<>();
            
            String brand = Build.BRAND;
            String device = Build.DEVICE;
            String product = Build.PRODUCT;
            String manufacturer = Build.MANUFACTURER;
            String model = Build.MODEL;
            String serial = SystemProperties.get("ro.serialno", "");
            
            String meid = SystemProperties.get("ro.ril.oem.imei", "");
            String imei = SystemProperties.get("ro.ril.oem.meid", "");
            String imei2 = SystemProperties.get("ro.ril.oem.imei2", "");
            
            telephonyInfos.add(toTaggedObj(toDER(imei), 714));
            telephonyInfos.add(toTaggedObj(toDER(meid), 715));
            telephonyInfos.add(toTaggedObj(toDER(imei2), 723));
            telephonyInfos.add(toTaggedObj(toDER(serial), 713));
            
            telephonyInfos.add(toTaggedObj(toDER(brand), 710));
            telephonyInfos.add(toTaggedObj(toDER(device), 711));
            telephonyInfos.add(toTaggedObj(toDER(product), 712));
            telephonyInfos.add(toTaggedObj(toDER(manufacturer), 716));
            telephonyInfos.add(toTaggedObj(toDER(model), 717));
        }
        return telephonyInfos;
    }

    public static DEROctetString toDER(String str) {
        return new DEROctetString(str.getBytes());
    }

    public static DERTaggedObject toTaggedObj(DEROctetString octetString, int tag) {
        return new DERTaggedObject(true, tag, octetString);
    }

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

    // Helper method to convert hex string to byte array
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

}