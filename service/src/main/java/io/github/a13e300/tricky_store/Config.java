package io.github.a13e300.tricky_store;

import android.content.pm.IPackageManager;
import android.os.Build;
import android.os.FileObserver;
import android.os.ServiceManager;
import android.os.SystemProperties;
import com.akuleshov7.ktoml.annotations.TomlComments;
import io.github.a13e300.tricky_store.keystore.CertHack;
import kotlinx.serialization.Serializable;

import java.io.File;
import java.util.Arrays;
import java.util.List;

public class Config {
    private static final List<String> generatePackages = Arrays.asList(
        "com.google.android.gsf", "com.google.android.gms", "com.android.vending",
        "io.github.vvb2060.keyattestation",
        "io.github.vvb2060.mahoshojo",
        "icu.nullptr.nativetest"
    );

    private static void updateKeyBox(File f) {
        try {
            String content = f != null ? new String(java.nio.file.Files.readAllBytes(f.toPath())) : null;
            CertHack.readFromXml(content);
        } catch (Exception e) {
            Logger.e("failed to update keybox", e);
        }
    }

    private static final String CONFIG_PATH = "/data/adb/tricky_store";
    private static final String KEYBOX_FILE = "keybox.xml";
    private static final File root = new File(CONFIG_PATH);

    private static final FileObserver ConfigObserver = new FileObserver(root, FileObserver.CLOSE_WRITE | FileObserver.DELETE | FileObserver.MOVED_FROM | FileObserver.MOVED_TO) {
        @Override
        public void onEvent(int event, String path) {
            if (path == null) return;
            
            File f = null;
            switch (event) {
                case FileObserver.CLOSE_WRITE:
                case FileObserver.MOVED_TO:
                    f = new File(root, path);
                    break;
                case FileObserver.DELETE:
                case FileObserver.MOVED_FROM:
                    f = null;
                    break;
                default:
                    return;
            }
            
            if (path.equals(KEYBOX_FILE)) {
                updateKeyBox(f);
            }
        }
    };

    public static void initialize() {
        root.mkdirs();
        File keybox = new File(root, KEYBOX_FILE);
        if (!keybox.exists()) {
            Logger.e("keybox file not found, please put it to " + keybox + " !");
        } else {
            updateKeyBox(keybox);
        }
        ConfigObserver.startWatching();
    }

    private static IPackageManager iPm = null;

    public static IPackageManager getPm() {
        if (iPm == null) {
            iPm = IPackageManager.Stub.asInterface(ServiceManager.getService("package"));
        }
        return iPm;
    }

    public static boolean needGenerate(int callingUid) {
        try {
            String[] ps = getPm().getPackagesForUid(callingUid);
            if (ps != null) {
                for (String p : ps) {
                    if (generatePackages.contains(p)) {
                        return true;
                    }
                }
            }
            return false;
        } catch (Exception e) {
            Logger.e("failed to get packages", e);
            return false;
        }
    }

}