package keybox;

import android.util.Log;

public class Logger {
    private static final String TAG = "TrickyStore";
    public static void d(String msg) {
        Log.d(TAG, msg);
    }

    public static void dd(String msg) {
        d("wtf: " + msg);
    }

    public static void e(String msg) {
        Log.e(TAG, msg);
    }

    public static void e(String msg, Throwable t) {
        Log.e(TAG, "wtf: " + msg, t);
    }

    public static void i(String msg) {
        Log.i(TAG, msg);
    }

}
