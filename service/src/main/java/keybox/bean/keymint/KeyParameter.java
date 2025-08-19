package keybox.bean.keymint;

import android.os.Parcel;
import android.os.Parcelable;


public class KeyParameter implements Parcelable {
    public static final Creator<KeyParameter> CREATOR = new Creator<KeyParameter>() {
        @Override
        public KeyParameter createFromParcel(Parcel in) {
            throw new RuntimeException();
        }

        @Override
        public KeyParameter[] newArray(int size) {
            throw new RuntimeException();
        }
    };
    public int tag = 0;
    public KeyParameterValue value;

    @Override
    public int describeContents() {
        throw new RuntimeException();
    }

    @Override
    public void writeToParcel(Parcel parcel, int i) {
        throw new RuntimeException();
    }
}
