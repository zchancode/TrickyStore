package keybox.bean;

import java.util.Objects;
public class Key {
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