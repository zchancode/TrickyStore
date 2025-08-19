package keybox.bean;

import java.util.Arrays;

public class Digest {
        public final byte[] digest;

        public Digest(byte[] digest) {
            this.digest = digest;
        }

        @Override
        public boolean equals(Object o) {
            if (o instanceof Digest) {
                Digest d = (Digest) o;
                return Arrays.equals(digest, d.digest);
            }
            return false;
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(digest);
        }
    }