package io.github.a13e300.tricky_store.binder;

import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;

import io.github.a13e300.tricky_store.Logger;

public class BinderInterceptor extends Binder {

    public static abstract class Result {
        private Result() {}
    }

    public static final class Skip extends Result {
        public static final Skip INSTANCE = new Skip();
        private Skip() {}
    }

    public static final class Continue extends Result {
        public static final Continue INSTANCE = new Continue();
        private Continue() {}
    }

    public static final class OverrideData extends Result {
        public final Parcel data;
        public OverrideData(Parcel data) {
            this.data = data;
        }
    }

    public static final class OverrideReply extends Result {
        public final int code;
        public final Parcel reply;
        public OverrideReply(int code, Parcel reply) {
            this.code = code;
            this.reply = reply;
        }
        public OverrideReply(Parcel reply) {
            this(0, reply);
        }
    }

    public Result onPreTransact(IBinder target, int code, int flags, int callingUid, int callingPid, Parcel data) {
        return Skip.INSTANCE;
    }

    public Result onPostTransact(IBinder target, int code, int flags, int callingUid, int callingPid, Parcel data, Parcel reply, int resultCode) {
        return Skip.INSTANCE;
    }

    public static IBinder getBinderBackdoor(IBinder b) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            if (!b.transact(0xdeadbeef, data, reply, 0)) {
                Logger.d("remote return false!");
                return null;
            }
            Logger.d("remote return true!");
            return reply.readStrongBinder();
        } catch (Throwable t) {
            Logger.e("failed to read binder", t);
            return null;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    public static void registerBinderInterceptor(IBinder backdoor, IBinder target, BinderInterceptor interceptor) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeStrongBinder(target);
            data.writeStrongBinder(interceptor);
            backdoor.transact(1, data, reply, 0);
        } catch (Throwable t) {
            Logger.e("register failed", t);
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    @Override
    protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
        Result result;
        if (code == 1) { // PRE_TRANSACT
            IBinder target = data.readStrongBinder();
            int theCode = data.readInt();
            int theFlags = data.readInt();
            int callingUid = data.readInt();
            int callingPid = data.readInt();
            long sz = data.readLong();
            Parcel theData = Parcel.obtain();
            try {
                theData.appendFrom(data, data.dataPosition(), (int) sz);
                theData.setDataPosition(0);
                result = onPreTransact(target, theCode, theFlags, callingUid, callingPid, theData);
            } finally {
                theData.recycle();
            }
        } else if (code == 2) { // POST_TRANSACT
            IBinder target = data.readStrongBinder();
            int theCode = data.readInt();
            int theFlags = data.readInt();
            int callingUid = data.readInt();
            int callingPid = data.readInt();
            int resultCode = data.readInt();
            Parcel theData = Parcel.obtain();
            Parcel theReply = Parcel.obtain();
            try {
                int sz = (int) data.readLong();
                theData.appendFrom(data, data.dataPosition(), sz);
                theData.setDataPosition(0);
                data.setDataPosition(data.dataPosition() + sz);
                int sz2 = (int) data.readLong();
                if (sz2 != 0) {
                    theReply.appendFrom(data, data.dataPosition(), sz2);
                    theReply.setDataPosition(0);
                }
                result = onPostTransact(target, theCode, theFlags, callingUid, callingPid, theData, sz2 == 0 ? null : theReply, resultCode);
            } finally {
                theData.recycle();
                theReply.recycle();
            }
        } else {
            try {
                return super.onTransact(code, data, reply, flags);
            } catch (RemoteException e) {
                throw new RuntimeException(e);
            }
        }

        if (result instanceof Skip) {
            reply.writeInt(1);
        } else if (result instanceof Continue) {
            reply.writeInt(2);
        } else if (result instanceof OverrideReply) {
            OverrideReply or = (OverrideReply) result;
            reply.writeInt(3);
            reply.writeInt(or.code);
            reply.writeLong(or.reply.dataSize());
            reply.appendFrom(or.reply, 0, or.reply.dataSize());
            or.reply.recycle();
        } else if (result instanceof OverrideData) {
            OverrideData od = (OverrideData) result;
            reply.writeInt(4);
            reply.writeLong(od.data.dataSize());
            reply.appendFrom(od.data, 0, od.data.dataSize());
            od.data.recycle();
        }

        return true;
    }
}
