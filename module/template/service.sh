DEBUG=@DEBUG@

MODDIR=${0%/*}

cd $MODDIR

resetprop "ro.build.version.security_patch" "2025-02-05"

(
while [ true ]; do
  resetprop "ro.build.version.security_patch" "2025-02-05"
  ./daemon
  if [ $? -ne 0 ]; then
    exit 1
  fi
done
) &
