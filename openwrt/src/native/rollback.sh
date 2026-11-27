#!/bin/sh
# Explicit uninstall, exact owned files only; preserve conflicts and recovery.
set -eu
umask 077
[ "$#" -ge 1 ] && [ "$#" -le 2 ] && [ "$1" = --rollback-authorized ] || { echo 'Usage: sh rollback.sh --rollback-authorized' >&2; exit 1; }
[ "$#" = 1 ] || [ "$2" = --service-lock-held ]
[ -d /etc/sing-box ] && [ ! -L /etc/sing-box ]
cd /etc/sing-box
[ -d /etc/sing-box-state ] && [ ! -L /etc/sing-box-state ]
[ -f /etc/sing-box-state/owner ] && [ ! -L /etc/sing-box-state/owner ]
[ "$(cat /etc/sing-box-state/owner)" = sing-box-native-v1 ]
for file in service.lock restoration-status service-exit mosdns.pid sing-box.pid core.pid; do
    [ ! -L "/etc/sing-box-state/$file" ]
    [ ! -e "/etc/sing-box-state/$file" ] || [ -f "/etc/sing-box-state/$file" ]
done
sha256sum -c SHA256SUMS
while read -r digest name; do
    case "$digest" in ''|*[!0-9a-f]*) exit 1;; esac
    [ "${#digest}" = 64 ]
    case "$name" in ''|.*|*[!A-Za-z0-9_.-]*|SHA256SUMS|sing-box|mosdns) exit 1;; esac
    [ -f "$name" ] && [ ! -L "$name" ]
done < SHA256SUMS
cmp /etc/init.d/sing-box sing-box.init
if [ "$#" = 1 ]; then
    /etc/init.d/sing-box stop
    # Wait for exit restoration, then exec this uninstall with the safe lock.
    exec ./sb-controller service-rollback
fi
flock -n -x 8
./sb-controller stop
sha256sum -c SHA256SUMS
cmp /etc/init.d/sing-box sing-box.init
for file in mosdns.pid sing-box.pid core.pid; do
    [ ! -e "/etc/sing-box-state/$file" ] && [ ! -L "/etc/sing-box-state/$file" ] || { echo "Runtime PID evidence remains: $file" >&2; exit 1; }
done
for path in /etc/sing-box-state/* /etc/sing-box-state/.[!.]* /etc/sing-box-state/..?*; do
    [ -e "$path" ] || [ -L "$path" ] || continue
    [ -f "$path" ] && [ ! -L "$path" ]
    case "$path" in
        /etc/sing-box-state/owner|/etc/sing-box-state/controller.lock|/etc/sing-box-state/service.lock|/etc/sing-box-state/journal.json|/etc/sing-box-state/service-exit|/etc/sing-box-state/restoration-status|/etc/sing-box-state/connection-cache-receipt.json|/etc/sing-box-state/connection-cache-proof.json) ;;
        *) echo "Recovery or unknown material retained: $path" >&2; exit 1;;
    esac
done
for path in /etc/sing-box/* /etc/sing-box/.[!.]* /etc/sing-box/..?*; do
    [ -e "$path" ] || [ -L "$path" ] || continue
    [ -f "$path" ] && [ ! -L "$path" ]
    name=${path##*/}
    [ "$name" = SHA256SUMS ] || awk -v filename="$name" '$2==filename { found=1 } END { exit !found }' SHA256SUMS || { echo "Unknown runtime file retained: $path" >&2; exit 1; }
done
/etc/init.d/sing-box disable
./sb-controller cache-rollback-clean
rm -f /etc/init.d/sing-box
while read -r digest name; do rm -f "/etc/sing-box/$name"; done < SHA256SUMS
rm -f /etc/sing-box/SHA256SUMS
rmdir /etc/sing-box
rm -f /etc/sing-box-state/owner /etc/sing-box-state/controller.lock /etc/sing-box-state/service.lock /etc/sing-box-state/journal.json /etc/sing-box-state/service-exit /etc/sing-box-state/restoration-status
rmdir /etc/sing-box-state
echo 'SING_BOX_UNINSTALLED: unrelated firewall/DHCP settings and historical backups retained.'
