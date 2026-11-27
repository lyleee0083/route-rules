#!/bin/sh
# Explicit activation after installation and reviewed native capability checks.
set -eu
umask 077
[ "$#" = 1 ] && [ "$1" = --activate-authorized ] || { echo 'Usage: sh activate.sh --activate-authorized' >&2; exit 1; }
cd /etc/sing-box
[ -f /etc/sing-box-state/owner ] && [ ! -L /etc/sing-box-state/owner ]
[ "$(cat /etc/sing-box-state/owner)" = sing-box-native-v1 ]
cmp /etc/init.d/sing-box /etc/sing-box/sing-box.init
[ -f /usr/bin/sing-box ] && [ ! -L /usr/bin/sing-box ]
[ "$(stat -c '%d:%i' /usr/bin/sing-box)" = "$(stat -c '%d:%i' /etc/sing-box/sing-box)" ] || { echo 'The /usr/bin alias is not the owned sing-box hard link.' >&2; exit 1; }
# This fixed-path, read-only gate must pass before preflight can prepare or
# activation can enable/start any service or alter owned integration.
./sb-controller cache-boot-check
./sb-controller preflight
# This command explicitly owns service start and startup integration, not a
# router reboot, WAN/firewall restart, ECM cache invalidation, or acceptance.
# For ctmark-v1, a receipt staged during this boot fails the gate until reboot.
/etc/init.d/sing-box enable
/etc/init.d/sing-box start
echo 'SING_BOX_START_REQUESTED: inspect startup log and controller state separately.'
