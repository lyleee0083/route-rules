#!/bin/sh
# Locked startup wrapper; the Go controller owns bounded readiness and restoration.
set -eu
umask 077
directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
settings=/etc/sing-box-state
[ -d "$settings" ] && [ ! -L "$settings" ]
[ -f "$settings/owner" ] && [ ! -L "$settings/owner" ]
# Check the boot-bound receipt before startup. A typed recovery-only result is
# accepted solely so the locked supervisor can restore a validated prior-boot
# journal; activation and same-boot failures remain hard stops.
gate_output=
if gate_output=$("$directory/sb-controller" cache-boot-check 2>&1); then
    gate_status=0
else
    gate_status=$?
fi
case "$gate_status" in
    0) printf '%s\n' "$gate_output" ;;
    2)
        case "$gate_output" in
            *'
'*) echo 'CACHE_GUARD_FAILED: malformed multiline recovery status.' >&2; exit 1;;
            RECOVERY_ONLY:\ REBOOT_REQUIRED:*|RECOVERY_ONLY:\ CACHE_GUARD_FAILED:*) printf '%s\n' "$gate_output" >&2;;
            *) printf '%s\n' "$gate_output" >&2; exit 1;;
        esac
        ;;
    *) printf '%s\n' "$gate_output" >&2; exit "$gate_status";;
esac
for file in service.lock restoration-status service-exit mosdns.pid sing-box.pid core.pid; do
    [ ! -L "$settings/$file" ]
    [ ! -e "$settings/$file" ] || [ -f "$settings/$file" ]
done
if [ "$#" = 0 ]; then
    exec "$directory/sb-controller" service-start
fi
[ "$#" = 1 ] && [ "$1" = --service-lock-held ]
# Descriptor 8 is opened without following links by the controller, not by sh.
flock -n -x 8
exec "$directory/sb-controller" supervise
