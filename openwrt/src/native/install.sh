#!/bin/sh
# Fresh installation only. No old fw3 migration, service start, firewall reload, or tuning.
set -eu
umask 077
[ "$#" = 1 ] && [ "$1" = --install-authorized ] || { echo 'Usage: sh install.sh --install-authorized' >&2; exit 1; }
cd "$(dirname "$0")"
package_dir=$(pwd -P)
[ "$(uname -m)" = aarch64 ]
for command in fw4 nft ip uci flock ubus jsonfilter sha256sum df du awk stat wc; do command -v "$command" >/dev/null; done
for path in /etc/sing-box /etc/sing-box-state /etc/sing-box-fw3 /etc/sing-box-fw4 /etc/init.d/sing-box /etc/init.d/sb-fw3 /etc/hotplug.d/iface/99-sb-fw3; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || { echo "Existing object requires explicit review: $path" >&2; exit 1; }
done
sha256sum -c SHA256SUMS
[ -f connection-cache.mode ] && [ ! -L connection-cache.mode ] || { echo 'Missing connection cache mode marker.' >&2; exit 1; }
cache_mode=$(cat connection-cache.mode)
cache_mode_bytes=$(wc -c < connection-cache.mode | awk 'NR==1 {print $1}')
case "$cache_mode:$cache_mode_bytes" in
    off-v1:7|ctmark-v1:10) ;;
    *) echo 'Invalid connection cache mode marker; expected exact versioned bytes.' >&2; exit 1;;
esac
[ -f mosdns.json ] && [ ! -L mosdns.json ]
[ -f dns-direct-domains.mdrs ] && [ ! -L dns-direct-domains.mdrs ]
while read -r digest name; do
    case "$digest" in ''|*[!0-9a-f]*) exit 1;; esac
    [ "${#digest}" = 64 ]
    case "$name" in ''|.*|*[!A-Za-z0-9_.-]*|SHA256SUMS|sing-box|mosdns) exit 1;; esac
    [ -f "$name" ] && [ ! -L "$name" ]
done < SHA256SUMS
package_kb=$(du -sk . | awk 'NR==1 {print $1}')
etc_available_kb=$(df -Pk /etc | awk 'NR==2 {print $4}')
case "$package_kb:$etc_available_kb" in
    *[!0-9:]*) echo 'Unable to determine writable flash space.' >&2; exit 1;;
esac
[ "$etc_available_kb" -ge $((package_kb + 1024)) ] || { echo 'Insufficient writable space for runtime files under /etc.' >&2; exit 1; }
[ -f sb-controller ] && [ ! -L sb-controller ]
chmod 700 sb-controller
./sb-controller verify-cores
# Read-only rejection also covers empty retired nft tables and UCI includes.
./sb-controller legacy-check
/usr/bin/sing-box -D . check -c config.json
# Basic installed-tool checks here; full read-only controller preflight runs
# from the installed path before the separate activation command.
nft --version >/dev/null
fw4 print >/dev/null
ip -4 -j rule show >/dev/null
for file in sing-box-service.sh sing-box.init install.sh activate.sh rollback.sh; do sh -n "$file"; done

created_runtime=0
created_state=0
init_stage=
init_identity=
created_owner=0
install_complete=0
cleanup_install() {
    result=$?
    trap - EXIT HUP INT TERM
    if [ "$install_complete" != 1 ]; then
        if [ -n "$init_identity" ] && [ -f /etc/init.d/sing-box ] && [ ! -L /etc/init.d/sing-box ] &&
            [ "$(stat -c '%d:%i' /etc/init.d/sing-box)" = "$init_identity" ] &&
            cmp -s /etc/init.d/sing-box "$package_dir/sing-box.init"; then
            rm -f /etc/init.d/sing-box
        fi
        if [ -n "$init_stage" ] && [ -d /etc/sing-box ] && [ ! -L /etc/sing-box ]; then
            rm -f "$init_stage"
        fi
        if [ "$created_runtime" = 1 ] && [ -d /etc/sing-box ] && [ ! -L /etc/sing-box ]; then
            while read -r digest name; do
                case "$digest" in ''|*[!0-9a-f]*) echo 'Invalid package digest; partial runtime retained for manual review.' >&2; continue;; esac
                [ "${#digest}" = 64 ] || { echo 'Invalid package digest; partial runtime retained for manual review.' >&2; continue; }
                case "$name" in ''|.*|*[!A-Za-z0-9_.-]*|SHA256SUMS|sing-box|mosdns) echo 'Invalid package filename; partial runtime retained for manual review.' >&2; continue;; esac
                path="/etc/sing-box/$name"
                if [ -f "$path" ] && [ ! -L "$path" ]; then
                    if printf '%s  %s\n' "$digest" "$path" | sha256sum -c - >/dev/null 2>&1; then
                        rm -f "$path"
                    else
                        echo "Changed partial runtime file retained for manual review: $path" >&2
                    fi
                fi
            done < "$package_dir/SHA256SUMS"
            if [ -f /etc/sing-box/SHA256SUMS ] && [ ! -L /etc/sing-box/SHA256SUMS ] && cmp -s /etc/sing-box/SHA256SUMS "$package_dir/SHA256SUMS"; then rm -f /etc/sing-box/SHA256SUMS; fi
            rmdir /etc/sing-box 2>/dev/null || echo 'Partial owned runtime directory retained for manual review.' >&2
        fi
        if [ "$created_owner" = 1 ] && [ -f /etc/sing-box-state/owner ] && [ ! -L /etc/sing-box-state/owner ] && [ "$(cat /etc/sing-box-state/owner)" = sing-box-native-v1 ]; then
            rm -f /etc/sing-box-state/owner
        fi
        if [ "$created_state" = 1 ] && [ -d /etc/sing-box-state ] && [ ! -L /etc/sing-box-state ]; then
            rmdir /etc/sing-box-state 2>/dev/null || echo 'Partial owned state directory retained for manual review.' >&2
        fi
    fi
    exit "$result"
}
trap cleanup_install EXIT
trap 'exit 1' HUP INT TERM

mkdir -m 700 /etc/sing-box
created_runtime=1
while read -r digest name; do
    case "$digest" in ''|*[!0-9a-f]*) exit 1;; esac
    [ "${#digest}" = 64 ]
    case "$name" in ''|.*|*[!A-Za-z0-9_.-]*|SHA256SUMS|sing-box|mosdns) exit 1;; esac
    [ -f "$name" ] && [ ! -L "$name" ]
    cp "$name" "/etc/sing-box/$name"
done < SHA256SUMS
cp SHA256SUMS /etc/sing-box/SHA256SUMS
chmod 700 /etc/sing-box/sb-controller /etc/sing-box/sing-box-service.sh
# Prepare the complete executable before publishing the public init path.
[ ! -e /etc/sing-box/.install-init ] && [ ! -L /etc/sing-box/.install-init ]
init_stage=/etc/sing-box/.install-init
cp sing-box.init "$init_stage"
chmod 755 "$init_stage"
init_identity=$(stat -c '%d:%i' "$init_stage")
./sb-controller publish-install-init
rm -f "$init_stage"
init_stage=
mkdir -m 700 /etc/sing-box-state
created_state=1
printf '%s\n' sing-box-native-v1 > /etc/sing-box-state/owner
created_owner=1
cd /etc/sing-box
sha256sum -c "$package_dir/SHA256SUMS"
cmp /etc/init.d/sing-box /etc/sing-box/sing-box.init
payload_sha256=$(sha256sum SHA256SUMS | awk 'NR==1 {print $1}')
case "$payload_sha256" in ''|*[!0-9a-f]*) echo 'Unable to hash installed payload manifest.' >&2; exit 1;; esac
[ "${#payload_sha256}" = 64 ]
./sb-controller stage-cache-receipt --payload-sha256 "$payload_sha256" --owner sing-box-native-v1 --package-version "$cache_mode"
install_complete=1
echo 'SING_BOX_INSTALLED_NOT_ACTIVE: no service enable/start, DNS/routes, or user settings changed.'
