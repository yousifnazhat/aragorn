#!/bin/sh

# Exact BusyBox 1.37 probe for the pinned Phase 2 gVisor qualification profile.
set -u

fail() {
    printf 'probe setup failed: %s\n' "$1" >&2
    exit 64
}

run_id=${ARAGORN_RUN_ID-}
host_pid=${ARAGORN_HOST_PID-}
case "$run_id" in
    ''|*[!0-9a-f]*) fail 'ARAGORN_RUN_ID is not lowercase hexadecimal' ;;
esac
[ "${#run_id}" -eq 32 ] || fail 'ARAGORN_RUN_ID must contain 32 characters'
case "$host_pid" in
    ''|*[!0-9]*) fail 'ARAGORN_HOST_PID is not decimal' ;;
esac
[ "$host_pid" -gt 0 ] || fail 'ARAGORN_HOST_PID must be positive'

input_path=/aragorn-input/control
input_token=Aragorn-input-$run_id
host_file_path=/aragorn-host-file-$run_id
host_process_token=Aragorn-host-process-$run_id
tcp_loopback_token=Aragorn-tcp-loopback-$run_id
udp_loopback_token=Aragorn-udp-loopback-$run_id
tcp_egress_token=Aragorn-tcp-egress-$run_id
udp_egress_token=Aragorn-udp-egress-$run_id
scratch=/tmp/aragorn-qualification-$run_id

mkdir "$scratch" || fail 'cannot create scratch directory'

uid=$(id -u) || fail 'cannot read uid'
gid=$(id -g) || fail 'cannot read gid'
supplementary_gids=$(
    awk -v primary="$gid" '
        /^Groups:/ {
            separator = ""
            for (field = 2; field <= NF; field++) {
                if ($field != primary) {
                    printf "%s%s", separator, $field
                    separator = ","
                }
            }
        }
    ' /proc/self/status
) || fail 'cannot read supplementary groups'
no_new_privileges=$(
    setpriv --dump | awk -F': ' '$1 == "no_new_privs" {print $2}'
) || fail 'cannot read no-new-privileges'
cap_inheritable=$(awk '$1 == "CapInh:" {print $2}' /proc/self/status)
cap_permitted=$(awk '$1 == "CapPrm:" {print $2}' /proc/self/status)
cap_effective=$(awk '$1 == "CapEff:" {print $2}' /proc/self/status)
cap_bounding=$(awk '$1 == "CapBnd:" {print $2}' /proc/self/status)
cap_ambient=$(awk '$1 == "CapAmb:" {print $2}' /proc/self/status)

tmpfs_path=$scratch/tmpfs-write
printf '%s' "$run_id" > "$tmpfs_path" 2> "$scratch/tmpfs-write.err"
tmpfs_write_rc=$?
tmpfs_read_match=0
[ "$(cat "$tmpfs_path" 2>/dev/null)" = "$run_id" ] && tmpfs_read_match=1
rm -f "$tmpfs_path" 2>> "$scratch/tmpfs-write.err"
tmpfs_removed=0
[ ! -e "$tmpfs_path" ] && tmpfs_removed=1

tcp_received=$scratch/tcp-loopback.received
(timeout 4 nc -n -l -p 39001 > "$tcp_received" 2> "$scratch/tcp-loopback.err") \
    2>/dev/null &
tcp_listener_pid=$!
sleep 1
printf '%s' "$tcp_loopback_token" |
    nc -n -w 2 127.0.0.1 39001 > /dev/null 2>> "$scratch/tcp-loopback.err"
tcp_loopback_send_rc=$?
wait "$tcp_listener_pid" 2>/dev/null
tcp_loopback_listener_rc=$?
tcp_loopback_match=0
[ "$(cat "$tcp_received" 2>/dev/null)" = "$tcp_loopback_token" ] &&
    tcp_loopback_match=1

udp_received=$scratch/udp-loopback.received
(timeout 4 nc -n -u -l -p 39002 > "$udp_received" 2> "$scratch/udp-loopback.err") \
    2>/dev/null &
udp_listener_pid=$!
sleep 1
printf '%s' "$udp_loopback_token" |
    nc -n -u -w 1 127.0.0.1 39002 > /dev/null 2>> "$scratch/udp-loopback.err"
udp_loopback_send_rc=$?
sleep 1
kill "$udp_listener_pid" 2>/dev/null
wait "$udp_listener_pid" 2>/dev/null
udp_loopback_listener_rc=$?
udp_loopback_match=0
[ "$(cat "$udp_received" 2>/dev/null)" = "$udp_loopback_token" ] &&
    udp_loopback_match=1

host_file_visible=0
[ -e "$host_file_path" ] && host_file_visible=1
host_process_visible=0
if [ -r "/proc/$host_pid/cmdline" ] &&
    tr '\000' '\n' < "/proc/$host_pid/cmdline" |
        grep -Fqx "$host_process_token"
then
    host_process_visible=1
fi

non_loopback_interfaces=$(
    awk -F: '
        NR > 2 {
            name = $1
            gsub(/[[:space:]]/, "", name)
            if (name != "lo") count++
        }
        END {print count + 0}
    ' /proc/net/dev
)
ipv4_routes=$(awk 'NR > 1 {count++} END {print count + 0}' /proc/net/route)
printf '%s' "$tcp_egress_token" |
    nc -n -w 1 192.0.2.1 9 > /dev/null 2> "$scratch/tcp-egress.err"
tcp_egress_send_rc=$?
printf '%s' "$udp_egress_token" |
    nc -n -u -w 1 192.0.2.1 9 > /dev/null 2> "$scratch/udp-egress.err"
udp_egress_send_rc=$?

rootfs_path=/aragorn-rootfs-write-$run_id
(printf '%s' "$run_id" > "$rootfs_path") 2> "$scratch/rootfs-write.err"
rootfs_write_rc=$?
rootfs_artifact_present=0
[ -e "$rootfs_path" ] && rootfs_artifact_present=1

input_read_match=0
[ "$(cat "$input_path" 2>/dev/null)" = "$input_token" ] && input_read_match=1
(printf 'mutated' > "$input_path") 2> "$scratch/input-write.err"
input_write_rc=$?
mv "$input_path" "$input_path.moved" 2> "$scratch/input-rename.err"
input_rename_rc=$?
rm "$input_path" 2> "$scratch/input-unlink.err"
input_unlink_rc=$?
input_post_match=0
[ "$(cat "$input_path" 2>/dev/null)" = "$input_token" ] && input_post_match=1

tmpfs_script=$scratch/tmpfs-exec
printf '#!/bin/sh\nexit 0\n' > "$tmpfs_script" 2> "$scratch/tmpfs-exec.err"
tmpfs_script_write_rc=$?
chmod 700 "$tmpfs_script" 2>> "$scratch/tmpfs-exec.err"
"$tmpfs_script" > /dev/null 2>> "$scratch/tmpfs-exec.err"
tmpfs_exec_rc=$?

mkdir "$scratch/mountpoint" 2> "$scratch/mount.err"
mount -t tmpfs none "$scratch/mountpoint" > /dev/null 2>> "$scratch/mount.err"
mount_rc=$?
[ "$mount_rc" -ne 0 ] || umount "$scratch/mountpoint" 2>> "$scratch/mount.err"

unshare -m /bin/true > /dev/null 2> "$scratch/unshare.err"
unshare_rc=$?

device_path=$scratch/device
mknod "$device_path" c 1 3 > /dev/null 2> "$scratch/mknod.err"
mknod_rc=$?
[ "$mknod_rc" -ne 0 ] || rm -f "$device_path"

nsenter -t $$ -S 0 /bin/true > /dev/null 2> "$scratch/setuid.err"
setuid_rc=$?
nsenter -t $$ -G 0 /bin/true > /dev/null 2> "$scratch/setgid.err"
setgid_rc=$?

printf '%s\n' \
    'schema=aragorn/gvisor-backend-qualification-probe-transcript/v1' \
    "run_id=$run_id" \
    "host_pid=$host_pid" \
    "uid=$uid" \
    "gid=$gid" \
    "supplementary_gids=$supplementary_gids" \
    "no_new_privileges=$no_new_privileges" \
    "cap_inheritable=$cap_inheritable" \
    "cap_permitted=$cap_permitted" \
    "cap_effective=$cap_effective" \
    "cap_bounding=$cap_bounding" \
    "cap_ambient=$cap_ambient" \
    "tmpfs_write_rc=$tmpfs_write_rc" \
    "tmpfs_read_match=$tmpfs_read_match" \
    "tmpfs_removed=$tmpfs_removed" \
    "tcp_loopback_send_rc=$tcp_loopback_send_rc" \
    "tcp_loopback_listener_rc=$tcp_loopback_listener_rc" \
    "tcp_loopback_match=$tcp_loopback_match" \
    "udp_loopback_send_rc=$udp_loopback_send_rc" \
    "udp_loopback_listener_rc=$udp_loopback_listener_rc" \
    "udp_loopback_match=$udp_loopback_match" \
    "host_file_visible=$host_file_visible" \
    "host_process_visible=$host_process_visible" \
    "non_loopback_interfaces=$non_loopback_interfaces" \
    "ipv4_routes=$ipv4_routes" \
    "tcp_egress_send_rc=$tcp_egress_send_rc" \
    "udp_egress_send_rc=$udp_egress_send_rc" \
    "rootfs_write_rc=$rootfs_write_rc" \
    "rootfs_artifact_present=$rootfs_artifact_present" \
    "input_read_match=$input_read_match" \
    "input_write_rc=$input_write_rc" \
    "input_rename_rc=$input_rename_rc" \
    "input_unlink_rc=$input_unlink_rc" \
    "input_post_match=$input_post_match" \
    "tmpfs_script_write_rc=$tmpfs_script_write_rc" \
    "tmpfs_exec_rc=$tmpfs_exec_rc" \
    "mount_rc=$mount_rc" \
    "unshare_rc=$unshare_rc" \
    "mknod_rc=$mknod_rc" \
    "setuid_rc=$setuid_rc" \
    "setgid_rc=$setgid_rc"
