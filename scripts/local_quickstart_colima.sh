#!/bin/bash
# Run only against the default *local* Colima Docker socket. Never pull or start a VM.
set -eu
umask 077
unset CDPATH
die() { printf 'quickstart: %s\n' "$*" >&2; exit 1; }
[[ $(uname -s) == Darwin ]] || die "This launcher targets macOS with Colima."
command -v docker >/dev/null || die "The Docker CLI is required."
repo=$(cd -P -- "$(dirname -- "$0")/.." && pwd -P)
usage() { die "Usage: $0 [--output NEW_FILE] [--capability DIR --approve-tree sha256:HEX] | --inventory DIR"; }
cap= inventory= approval= output=
while (( $# )); do
    (( $# >= 2 )) && [[ -n $2 ]] || usage
    case "$1" in
        --inventory) [[ -z $inventory ]] || usage; inventory=$2 ;;
        --capability) [[ -z $cap ]] || usage; cap=$2 ;;
        --approve-tree) [[ -z $approval ]] || usage; approval=$2 ;;
        --output) [[ -z $output ]] || usage; output=$2 ;;
        *) usage ;;
    esac
    shift 2
done
if [[ -n $inventory ]]; then
    [[ -z $cap && -z $approval && -z $output ]] || usage
    cap=$inventory
    set -- --inventory
elif [[ -n $cap || -n $approval ]]; then
    [[ -n $cap && $approval =~ ^sha256:[0-9a-f]{64}$ ]] || usage
    set -- --approve-tree "$approval"
else
    cap="$repo/examples/local-quickstart/capability"
fi
safe_mount_path() {
    # Docker --mount is a CSV argument. Reject ambiguous separators/quoting.
    [[ $1 != *,* && $1 != *'"'* && $1 != *$'\n'* && $1 != *$'\r'* ]]
}
within() {
    # Both paths are physical and absolute. Compare directory identities too:
    # on case-insensitive Mac volumes equivalent paths can have different text.
    local path=$1 root=$2
    while :; do
        [[ $path -ef $root ]] && return 0
        [[ $path != / ]] || return 1
        path=${path%/*}; path=${path:-/}
    done
}
safe_mount_path "$repo" && safe_mount_path "$cap" || die "Unsupported character in a bind mount path."
case "$cap" in /*) ;; *) cap="$PWD/$cap" ;; esac
while [[ $cap != / && ( $cap == */ || $cap == */. ) ]]; do
    if [[ $cap == */. ]]; then cap=${cap%/.}; else cap=${cap%/}; fi
    [[ -n $cap ]] || cap=/
done
[[ ! -L $cap && -d $cap ]] || die "Capability must be a real directory, not a symlink."
cap=$(cd -P -- "$cap" && pwd -P) || die "Cannot access the capability directory."
safe_mount_path "$cap" && [[ $cap != / ]] || die "Unsafe capability mount."
if within "$cap" "$repo/src"; then die "Keep the capability outside the trusted source mount."; fi
# Never nominate a whole home/checkout as a capability mount. The guest
# performs the authoritative bounded inventory on the bytes it actually sees.
/usr/bin/perl -e '
    opendir(my $dir, $ARGV[0]) or exit 1;
    my $n = 0;
    while (defined(my $leaf = readdir $dir)) {
        next if $leaf eq "." || $leaf eq "..";
        exit 1 unless $leaf eq "worker.py" && ++$n == 1;
    }
    exit !($n == 1 && -f "$ARGV[0]/worker.py" && !-l "$ARGV[0]/worker.py");
' "$cap" || die "Capability directory must contain only a regular worker.py."
export_leaf=
if [[ -n $output ]]; then
    [[ $output != */ ]] || die "Choose a new file, not a directory."
    export_leaf=${output##*/}
    [[ $export_leaf != . && $export_leaf != .. ]] || die "Choose a new file, not a directory."
    # Keep cwd on the chosen directory through publication, including if its
    # original pathname is renamed. Never pass this path in the Docker argv.
    parent=.
    if [[ $output == */* ]]; then parent=${output%/*}; fi
    parent=${parent:-/}
    case "$parent" in /*) ;; *) parent="$PWD/$parent" ;; esac
    cd -P -- "$parent" || die "Output directory does not exist."
    if within "$PWD" "$repo/src" || within "$PWD" "$repo/examples/local-quickstart" || within "$PWD" "$cap"; then
        die "Choose an output outside the read-only source and capability mounts."
    fi
    [[ ! -e "./$export_leaf" && ! -L "./$export_leaf" ]] || die "Output already exists; refusing to overwrite."
    set -- "$@" --emit-result
fi
example="$repo/examples/local-quickstart"
[[ -d "$repo/src/aragorn" && -f "$example/coordinator.py" && -f "$example/local_approval.py" ]] ||
    die "Run this script from a complete Aragorn checkout."
socket="$HOME/.colima/default/docker.sock"
[[ -S "$socket" && -O "$socket" && ! -L "$socket" ]] ||
    die "The default Colima Docker socket is unavailable. Start your local Docker-runtime Colima profile first."

# Ignore the selected Docker context and all credential/proxy configuration.
# No host environment variables, Docker socket or writable host paths go to the worker.
unset DOCKER_CONTEXT DOCKER_HOST DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH DOCKER_API_VERSION DOCKER_DEFAULT_PLATFORM
scratch=$(mktemp -d "${TMPDIR:-/tmp}/aragorn-local-quickstart.XXXXXXXX")
key=org.aragorn.local-quickstart
token=${scratch##*/}
engine=(docker --config "$scratch/config" --host "unix://$socket")
started=0
cleanup() {
    local status=$? ids cid
    trap - EXIT HUP INT TERM
    if [[ $started == 1 ]]; then
        # --rm normally wins. Only clean a leftover when the exact CID from our
        # private file is also the sole container bearing this run's label.
        if ids=$("${engine[@]}" ps -aq --no-trunc --filter "label=$key=$token"); then
            if [[ -n "$ids" ]]; then
                cid=''
                [[ ! -f "$scratch/cid" ]] || cid=$(< "$scratch/cid")
                if [[ "$cid" =~ ^[0-9a-f]{64}$ && "$ids" == "$cid" ]]; then
                    "${engine[@]}" rm -f "$cid" >/dev/null || status=1
                    ids=$("${engine[@]}" ps -aq --no-trunc --filter "label=$key=$token") || status=1
                fi
                if [[ -n "$ids" ]]; then
                    printf 'quickstart: leftover container; inspect label %s=%s. Not touching other containers.\n' "$key" "$token" >&2
                    status=1
                fi
            fi
        else
            printf 'quickstart: cannot verify cleanup; inspect local Colima label %s=%s.\n' "$key" "$token" >&2
            status=1
        fi
    fi
    if [[ $status == 0 && -n "$export_leaf" ]]; then
        /usr/bin/perl "$repo/scripts/local_quickstart_publish.pl" "$scratch/result" "./$export_leaf" || status=1
        if [[ $status == 0 ]]; then printf 'Verified result saved: %s/%s\n' "$PWD" "$export_leaf"; fi
    fi
    rm -rf -- "$scratch"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$scratch/config"
"${engine[@]}" version --format '{{.Server.Version}}' >/dev/null ||
    die "Cannot contact the local default Colima Docker daemon."
tag=python:3.12-slim-bookworm
image=$("${engine[@]}" image inspect --format '{{.Id}}' "$tag" 2>/dev/null) ||
    die "No cached $tag image. Load a trusted offline image archive into local Colima with: docker --host unix://$socket load -i /path/to/image.tar"
[[ "$image" =~ ^sha256:[0-9a-f]{64}$ ]] || die "Could not resolve $tag to an immutable local image ID."
if [[ -n $inventory ]]; then
    printf 'Local Colima inventory | image %s\n' "$image" >&2
else
    printf 'Local Colima quickstart | image %s\n' "$image"
fi
run_guest() {
    "${engine[@]}" run --rm --cidfile "$scratch/cid" --label "$key=$token" \
    --pull=never --network=none --read-only --cap-drop=ALL --cap-add=SETUID --cap-add=SETGID \
    --security-opt=no-new-privileges --user 0:0 --cpus=1 --memory=128m --memory-swap=128m \
    --pids-limit=32 --stop-timeout=3 --ipc=none --log-driver=none \
    --tmpfs /fixture:rw,nosuid,nodev,noexec,size=2m,mode=0755 \
    --mount "type=bind,source=$repo/src,target=/opt/aragorn/src,readonly" \
    --mount "type=bind,source=$example/coordinator.py,target=/opt/aragorn/example/coordinator.py,readonly" \
    --mount "type=bind,source=$example/local_approval.py,target=/opt/aragorn/example/local_approval.py,readonly" \
    --mount "type=bind,source=$cap,target=/root/aragorn-capability,readonly" \
    --entrypoint /usr/local/bin/python3 "$image" -I -B -S /opt/aragorn/example/coordinator.py "$@"
}
started=1
if [[ -n "$export_leaf" ]]; then
    run_guest "$@" >"$scratch/result"
else
    run_guest "$@"
fi
