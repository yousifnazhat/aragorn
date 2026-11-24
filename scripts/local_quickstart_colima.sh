#!/bin/bash
# Run only against the default *local* Colima Docker socket. Never pull or start a VM.
set -eu
umask 077
die() { printf 'quickstart: %s\n' "$*" >&2; exit 1; }
[[ $(uname -s) == Darwin ]] || die "This launcher targets macOS with Colima."
command -v docker >/dev/null || die "The Docker CLI is required."
repo=$(cd -P -- "$(dirname -- "$0")/.." && pwd -P)
export_leaf=
guest_args=()
if (( $# )); then
    [[ $# == 2 && $1 == --output && -n $2 && $2 != */ ]] || die "Usage: $0 [--output NEW_FILE]"
    export_leaf=${2##*/}
    [[ $export_leaf != . && $export_leaf != .. ]] || die "Choose a new file, not a directory."
    # Keep cwd on the chosen directory through publication, including if its
    # original pathname is renamed. Never pass this path in the Docker argv.
    parent=.
    if [[ $2 == */* ]]; then parent=${2%/*}; fi
    cd -P -- "${parent:-/}" || die "Output directory does not exist."
    case "$PWD/" in "$repo/src/"*|"$repo/examples/local-quickstart/"*) die "Choose an output outside the two read-only source mounts.";; esac
    [[ ! -e "./$export_leaf" && ! -L "./$export_leaf" ]] || die "Output already exists; refusing to overwrite."
    guest_args=(--emit-result)
fi
[[ "$repo" != *,* ]] || die "Use a clone path without commas for Docker bind mounts."
[[ -d "$repo/src/aragorn" && -f "$repo/examples/local-quickstart/coordinator.py" ]] ||
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
printf 'Local Colima quickstart | image %s\n' "$image"
run_guest() {
    "${engine[@]}" run --rm --cidfile "$scratch/cid" --label "$key=$token" \
    --pull=never --network=none --read-only --cap-drop=ALL --cap-add=SETUID --cap-add=SETGID \
    --security-opt=no-new-privileges --user 0:0 --cpus=1 --memory=128m --memory-swap=128m \
    --pids-limit=32 --stop-timeout=3 --ipc=none --log-driver=none \
    --tmpfs /fixture:rw,nosuid,nodev,noexec,size=2m,mode=0755 \
    --mount "type=bind,source=$repo/src,target=/opt/aragorn/src,readonly" \
    --mount "type=bind,source=$repo/examples/local-quickstart,target=/opt/aragorn/example,readonly" \
    --entrypoint /usr/local/bin/python3 "$image" -I -B -S /opt/aragorn/example/coordinator.py "$@"
}
started=1
if [[ -n "$export_leaf" ]]; then
    run_guest "${guest_args[@]}" >"$scratch/result"
else
    run_guest
fi
