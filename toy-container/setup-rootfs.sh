#!/usr/bin/env bash

set -euo pipefail

rootfs=$(readlink -m "${1:-.rootfs}")

mkdir -p "$rootfs/bin" "$rootfs/proc" "$rootfs/tmp"
install -m 0755 /usr/bin/busybox "$rootfs/bin/busybox"

for applet in cat hostname id ip ls ping ps pwd readlink sh; do
    ln -sfn busybox "$rootfs/bin/$applet"
done

printf 'toy root filesystem ready: %s\n' "$rootfs"
printf 'contents: static BusyBox plus /proc and /tmp mount points\n'
