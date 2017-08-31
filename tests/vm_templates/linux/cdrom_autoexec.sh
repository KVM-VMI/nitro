#!/usr/bin/env bash

set -e

NAME="cdrom_autoexec.sh"
DEVNAME="/dev/sr0"
MOUNT_POINT="/mnt/cdrom"
AUTOEXEC_SCRIPT="autoexec.sh"

exec 1>/dev/kmsg 2>&1

blkid "$DEVNAME" > /dev/null 2>&1

if [[ "$?" -eq 0 ]]; then
    echo "${NAME}: mounting the device"
    mkdir -p "$MOUNT_POINT"
    mount -o  ro "$DEVNAME" "$MOUNT_POINT" || exit 1

    if [[ -x "${MOUNT_POINT}/${AUTOEXEC_SCRIPT}" ]]; then
        echo "${NAME}: executing ${AUTOEXEC_SCRIPT} from ${MOUNT_POINT}"
        "${MOUNT_POINT}/${AUTOEXEC_SCRIPT}"
        echo "${NAME}: script finished with status code $?"
    fi
else
    echo "${NAME}: unmounting the device"
    umount "$MOUNT_POINT" || exit 1
    rm -rf "$MOUNT_POINT"
fi

