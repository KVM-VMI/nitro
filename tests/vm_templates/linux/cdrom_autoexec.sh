#!/usr/bin/env bash

set -e

MOUNT_POINT="/mnt/cdrom"
AUTOEXEC_SCRIPT="autoexec.sh"

if [[ "$ID_CDROM_MEDIA" -eq 1 ]]; then
    mkdir -p "$MOUNT_POINT"
    mount -t "$ID_FS_TYPE" -o  ro "$DEVNAME" "$MOUNT_POINT" || exit 1

    if [[ -x "${MOUNT_POINT}/${AUTOEXEC_SCRIPT}" ]]; then
        echo "Executing ${AUTOEXEC_SCRIPT} from ${MOUNT_POINT}" 1>&2
        # And here we automatically run scripts from attached CDROMs as root...
        exec "${MOUNT_POINT}/${AUTOEXEC_SCRIPT}"
    fi
else
    umount "$MOUNT_POINT" || exit 1
    rm -rf "$MOUNT_POINT"
fi

