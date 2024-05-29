#!/bin/sh

# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2016-present Datadog, Inc.

set -e
set -x

if [ "$#" -ne "1" ]; then
    echo "Usage: $0 <certs_path>"
    exit 1
fi

VOLUME_NAME="test_tls_certs"
CERTS_DIR="$1"

check_volume_exists() {
    if docker volume ls | grep "$VOLUME_NAME"; then
        echo "Volume already exists. Nothing to do."
        exit 0
    fi
}

create_volume_with_certs() {
    docker volume create "$VOLUME_NAME"
    # Copy content to volume
    docker run --rm -v $CERTS_DIR:/source -v $VOLUME_NAME:/destination alpine sh -c "cp -r /source/* /destination"
    # Change permissions
    docker run --rm -v $VOLUME_NAME:/destination alpine sh -c "chmod -R 644 /destination/*"
}

check_volume_exists
create_volume_with_certs
