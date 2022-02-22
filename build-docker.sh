#!/usr/bin/env bash

docker build -t fobnail/fobnail-attester .

docker run \
    --rm \
    -v $PWD:/build \
    -w /build \
    -e USER_ID="$(id -u)" \
    -e GROUP_ID="$(id -g)" \
    --init \
    fobnail/fobnail-attester "make"
