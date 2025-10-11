#!/bin/sh

cd "$(dirname $0)"

mkdir -p build_out

# pass path of libc and linker so container knows where to copy out from
# configure these if you use arm and it needs to change
LIB_PATH="/srv/lib/x86_64-linux-gnu"
export LIBC_PATH="$LIB_PATH/libc.so.6"
export LINKER_PATH="$LIB_PATH/ld-linux-x86-64.so.2"

# pass user id and group id we want chall build file to have to docker-compose
export USER_ID=$(id -u)
export GROUP_ID=$(id -g)
export CHALL_HASH='{hash}' # please include this envar in your final build

# Don't use sudo to run docker-compose here, you have to add yourself to docker group
# If you need to use sudo, you have to pass options to sudo to make sure
# USER_ID and GROUP_ID env variables are passed into docker-compose
# Otherwise outputed files in dist will be owned by root
cd deploy \
    && sudo -E docker-compose up --build build \
    && sudo -E docker-compose up --build libc
