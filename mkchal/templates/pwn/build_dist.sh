#!/bin/sh

cd $(dirname $0)

# pass user id and group id we want chall build file to have to docker-compose
export USER_ID=$(id -u)
export GROUP_ID=$(id -g)
export CHALL_HASH='{hash}' # please include this envar in your final build

# Don't use sudo to run docker-compose here, you have to add yourself to docker group
# If you need to use sudo, you have to pass options to sudo to make sure
# USER_ID and GROUP_ID env variables are passed into docker-compose
# Otherwise outputed files in dist will be owned by root
cd deploy && sudo -E docker-compose up --build {name}_build
