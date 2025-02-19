#!/bin/sh

cd $(dirname $0)

# pass user id and group id we want chall build file to have to docker-compose
export USER_ID=$(id -u)
export GROUP_ID=$(id -g)

cd deploy && sudo docker-compose up {name}_build --build
