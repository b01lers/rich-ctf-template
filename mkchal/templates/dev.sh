#!/bin/sh
set -e
cd -- "$(dirname -- "$0")/deploy"
sudo docker compose up -d --build chall
echo '


If you are testing locally:
> {local_command}'
