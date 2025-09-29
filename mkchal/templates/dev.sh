#!/bin/sh
set -e

if command -v docker >/dev/null 2>&1; then
    runner="sudo docker"
elif command -v podman >/dev/null 2>&1; then
    runner="podman"
else
    echo "Docker/Podman not found"
    exit 1
fi

cd -- "$(dirname -- "$0")/deploy"
$runner compose up -d --build chall
echo '


If you are testing locally:
> {local_command}'
