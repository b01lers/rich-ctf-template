#!/bin/sh
set -e
cd -- "$(dirname -- "$0")/deploy"

if command -v docker >/dev/null 2>&1; then
    runner="docker"
elif command -v podman >/dev/null 2>&1; then
    runner="podman"
else
    echo "Docker/Podman not found"
    exit 1
fi

if [ -f docker-compose.prod.yml ]; then
	$runner compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build chall
else
	$runner compose up -d --build chall
fi
echo '


If you are on prod or testing server, here is how you connect:
> {remote_command}'
