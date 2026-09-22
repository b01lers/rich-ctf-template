#!/bin/sh
set -eu

challenge_root="$(cd -- "$(dirname -- "$0")" && pwd)"

if command -v docker >/dev/null 2>&1; then
    runner="docker"
elif command -v podman >/dev/null 2>&1; then
    runner="podman"
else
    echo "Docker/Podman not found"
    exit 1
fi

cd -- "$challenge_root/src"
"$runner" compose --profile build build builder
"$runner" compose --profile build run --rm --no-deps \
    --user "$(id -u):$(id -g)" \
    --volume "$PWD:/out" \
    builder
