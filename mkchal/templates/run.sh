#!/bin/sh
set -e
cd -- "$(dirname -- "$0")/deploy"
if [ -f docker-compose.prod.yml ]; then
	docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build chall
else 
	docker compose up -d --build chall
fi
echo '


If you are on prod or testing server, here is how you connect:
> {remote_command}'
