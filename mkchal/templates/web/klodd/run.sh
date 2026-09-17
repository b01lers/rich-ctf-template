#!/bin/sh
set -e
cd -- "$(dirname -- "$0")"
sudo docker build src -t '{name}'
sudo -E docker push '{registry}/{name}'
kubectl create -f deploy/challenge.yml
