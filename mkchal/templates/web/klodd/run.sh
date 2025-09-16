#!/bin/sh
set -e
cd deploy
sudo docker build . -t '{name}'
sudo -E docker push '{registry}/{name}'
kubectl create -f challenge.yml
                