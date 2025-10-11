#!/bin/sh

# builds your challenge
# can be used locally for testing, but is used inside build container

cd "$(dirname $0)"

# by default Dockerfile_build copies chall out to dist
# if multiple build files are desired, copy those as well
gcc sample.c -o chall
